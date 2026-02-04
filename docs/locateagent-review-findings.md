# LocateAgent() Review Findings

**File**: [agent_utils.go:99-414](../v2/agent_utils.go#L99-L414)
**Date**: 2026-02-04
**Reviewer**: Claude Code
**Status**: Phase 2 - Review Complete

## Executive Summary

The `LocateAgent()` function performs asynchronous DNS-based discovery of remote agents. While the overall design is sound, there are several **critical concurrency issues** and **race conditions** that can lead to incomplete discovery, goroutine leaks, and unpredictable behavior. The function launches multiple nested goroutines with no coordination or completion tracking, making it difficult to determine when discovery is actually complete.

**Risk Level**: HIGH - Production deployment not recommended without fixes

---

## Critical Issues

### Issue 1: Uncoordinated Parallel Goroutines with No Completion Tracking

**Location**: Lines 175-336

**Problem**:
The function launches 5 separate goroutines for DNS lookups (API URI, DNS URI, API SVCB, DNS SVCB, KEY, TLSA) with **no synchronization** or completion tracking. Each goroutine:
- Runs independently and updates the `agent` struct via mutex
- Has no way to signal completion
- Has no coordination with other goroutines
- May fail silently (just logs and returns)

The main loop checks completion at line 338-354, but this check happens **immediately** after launching the goroutines, before they've had time to complete. This is a classic race condition.

**Code Example**:
```go
// Lines 175-198: Launch API URI goroutine
go func() {
    qname := string("_https._tcp." + remoteid)
    rrset, err := RecursiveDNSQueryWithServers(qname, dns.TypeURI, timeout, retries, resolvers)
    if err != nil {
        log.Printf("...")
        return  // ← Failure not reported to caller
    }
    // ... update agent.ApiDetails.UriRR
}()

// Lines 338-354: Immediately check completion (race!)
agent.mu.Lock()
if agent.ApiDetails.UriRR != nil && agent.ApiDetails.TlsaRR != nil && len(agent.ApiDetails.Addrs) > 0 {
    agent.ApiDetails.ContactInfo = "complete"
    // ... but goroutines above may not have run yet!
}
agent.mu.Unlock()
```

**Impact**:
- Discovery may be marked "complete" before DNS lookups actually finish
- Subsequent retry loop iterations may re-launch goroutines (goroutine leak)
- Race conditions lead to unpredictable behavior
- No guarantee that all required records are discovered

**Proposed Fix**:
Use `sync.WaitGroup` to track goroutine completion:

```go
var wg sync.WaitGroup
lookupErrors := make([]error, 0)
var errMu sync.Mutex

// Launch API URI lookup
if agent.ApiDetails.UriRR == nil {
    wg.Add(1)
    go func() {
        defer wg.Done()
        qname := string("_https._tcp." + remoteid)
        rrset, err := RecursiveDNSQueryWithServers(...)
        if err != nil {
            errMu.Lock()
            lookupErrors = append(lookupErrors, fmt.Errorf("API URI lookup: %w", err))
            errMu.Unlock()
            return
        }
        // ... update agent
    }()
}

// ... repeat for other lookups

// Wait for all lookups to complete
wg.Wait()

// Now check completion with all data available
agent.mu.Lock()
if agent.ApiDetails.UriRR != nil && agent.ApiDetails.TlsaRR != nil && len(agent.ApiDetails.Addrs) > 0 {
    agent.ApiDetails.ContactInfo = "complete"
}
agent.mu.Unlock()
```

---

### Issue 2: Infinite Loop with No Escape on Permanent Failure

**Location**: Lines 153-413

**Problem**:
The discovery goroutine runs in an infinite `for` loop that only exits when `agent.ApiDetails.State == AgentStateKnown` (line 360). However:

1. If DNS records don't exist or are permanently misconfigured, the loop will retry **forever**
2. The only sleep is at line 409: `time.Sleep(time.Duration(ar.LocateInterval) * time.Second)`
3. No maximum retry count or timeout
4. No way to cancel discovery externally (no context.Context parameter)

**Impact**:
- Goroutine leak: discovery goroutine runs forever for non-existent agents
- Resource consumption: repeated DNS queries forever
- No way to clean up stale discoveries
- Agent registry fills with "NEEDED" agents that will never become "KNOWN"

**Proposed Fix**:
Add maximum retry count and context-based cancellation:

```go
func (ar *AgentRegistry) LocateAgent(ctx context.Context, remoteid AgentId, zonename ZoneName, deferredTask *DeferredAgentTask) {
    // ... initialization ...

    go func() {
        maxRetries := 10 // or configurable
        retryCount := 0

        for {
            select {
            case <-ctx.Done():
                log.Printf("LocateAgent: discovery cancelled for %s: %v", remoteid, ctx.Err())
                agent.mu.Lock()
                agent.State = AgentStateError
                agent.ErrorMsg = fmt.Sprintf("discovery cancelled: %v", ctx.Err())
                agent.mu.Unlock()
                return
            default:
            }

            // ... perform DNS lookups ...

            if agent.ApiDetails.State == AgentStateKnown {
                // Success, exit
                return
            }

            retryCount++
            if retryCount >= maxRetries {
                log.Printf("LocateAgent: max retries reached for %s", remoteid)
                agent.mu.Lock()
                agent.State = AgentStateError
                agent.ErrorMsg = fmt.Sprintf("discovery failed after %d retries", maxRetries)
                agent.mu.Unlock()
                return
            }

            log.Printf("LocateAgent: retry %d/%d for %s", retryCount, maxRetries, remoteid)
            time.Sleep(time.Duration(ar.LocateInterval) * time.Second)
        }
    }()
}
```

**Breaking Change Note**: This changes the function signature to add `context.Context`. All callers must be updated.

---

### Issue 3: Race Condition in SVCB/KEY/TLSA Lookups

**Location**: Lines 231-336

**Problem**:
The SVCB, KEY, and TLSA lookups depend on data from the URI lookups (specifically `Host` field):

```go
// Line 233: Read tmpniluri
agent.mu.RLock()
tmpniluri = agent.ApiDetails.UriRR == nil
tmpaddrs := agent.ApiDetails.Addrs
agent.mu.RUnlock()

// Line 236: Launch SVCB lookup using agent.ApiDetails.BaseUri
if tmpniluri && len(tmpaddrs) == 0 {
    go func() {
        _, addrs, port, targetName, err := FetchSVCB(agent.ApiDetails.BaseUri, ...) // ← RACE!
        // ...
    }()
}
```

The problem:
1. Check `tmpniluri` (line 233)
2. If true, launch goroutine (line 237)
3. Inside goroutine, read `agent.ApiDetails.BaseUri` (line 238)
4. **But** `BaseUri` may still be nil/empty when the goroutine runs!

The check at line 236 (`tmpniluri && len(tmpaddrs) == 0`) prevents launching if URI exists, but the SVCB goroutine reads `BaseUri` directly without re-checking. If the URI goroutine hasn't completed yet, `BaseUri` will be empty.

**Impact**:
- SVCB lookup may fail because `BaseUri` is still empty
- Similar issue for KEY lookup (line 282) and TLSA lookup (line 314)
- Dependent lookups may never execute successfully
- Discovery may get stuck in retry loop

**Proposed Fix**:
Capture the required data **before** launching the goroutine:

```go
agent.mu.RLock()
baseUri := agent.ApiDetails.BaseUri
tmpniluri := agent.ApiDetails.UriRR == nil
tmpaddrs := agent.ApiDetails.Addrs
agent.mu.RUnlock()

if !tmpniluri && baseUri != "" && len(tmpaddrs) == 0 {
    wg.Add(1)
    go func(uri string) {  // Pass as parameter
        defer wg.Done()
        _, addrs, port, targetName, err := FetchSVCB(uri, resolvers, timeout, retries)
        // ...
    }(baseUri)  // Pass value, not reference
}
```

---

### Issue 4: Missing JWK Record Lookup

**Location**: Entire function (lines 99-414)

**Problem**:
The function does **not** look up JWK records for public key discovery. It only looks up:
- URI records (_https._tcp, _dns._tcp) ✓
- SVCB records ✓
- KEY records (SIG(0) for DNS transport) ✓
- TLSA records (TLS cert for API transport) ✓
- **JWK records - MISSING** ✗

This is critical because the purpose of this implementation plan is to add JWK-based discovery.

**Impact**:
- No long-term public key discovery
- Cannot establish secure communication using JWK keys
- Discovery is incomplete for the intended use case

**Proposed Fix**:
Add JWK lookup similar to KEY lookup:

```go
// Look up JWK record for long-term public key
agent.mu.RLock()
tmpniljwk := agent.ApiDetails.JWK == nil  // or agent.DnsDetails.JWK
tmpidentity := string(remoteid)
agent.mu.RUnlock()

if tmpniljwk {
    wg.Add(1)
    go func(identity string) {
        defer wg.Done()
        qname := dns.Fqdn(identity)
        rrset, err := RecursiveDNSQueryWithServers(qname, dns.TypeJWK, timeout, retries, resolvers)
        if err != nil {
            log.Printf("LocateAgent: error response to JWK query for %s: %v", qname, err)
            return
        }

        if rrset == nil {
            log.Printf("LocateAgent: no JWK record found for %s", qname)
            return
        }

        for _, rr := range rrset.RRs {
            if jwk, ok := rr.(*dns.JWK); ok {
                log.Printf("LocateAgent: JWK record for %q: %s", identity, jwk.String())
                agent.mu.Lock()
                agent.ApiDetails.JWK = jwk  // Add JWK field to AgentDetails
                agent.mu.Unlock()
                break
            }
        }
    }(tmpidentity)
}
```

**Note**: `AgentDetails` struct needs a new `JWK *dns.JWK` field.

---

## Major Issues

### Issue 5: No Integration with TransportManager PeerRegistry

**Location**: Lines 381-383

**Problem**:
The function calls `ar.TransportManager.OnAgentDiscoveryComplete(agent)` but:
1. This callback is not visible in the provided code
2. No guarantee that the agent is registered in `PeerRegistry`
3. Discovery result is not converted to `AgentDiscoveryResult` format
4. Integration with `RegisterDiscoveredAgent()` (from agent_discovery.go) is unclear

**Impact**:
- Inconsistent agent registration between AgentRegistry and PeerRegistry
- TransportManager may not be aware of discovered agents
- Breaks integration goal of "single discovery mechanism"

**Proposed Fix**:
Call `RegisterDiscoveredAgent()` explicitly:

```go
// After agent is KNOWN
if agent.ApiDetails.State == AgentStateKnown {
    agent.mu.Lock()
    agent.State = AgentStateKnown
    agent.LastState = time.Now()
    agent.mu.Unlock()

    // Register with TransportManager's PeerRegistry
    if ar.TransportManager != nil {
        result := &AgentDiscoveryResult{
            Identity:  string(remoteid),
            APIUri:    agent.ApiDetails.BaseUri,
            DNSUri:    agent.DnsDetails.BaseUri,
            PublicKey: agent.DnsDetails.KeyRR,  // TODO: Replace with JWK
            TLSA:      agent.ApiDetails.TlsaRR,
            Addresses: agent.ApiDetails.Addrs,
            Port:      agent.ApiDetails.Port,
        }
        err := ar.TransportManager.RegisterDiscoveredAgent(result)
        if err != nil {
            log.Printf("LocateAgent: failed to register agent with TransportManager: %v", err)
        }
    }

    // ... rest of the code
}
```

---

### Issue 6: State Transition Logic Incomplete

**Location**: Lines 338-364

**Problem**:
State transitions are inconsistent:

1. Line 343: `agent.ApiDetails.State = AgentStateKnown` (detail state)
2. Line 350: `agent.DnsDetails.State = AgentStateKnown` (detail state)
3. Line 362: `agent.State = AgentStateKnown` (overall state)

But:
- Overall `agent.State` only set if `ApiDetails.State == AgentStateKnown`
- If only DNS transport is available, agent never becomes "KNOWN"
- Lines 358-360: Only checks `tmpstate := agent.ApiDetails.State`, ignores `DnsDetails.State`

**Code**:
```go
// Line 357-364: Only checks API state!
agent.mu.RLock()
tmpstate := agent.ApiDetails.State
agent.mu.RUnlock()
if tmpstate == AgentStateKnown {
    agent.mu.Lock()
    agent.State = AgentStateKnown
    // ...
}
```

**Impact**:
- DNS-only agents never become operational
- Transport fallback doesn't work correctly
- Bias toward API transport even if DNS is preferred

**Proposed Fix**:
Check both transports:

```go
agent.mu.RLock()
apiState := agent.ApiDetails.State
dnsState := agent.DnsDetails.State
agent.mu.RUnlock()

// Agent is KNOWN if either transport is complete
if apiState == AgentStateKnown || dnsState == AgentStateKnown {
    agent.mu.Lock()
    agent.State = AgentStateKnown
    agent.LastState = time.Now()
    agent.mu.Unlock()

    // Prefer API, but create client for whatever is available
    if apiState == AgentStateKnown {
        err := agent.NewAgentSyncApiClient(ar.LocalAgent)
        // ...
    }

    // DNS client setup would go here (not visible in current code)

    // ... continue with Hello
    return
}
```

---

### Issue 7: Error Handling Does Not Propagate

**Location**: Lines 178-335 (all goroutines)

**Problem**:
All DNS lookup goroutines handle errors by:
```go
if err != nil {
    log.Printf("...")
    return  // ← Error silently discarded
}
```

There is **no way** for the caller or the main loop to know:
- Which lookups failed
- Why they failed
- Whether to retry or give up

The agent remains in `AgentStateNeeded` forever, and the loop retries indefinitely.

**Impact**:
- Cannot distinguish between "no records published" and "DNS query failed"
- Cannot provide meaningful error messages to user
- Debugging is difficult (must read logs)
- No programmatic error handling

**Proposed Fix**:
Collect errors and set agent to error state after max retries:

```go
var lookupErrors []error
var errMu sync.Mutex

go func() {
    defer wg.Done()
    rrset, err := RecursiveDNSQueryWithServers(...)
    if err != nil {
        errMu.Lock()
        lookupErrors = append(lookupErrors, fmt.Errorf("API URI lookup: %w", err))
        errMu.Unlock()
        return
    }
    // ...
}()

// After wg.Wait()
if len(lookupErrors) > 0 {
    log.Printf("LocateAgent: DNS lookup errors for %s: %v", remoteid, lookupErrors)
    // If all critical lookups failed, may want to set error state
}
```

---

### Issue 8: `HelloRetrierNG()` Started Without Checking Prerequisites

**Location**: Lines 389-402

**Problem**:
After the agent becomes `AgentStateKnown`, the code starts `HelloRetrierNG()`:

```go
if zonename != "" {
    ar.AddZoneToAgent(remoteid, zonename)
    ctx, cancel := context.WithCancel(context.Background())
    ar.mu.Lock()
    if existingCancel, exists := ar.helloContexts[remoteid]; exists {
        existingCancel()
    }
    ar.helloContexts[remoteid] = cancel
    ar.mu.Unlock()
    go ar.HelloRetrierNG(ctx, agent)
}
```

**Issues**:
1. `HelloRetrierNG()` is started **only if** `zonename != ""` - but what if multiple zones share this agent?
2. No check if agent has necessary transport configured (API client, DNS client)
3. `NewAgentSyncApiClient()` error at line 367 is logged but doesn't prevent Hello
4. If API client creation failed, Hello will also fail

**Impact**:
- Hello may be sent even though transport is not ready
- Hello will fail, triggering retries unnecessarily
- Zone-specific behavior inconsistent

**Proposed Fix**:
Check transport readiness before starting Hello:

```go
if zonename != "" {
    ar.AddZoneToAgent(remoteid, zonename)

    // Verify transport is ready
    if agent.Api == nil && agent.DnsDetails.KeyRR == nil {
        log.Printf("LocateAgent: agent %s has no working transport, cannot send Hello", remoteid)
        agent.mu.Lock()
        agent.State = AgentStateError
        agent.ErrorMsg = "no working transport available"
        agent.mu.Unlock()
        return
    }

    // Start Hello retrier
    ctx, cancel := context.WithCancel(context.Background())
    ar.mu.Lock()
    if existingCancel, exists := ar.helloContexts[remoteid]; exists {
        existingCancel()
    }
    ar.helloContexts[remoteid] = cancel
    ar.mu.Unlock()

    go ar.HelloRetrierNG(ctx, agent)
}
```

---

## Minor Issues

### Issue 9: Inefficient Mutex Usage

**Location**: Throughout function (multiple Read-Modify-Write sequences)

**Problem**:
Many sequences like:
```go
agent.mu.RLock()
tmpniluri := agent.ApiDetails.UriRR == nil
agent.mu.RUnlock()
if tmpniluri {
    // ...
}
```

This pattern is correct but verbose. More problematic:

```go
// Line 171-173: RLock → read → RUnlock
agent.mu.RLock()
tmpniluri := agent.ApiDetails.UriRR == nil
agent.mu.RUnlock()

// Line 175: Launch goroutine
if tmpniluri {
    go func() {
        // Line 191-195: Lock → write → Unlock
        agent.mu.Lock()
        agent.ApiDetails.UriRR = u
        agent.ApiDetails.BaseUri = u.Target
        agent.mu.Unlock()
    }()
}

// Line 201-203: RLock → read → RUnlock (check same field again!)
agent.mu.RLock()
tmpniluri = agent.DnsDetails.UriRR == nil
agent.mu.RUnlock()
```

**Impact**:
- Many lock/unlock cycles
- Not a correctness issue, but could be optimized
- Repeated checks of same fields

**Proposed Fix** (low priority):
Batch reads under single lock:

```go
agent.mu.RLock()
apiUriNil := agent.ApiDetails.UriRR == nil
dnsUriNil := agent.DnsDetails.UriRR == nil
apiAddrs := agent.ApiDetails.Addrs
dnsAddrs := agent.DnsDetails.Addrs
apiHost := agent.ApiDetails.Host
// ... etc
agent.mu.RUnlock()

// Now launch goroutines based on captured state
```

---

### Issue 10: Commented-Out Code Should Be Removed

**Location**: Lines 144-151, 165-168

**Problem**:
Large blocks of commented-out code:

```go
// lagent := agent.CleanCopy()
//	tmp := SanitizeForJSON(agent)
//	var lagent *Agent
//	var ok bool
//	if lagent, ok = tmp.(*Agent); !ok {
//		log.Printf("LocateAgent: error: failed to assert tmp agent to *Agent")
//		return
//	}
```

And:
```go
// Look up URIs for both transports
// for _, transport := range []string{"DNS", "API"} {
//	details := lagent.Details[transport]
// var targetName string
```

**Impact**:
- Code maintenance confusion
- Suggests incomplete refactoring
- Makes code harder to read

**Proposed Fix**:
Remove commented code or convert to TODO comments if it represents unfinished work.

---

### Issue 11: DNS Query Parameters Not Configurable

**Location**: Lines 157-163

**Problem**:
DNS query parameters are hardcoded:

```go
resolverAddress := viper.GetString("resolver.address")
if Globals.Debug {
    log.Printf("LocateAgent: using debug resolver %s", resolverAddress)
}
resolvers := []string{resolverAddress}
timeout := 2 * time.Second
retries := 3
```

Issues:
1. Only uses single resolver from config
2. Timeout and retries are hardcoded (not configurable)
3. No fallback to system resolvers if config resolver fails

**Impact**:
- Limited flexibility
- Cannot adjust timeouts for different network conditions
- Single point of failure for DNS resolution

**Proposed Fix**:
Make parameters configurable:

```go
resolverAddress := viper.GetString("agent.discovery.resolver")
if resolverAddress == "" {
    resolverAddress = "8.8.8.8:53"  // fallback
}
resolvers := []string{resolverAddress}

timeout := viper.GetDuration("agent.discovery.timeout")
if timeout == 0 {
    timeout = 5 * time.Second
}

retries := viper.GetInt("agent.discovery.retries")
if retries == 0 {
    retries = 3
}
```

---

### Issue 12: No Metrics or Observability

**Location**: Entire function

**Problem**:
The function only logs messages, with no:
- Prometheus metrics for discovery success/failure rate
- Discovery latency measurements
- Counter for DNS query attempts
- Gauge for agents in each state

**Impact**:
- Difficult to monitor discovery health in production
- Cannot alert on discovery failures
- No visibility into performance

**Proposed Fix** (future enhancement):
Add metrics:

```go
var (
    discoveryAttempts = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "agent_discovery_attempts_total",
            Help: "Total number of agent discovery attempts",
        },
        []string{"agent", "result"},
    )

    discoveryDuration = promauto.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "agent_discovery_duration_seconds",
            Help: "Agent discovery duration in seconds",
        },
        []string{"agent"},
    )
)

// In LocateAgent()
startTime := time.Now()
defer func() {
    duration := time.Since(startTime).Seconds()
    discoveryDuration.WithLabelValues(string(remoteid)).Observe(duration)

    result := "success"
    if agent.State == AgentStateError {
        result = "error"
    }
    discoveryAttempts.WithLabelValues(string(remoteid), result).Inc()
}()
```

---

## Recommendations

### Immediate Actions (Before Integration)

1. **Fix Issue 1 (Critical)**: Add `sync.WaitGroup` to coordinate parallel goroutines
2. **Fix Issue 2 (Critical)**: Add context.Context parameter for cancellation and max retry limit
3. **Fix Issue 3 (Critical)**: Fix race conditions in dependent lookups
4. **Fix Issue 6 (Major)**: Support DNS-only agents (check both transport states)
5. **Fix Issue 7 (Major)**: Propagate errors properly

### Integration Phase Actions

6. **Fix Issue 4 (Critical)**: Add JWK record lookup
7. **Fix Issue 5 (Major)**: Integrate with `RegisterDiscoveredAgent()`
8. **Fix Issue 8 (Major)**: Check transport readiness before Hello

### Cleanup Actions

9. **Fix Issue 10 (Minor)**: Remove commented-out code
10. **Fix Issue 11 (Minor)**: Make DNS parameters configurable
11. **Fix Issue 9 (Minor)**: Optimize mutex usage (low priority)
12. **Fix Issue 12 (Minor)**: Add observability (future enhancement)

---

## Refactoring Strategy

Given the number of issues, consider **rewriting** `LocateAgent()` rather than patching:

### Proposed New Structure

```go
func (ar *AgentRegistry) LocateAgent(ctx context.Context, remoteid AgentId, zonename ZoneName, deferredTask *DeferredAgentTask) error {
    // 1. Validation and early returns
    // 2. Initialize agent
    // 3. Launch discovery goroutine with proper coordination
    // 4. Discovery goroutine:
    //    a. Use WaitGroup for parallel lookups
    //    b. Call common helper functions (from agent_discovery_common.go)
    //    c. Check context cancellation
    //    d. Enforce max retries
    //    e. Collect and report errors
    //    f. Transition states correctly
    //    g. Register with both AgentRegistry and PeerRegistry
    //    h. Start Hello only if transport ready
}
```

### Use Common Helpers

Extract to `agent_discovery_common.go`:
- `lookupAgentAPIURI(ctx, identity, resolvers) (*dns.URI, error)`
- `lookupAgentDNSURI(ctx, identity, resolvers) (*dns.URI, error)`
- `lookupAgentJWK(ctx, identity, resolvers) (*dns.JWK, error)`
- `lookupAgentTLSA(ctx, identity, port, resolvers) (*dns.TLSA, error)`
- `lookupAgentKEY(ctx, identity, resolvers) (*dns.KEY, error)`
- `lookupAgentAddresses(ctx, identity, resolvers) ([]string, error)`
- `lookupAgentSVCB(ctx, baseUri, resolvers) ([]string, uint16, string, error)`

This makes `LocateAgent()` much simpler and testable.

---

## Testing Requirements

After fixes, `LocateAgent()` must be tested for:

1. **Success Cases**:
   - Agent with API transport only
   - Agent with DNS transport only
   - Agent with both transports
   - Multiple agents discovered concurrently

2. **Failure Cases**:
   - Agent with no DNS records (should error after max retries)
   - Agent with partial records (should stay in retry loop or error)
   - DNS query failures (should retry and eventually error)
   - Context cancellation (should stop immediately)

3. **Edge Cases**:
   - Self-identification (should skip)
   - Agent already in registry (should not re-discover)
   - Multiple zones referencing same agent
   - Concurrent `LocateAgent()` calls for same agent

4. **Concurrency**:
   - No goroutine leaks
   - No race conditions (run with `-race` flag)
   - Proper mutex usage

---

## Estimated Effort

**Complexity**: High
**Risk**: High (core discovery functionality)
**Approach**: Rewrite recommended over incremental fixes

**Breakdown**:
1. Write common discovery helpers: Medium
2. Rewrite `LocateAgent()` with proper coordination: Large
3. Update all callers (add context.Context): Medium
4. Add comprehensive tests: Large
5. Integration with RegisterDiscoveredAgent(): Medium

**Total**: Large effort (requires careful design and extensive testing)

---

## Conclusion

The `LocateAgent()` function has **fundamental concurrency issues** that prevent reliable discovery. While the overall approach is sound, the implementation has critical race conditions and lacks proper goroutine coordination.

**Recommendation**: Rewrite the function using common discovery helpers (Phase 3 of the implementation plan) rather than attempting to patch the existing code. This will result in cleaner, more maintainable, and more reliable code.

The refactored version should:
- Use `sync.WaitGroup` for goroutine coordination
- Accept `context.Context` for cancellation
- Call shared helper functions for DNS lookups
- Add JWK record lookup
- Integrate with `RegisterDiscoveredAgent()`
- Support both API and DNS transports equally
- Properly propagate errors
- Enforce maximum retry limits
- Transition states correctly
- Include comprehensive tests

---

## Next Steps

1. ✅ Complete this review (DONE)
2. → Proceed to Phase 1: Implement JWK RRtype
3. → Return to Phase 2: Apply fixes from this review
4. → Proceed to Phase 3: Extract common helpers and integrate discovery paths
5. → Phase 4: Auto-publication
6. → Phase 5: Testing

---

## References

- [agent_utils.go](../v2/agent_utils.go) - Current implementation
- [agent_discovery.go](../v2/agent_discovery.go) - Newer synchronous implementation
- [Implementation Plan](jwk-discovery-implementation-plan.md) - Overall project plan
- Go concurrency patterns: https://go.dev/blog/pipelines
- Effective Go - Concurrency: https://go.dev/doc/effective_go#concurrency
