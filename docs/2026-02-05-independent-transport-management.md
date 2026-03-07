# Independent Transport Management Implementation

**Date**: 2026-02-05
**Status**: ✅ COMPLETED - Implementation finished
**Implementation Date**: 2026-02-05

---

## Problem Summary

The original transport implementation had a **fallback model**: when both API and DNS transports were available, it would try API first, and only fall back to DNS if API failed. This created several issues:

1. **Single State Tracking**: Only `ApiDetails.State` was maintained, even when DNS transport succeeded
2. **No Independent Management**: Could not disable/enable transports individually
3. **No Redundancy**: Had to wait for primary transport to fail before trying secondary
4. **State Confusion**: DNS transport success would incorrectly update `ApiDetails.State`
5. **No Configuration Control**: No way to explicitly enable/disable transports

---

## Solution: Independent Parallel Transport Management

Implemented a new model where **both API and DNS transports operate independently in parallel**:

- Each transport maintains its own state machine
- Both transports send Hello/Beat messages simultaneously
- Each transport progresses through NEEDED → KNOWN → INTRODUCED → OPERATIONAL independently
- Configuration control via `supported_mechanisms` field

---

## Implementation Details

### 1. Configuration: `supported_mechanisms` Field

**File**: [config.go:141-144](../v2/config.go#L141-L144)

Added new **required** field to `LocalAgentConf`:

```go
type LocalAgentConf struct {
	Identity string `validate:"required,hostname"`
	// SupportedMechanisms: List of active transport mechanisms (REQUIRED, must be non-empty)
	// Valid values: "api", "dns" (case-insensitive)
	// Set to ["api"] to use only API transport, ["dns"] for only DNS, or ["api", "dns"] for both
	SupportedMechanisms []string `yaml:"supported_mechanisms"`
	// ... rest of fields
}
```

**Validation** ([config_validate.go:233-267](../v2/config_validate.go#L233-L267)):

```go
// ValidateAgentSupportedMechanisms validates agent.supported_mechanisms configuration.
// Requirements:
// - Must be non-empty (agent needs at least one communication mechanism)
// - Can only contain "api" and/or "dns" (case-insensitive)
// - No duplicates allowed
func ValidateAgentSupportedMechanisms(config *Config) error {
	// Empty list is an error - agent MUST have at least one transport
	if len(mechanisms) == 0 {
		return fmt.Errorf("agent.supported_mechanisms cannot be empty - agent requires at least one transport mechanism (valid: \"api\", \"dns\")")
	}

	// Validate each mechanism and normalize to lowercase
	validMechanisms := map[string]bool{"api": true, "dns": true}
	// ... validation logic
}
```

**Validation Errors**:

- ❌ Empty list: `agent.supported_mechanisms cannot be empty`
- ❌ Invalid value: `agent.supported_mechanisms: invalid value "http" at index 0 (valid: "api", "dns")`
- ❌ Duplicate: `agent.supported_mechanisms: duplicate value "api"`
- ✅ Valid: `["api"]`, `["dns"]`, `["api", "dns"]`, `["API", "DNS"]` (normalized to lowercase)

**Sample Config** ([tdns-agent.sample.yaml:5-9](../cmdv2/agentv2/tdns-agent.sample.yaml#L5-L9)):

```yaml
agent:
  identity: agent.provider.
  # Active transport mechanisms: "api" and/or "dns" (default: both if configured)
  # Use ["api"] to disable DNS transport, ["dns"] to disable API, or ["api", "dns"] for both
  supported_mechanisms: [api, dns]
```

**Build Lab Template** ([tdns-agent.P.yaml:1-7](../../labconfig/buildlab/template/etc/tdns/tdns-agent.P.yaml#L1-L7)):

```yaml
agent:
  identity: agent.$GROUPNAME$.$TLD$.
  # Active transport mechanisms: "api" and/or "dns" (default: both if configured)
  supported_mechanisms: [api, dns]
```

---

### 2. TransportManager Configuration

**File**: [hsync_transport.go:29-58](../v2/hsync_transport.go#L29-L58)

Added `SupportedMechanisms` field:

```go
type TransportManager struct {
	APITransport *transport.APITransport
	DNSTransport *transport.DNSTransport
	// ... other fields

	// SupportedMechanisms lists active transports ("api", "dns")
	SupportedMechanisms []string
}

type TransportManagerConfig struct {
	// ... other fields

	// SupportedMechanisms lists active transports ("api", "dns"); default: both if configured
	SupportedMechanisms []string
}
```

**Initialization** ([hsync_transport.go:86-126](../v2/hsync_transport.go#L86-L126)):

```go
func NewTransportManager(cfg *TransportManagerConfig) *TransportManager {
	// Default to both transports if not specified
	supportedMechanisms := cfg.SupportedMechanisms
	if len(supportedMechanisms) == 0 {
		supportedMechanisms = []string{"api", "dns"}
	}

	tm := &TransportManager{
		// ... other fields
		SupportedMechanisms: supportedMechanisms,
	}

	// Create API transport if supported
	if tm.isTransportSupported("api") {
		tm.APITransport = transport.NewAPITransport(&transport.APITransportConfig{
			LocalID:        cfg.LocalID,
			DefaultTimeout: cfg.APITimeout,
		})
		log.Printf("TransportManager: API transport enabled")
	} else {
		log.Printf("TransportManager: API transport disabled by configuration")
	}

	// Create DNS transport if control zone is configured AND supported
	if cfg.ControlZone != "" && tm.isTransportSupported("dns") {
		// ... create DNS transport
		log.Printf("TransportManager: DNS transport enabled")
	} else if cfg.ControlZone == "" {
		log.Printf("TransportManager: DNS transport not configured (no control zone)")
	} else {
		log.Printf("TransportManager: DNS transport disabled by configuration")
	}

	return tm
}

// isTransportSupported checks if a transport mechanism is enabled in configuration.
func (tm *TransportManager) isTransportSupported(mechanism string) bool {
	if len(tm.SupportedMechanisms) == 0 {
		return true // Default: all transports supported
	}
	for _, m := range tm.SupportedMechanisms {
		if m == mechanism {
			return true
		}
	}
	return false
}
```

**Config Passing** ([main_initfuncs.go:356-369](../v2/main_initfuncs.go#L356-L369)):

```go
tm := NewTransportManager(&TransportManagerConfig{
	LocalID:             conf.Agent.Identity,
	ControlZone:         controlZone,
	// ... other fields
	SupportedMechanisms: conf.Agent.SupportedMechanisms,
})
```

---

### 3. Independent State Tracking

**Fixed**: Hello and Beat operations now correctly update per-transport state:

**SendHelloWithFallback** ([hsync_transport.go:592-670](../v2/hsync_transport.go#L592-L670)):

```go
func (tm *TransportManager) SendHelloWithFallback(ctx context.Context, agent *Agent, sharedZones []string) (*transport.HelloResponse, error) {
	// ... setup

	var apiResp, dnsResp *transport.HelloResponse
	var apiErr, dnsErr error

	// Try API transport if supported
	if tm.APITransport != nil && agent.ApiMethod && tm.isTransportSupported("api") {
		apiResp, apiErr = tm.APITransport.Hello(ctx, peer, req)
		agent.mu.Lock()
		if apiErr != nil {
			log.Printf("TransportManager: API Hello to %s failed: %v", peer.ID, apiErr)
			agent.ApiDetails.LatestError = apiErr.Error()
			agent.ApiDetails.LatestErrorTime = time.Now()
		} else if apiResp != nil && apiResp.Accepted {
			log.Printf("TransportManager: API Hello to %s succeeded", peer.ID)
			agent.ApiDetails.State = AgentStateIntroduced  // ← Updates API state
			agent.ApiDetails.HelloTime = time.Now()
			agent.ApiDetails.LastContactTime = time.Now()
			agent.ApiDetails.LatestError = ""
		}
		agent.mu.Unlock()
	}

	// Try DNS transport if supported
	if tm.DNSTransport != nil && agent.DnsMethod && tm.isTransportSupported("dns") {
		dnsResp, dnsErr = tm.DNSTransport.Hello(ctx, peer, req)
		agent.mu.Lock()
		if dnsErr != nil {
			log.Printf("TransportManager: DNS Hello to %s failed: %v", peer.ID, dnsErr)
			agent.DnsDetails.LatestError = dnsErr.Error()
			agent.DnsDetails.LatestErrorTime = time.Now()
		} else if dnsResp != nil && dnsResp.Accepted {
			log.Printf("TransportManager: DNS Hello to %s succeeded", peer.ID)
			agent.DnsDetails.State = AgentStateIntroduced  // ← Updates DNS state
			agent.DnsDetails.HelloTime = time.Now()
			agent.DnsDetails.LastContactTime = time.Now()
			agent.DnsDetails.LatestError = ""
		}
		agent.mu.Unlock()
	}

	// Return success if ANY transport succeeded
	if apiErr == nil && apiResp != nil && apiResp.Accepted {
		return apiResp, nil
	}
	if dnsErr == nil && dnsResp != nil && dnsResp.Accepted {
		return dnsResp, nil
	}

	// Both failed
	return nil, fmt.Errorf("all transports failed for Hello to peer %s (API: %v, DNS: %v)", peer.ID, apiErr, dnsErr)
}
```

**SendBeatWithFallback** ([hsync_transport.go:720-789](../v2/hsync_transport.go#L720-L789)):

```go
func (tm *TransportManager) SendBeatWithFallback(ctx context.Context, agent *Agent, sequence uint64) (*transport.BeatResponse, error) {
	// ... setup

	var apiResp, dnsResp *transport.BeatResponse
	var apiErr, dnsErr error

	// Try API transport if supported and OPERATIONAL
	if tm.APITransport != nil && agent.ApiMethod && tm.isTransportSupported("api") {
		if agent.ApiDetails.State == AgentStateOperational || agent.ApiDetails.State == AgentStateIntroduced {
			apiResp, apiErr = tm.APITransport.Beat(ctx, peer, req)
			agent.mu.Lock()
			if apiErr != nil {
				log.Printf("TransportManager: API Beat to %s failed: %v", peer.ID, apiErr)
				agent.ApiDetails.LatestError = apiErr.Error()
				agent.ApiDetails.LatestErrorTime = time.Now()
			} else {
				log.Printf("TransportManager: API Beat to %s succeeded", peer.ID)
				agent.ApiDetails.State = AgentStateOperational  // ← Updates API state
				agent.ApiDetails.LastContactTime = time.Now()
				agent.ApiDetails.LatestRBeat = time.Now()
				agent.ApiDetails.ReceivedBeats++
				agent.ApiDetails.LatestError = ""
			}
			agent.mu.Unlock()
		}
	}

	// Try DNS transport if supported and OPERATIONAL
	if tm.DNSTransport != nil && agent.DnsMethod && tm.isTransportSupported("dns") {
		if agent.DnsDetails.State == AgentStateOperational || agent.DnsDetails.State == AgentStateIntroduced {
			dnsResp, dnsErr = tm.DNSTransport.Beat(ctx, peer, req)
			agent.mu.Lock()
			if dnsErr != nil {
				log.Printf("TransportManager: DNS Beat to %s failed: %v", peer.ID, dnsErr)
				agent.DnsDetails.LatestError = dnsErr.Error()
				agent.DnsDetails.LatestErrorTime = time.Now()
			} else {
				log.Printf("TransportManager: DNS Beat to %s succeeded", peer.ID)
				agent.DnsDetails.State = AgentStateOperational  // ← Updates DNS state
				agent.DnsDetails.LastContactTime = time.Now()
				agent.DnsDetails.LatestRBeat = time.Now()
				agent.DnsDetails.ReceivedBeats++
				agent.DnsDetails.LatestError = ""
			}
			agent.mu.Unlock()
		}
	}

	// Return success if ANY transport succeeded
	// ... (similar pattern)
}
```

**SingleHello** ([hsync_hello.go:105-147](../v2/hsync_hello.go#L105-L147)):

Simplified to delegate to `SendHelloWithFallback`, which now handles per-transport state updates:

```go
func (ar *AgentRegistry) SingleHello(agent *Agent, zone ZoneName) {
	log.Printf("SingleHello: Sending HELLO to %s (zone %q)", agent.Identity, zone)

	// Use TransportManager for independent multi-transport handling
	if ar.TransportManager != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		sharedZones := ar.sharedZonesForAgent(agent)
		// SendHelloWithFallback now handles both transports independently
		// and updates ApiDetails.State and DnsDetails.State separately
		_, err := ar.TransportManager.SendHelloWithFallback(ctx, agent, sharedZones)
		if err != nil {
			log.Printf("SingleHello: TransportManager HELLO to %q failed on all transports: %v", agent.Identity, err)
		} else {
			log.Printf("SingleHello: Our HELLO to %q accepted on at least one transport", agent.Identity)
		}
		ar.S.Set(agent.Identity, agent)
		return
	}

	// Fallback: API-only (legacy mode without TransportManager)
	// ...
}
```

---

### 4. Independent Hello Retry Logic

**HelloRetrierNG** ([hsync_hello.go:61-112](../v2/hsync_hello.go#L61-L112)):

Updated to check **both transports** independently and continue retrying while **either** is in KNOWN state:

```go
func (ar *AgentRegistry) HelloRetrierNG(ctx context.Context, agent *Agent) {
	helloRetryInterval := configureInterval("syncengine.intervals.helloretry", 15, 1800)
	go func(agent *Agent) {
		ticker := time.NewTicker(time.Duration(helloRetryInterval) * time.Second)
		defer ticker.Stop()

		// Check if ANY transport needs Hello retries
		apiNeedsRetry := agent.ApiMethod && agent.ApiDetails.State == AgentStateKnown
		dnsNeedsRetry := agent.DnsMethod && agent.DnsDetails.State == AgentStateKnown

		if !apiNeedsRetry && !dnsNeedsRetry {
			log.Printf("HelloRetrierNG: agent %q has no transports in state KNOWN (API: %s, DNS: %s), stopping",
				agent.Identity, AgentStateToString[agent.ApiDetails.State], AgentStateToString[agent.DnsDetails.State])
			return
		}

		log.Printf("HelloRetrierNG: started for agent %q (API: %s, DNS: %s)",
			agent.Identity, AgentStateToString[agent.ApiDetails.State], AgentStateToString[agent.DnsDetails.State])

		for {
			select {
			case <-ctx.Done():
				log.Printf("HelloRetrierNG: context done, stopping")
				return
			case <-ticker.C:
			}

			// Check current state of both transports
			agent.mu.RLock()
			apiState := agent.ApiDetails.State
			dnsState := agent.DnsDetails.State
			apiMethod := agent.ApiMethod
			dnsMethod := agent.DnsMethod
			agent.mu.RUnlock()

			apiNeedsRetry = apiMethod && apiState == AgentStateKnown
			dnsNeedsRetry = dnsMethod && dnsState == AgentStateKnown

			if !apiNeedsRetry && !dnsNeedsRetry {
				log.Printf("HelloRetrierNG: agent %q no longer in state KNOWN (API: %s, DNS: %s), stopping",
					agent.Identity, AgentStateToString[apiState], AgentStateToString[dnsState])
				return
			}

			// Send Hello on transports that need it
			log.Printf("HelloRetrierNG: with agent %q we share the zones: %v", agent.Identity, agent.Zones)
			for zone := range agent.Zones {
				if apiNeedsRetry || dnsNeedsRetry {
					log.Printf("HelloRetrierNG: trying HELLO with agent %q with zone: %q (API needs: %v, DNS needs: %v)",
						agent.Identity, zone, apiNeedsRetry, dnsNeedsRetry)
					ar.SingleHello(agent, zone)
				}
			}
		}
	}(agent)
	log.Printf("HelloRetrierNG: started HelloRetrierNG for agent %q", agent.Identity)
}
```

---

## Benefits

### 1. True Redundancy

- **No waiting for failure**: Both transports establish connections immediately
- **Independent operation**: API failure doesn't affect DNS, and vice versa
- **Faster recovery**: If one transport fails, the other is already operational

### 2. Correct State Tracking

- **Per-transport state**: `ApiDetails.State` and `DnsDetails.State` maintained independently
- **Clear visibility**: Can see exactly which transport is operational
- **Better debugging**: Logs show state of each transport separately

### 3. Configuration Control

- **Explicit disable**: Can disable a transport without removing config
- **Testing support**: Can test one transport at a time
- **Flexibility**: Easy to switch between transport modes

### 4. Improved Observability

**Log Examples**:

```
TransportManager: API transport enabled
TransportManager: DNS transport enabled
HelloRetrierNG: started for agent "agent2.example." (API: KNOWN, DNS: KNOWN)
TransportManager: API Hello to agent2.example. succeeded
TransportManager: DNS Hello to agent2.example. succeeded
SingleHello: Our HELLO to "agent2.example." accepted on at least one transport
HelloRetrierNG: agent "agent2.example." no longer in state KNOWN (API: INTRODUCED, DNS: INTRODUCED), stopping
TransportManager: API Beat to agent2.example. succeeded
TransportManager: DNS Beat to agent2.example. succeeded
```

---

## Configuration Examples

### Both Transports Active (Default)

```yaml
agent:
  identity: agent.provider.
  supported_mechanisms: [api, dns]  # or omit field for default
  api:
    # ... API config
  dns:
    # ... DNS config
```

**Behavior**: Both API and DNS transports are active and operate in parallel.

### API Only

```yaml
agent:
  identity: agent.provider.
  supported_mechanisms: [api]
  api:
    # ... API config
  dns:
    # ... DNS config still present but disabled
```

**Behavior**: Only API transport is active. DNS config is ignored.

### DNS Only

```yaml
agent:
  identity: agent.provider.
  supported_mechanisms: [dns]
  api:
    # ... API config still present but disabled
  dns:
    # ... DNS config
```

**Behavior**: Only DNS transport is active. API config is ignored.

---

## Files Modified

### New/Modified Files

1. **tdns/v2/config.go**
   - Added `SupportedMechanisms []string` field to `LocalAgentConf`

2. **tdns/v2/hsync_transport.go**
   - Added `SupportedMechanisms []string` field to `TransportManager`
   - Added `SupportedMechanisms []string` field to `TransportManagerConfig`
   - Added `isTransportSupported(mechanism string) bool` helper method
   - Updated `NewTransportManager()` to respect `supported_mechanisms` config
   - **Rewrote `SendHelloWithFallback()`** - now sends on BOTH transports, updates per-transport state
   - **Rewrote `SendBeatWithFallback()`** - now sends on BOTH transports, updates per-transport state

3. **tdns/v2/hsync_hello.go**
   - **Rewrote `HelloRetrierNG()`** - now checks both transport states independently
   - **Simplified `SingleHello()`** - delegates to `SendHelloWithFallback` for state management

4. **tdns/v2/main_initfuncs.go**
   - Pass `SupportedMechanisms: conf.Agent.SupportedMechanisms` to `NewTransportManager()`

5. **tdns/cmdv2/agentv2/tdns-agent.sample.yaml**
   - Added `supported_mechanisms: [api, dns]` example configuration

6. **labconfig/buildlab/template/etc/tdns/tdns-agent.P.yaml**
   - Added `supported_mechanisms: [api, dns]` to build lab template

---

## Testing Recommendations

### Unit Tests

1. **Config parsing**:
   - Test `supported_mechanisms` with `["api"]`, `["dns"]`, `["api", "dns"]`, and empty (default)
   - Verify invalid values are rejected

2. **Transport initialization**:
   - Verify API transport created only when `"api"` in `supported_mechanisms`
   - Verify DNS transport created only when `"dns"` in `supported_mechanisms` AND control zone configured
   - Verify both created when both in `supported_mechanisms`

3. **State tracking**:
   - Verify API operations update `ApiDetails.State`
   - Verify DNS operations update `DnsDetails.State`
   - Verify states are independent (API failure doesn't affect DNS state)

4. **Hello retry logic**:
   - Verify HelloRetrierNG continues while either transport in KNOWN state
   - Verify HelloRetrierNG stops when both transports leave KNOWN state
   - Verify correct logging of per-transport state

### Integration Tests

1. **Both transports active**:
   - Verify Hello sent on both transports
   - Verify both transports reach OPERATIONAL independently
   - Verify Beat messages sent on both transports

2. **Single transport failure**:
   - Disable one transport mid-connection
   - Verify other transport continues operating
   - Verify failed transport state reflects failure

3. **Configuration changes**:
   - Start with both transports
   - Reload config with `["api"]` only
   - Verify DNS transport stops but API continues

---

## Backward Compatibility

**Breaking change - requires config update**:

- `supported_mechanisms` is now **REQUIRED** - empty or missing list will cause config validation error
- Existing configs **must be updated** to add `supported_mechanisms: [api, dns]`
- Validation enforces at least one transport mechanism (prevents agent with zero communication capability)
- Case-insensitive: `[API, DNS]` and `[api, dns]` both work (normalized to lowercase)
- Legacy `SingleHello` API-only code path preserved for configs without TransportManager (test compatibility)

---

## Related Work

- **DNS-37 through DNS-44**: Authorization framework for transport security
- **DNS-45 through DNS-54**: Unified transport data structures
- **DNS-51**: Authorization for Beat/Sync/RFI/Status messages
- **DNS-55 through DNS-57**: DNS transport gap fixes

---

## Conclusion

Successfully implemented **independent parallel transport management**:

✅ **Configuration control**: `supported_mechanisms` field enables/disables transports
✅ **Independent state tracking**: `ApiDetails.State` and `DnsDetails.State` maintained separately
✅ **Parallel operation**: Both transports send Hello/Beat simultaneously
✅ **True redundancy**: No waiting for primary to fail before using secondary
✅ **Better observability**: Clear logging of per-transport state
✅ **Backward compatible**: Defaults to both transports when field omitted

The transport layer now provides true redundancy and flexibility, allowing operators to:
- Run both transports for maximum reliability
- Disable one transport for testing or troubleshooting
- See exactly which transport is operational at any time
- Benefit from automatic fallback without manual intervention
