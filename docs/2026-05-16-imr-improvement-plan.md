# IMR Improvement Implementation Plan

**Date:** 2026-05-16
**Companion to:** [2026-05-16-imr-review.md](2026-05-16-imr-review.md)
**Scope:** strictly `tdns/v2/` — do not touch `tdns/tdns/`,
`tdns/obe/`, or `tdns/music/`.
**Audience:** a fresh agent. This document is intended to be
implementable end-to-end without re-reading the review doc,
though doing so is recommended for context.

---

## 0. Executive summary

The review identified twelve candidate improvements (S1–S12).
Deep planning consolidates them into **seven implementable
work items**, three "absorbed into another item," and zero
rejections. The consolidation comes from one structural
insight: implementing per-(addr, transport) backoff (S1)
properly via a refactor of `prioritizeServers` naturally
delivers what S2 (transport demotion) and S4 (cross-transport
fallback) were trying to add. They were workarounds for a
limitation that S1 removes.

**Final work items, in implementation order:**

| #  | Title                                       | Phase | Effort | Source items |
|----|---------------------------------------------|-------|--------|--------------|
| W1 | Configurability foundation                  | 0     | S      | enables S3   |
| W2 | Quick wins: constants, RecursorCh, budget   | 1     | S      | S3, S10, S11 |
| W3 | Cache-upgrade policy (opt-in)               | 1     | S      | S7           |
| W4 | Observability v1 (using current data)       | 1     | S      | S8 phase 1   |
| W5 | DNSClient interface + Exchange consolidation | 2     | S      | enables tests for W6+ |
| W6 | Structural refactor: (addr,transport) tuple | 2     | L      | S1+S2+S4     |
| W7 | RTT collection and use                      | 3     | M      | S6           |
| W8 | Address-family reachability tracking        | 4     | M      | S12          |
| W9 | Discovery state machine                     | 5     | M      | S5           |
| W10 | Parallel-NS first-success (deferred)        | 6     | S      | S9           |

S = small (hours), M = medium (a day), L = large (multi-day).

**Recommended order:** W1 → W2 → W4 → W3 → W5 → W6 → W7 →
W8 → W9. W10 is deferred — re-evaluate *after* W7 and W8
land; if address-family deprioritization plus RTT sort
already kill the v6-times-out-first symptom, W10 may be
unnecessary.

**No item is rejected.** Three (S2, S4, and partially S8) are
absorbed into other items because deep planning showed they
would otherwise duplicate work or create overlap.

---

## 1. Cross-cutting design decisions

Before implementing anything, agree on these. They affect
multiple work items.

### 1.1 Backoff keying

**Decision:** All address backoffs become keyed by
`addrXport{addr, transport}` instead of `addr`. The same
keying applies to the *zone-scoped* lame-delegation backoffs.

**Rationale:** Once we believe a (TCP) timeout doesn't tell us
anything about UDP reachability, the rest of the data
structures should agree — including the zone-scoped backoffs.
A REFUSED on DoT could in principle differ from REFUSED on
Do53 (rare but possible — different code paths in the
auth server software). Single keying scheme is easier to
reason about.

**Tradeoff:** ~2× memory for the backoff map in the worst case
(both v4 and v6 of every NS, plus per-transport). Negligible
in practice.

### 1.2 Selection happens up front, in one place

**Decision:** `prioritizeServers` returns a flat list of
`(server, addr, transport)` tuples. `pickTransport` becomes
*internal* to `prioritizeServers` — it is no longer called from
`tryServer`. `tryServer` simply executes the query for the
tuple it's given.

**Rationale:** Today the choice of transport is made inside
`tryServer` after `prioritizeServers` has already decided what
to try. That layering hides crucial information: when
`prioritizeServers` filters out an in-backoff address, it
doesn't know which transport caused the backoff and can't
make the "try same addr, different transport" decision. Moving
the transport choice into `prioritizeServers` (where it has
the full filter state) is what makes S1, S2, and S4 collapse
into one work item.

**Side effect:** `pickTransport`'s deterministic-hash property
is preserved by computing it inside the new tuple-expansion
logic for tuples whose other state is healthy.

### 1.3 No backwards compatibility

Per project convention: no migration code, no dual-format
parsing, no compatibility shims. Every change cuts over
cleanly. This applies to config too — if a config key changes
name, it just changes.

### 1.4 Test scaffolding

`tdns/v2/cache/cache_test.go` exists but covers DnskeyCache
and basic RRset operations. There is no authserver test file.
For each work item below that warrants tests, the plan calls
out which test file to create. Use Go's standard
`testing` package — match existing patterns in `cache_test.go`.

### 1.5 Build verification

Per project memory rule, every phase MUST end with a clean
`cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make`. If touching
tdns-mp, also `cd tdns-mp/cmd && GOROOT=/opt/local/lib/go
make`. Do not commit without a green build.

---

## 2. Work items in detail

### W1. Configurability foundation [Phase 0, S effort]

**Goal:** Add a single config type holding all tunables we'll
introduce. Every later work item references its fields rather
than carrying its own ad-hoc config plumbing.

**Files touched:**
- `tdns/v2/config.go` — add `ImrTuningConf` type, embed in
  `ImrEngineConf`
- `tdns/v2/imrengine.go` — propagate tuning into `Imr` struct
  during `InitImrEngine` (line 84)

**Struct additions (config.go, after ImrEngineConf definition):**

```go
// ImrTuningConf holds runtime-tunable behavior knobs for the
// IMR. All fields are optional in YAML; defaults applied in
// loadImrTuningDefaults.
type ImrTuningConf struct {
   Backoff       BackoffConf       `yaml:"backoff" mapstructure:"backoff"`
   AddressFamily AddressFamilyConf `yaml:"address_family" mapstructure:"address_family"`
   Discovery     DiscoveryConf     `yaml:"discovery" mapstructure:"discovery"`
   QueryBudget   time.Duration     `yaml:"query_budget" mapstructure:"query_budget"`
   UpgradeIndirectCacheHits *bool `yaml:"upgrade_indirect_cache_hits" mapstructure:"upgrade_indirect_cache_hits"`
}

type BackoffConf struct {
   FirstFailure   time.Duration `yaml:"first_failure" mapstructure:"first_failure"`
   MaxFailure     time.Duration `yaml:"max_failure" mapstructure:"max_failure"`
   Multiplier     float64       `yaml:"multiplier" mapstructure:"multiplier"`
   JitterFraction float64       `yaml:"jitter_fraction" mapstructure:"jitter_fraction"`
   RoutingFailure time.Duration `yaml:"routing_failure" mapstructure:"routing_failure"`
   LameDelegation time.Duration `yaml:"lame_delegation" mapstructure:"lame_delegation"`
}

type AddressFamilyConf struct {
   WindowDuration  time.Duration `yaml:"window_duration" mapstructure:"window_duration"`
   FailureThreshold int          `yaml:"failure_threshold" mapstructure:"failure_threshold"`
   SuspectDuration time.Duration `yaml:"suspect_duration" mapstructure:"suspect_duration"`
   ProbeInterval   time.Duration `yaml:"probe_interval" mapstructure:"probe_interval"`
}

type DiscoveryConf struct {
   RetryAfterFailure time.Duration `yaml:"retry_after_failure" mapstructure:"retry_after_failure"`
   MaxFailures       int           `yaml:"max_failures" mapstructure:"max_failures"`
}
```

**Embed in `ImrEngineConf`** (config.go, the existing
`ImrEngineConf` struct):

```go
   Tuning ImrTuningConf `yaml:"tuning" mapstructure:"tuning"`
```

**Defaults function** (config.go, new):

```go
func loadImrTuningDefaults(t *ImrTuningConf) {
   if t.Backoff.FirstFailure == 0       { t.Backoff.FirstFailure = 15 * time.Second }
   if t.Backoff.MaxFailure == 0         { t.Backoff.MaxFailure = 1 * time.Hour }
   if t.Backoff.Multiplier == 0         { t.Backoff.Multiplier = 3.0 }
   if t.Backoff.JitterFraction == 0     { t.Backoff.JitterFraction = 0.25 }
   if t.Backoff.RoutingFailure == 0     { t.Backoff.RoutingFailure = 1 * time.Hour }
   if t.Backoff.LameDelegation == 0     { t.Backoff.LameDelegation = 1 * time.Hour }
   if t.AddressFamily.WindowDuration == 0   { t.AddressFamily.WindowDuration = 10 * time.Minute }
   if t.AddressFamily.FailureThreshold == 0 { t.AddressFamily.FailureThreshold = 5 }
   if t.AddressFamily.SuspectDuration == 0  { t.AddressFamily.SuspectDuration = 10 * time.Minute }
   if t.AddressFamily.ProbeInterval == 0    { t.AddressFamily.ProbeInterval = 30 * time.Second }
   if t.Discovery.RetryAfterFailure == 0    { t.Discovery.RetryAfterFailure = 30 * time.Second }
   if t.Discovery.MaxFailures == 0          { t.Discovery.MaxFailures = 3 }
   if t.QueryBudget == 0                    { t.QueryBudget = 8 * time.Second }
   // UpgradeIndirectCacheHits: nil means "use legacy behaviour (true)"
}
```

**Propagate to `Imr`** (imrengine.go, modify `Imr` struct at
line 27 — add field):

```go
   Tuning ImrTuningConf
```

**Wire in `InitImrEngine`** (imrengine.go, modify
construction at line 101):

```go
   loadImrTuningDefaults(&conf.Imr.Tuning)
   imr := &Imr{
       // existing fields...
       Tuning: conf.Imr.Tuning,
   }
```

**Verification:** build cleanly with empty `tuning:` block in
config (defaults apply) and with all knobs populated.

**Testing:** add `tdns/v2/config_tuning_test.go` exercising
`loadImrTuningDefaults` with empty / partial / full input.

---

### W2. Quick wins bundle [Phase 1, S effort]

Three small independent changes, bundled in one commit because
each is too small to stand alone and they share the W1
plumbing.

#### W2.a — Use configurable backoff constants (was S3)

**Files touched:**
- `tdns/v2/cache/authserver.go` — `categorizeError` (line 528),
  `RecordAddressFailure` (line 566)
- `tdns/v2/cache/zone_errors.go` — `RecordZoneAddressFailureForRcode`
  (line 16)

**The challenge:** these methods live in the `cache` package
and can't import the parent `tdns` package's `BackoffConf`
without an import cycle.

**Solution:** define a small unexported interface in the
`cache` package:

```go
// In tdns/v2/cache/authserver.go (or new file backoff_conf.go):
type BackoffPolicy interface {
   FirstFailure() time.Duration
   MaxFailure() time.Duration
   Multiplier() float64
   JitterFraction() float64
   RoutingFailure() time.Duration
   LameDelegation() time.Duration
}

// Set via package-level setter from the parent tdns package:
var globalBackoffPolicy BackoffPolicy
func SetBackoffPolicy(p BackoffPolicy) { globalBackoffPolicy = p }
```

In `tdns/v2/imrengine.go` after `InitImrEngine` constructs
`imr.Tuning`, call:

```go
cache.SetBackoffPolicy(&backoffPolicyAdapter{conf: &conf.Imr.Tuning.Backoff})
```

Where `backoffPolicyAdapter` is a tiny adapter type in
imrengine.go (or backoff_policy.go) that wraps `*BackoffConf`
and implements `cache.BackoffPolicy`.

**Replace constants in `categorizeError`**
(authserver.go:528–556): replace the hardcoded
`2 * time.Minute`, `1 * time.Hour`, and routing-failure logic
with calls to the policy. Implement exponential backoff:

```go
func categorizeError(err error, prev *AddressBackoff) time.Duration {
   p := globalBackoffPolicy
   if p == nil { /* legacy defaults as fallback */ }
   if err != nil && isRoutingError(err) {
      return jitter(p.RoutingFailure(), p.JitterFraction())
   }
   var base time.Duration
   if prev == nil {
      base = p.FirstFailure()
   } else {
      base = time.Duration(float64(p.FirstFailure()) *
         math.Pow(p.Multiplier(), float64(prev.FailureCount)))
      if base > p.MaxFailure() { base = p.MaxFailure() }
   }
   return jitter(base, p.JitterFraction())
}

func jitter(d time.Duration, frac float64) time.Duration {
   if frac <= 0 { return d }
   delta := float64(d) * frac * (2*rand.Float64() - 1) // ±frac
   return d + time.Duration(delta)
}
```

Helper `isRoutingError` factored out of the existing string
checks at authserver.go:539–542.

**Caller change required:** `RecordAddressFailure` (line 566)
currently calls `categorizeError(err, true)` for first
failures. Change call signature to pass the existing backoff
struct (or nil for first failure):

```go
backoffDuration := categorizeError(err, backoff) // nil = first
```

**Same treatment for `RecordZoneAddressFailureForRcode`**
(zone_errors.go:16) — replace hardcoded `1 * time.Hour` for
REFUSED/NOTAUTH with `p.LameDelegation()`, etc.

**Testing:** new file `tdns/v2/cache/backoff_test.go`. Cases:
- First failure with various error types returns expected
  base duration ± jitter window.
- 1st, 2nd, 3rd, ...Nth consecutive failure shows exponential
  growth capped at `MaxFailure`.
- Routing-error bypass goes straight to `RoutingFailure` regardless
  of count.
- Jitter staying within the expected ±fraction range across
  many invocations.

**Build verification mandatory** before moving on.

#### W2.b — Drop RecursorCh serialization (was S11)

**File:** `tdns/v2/imrengine.go`, the engine loop at
lines 211–289.

**Change:** wrap the synchronous `ImrQuery` call (line 278) in
a goroutine. Move the cache-hit fast path into the goroutine
too so that it doesn't block the channel either (currently
the cache check at lines 232–272 also runs in the loop body).

```go
case rrq, ok := <-recursorch:
   if !ok { return nil }
   if rrq.ResponseCh == nil {
      lgImr.Warn("received nil or invalid request (no response channel)")
      continue
   }
   go imr.handleRecursorRequest(ctx, rrq)
```

Where `handleRecursorRequest` is the body extracted from the
current loop (lines 224–288).

**Why not just delete the channel?** The user notes only
`cli/imr_cmds.go:57` uses it, but the channel does serve as
a stable RPC seam between subsystems. Keep it; just don't
serialize.

**Testing:** no new test needed — the existing `imr query`
CLI path exercises this and the build catches signature
errors.

#### W2.c — Per-query budget (was S10)

**File:** `tdns/v2/dnslookup.go`, function
`IterativeDNSQueryWithLoopDetection` at line 759.

**Change:** at the top of the function:

```go
budget := imr.Tuning.QueryBudget
if budget > 0 {
   var cancel context.CancelFunc
   ctx, cancel = context.WithTimeout(ctx, budget)
   defer cancel()
}
```

**Caveat:** DNSSEC chain validation
(`ValidateRRsetWithParentZone`) is itself a chain of IMR
lookups. Default budget of 8s is generous enough; if it
proves too tight for deep chains the user can lift it via
config (W1).

**Testing:** add to a new `tdns/v2/dnslookup_test.go` (will
exist as part of W6 anyway) — assert that a query with a 1s
budget against an unreachable address returns an error within
~1s.

---

### W3. Cache-upgrade policy (was S7) [Phase 1, S effort]

**Files touched:**
- `tdns/v2/imrengine.go` — `ImrQuery` cache check (line 338),
  `ImrResponder` cache check (line 564)
- `tdns/v2/dnslookup.go` — `IterativeDNSQueryWithLoopDetection`
  cache check (line 794)

**Change:** the three "cache hit with indirect context →
re-query" branches each gain a check:

```go
case cache.ContextReferral, cache.ContextGlue, cache.ContextHint:
   upgrade := true
   if imr.Tuning.UpgradeIndirectCacheHits != nil {
      upgrade = *imr.Tuning.UpgradeIndirectCacheHits
   }
   if !upgrade && crrset.RRset != nil && crrset.RRset.RRtype == qtype {
      // Return the cached indirect data instead of re-querying.
      // We do not promise DNSSEC signatures in this path.
      return crrset.RRset, int(crrset.Rcode), crrset.Context, crrset.Transport, nil
   }
   // fall through to issue query (legacy behaviour)
```

`ContextFailure` and `ContextPriming` are *not* affected by
the toggle — those are always re-queried.

**Why opt-in (default = upgrade):** the existing behavior is
conservative correctness (DNSSEC signatures preserved). The
opt-in path trades signatures for fewer queries. Operators
running gossip-heavy lab environments will opt in; operators
running production validating recursors will not.

**Testing:** new test in `tdns/v2/imr_cache_upgrade_test.go`:
- With flag false and cached Glue matching qtype: returns
  cached data, no network query.
- With flag true (default): re-queries even for matching Glue.
- With flag false but cached Glue *not* matching qtype:
  re-queries.

---

### W4. Observability v1 (was S8 phase 1) [Phase 1, S effort]

The CLI `imr dump auth-servers` already emits per-address
backoff info in verbose mode (imr_dump_cmds.go around lines
150–170). Phase 1 of S8 just **extends what's already there**:

**Files touched:**
- `tdns/v2/cli/imr_dump_cmds.go` — extend `auth-servers`
  output; extend `zones` output

**Auth-servers extension:** for each AuthServer, in addition
to the current `TransportCounters`, print:
- `LastSuccess` / `LastFailure` timestamps per address
- For each address-in-backoff: full `NextTry`, `FailureCount`,
  `LastError` (already present)

**Zones extension:** for each Zone, print its
`AddressBackoffs` if any are present (lame-delegation
tracking). Today this map is invisible from the CLI.

**Where the data is:** `Zone.AddressBackoffs`
([cache/cache_structs.go:71-78](tdns/v2/cache/cache_structs.go))
is already populated by `RecordZoneAddressFailureForRcode`
in [zone_errors.go:16](tdns/v2/cache/zone_errors.go). Add a
zone-scoped section to the dump similar to the existing
auth-server backoff section.

**Note:** the per-(addr, transport) detail proper to S8 phase 2
arrives with W6 — the underlying data doesn't exist yet.

**Testing:** manual; CLI output is the contract. No
automated tests for CLI formatting in this repo's convention.

---

### W5. DNSClient interface + Exchange consolidation [Phase 2, S effort]

**Goal:** turn `core.DNSClient` into an interface so the W6+
refactor can be tested without network, and consolidate the
two UDP→TCP fallback paths into one location.

**Why now:** every subsequent work item changes query
behaviour. Without testability we're flying blind. The
interface is small, the consolidation cleans up real
duplication.

#### 5.1 Define the interface

**File:** `tdns/v2/core/dnsclient.go` (existing file, add near
top after imports).

```go
// DNSClienter abstracts the network exchange so callers can
// be tested with a fake. The concrete *DNSClient still
// implements it.
type DNSClienter interface {
   Exchange(msg *dns.Msg, server string, debug bool) (*dns.Msg, time.Duration, error)
   Transport() core.Transport
}

// Already exists as a method-less concept; add an accessor on
// the concrete type:
func (c *DNSClient) TransportKind() core.Transport { return c.Transport }
```

(`Transport()` is named `TransportKind` on the struct to
avoid colliding with the existing field name `Transport`.)

#### 5.2 Consolidate UDP→TCP fallback

Today the timeout-induced UDP→TCP fallback lives in
`tryServer` ([dnslookup.go:1688-1708](tdns/v2/dnslookup.go))
and the TC=1-induced fallback lives in `Exchange`
([core/dnsclient.go:185-188](tdns/v2/core/dnsclient.go)).
Both reach into `DNSClientTCP`. Move the timeout fallback
into `Exchange`:

```go
// core/dnsclient.go, in Exchange's TransportDo53 case:
r, rtt, err := c.DNSClientUDP.Exchange(msg, addr)
if err == nil && r != nil && r.Truncated && !c.DisableFallback {
   log.Printf("Do53: UDP TC=1 from %s; retrying over TCP", addr)
   return c.DNSClientTCP.Exchange(msg, addr)
}
if err != nil && c.DNSClientTCP != nil && !c.DisableFallback && isTransientNetErr(err) {
   // Single TCP retry for UDP transient errors (timeout,
   // ECONNREFUSED, etc.). Mirrors classic resolver behaviour
   // and consolidates what used to live in tryServer.
   tr, trtt, terr := c.DNSClientTCP.Exchange(msg, addr)
   if terr == nil { return tr, trtt, nil }
}
return r, rtt, err
```

**Note:** `isTransientNetErr` currently lives in
`tdns/v2/dnslookup.go:32`. Move to `core/dnsclient.go`
(or a new `core/net_errors.go`) so `Exchange` can call it
without importing the parent package.

After this consolidation, `tryServer` lines 1688-1708 become
dead code — delete them. `tryServer` then no longer needs
direct access to `DNSClientTCP`.

#### 5.3 Convert call sites to interface

**File:** `tdns/v2/cache/cache_structs.go` — the
`DNSClient map[core.Transport]*core.DNSClient` field on
`RRsetCacheT` changes to `map[core.Transport]core.DNSClienter`.

**File:** `tdns/v2/dnslookup.go:1614` — `c, exist :=
imr.Cache.DNSClient[t]` now yields a `DNSClienter`. Most
usages are already through `c.Exchange(...)`. Only the
direct `c.DNSClientTCP` access in the now-deleted timeout
block was a problem; that's gone.

Construction sites that build the map of clients (search for
`DNSClient[core.TransportDo53] =` and similar) keep using the
concrete `*DNSClient` — it satisfies the interface.

#### 5.4 Fake client for tests

New file `tdns/v2/core/dnsclient_fake.go` (or in a `_test.go`
file in the package that needs it):

```go
type FakeDNSClient struct {
   transport core.Transport
   // Responses keyed by (qname, addr). Either field optional —
   // empty matches any.
   Responses map[FakeKey]FakeResponse
   QueryLog  []FakeQuery // appended on each Exchange
}

type FakeKey struct { Qname, Addr string }
type FakeResponse struct {
   Msg *dns.Msg
   RTT time.Duration
   Err error
}
type FakeQuery struct {
   Qname, Addr string
   Transport   core.Transport
   At          time.Time
}

func (f *FakeDNSClient) Exchange(msg *dns.Msg, server string, debug bool) (*dns.Msg, time.Duration, error) {
   qname := msg.Question[0].Name
   f.QueryLog = append(f.QueryLog, FakeQuery{Qname: qname, Addr: server, Transport: f.transport, At: time.Now()})
   // Lookup: exact match first, then qname-only, then addr-only, then default.
   if r, ok := f.Responses[FakeKey{qname, server}]; ok { return r.Msg, r.RTT, r.Err }
   if r, ok := f.Responses[FakeKey{qname, ""}]; ok { return r.Msg, r.RTT, r.Err }
   if r, ok := f.Responses[FakeKey{"", server}]; ok { return r.Msg, r.RTT, r.Err }
   if r, ok := f.Responses[FakeKey{}]; ok { return r.Msg, r.RTT, r.Err }
   return nil, 0, fmt.Errorf("FakeDNSClient: no programmed response for %s @ %s", qname, server)
}

func (f *FakeDNSClient) TransportKind() core.Transport { return f.transport }
```

#### 5.5 Testing

New `tdns/v2/core/dnsclient_test.go`:
- TC=1 fallback: program a UDP response with TC=1, assert TCP
  is called and its response returned.
- Timeout fallback: program a UDP timeout, assert TCP is
  called and its response returned.
- `DisableFallback=true` blocks both fallbacks.

Used by every subsequent work item's tests.

#### 5.6 Effort

Half a day to a day. The largest part is being thorough about
moving `isTransientNetErr` cleanly and verifying no caller
besides `tryServer` was depending on the timeout-TCP fallback
landing at a specific level.

---

### W6. Structural refactor: (addr, transport) tuple [Phase 2, L effort]

This is the central change. Implementing it unifies S1, S2,
and S4 from the review doc.

#### 6.1 Type changes

**File:** `tdns/v2/cache/authserver.go`

Replace the `AddressBackoffs` field on `AuthServer` (line 44):

```go
// before:
AddressBackoffs map[string]*AddressBackoff
// after:
AddressBackoffs map[AddrXport]*AddressBackoff
```

New key type (same file, near `AddressBackoff`):

```go
// AddrXport keys backoff state by both address and transport.
// A timeout on (1.2.3.4:53, DoT) does not poison
// (1.2.3.4:53, Do53) or vice versa.
type AddrXport struct {
   Addr      string
   Transport core.Transport
}
```

**File:** `tdns/v2/cache/cache_structs.go`

Same treatment for `Zone.AddressBackoffs` (line ~75):

```go
AddressBackoffs map[AddrXport]*AddressBackoff
```

#### 6.2 API changes

All affected APIs in `tdns/v2/cache/authserver.go`:

| Old signature | New signature |
|--------------|--------------|
| `RecordAddressFailure(addr string, err error)` | `RecordAddressFailure(addr string, t core.Transport, err error)` |
| `RecordAddressFailureForRcode(addr string, rcode uint8)` | `RecordAddressFailureForRcode(addr string, t core.Transport, rcode uint8)` |
| `RecordAddressSuccess(addr string)` | `RecordAddressSuccess(addr string, t core.Transport)` |
| `GetAvailableAddresses() []string` | *removed* — replaced by new tuple expansion (see 5.3) |
| `AllAddressesInBackoff() bool` | *removed* — unused (Explore agent confirmed: 0 callers) |

In `tdns/v2/cache/zone_errors.go`:

| Old signature | New signature |
|--------------|--------------|
| `RecordZoneAddressFailureForRcode(addr string, rcode uint8, debug bool)` | `RecordZoneAddressFailureForRcode(addr string, t core.Transport, rcode uint8, debug bool)` |
| `RecordZoneAddressSuccess(addr string)` | `RecordZoneAddressSuccess(addr string, t core.Transport)` |
| `IsZoneAddressAvailable(addr string) bool` | `IsZoneAddressAvailable(addr string, t core.Transport) bool` |

#### 6.3 New tuple-expansion in prioritizeServers

**File:** `tdns/v2/dnslookup.go`

Replace `ServerAddrTuple` (lines 698-703):

```go
type ServerAddrXportTuple struct {
   Server    *cache.AuthServer
   Addr      string
   NSName    string
   Transport core.Transport
}
```

Rewrite `prioritizeServers` (lines 705-744). Pseudocode:

```go
func (imr *Imr) prioritizeServers(qname string, serverMap map[string]*cache.AuthServer, requireEncrypted bool) (string, *cache.Zone, []ServerAddrXportTuple) {
   zoneName, _, _ := imr.Cache.FindClosestKnownZone(qname)
   zone := ... // existing logic

   var tuples []ServerAddrXportTuple
   for nsname, server := range serverMap {
      for _, addr := range server.GetAddrs() {
         // Determine candidate transports for this (server, addr).
         candidates := candidateTransports(server, requireEncrypted)
         if len(candidates) == 0 { continue }

         // Apply backoff filters per-transport.
         for _, t := range candidates {
            ax := cache.AddrXport{Addr: addr, Transport: t}
            if !server.IsAddrXportAvailable(ax) { continue }
            if zone != nil && !zone.IsZoneAddrXportAvailable(ax) { continue }
            // Apply address-family suspect filter (W8 adds this).
            tuples = append(tuples, ServerAddrXportTuple{
               Server: server, Addr: addr, NSName: nsname, Transport: t,
            })
         }
      }
   }
   // Sort tuples — initial order: existing pickTransport bucket
   // weight, evaluated per (qname, server.Name). RTT-aware sort
   // arrives in W7.
   sortTuplesByWeightedPreference(tuples, qname)
   return zoneName, zone, tuples
}
```

Helpers (same file):

```go
// candidateTransports returns the transports configured for
// this server, in the order pickTransport would consider them.
// Filters for encrypted-only if required.
func candidateTransports(server *cache.AuthServer, requireEncrypted bool) []core.Transport {
   // Extract the core of the existing pickTransport logic at
   // dnslookup.go:1375-1476: weighted candidates list including
   // the implicit Do53 remainder when not requireEncrypted.
   // Return ordered by descending preference.
}

func sortTuplesByWeightedPreference(tuples []ServerAddrXportTuple, qname string) {
   // For each tuple, compute the same fnv32(qname|server.Name)
   // bucket the legacy pickTransport used. Sort so that the
   // tuple matching the bucket comes first per server, then
   // remaining transports for the same server, then other
   // servers' tuples. This preserves the deterministic
   // distribution while exposing alternative transports as
   // fallback candidates within the same iteration.
}
```

#### 6.4 tryServer simplification

**File:** `tdns/v2/dnslookup.go`, `tryServer` (line 1603).

`tryServer` no longer calls `pickTransport`. New signature:

```go
func (imr *Imr) tryServer(ctx context.Context, server *cache.AuthServer, addr string, t core.Transport, m *dns.Msg, qname string, qtype uint16) (*dns.Msg, time.Duration, error)
```

The `requireEncrypted` parameter goes away — encrypted-only
filtering is now done up front in `prioritizeServers`. RTT is
returned (already available from `c.Exchange`); rtt arg flows
into W7.

The body of `tryServer` shrinks: delete the `pickTransport`
call (lines 1610-1613), delete the `requireEncrypted` check
(absorbed into `prioritizeServers`), update the
`RecordAddressFailure`/`RecordAddressSuccess` calls at lines
1716 and 1720 to pass `t`.

#### 6.5 IterativeDNSQuery call-site updates

**File:** `tdns/v2/dnslookup.go`, lines 855-1006.

- `prioritized` is now `[]ServerAddrXportTuple` (was
  `[]ServerAddrTuple`).
- `tryServer` call at line 877 passes `tuple.Transport`.
- The `requireEncrypted` error-string check at line 880-885
  becomes dead code (filtering now happens up front); delete.
- Lame-delegation recording at lines 919-922 passes
  `tuple.Transport` to both `RecordZoneAddressFailureForRcode`
  and `RecordAddressFailureForRcode`.
- Success recording at lines 929 and 935 passes
  `tuple.Transport` to `RecordZoneAddressSuccess`.

#### 6.6 pickTransport: keep or remove?

After W6, `pickTransport` is unused by query paths but is
called from `applyTransportSignalToServer` and similar config
paths. Keep it for those (rename to `defaultTransportFor` if
desired for clarity), but its determinism is now embedded in
`sortTuplesByWeightedPreference`.

#### 6.7 Behavior verification

After W6:
- A timeout on DoT to addr X marks `(X, DoT)` bad but leaves
  `(X, Do53)` available.
- The next query for the same `(qname, server)` walks
  prioritized tuples; if the top tuple is `(X, DoT)` and it's
  in backoff, the loop moves to the next tuple, which may be
  `(X, Do53)` — same address, different transport.
- The existing TC=1 Do53→TCP fallback in
  [core/dnsclient.go:185](tdns/v2/core/dnsclient.go) keeps
  working (orthogonal to this change).
- The 3-attempt UDP retry + 1-shot TCP fallback in
  `tryServer` (lines 1646-1708) keeps working as the
  intra-transport retry policy.

This delivers S1 (per-transport keying), S2 (transport gets
deprioritized via backoff filter), and S4 (cross-transport
fallback within the prioritized loop) in one change.

#### 6.8 Testing

New file `tdns/v2/cache/authserver_test.go`:
- `RecordAddressFailure(addr, DoT, err)` then
  `IsAddrXportAvailable(addr, Do53)` returns true.
- Same setup, `IsAddrXportAvailable(addr, DoT)` returns false.
- Recording success on (addr, DoT) clears only that transport.

New file `tdns/v2/dnslookup_prioritize_test.go`:
- Build a `serverMap` with one server, two addrs, three
  transports configured. Place backoffs on selected
  (addr, transport) pairs. Assert the prioritized output
  contains exactly the available tuples in the expected order.
- Encrypted-only filter excludes Do53 tuples.

#### 6.9 Estimated effort

Several days. The struct/API change touches every backoff
caller (Explore agent identified ~7 call sites — manageable).
The `prioritizeServers` rewrite is the bulk of the work. Tests
should account for ~40% of the time.

---

### W7. RTT collection and use (was S6) [Phase 3, M effort]

**Goal:** capture per-(addr, transport) round-trip time and use
it to sort tuples in `prioritizeServers`.

**Depends on:** W6 (uses `AddrXport` keying).

**Files touched:**
- `tdns/v2/cache/authserver.go` — new field + methods on
  `AuthServer`
- `tdns/v2/dnslookup.go` — `tryServer` reports RTT;
  `prioritizeServers` sorts by RTT

#### 7.1 AuthServer additions

```go
// In AuthServer struct (existing file, after AddressBackoffs):
RTTEstimates map[AddrXport]*RTTEstimate

// New type in same file:
type RTTEstimate struct {
   EMA          time.Duration // Exponential moving average
   Samples      uint32        // Number of samples folded in
   LastSample   time.Duration
   LastSampleAt time.Time
}

// Methods:
func (as *AuthServer) RecordRTT(addr string, t core.Transport, rtt time.Duration) {
   if as == nil || rtt <= 0 { return }
   as.mu.Lock(); defer as.mu.Unlock()
   if as.RTTEstimates == nil { as.RTTEstimates = make(map[AddrXport]*RTTEstimate) }
   k := AddrXport{Addr: addr, Transport: t}
   r, ok := as.RTTEstimates[k]
   if !ok {
      r = &RTTEstimate{EMA: rtt, Samples: 1}
   } else {
      // EMA with alpha=0.25. Tune via tuning conf later if needed.
      const alpha = 0.25
      r.EMA = time.Duration(alpha*float64(rtt) + (1-alpha)*float64(r.EMA))
      if r.Samples < math.MaxUint32 { r.Samples++ }
   }
   r.LastSample = rtt
   r.LastSampleAt = time.Now()
   as.RTTEstimates[k] = r
}

func (as *AuthServer) GetRTT(addr string, t core.Transport) (time.Duration, bool) {
   if as == nil { return 0, false }
   as.mu.Lock(); defer as.mu.Unlock()
   r, ok := as.RTTEstimates[AddrXport{Addr: addr, Transport: t}]
   if !ok { return 0, false }
   return r.EMA, true
}
```

#### 7.2 tryServer wires RTT

`tryServer` already receives `rtt` from `c.Exchange`
(currently discarded with `_` at
[dnslookup.go:1667](tdns/v2/dnslookup.go:1667)). Capture it:

```go
r, rtt, err := c.Exchange(m, addr, Globals.Debug && !imr.Quiet)
// ... after success:
if r != nil {
   server.RecordAddressSuccess(addr, t)
   server.RecordRTT(addr, t, rtt)
}
```

For timeout cases, record a "penalty RTT" equal to the
attempt's effective deadline:

```go
// On final transient timeout, after backoff exhausted:
server.RecordRTT(addr, t, penaltyRTT) // e.g. 5s
```

A penalty RTT entry naturally pushes the tuple to the bottom
of the sort, which is the "natural deprioritization on
failure" property we want.

#### 7.3 prioritizeServers sort

In `sortTuplesByWeightedPreference` (or rename to
`sortTuplesByRTT`), use `GetRTT(addr, t)` as the primary key.
For tuples without RTT data yet, use a midpoint sentinel
(e.g. 200ms) so unprobed tuples sit between the known-fast
and the known-slow. Break ties using the deterministic
weighted-hash bucket from W6.5.

#### 7.4 Decay

Without decay, an old fast RTT can mask a server that has
since become slow. Simplest decay: when `LastSampleAt` is
older than `BackoffConf.MaxFailure` (1h default), treat the
tuple as "no data" — re-probe.

#### 7.5 Testing

Extend `tdns/v2/cache/authserver_test.go`:
- `RecordRTT(addr, Do53, 100ms)` then `GetRTT(addr, Do53)`
  returns ~100ms.
- 10 samples drift the EMA toward the new value (not jumpy).
- `GetRTT` on a non-existent key returns `(0, false)`.

Extend `tdns/v2/dnslookup_prioritize_test.go`:
- Two servers; one has RTT 50ms recorded, the other 500ms;
  assert the 50ms server's tuples come first.

---

### W8. Address-family reachability tracking (was S12) [Phase 4, M effort]

**Goal:** if N distinct v6 attempts fail with timeout/no-route
within a sliding window and zero succeed, deprioritize v6
addresses across the board. Recover via probe.

**Depends on:** W1 (uses `AddressFamilyConf`); benefits from
W6 (the tuple-expansion code is the natural place to add the
filter).

#### 8.1 New type in cache package

**File:** new `tdns/v2/cache/family_tracker.go`

```go
package cache

import (
   "sync"
   "time"
)

type AddressFamily int

const (
   FamilyV4 AddressFamily = 4
   FamilyV6 AddressFamily = 6
)

// FamilyTracker accumulates per-family reachability evidence
// from query outcomes and reports a "suspect" verdict for
// a family when the local host appears to have no working
// connectivity over it.
type FamilyTracker struct {
   mu       sync.Mutex
   window   time.Duration
   threshold int
   suspectDuration time.Duration
   probeInterval   time.Duration

   v4 familyStats
   v6 familyStats
}

type familyStats struct {
   recentFailures []time.Time         // sliding window
   recentSuccesses []time.Time        // sliding window (for clarity in dumps)
   suspectUntil   time.Time           // zero if not suspect
   lastProbeAt    time.Time
}

func NewFamilyTracker(window, suspect, probe time.Duration, threshold int) *FamilyTracker {
   return &FamilyTracker{
      window: window, threshold: threshold,
      suspectDuration: suspect, probeInterval: probe,
   }
}

func (f *FamilyTracker) RecordResult(addr string, success bool) {
   fam := familyOf(addr)
   if fam == 0 { return }
   f.mu.Lock(); defer f.mu.Unlock()
   stats := f.statsFor(fam)
   now := time.Now()
   f.expire(stats, now)
   if success {
      stats.recentSuccesses = append(stats.recentSuccesses, now)
      stats.suspectUntil = time.Time{} // a success clears suspect
   } else {
      stats.recentFailures = append(stats.recentFailures, now)
      if len(stats.recentFailures) >= f.threshold && len(stats.recentSuccesses) == 0 {
         stats.suspectUntil = now.Add(f.suspectDuration)
      }
   }
}

// IsSuspect reports whether a family is currently deprioritized.
// Returns false if the suspect window has expired.
func (f *FamilyTracker) IsSuspect(fam AddressFamily) bool {
   f.mu.Lock(); defer f.mu.Unlock()
   stats := f.statsFor(fam)
   return !stats.suspectUntil.IsZero() && time.Now().Before(stats.suspectUntil)
}

// ShouldProbe returns true once per ProbeInterval while suspect,
// so the caller can include one probe tuple in the prioritized list.
func (f *FamilyTracker) ShouldProbe(fam AddressFamily) bool {
   f.mu.Lock(); defer f.mu.Unlock()
   stats := f.statsFor(fam)
   if stats.suspectUntil.IsZero() { return false }
   if time.Since(stats.lastProbeAt) < f.probeInterval { return false }
   stats.lastProbeAt = time.Now()
   return true
}

func (f *FamilyTracker) Snapshot() (v4, v6 FamilyStatsSnapshot) { /* ... */ }

func familyOf(addr string) AddressFamily {
   // Strip port if present.
   host, _, err := net.SplitHostPort(addr)
   if err != nil { host = addr }
   ip := net.ParseIP(host)
   if ip == nil { return 0 }
   if ip.To4() != nil { return FamilyV4 }
   return FamilyV6
}

func (f *FamilyTracker) statsFor(fam AddressFamily) *familyStats {
   if fam == FamilyV4 { return &f.v4 }
   return &f.v6
}

func (f *FamilyTracker) expire(s *familyStats, now time.Time) {
   cutoff := now.Add(-f.window)
   s.recentFailures = trimBefore(s.recentFailures, cutoff)
   s.recentSuccesses = trimBefore(s.recentSuccesses, cutoff)
}
```

#### 8.2 Hook into Imr

`Imr` struct gains a `FamilyTracker *cache.FamilyTracker`
field (imrengine.go:27). `InitImrEngine` (line 84)
instantiates it from `conf.Imr.Tuning.AddressFamily`.

#### 8.3 Hook into tryServer

After every `tryServer` outcome:

```go
imr.FamilyTracker.RecordResult(addr, err == nil)
```

#### 8.4 Hook into prioritizeServers

In the tuple-expansion loop from W6.3, before appending:

```go
fam := cache.FamilyOf(addr)
if imr.FamilyTracker.IsSuspect(fam) {
   // Push to bottom: collect into suspect bucket
   if imr.FamilyTracker.ShouldProbe(fam) {
      // include one probe tuple at the back
      suspectTuples = append(suspectTuples, ServerAddrXportTuple{...})
   }
   continue
}
tuples = append(tuples, ServerAddrXportTuple{...})
```

After the main loop:

```go
// Suspect tuples go after healthy ones — they remain reachable
// but only after everything else has been tried.
tuples = append(tuples, suspectTuples...)
```

(If you want hard deprioritization with NO probe attempts,
just `continue` without recording into suspectTuples. The
tunable approach is to make probing controlled by
`ProbeInterval` — set to 0 in config to disable probing.)

#### 8.5 Observability

Extend `imr dump auth-servers` (W4) with a section showing
family tracker state: window contents, suspect status, last
probe time. Optionally a new command `imr dump family` that
just prints the snapshot.

#### 8.6 Testing

New file `tdns/v2/cache/family_tracker_test.go`:
- 5 v6 failures with 0 successes within window → IsSuspect(v6)
  is true.
- One v6 success clears IsSuspect.
- After SuspectDuration elapses, IsSuspect returns false.
- ShouldProbe returns true at most once per ProbeInterval.
- Sliding window: failures older than WindowDuration don't
  count.

---

### W9. Discovery state machine (was S5) [Phase 5, M effort]

**Goal:** replace the fire-and-forget transport-signal
discovery with a per-server state machine that retries on
failure with backoff and surfaces state in CLI dumps.

**Files touched:**
- `tdns/v2/cache/discovery_state.go` (new)
- `tdns/v2/imr_helpers.go` — `maybeQueryTransportSignal` and
  `launchTransportSignalQuery`
- `tdns/v2/cli/imr_dump_cmds.go` — dump new state

#### 9.1 Replace simple "in-flight" tracking

Today the cache uses `transportQueryInFlight map[string]struct{}`
([rrset_cache.go:353-422](tdns/v2/cache/rrset_cache.go)) with
`MarkTransportQuery` / `ClearTransportQuery`. This is a *mutex*,
not a *state*. Replace with:

```go
// tdns/v2/cache/discovery_state.go
type DiscoveryStatus int

const (
   DiscoveryNotAttempted DiscoveryStatus = iota
   DiscoveryInProgress
   DiscoverySucceeded
   DiscoveryFailed
)

type DiscoveryState struct {
   Status        DiscoveryStatus
   AttemptCount  int
   LastAttemptAt time.Time
   NextAttemptAt time.Time
   LastError     string
}

type DiscoveryTracker struct {
   mu sync.Mutex
   states map[string]*DiscoveryState // key: owner FQDN
   maxFailures int
   retryAfter  time.Duration
}

func NewDiscoveryTracker(retryAfter time.Duration, maxFailures int) *DiscoveryTracker {
   return &DiscoveryTracker{
      states: make(map[string]*DiscoveryState),
      retryAfter: retryAfter, maxFailures: maxFailures,
   }
}

// Begin returns true if the caller should attempt discovery now.
// Returns false if already in progress, or if recently failed
// and within retry cooldown.
func (d *DiscoveryTracker) Begin(owner string) bool {
   d.mu.Lock(); defer d.mu.Unlock()
   s, ok := d.states[owner]
   if !ok {
      d.states[owner] = &DiscoveryState{Status: DiscoveryInProgress, LastAttemptAt: time.Now()}
      return true
   }
   switch s.Status {
   case DiscoveryInProgress: return false
   case DiscoverySucceeded:  return false
   case DiscoveryFailed:
      if time.Now().Before(s.NextAttemptAt) { return false }
   }
   s.Status = DiscoveryInProgress
   s.LastAttemptAt = time.Now()
   return true
}

func (d *DiscoveryTracker) Succeed(owner string) {
   d.mu.Lock(); defer d.mu.Unlock()
   if s, ok := d.states[owner]; ok {
      s.Status = DiscoverySucceeded
      s.LastError = ""
   }
}

func (d *DiscoveryTracker) Fail(owner string, err error) {
   d.mu.Lock(); defer d.mu.Unlock()
   s, ok := d.states[owner]
   if !ok { return }
   s.Status = DiscoveryFailed
   s.AttemptCount++
   if err != nil { s.LastError = err.Error() }
   // Exponential cooldown capped at retryAfter * 2^maxFailures.
   cooldown := d.retryAfter * time.Duration(1<<min(s.AttemptCount, d.maxFailures))
   s.NextAttemptAt = time.Now().Add(cooldown)
}
```

#### 9.2 Wire into imr_helpers.go

Replace `MarkTransportQuery`/`ClearTransportQuery` calls in
`launchTransportSignalQuery` ([imr_helpers.go:76-92](tdns/v2/imr_helpers.go)):

```go
func (imr *Imr) launchTransportSignalQuery(ctx context.Context, owner string, reason string) {
   if owner == "" || ctx == nil || imr.Cache == nil { return }
   if imr.TransportSignalCached(owner) { return }
   if !imr.Cache.DiscoveryTracker.Begin(owner) { return }
   go func() {
      queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
      defer cancel()
      rrtype := imr.TransportSignalRRType()
      resp, err := imr.ImrQuery(queryCtx, owner, rrtype, dns.ClassINET, nil)
      if err != nil || resp == nil || resp.RRset == nil || len(resp.RRset.RRs) == 0 {
         imr.Cache.DiscoveryTracker.Fail(owner, err)
         return
      }
      imr.Cache.DiscoveryTracker.Succeed(owner)
   }()
}
```

Same treatment for `maybeQueryTLSA` (imr_helpers.go:95-132) —
use a *separate* `DiscoveryTracker` for TLSA so TLSA failures
don't backoff transport queries and vice versa. Or use a
single tracker with a (kind, owner) key. The user's call.

#### 9.3 Observability

Extend `imr dump auth-servers` with discovery state per
relevant owner (the `_dns.<nsname>` SVCB owner and TLSA
owners). New `imr dump discovery` command is also reasonable.

#### 9.4 Testing

New file `tdns/v2/cache/discovery_tracker_test.go`:
- `Begin(owner)` returns true on first call.
- Second `Begin` while InProgress returns false.
- After `Succeed`, `Begin` returns false (we've discovered it,
  no retry needed unless cache expires — which is a separate
  concern handled by `TransportSignalCached`).
- After `Fail`, `Begin` returns false until `NextAttemptAt`
  passes.
- Exponential backoff: 1st fail = retryAfter, 2nd = 2x, etc.
  up to maxFailures.

#### 9.5 Note

This change preserves the existing fire-and-forget
*timing semantics* (callers don't block on discovery). It just
adds memory of failures so we don't silently stop probing
broken servers and silently keep probing healthy ones.

---

### W10. Parallel-NS first-success — DEFERRED [Phase 6, S effort]

**Decision (2026-05-16):** defer until after W7 and W8 land
and lab metrics are collected. The combination of address-
family deprioritization (W8) and RTT-based sort (W7) should
already eliminate the "v6 tried first and blocks" pathology
that motivates W10. Implementing W10 speculatively risks
cancellation-correctness bugs in a path that may not need to
change at all.

**If pursued:**

**File:** `tdns/v2/imrengine.go`, `resolveNSAddresses`
(line 501).

The function already launches A and AAAA queries in parallel
via `CollectNSAddresses`. The change is in the response loop
(lines 528-552): exit as soon as `processAddressRecords` plus
the `onResponse` callback signals success, rather than
draining all expected responses.

The risk is losing late-arriving cache population for the
non-winning queries. Mitigation: the `respch` consumer in
`ImrQuery` (imrengine.go:319-329) already writes responses to
the response channel; if we change semantics, late writes
might block. Add a background drain goroutine that
continues reading from `respch` until all in-flight queries
complete, populating cache but discarding response delivery.

Testing: integration test in `tdns/v2/dnslookup_resolve_ns_test.go`:
- Configure one slow NS (deliberate sleep) and one fast NS.
- Assert overall lookup latency is bounded by the fast NS,
  not the slow one.

---

## 3. Items absorbed (with rationale)

### S2 — Demote a transport after N consecutive failures
**Absorbed into W6.** After W6, the backoff filter is keyed
by `(addr, transport)`. A failure on `(X, DoT)` automatically
removes that tuple from the prioritized list until the
backoff expires. A separate "weight = 0" mechanism would
duplicate this. The W6 mechanism is strictly better because
it preserves the configured weight policy (for the *next*
qname) while still removing this specific failing path from
*this* query.

### S4 — Cross-transport fallback ladder
**Absorbed into W6.** In the W6 design, `prioritizeServers`
emits multiple tuples for the same server when multiple
transports are available. The query loop in
`IterativeDNSQuery` already walks these sequentially. If
`(X, DoT)` fails, the next tuple in the list may be
`(X, Do53)` — same server, different transport. No separate
"fallback ladder" needed. The TC=1 / timeout UDP→TCP
fallbacks, consolidated into `core.DNSClient.Exchange` in W5,
remain as the intra-transport recovery layer.

### S8 phase 2 (per-(addr, transport) observability)
**Folded into W6 and W7.** Phase 1 (W4) extends what's
already there. Per-(addr, transport) detail requires the
underlying data, which appears in W6 and W7. The CLI changes
land alongside the data they expose.

---

## 4. Items NOT planned for implementation

After deep planning, every original item is either kept
(W1–W9) or absorbed (S2, S4, partial S8). **Zero outright
rejections.**

The deferred item — W10 (parallel A+AAAA first-success) — is
not rejected; it's *contingent* on post-W7 + post-W8
measurement. Implementing it speculatively would add
complexity for a benefit W7+W8 may already deliver.

---

## 5. Testing strategy

### 5.1 Unit tests

Per work item; called out in each W section above.

### 5.2 Integration testing

`tdns-mp` lab integration is the eventual proving ground, but
the deployment cadence is too slow for inner-loop development.
Suggest a `tdns/v2/imr_integration_test.go` (build tag
`integration`) that:
- Stands up an in-process `Imr` with a stub cache
- Uses a fake `DNSClient` interface that can be programmed to
  return specific (response, rtt, error) per (addr, transport)
- Verifies end-to-end behaviour: backoff lookup, family
  tracker integration, discovery state machine, RTT sort.

**Note:** the `DNSClienter` interface and `FakeDNSClient`
introduced in W5 are exactly what enable this integration
test suite — that's a major reason W5 exists.

### 5.3 Manual lab verification

After each significant phase:
- Run on the lab testbed
- Capture `tdns-mpcli agent gossip group state --group <id>`
- Confirm provider→auditor and auditor→auditor convergence
  improves measurably

After all phases: the matrix from the original symptom should
show no NEEDED cells beyond the first 30s after a peer
restart.

---

## 6. Implementation conventions

- **Per memory rule:** every Go edit followed by
  `gofmt -w <file>`. Never manually adjust indentation.
- **Per memory rule:** build before commit. `cd tdns/cmdv2 &&
  GOROOT=/opt/local/lib/go make`. If tdns-mp is also touched,
  build that too.
- **Per memory rule:** no `git commit --amend`. New commits
  per logical change.
- **Per memory rule:** commit + push to feature branches OK;
  PR creation/merge needs explicit approval.
- **Branching (decided 2026-05-16):** single long-running
  branch `imr-overhaul` containing all work items as
  separate commits, landing as one large PR at the end.
  Commits per work item so they can still be reviewed in
  order.
- **Doc updates:** when each work item lands, mark its status
  in this plan and update the review doc's "Suggestions"
  section to reflect what was done vs. modified.

---

## 7. Decisions (locked in 2026-05-16)

1. **Branching strategy.** Single long-running branch
   `imr-overhaul`, one commit per work item, single PR at
   the end. Memory rule about feature-branch pushes still
   applies (commit + push OK; merge needs approval).

2. **DNSClient interface.** Accepted as W5 — running-code
   cost is essentially nil, testability gain is large, and
   the adjacent cleanup (move timeout-UDP→TCP fallback into
   `Exchange` next to the existing TC=1 fallback) is a clear
   improvement on its own.

3. **Cache-upgrade default.** `UpgradeIndirectCacheHits`
   defaults to `true` in the tdns library (preserves DNSSEC
   correctness for scanner, KSK rollover, delegation
   analysis). tdns-mp overrides to `false` in its default
   config (gossip workload benefits from cache reuse). The
   override lives in tdns-mp's config-defaults code — find
   the analogue of `loadImrTuningDefaults` in tdns-mp or add
   one.

4. **Address-family probing.** `ProbeInterval` defaults to
   30s. Confirmed appropriate.

5. **W10 (parallel A+AAAA first-success).** Deferred. Re-
   evaluate after W7 + W8 land. The combination of address-
   family deprioritization (W8) and RTT-based sort (W7)
   should already eliminate the "v6 tried first and blocks"
   pathology; if residual tail latency remains in lab
   metrics, revisit.

---

## 8. Status tracking

| Work item | Status | PR | Notes |
|-----------|--------|----|----|
| W1 Config foundation         | landed (720023c) | (branch imr-overhaul) | |
| W2 Quick wins bundle         | landed (22305af) | (branch imr-overhaul) | S3+S10+S11 |
| W3 Cache-upgrade policy      | landed (4b0c2b1) | (branch imr-overhaul) | |
| W4 Observability v1          | landed (32cf1f0) | (branch imr-overhaul) | |
| W5 DNSClient interface       | not started | - | Enables W6+ tests |
| W6 (addr,transport) refactor | not started | - | Largest item; depends on W5 |
| W7 RTT                       | not started | - | Depends on W6 |
| W8 Address-family tracker    | not started | - | Depends on W1 |
| W9 Discovery state machine   | not started | - | Independent |
| W10 Parallel NS first-success | deferred   | - | Re-evaluate after W7+W8 |
