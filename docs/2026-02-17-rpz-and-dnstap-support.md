# RPZ and DNSTAP Support for TDNS

**Date**: 2026-02-17
**Status**: Future project (effort estimate, not yet scheduled)

## Motivation

Two features that would significantly improve TDNS's utility as a production DNS platform:

1. **RPZ (Response Policy Zones)** — DNS-based policy enforcement in the recursive resolver (tdns-imr). Enables blocking, redirecting, or rewriting DNS responses based on policy rules distributed as standard DNS zone data. Widely used for security filtering, parental controls, and compliance.

2. **DNSTAP** — Structured binary logging of DNS transactions across all TDNS applications. Provides low-overhead, machine-parseable visibility into query/response traffic, replacing or supplementing text-based logging. Supported by all major DNS implementations (BIND, Unbound, Knot, PowerDNS, CoreDNS).

---

## Part A: RPZ Support in the IMR

### Overview

RPZ policy checks are inserted into the IMR's resolution pipeline at two points:

1. **Pre-resolution (QNAME trigger)** — check the query name before resolving
2. **Post-resolution (response triggers)** — check answer data before returning to client:
   - IP trigger: match A/AAAA answer addresses
   - NSDNAME trigger: match authoritative NS names
   - NSIP trigger: match authoritative NS addresses
   - Client IP trigger (lower priority, optional)

### RPZ Encoding

RPZ rules are encoded as standard DNS records in a specially-formatted zone:

| Trigger Type | Owner Name Format | Example |
|-------------|-------------------|---------|
| QNAME | `<domain>.rpz-zone.` | `bad.example.com.rpz.` |
| IP | `<reversed-ip>.rpz-ip.` | `32.2.0.168.192.rpz-ip.rpz.` |
| NSDNAME | `<ns-name>.rpz-nsdname.` | `ns1.bad.example.rpz-nsdname.rpz.` |
| NSIP | `<reversed-ip>.rpz-nsip.` | `24.0.51.198.rpz-nsip.rpz.` |

Actions are encoded via RDATA:

| Action | Encoding |
|--------|----------|
| NXDOMAIN | `CNAME .` |
| NODATA | `CNAME *.` |
| Redirect | `CNAME <target>.` |
| Substitute | A/AAAA records with replacement addresses |
| Passthrough | No record at trigger name |

### Components

1. **RPZ zone loader** — RPZ zones are standard DNS zones. The existing `ZoneData` zone file parser and AXFR/IXFR transfer machinery can be reused directly. No custom parser needed.

2. **RPZ policy engine** — Core new code. Given a trigger (qname, IP, nsdname, nsip), look up matching rules in the RPZ zone and return the action:
   - QNAME matching: direct owner name lookup in the RPZ zone
   - IP matching: reverse IP into RPZ format, walk from /32 to shorter prefixes looking for matches
   - NSDNAME/NSIP matching: similar patterns under their respective suffixes
   - Action decoding: inspect RDATA of matching records
   - Wildcard support: `*.example.com.rpz.` matches all subdomains

3. **Resolution pipeline integration** — Hook into `ImrResponder()` (imrengine.go) and `IterativeDNSQuery()` (dnslookup.go):
   - Pre-resolution QNAME check in `ImrResponder()` before calling `ImrQuery()`
   - Post-resolution IP check in `handleAnswer()` after DNSSEC validation, before caching
   - Optional: NS name/IP checks in `handleReferral()` during iterative resolution

4. **RPZ zone refresh** — Standard AXFR/IXFR with NOTIFY-triggered refresh. TDNS already implements all of this for authoritative zones — reuse directly.

5. **Configuration** — RPZ zone list in IMR config with zone name, source (file or primary server), and priority ordering.

6. **CLI** — `imr rpz list`, `imr rpz reload`, `imr rpz stats`.

### Key integration points

| File | Integration |
|------|-------------|
| `imrengine.go` | Pre-resolution QNAME check in `ImrResponder()` (~line 486) |
| `dnslookup.go` | Post-resolution IP check in `handleAnswer()` (~line 1938) |
| `dnslookup.go` | Optional NSDNAME/NSIP checks in `handleReferral()` (~line 2070) |
| `config.go` | RPZ zone configuration |
| New: `imr_rpz.go` | Policy engine (matching, action decoding, zone management) |

### Effort estimate

**~1000-1500 lines of new code**

| Component | Lines |
|-----------|-------|
| Policy engine (matching + action decoding) | ~400-600 |
| Resolution pipeline hooks | ~200-300 |
| Zone management, refresh, config | ~200-300 |
| CLI commands | ~100 |
| Tests | ~300-400 |

**Files**: 1-2 new files + 3-4 modified

**Comparable to**: Reliable Message Queue (Phases 5-9) in scope — a new subsystem with its own data structures wired into an existing processing pipeline. Slightly less total code because zone loading is free.

### Risk factors

- IP trigger prefix walking (/32 to /0) needs efficient lookup — could use a radix tree, or brute-force walk (RPZ zones are typically small enough)
- Wildcard QNAME matching requires walking up the domain hierarchy
- Multiple RPZ zones with priority ordering needs care (first match wins, ordered by zone priority)
- DNSSEC interaction: RPZ-modified responses break DNSSEC validation by design — need to handle this gracefully (set AD=0, optionally add EDE extended error code)

### No new external dependencies

RPZ uses standard DNS zone data. The existing zone file parser, ZoneData structures, and AXFR/IXFR machinery in TDNS handle all the data management. The only new code is the policy matching and action logic.

---

## Part B: DNSTAP Support in All TDNS Apps

### Overview

DNSTAP captures DNS query/response pairs with metadata and streams them to a collector via Unix socket, TCP, or file. The [golang-dnstap](https://github.com/dnstap/golang-dnstap) library (v0.4.0, used by CoreDNS) provides Protocol Buffer encoding and Frame Streams framing.

### DNSTAP message types relevant to TDNS

| Message Type | App | When |
|-------------|-----|------|
| `AUTH_QUERY` / `AUTH_RESPONSE` | tdns-auth, tdns-agent, tdns-combiner | Authoritative query serving |
| `CLIENT_QUERY` / `CLIENT_RESPONSE` | tdns-imr | Client queries to the resolver |
| `RESOLVER_QUERY` / `RESOLVER_RESPONSE` | tdns-imr | Outgoing iterative queries during resolution |
| `UPDATE_QUERY` / `UPDATE_RESPONSE` | tdns-auth, tdns-agent | Dynamic UPDATE processing |

### Components

1. **DNSTAP output manager** — Initialize and manage a dnstap output stream (Unix socket or TCP). Connection management, buffering, graceful shutdown. The golang-dnstap library provides `FrameStreamSockOutput` — this is thin wrapper code.

2. **ResponseWriter wrapper** — A `dns.ResponseWriter` wrapper that intercepts `WriteMsg()`, captures the response alongside the original query, builds a `dnstap.Message`, and sends it to the output stream:

   ```go
   type dnstapWriter struct {
       dns.ResponseWriter
       query     *dns.Msg
       output    *dnstap.Output
       transport dnstap.SocketProtocol
       queryTime time.Time
   }

   func (w *dnstapWriter) WriteMsg(m *dns.Msg) error {
       // Build dnstap.Message with query + response + metadata
       // Send to output (non-blocking, buffered)
       // Forward to wrapped ResponseWriter
       return w.ResponseWriter.WriteMsg(m)
   }
   ```

3. **Handler wrapping** — Wrap the DNS handler in `createAuthDnsHandler()` (do53.go) to inject the dnstap writer. **One wrapper point covers three apps** — tdns-auth, tdns-agent, and tdns-combiner all share `DnsEngine()`.

4. **Transport-specific adaptations**:
   - **Do53 (UDP/TCP)**: Standard `dns.ResponseWriter` — wrap directly
   - **DoT**: Same (miekg/dns handles TLS transparently)
   - **DoH**: Custom `dohResponseWriter` in doh.go — needs its own dnstap wrapper (~50 lines)
   - **DoQ**: Custom `doqResponseWriter` in doq.go — needs its own dnstap wrapper (~50 lines)

5. **IMR resolver hooks** — Two additional instrumentation points:
   - Outgoing iterative queries in `tryServer()` (dnslookup.go) — capture RESOLVER_QUERY before sending, RESOLVER_RESPONSE after receiving
   - Cache hits in `ImrResponder()` (imrengine.go) — capture CLIENT_RESPONSE when returning cached data

6. **Per-app configuration** — Add dnstap config to each app's config structure:
   ```yaml
   dnstap:
     enabled: true
     socket: /var/run/tdns/dnstap.sock
     # or: tcp: 127.0.0.1:6000
     # or: file: /var/log/tdns/dnstap.log
   ```

7. **CLI** — `<app> dnstap status` for runtime introspection.

### Key integration points

| File | Integration |
|------|-------------|
| New: `dnstap.go` | Output manager, ResponseWriter wrapper, message builder |
| `do53.go` | Wrap handler in `DnsEngine()` / `createAuthDnsHandler()` |
| `doh.go` | Wrap `dohResponseWriter` |
| `doq.go` | Wrap `doqResponseWriter` |
| `imrengine.go` | Wrap handler in `StartImrEngineListeners()`, cache hit capture |
| `dnslookup.go` | RESOLVER_QUERY/RESOLVER_RESPONSE in `tryServer()` |
| Config files | Add dnstap configuration per app |

### Effort estimate

**~600-900 lines of new code**

| Component | Lines |
|-----------|-------|
| Output manager (init, connect, shutdown) | ~100-150 |
| ResponseWriter wrapper + message builder | ~150-200 |
| Handler wrapping in DnsEngine | ~50 |
| DoH wrapper | ~50 |
| DoQ wrapper | ~50 |
| IMR resolver hooks | ~100-150 |
| Config additions | ~50 |
| CLI | ~50-100 |
| Tests | ~200-300 |

**Files**: 1 new file + 5-6 modified

**Comparable to**: Phase 1a+1b (Transport Unification Foundation) — mechanical wiring across multiple files/apps. The golang-dnstap library handles all the heavy lifting (protobuf encoding, Frame Streams framing).

### Risk factors

- DoH and DoQ custom ResponseWriter types don't use the standard `dns.ResponseWriter` interface identically — the dnstap wrapper needs transport-specific variants
- Buffer sizing and backpressure: if the dnstap collector is slow, the output buffer (default 10,000 messages in CoreDNS) can fill up. Drop policy needed (drop oldest vs. drop newest)
- Wire-format DNS message capture: `WriteMsg()` receives a parsed `*dns.Msg` — need to call `Pack()` to get wire format for the dnstap protobuf. Minor performance cost per message

### New external dependency

- `github.com/dnstap/golang-dnstap` — Protocol Buffers + Frame Streams for dnstap encoding/transport

---

## Combined Effort Summary

| Feature | New Code | Files | Complexity | Comparable Phase |
|---------|----------|-------|------------|-----------------|
| **RPZ** | ~1000-1500 lines | 1-2 new + 3-4 modified | Medium-High | Reliable Message Queue (Phases 5-9) |
| **DNSTAP** | ~600-900 lines | 1 new + 5-6 modified | Medium | Transport Unification 1a+1b |
| **Both** | ~1600-2400 lines | 2-3 new + 7-9 modified | — | Slightly less than full Transport Unification (Phases 1-2) |

### Comparison to recent completed work

| Project | Lines | Files | Notes |
|---------|-------|-------|-------|
| JOSE/HPKE crypto (Phases 2+3) | ~1600 | 4 | New subsystem with tests |
| Reliable Message Queue + Confirmations (Phases 5-9) | ~2000 | 11 | New state machine + integration |
| Transport Unification Phase 1 (all sub-steps) | ~1500 | 8 | Architecture refactor |
| CLI Peer Restructure | ~300 | 5 | Command tree reorganization |
| **RPZ + DNSTAP (estimated)** | **~1600-2400** | **9-12** | **New subsystem + cross-app wiring** |

### Suggested implementation order

1. **DNSTAP first** — simpler, provides immediate operational value, and the instrumentation helps debug RPZ once it's added
2. **RPZ second** — builds on a well-instrumented resolver where query flow is visible via DNSTAP

### Phasing sketch

**DNSTAP** (2-3 phases):
1. Core output manager + Do53/DoT wrapper (covers auth/agent/combiner)
2. DoH + DoQ wrappers
3. IMR resolver hooks (RESOLVER_QUERY/RESOLVER_RESPONSE)

**RPZ** (3-4 phases):
1. RPZ zone loader (reuse ZoneData) + QNAME trigger
2. IP trigger (post-resolution answer checking)
3. NSDNAME + NSIP triggers (during referral handling)
4. RPZ zone refresh via AXFR/IXFR + NOTIFY
