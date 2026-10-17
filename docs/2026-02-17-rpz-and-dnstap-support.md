# RPZ and DNSTAP Support for TDNS

**Date**: 2026-02-17
**Status**: Future project (effort estimate, not yet scheduled)
**Updated**: 2026-10-01 — Part B (DNSTAP) re-scoped against current `v2/`. Part A (RPZ) has not been re-evaluated; only its stale line numbers were removed.

## Motivation

Two features that would significantly improve TDNS's utility as a production DNS platform:

1. **RPZ (Response Policy Zones)** — DNS-based policy enforcement in the recursive resolver (tdns-imr). Enables blocking, redirecting, or rewriting DNS responses based on policy rules distributed as standard DNS zone data. Widely used for security filtering, parental controls, and compliance.

2. **DNSTAP** — Structured binary logging of DNS transactions in tdns-auth and tdns-imr. Provides low-overhead, machine-parseable visibility into query/response traffic, replacing or supplementing text-based logging. Supported by all major DNS implementations (BIND, Unbound, Knot, PowerDNS, CoreDNS).

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
| `imrengine.go` | Pre-resolution QNAME check in `ImrResponder()` |
| `dnslookup.go` | Post-resolution IP check in `handleAnswer()` |
| `dnslookup.go` | Optional NSDNAME/NSIP checks in `handleReferral()` |
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

## Part B: DNSTAP Support in tdns-auth and tdns-imr

*Re-scoped 2026-10-01 against `v2/` at `cf5bc243`. File names below are relative to `v2/`.*

### Overview

DNSTAP captures DNS query/response pairs with metadata and streams them to a collector via Unix socket, TCP, or file. The [golang-dnstap](https://github.com/dnstap/golang-dnstap) library provides Protocol Buffer encoding and Frame Streams framing.

**Assessment: clean fit, no refactor.** Since the original estimate the code has grown the extension points dnstap needs: embedding `dns.ResponseWriter` wrappers (`truncatingResponseWriter` in `udp_truncate.go`, `tsigSignResponseWriter` in `tsig_peer.go`), per-transport handler wrapping in the IMR (`listenerHandlers()` in `imr_client_stats.go`), and a single outbound exchange path (`core.DNSClient.exchangeInner()`).

### DNSTAP message types relevant to TDNS

| Message Type | App | When |
|-------------|-----|------|
| `AUTH_QUERY` / `AUTH_RESPONSE` | tdns-auth (and any other app that starts `DnsEngine()`) | Authoritative query serving |
| `UPDATE_QUERY` / `UPDATE_RESPONSE` | tdns-auth | Dynamic UPDATE processing |
| `CLIENT_QUERY` / `CLIENT_RESPONSE` | tdns-imr | Client queries to the resolver |
| `RESOLVER_QUERY` / `RESOLVER_RESPONSE` | tdns-imr | Outgoing iterative queries |
| `FORWARDER_QUERY` / `FORWARDER_RESPONSE` | tdns-imr | Outgoing queries to forward-zone upstreams |

### Components

1. **DNSTAP output manager** — Initialize and manage the output stream (Unix socket, TCP or file): reconnect, bounded channel, drop-on-full with counters, graceful shutdown on ctx cancel.

2. **ResponseWriter wrapper** — One embedding wrapper, same shape as `truncatingResponseWriter`: emit the query frame on entry, override `WriteMsg()` to emit the response frame, forward to the inner writer.

   ```go
   type dnstapWriter struct {
       dns.ResponseWriter
       out       *dnstapOutput
       query     *dns.Msg
       proto     dnstap.SocketProtocol
       mtype     dnstap.Message_Type // AUTH_*, UPDATE_*, CLIENT_*
       queryTime time.Time
   }
   ```

   No transport-specific variants are needed: `dohResponseWriter` and `doqResponseWriter` implement `dns.ResponseWriter` in full, so the same wrapper embeds them. (The original estimate budgeted ~50 lines each for DoH and DoQ; that is no longer required.)

3. **Inbound wiring, tdns-auth** — Wrap the handler from `createAuthDnsHandler()` once per listener so the wrapper knows its transport. Four sites:
   - Do53 mux in `DnsEngine()` (`do53.go`). Must be outermost: `dnstap(TsigSigningHandler(udpTruncate(h)))`, otherwise the frame holds the untruncated response.
   - `DnsDoTEngine()` (`dot.go`), outside its `TsigSigningHandler`.
   - `DnsDoHEngine()` (`doh.go`) and `DnsDoQEngine()` (`doq.go`), which take the bare handler.

4. **Inbound wiring, tdns-imr** — Extend `listenerHandlers()`, which already returns one handler per transport (udp/tcp/dot/doh/doq) for the client-stats counters. Because the wrapper sits at the listener, cache hits, CNAME-chain answers and error paths are covered without touching `ImrResponder()`.

5. **Outbound wiring, tdns-imr** — Two call sites:
   - `tryServer()` (`dnslookup.go`), around `core.ExchangeCtxWithResult()` → `RESOLVER_*`
   - `forwardQuery()` (`imr_forward.go`), around `core.ExchangeCtx()` → `FORWARDER_*`

   Alternative: instrument once inside `core.DNSClient.exchangeInner()`. That records a UDP→TCP retry as two exchanges (more faithful), but puts dnstap in `core` and needs the message type passed down.

   The existing `ImrOutboundQueryHookFunc` / `ImrResponseHookFunc` (`registration.go`) cannot be reused as-is: they carry neither the query message nor timing.

6. **Configuration** — A `dnstap:` block per app, plus validation and a reload-guardrail entry:
   ```yaml
   dnstap:
     enabled: true
     socket: /var/run/tdns/dnstap.sock
     # or: tcp: 127.0.0.1:6000
     # or: file: /var/log/tdns/dnstap.log
   ```

7. **API/CLI** — `<app> dnstap status` (connection state, frames sent, frames dropped).

### Key integration points

| File | Integration |
|------|-------------|
| New: `dnstap.go` | Output manager, ResponseWriter wrapper, message builder |
| `do53.go`, `dot.go`, `doh.go`, `doq.go` | Wrap the handler at each listener |
| `imr_client_stats.go` | Add the dnstap wrapper in `listenerHandlers()` |
| `dnslookup.go` | `RESOLVER_*` in `tryServer()` |
| `imr_forward.go` | `FORWARDER_*` in `forwardQuery()` |
| `config.go`, `parseconfig.go`, `config_validate.go`, `config_reload_guardrail.go` | Configuration |

### Effort estimate

**~600-900 lines of non-test code, ~1000-1400 with tests**

| Component | Lines |
|-----------|-------|
| Output manager + message builder | ~250-350 |
| Inbound wrappers (auth + IMR) | ~100-150 |
| IMR outbound (iterative + forwarder) | ~80-150 |
| Config, validation, reload | ~80-120 |
| Status API + CLI | ~100-150 |
| Tests | ~300-500 |

**Files**: 1 new file + 8-10 modified

### Limitations and open decisions

- **Wire fidelity**: handlers see a parsed `*dns.Msg` in both directions, so frames carry a re-packed message, not the bytes on the wire. Costs one extra `Pack()` per message and is not byte-exact (compression, malformed input). Byte-exact capture needs raw bytes exposed by the `johanix/dns` fork.
- **TSIG**: on Do53 and DoT the response MAC is added below the handler chain, so the frame holds the pre-TSIG message.
- **Outbound local address**: `core.DNSClient` hides the connection, so the resolver-side source address/port is unavailable without extra plumbing.
- **Stragglers**: bare `dns.Exchange()` calls in `dnslookup.go` (`AuthDNSQuery()` among them, and `RecursiveDNSQuery()`) bypass `core.DNSClient`. Auth-side outbound traffic (NOTIFY, SOA probes, UPDATE to the parent) is a separate set of sites if it should be covered.
- **Unanswered queries and XFR**: a query dropped without `WriteMsg()` yields a query frame only; a zone transfer yields several response frames per query.
- **Backpressure**: drop policy when the collector is slow (drop newest is simplest; count drops).

### New external dependency

- `github.com/dnstap/golang-dnstap` — brings in `google.golang.org/protobuf` and `github.com/farsightsec/golang-framestream`

---

## Combined Effort Summary

| Feature | New Code | Files | Complexity | Comparable Phase |
|---------|----------|-------|------------|-----------------|
| **RPZ** | ~1000-1500 lines | 1-2 new + 3-4 modified | Medium-High | Reliable Message Queue (Phases 5-9) |
| **DNSTAP** | ~1000-1400 lines | 1 new + 8-10 modified | Low-Medium | Transport Unification 1a+1b |
| **Both** | ~2000-2900 lines | 2-3 new + 10-13 modified | — | Slightly less than full Transport Unification (Phases 1-2) |

### Comparison to recent completed work

| Project | Lines | Files | Notes |
|---------|-------|-------|-------|
| JOSE/HPKE crypto (Phases 2+3) | ~1600 | 4 | New subsystem with tests |
| Reliable Message Queue + Confirmations (Phases 5-9) | ~2000 | 11 | New state machine + integration |
| Transport Unification Phase 1 (all sub-steps) | ~1500 | 8 | Architecture refactor |
| CLI Peer Restructure | ~300 | 5 | Command tree reorganization |
| **RPZ + DNSTAP (estimated)** | **~2000-2900** | **12-16** | **New subsystem + cross-app wiring** |

### Suggested implementation order

1. **DNSTAP first** — simpler, provides immediate operational value, and the instrumentation helps debug RPZ once it's added
2. **RPZ second** — builds on a well-instrumented resolver where query flow is visible via DNSTAP

### Phasing sketch

**DNSTAP** (2-3 phases):
1. Core output manager + config + inbound wrapper on all tdns-auth listeners
2. IMR inbound via `listenerHandlers()` (CLIENT_QUERY/CLIENT_RESPONSE)
3. IMR outbound (RESOLVER_* and FORWARDER_*) + status API/CLI

**RPZ** (3-4 phases):
1. RPZ zone loader (reuse ZoneData) + QNAME trigger
2. IP trigger (post-resolution answer checking)
3. NSDNAME + NSIP triggers (during referral handling)
4. RPZ zone refresh via AXFR/IXFR + NOTIFY
