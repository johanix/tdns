# QUIC/TLS Connection Reuse, and Why XFR-over-QUIC (XoQ) Is Deferred

**Date:** 2026-07-22
**Scope:** `v2/` (module `github.com/johanix/tdns/v2`). The encrypted-transport
client path (`v2/core/dnsclient.go`), the DoQ/DoT listeners (`v2/doq.go`,
`v2/dot.go`), and the XoT transfer path (`v2/dnsutils.go`, `v2/zone_utils.go`,
`v2/xot.go`). The legacy `tdns/` and `cmd/` trees are out of scope.
**Standards:** [RFC 9250](https://www.rfc-editor.org/rfc/rfc9250.html) (DNS over
Dedicated QUIC Connections), [RFC 9103](https://www.rfc-editor.org/rfc/rfc9103.html)
(XFR-over-TLS), [RFC 7766](https://www.rfc-editor.org/rfc/rfc7766.html) (DNS
over TCP, connection reuse & out-of-order responses).
**Status:** Design note / analysis. No implementation is proposed for merge here;
this records the design and the deferral rationale so we do not re-derive it.

---

## 1. Executive summary

Two related questions came up while looking at the encrypted-transport client:

1. **Connection reuse.** The DoQ (and DoT) clients open a fresh transport
   connection for *every* query and tear it down afterwards. Each query pays a
   full handshake. Can we reuse connections, and ideally let the transport
   library manage that for us?

2. **XFR-over-QUIC (XoQ).** Given we already speak DoQ, how much work is it to
   carry AXFR/IXFR over QUIC, the way XoT carries it over TLS?

The short answers:

- **Connection reuse is worth doing, and the library will *not* do it for us for
  raw QUIC or DoT.** quic-go multiplexes streams on a connection natively (that
  part is free) but offers no destination-keyed connection cache with lifecycle
  management — that is an application concern. `net/http` is the outlier that
  pools for us, which is why **DoH already reuses connections**. A DoQ pool is a
  contained ~2–3 day job; a *correct* DoT pool is harder (~3–5 days) because
  TCP/TLS multiplexes by DNS message-ID with out-of-order responses (RFC 7766),
  not by stream.

- **XoQ should be deferred.** XoT was cheap because it rode the forked
  miekg/dns transfer machinery and TLS is a transparent byte-stream wrapper
  around TCP. Neither property holds for QUIC: the fork's `dns.Transfer` has no
  QUIC path, and our own DoQ code is hard-wired to the one-message-per-stream
  model in both client and server — exactly the assumption a multi-message AXFR
  breaks. The *auth* layer (pin/dane/pkix) is transport-independent and would
  carry over unchanged; the *transfer* layer is net-new. Budget ~3–5 days if we
  mirror the existing "no TSIG on encrypted transports" decision, ~1.5–2 weeks
  for full TSIG parity — and it interoperates with essentially only Knot today.

A useful dependency links the two: **a clean DoQ connection pool is exactly the
foundation an eventual XoQ would need** ("acquire a managed QUIC connection to
this peer"). So the connection-reuse work is the higher-leverage investment and
a natural prerequisite.

---

## 2. Background: the current client connection model

The IMR shares **one `DNSClient` per transport**, cached and reused across
queries: `tryServer` looks the client up as `imr.Cache.DNSClient[eff]`
(`v2/dnslookup.go:1913`) rather than constructing one per query. So the *client
object* is already long-lived. What is not long-lived is the underlying
**transport connection**:

- **DoQ** — `exchangeDoQ` calls `quic.DialAddr(...)` (`v2/core/dnsclient.go:362`)
  and `defer conn.CloseWithError(0, "")` (`:367`) on every exchange. One full
  QUIC handshake per query, then discard.
- **DoT** — dispatch calls `c.DNSClientTLS.Exchange(...)`
  (`v2/core/dnsclient.go:274`). miekg's `dns.Client.Exchange` dials a fresh
  TCP+TLS connection and closes it each call. Same per-query handshake cost.
- **DoH** — dispatch calls `exchangeDoH`, which uses an `http.Client` backed by
  an `http.Transport` (`v2/core/dnsclient.go:179`). `net/http` maintains its own
  idle-connection pool, so **DoH already reuses connections** (and HTTP/2
  multiplexes concurrent requests on one connection) for free.

So "connection reuse" concretely means: build it for **DoQ and DoT**; DoH
already has it.

---

## 3. Part A — DoQ / DoT connection reuse

### 3.1 Stream is not connection: one-message-per-stream is correct

It is tempting to frame the inefficiency as "tdns only allows one message per
stream." That framing is a category error. Per **RFC 9250 §4.2**, DoQ *requires*
that each query and its response(s) use their **own** bidirectional stream;
pipelining multiple queries onto a single stream is explicitly disallowed. So
one-message-per-stream is not a defect — it is the specification.

The real waste is one level up: **one connection per query**. Connection reuse
means keeping the `quic.Conn` alive and opening a **new stream per query** on the
shared connection. QUIC multiplexes many concurrent streams on one connection
natively, so the streams are free — it is only the *connection lifecycle* that
is missing today.

### 3.2 Current state

| Transport | Connection reuse today | Mechanism |
|-----------|------------------------|-----------|
| **DoH**   | ✅ Yes                 | `net/http` idle-conn pool + HTTP/2 multiplexing |
| **DoT**   | ❌ No                  | miekg `dns.Client.Exchange` dials + closes per query |
| **DoQ**   | ❌ No                  | `quic.DialAddr` + `CloseWithError` per query |

### 3.3 Will the library manage it? Not for raw QUIC or DoT

quic-go hands you a `quic.Conn` and `OpenStreamSync`; it does **not** provide a
destination-keyed connection cache with liveness/idle management. For raw DoQ
that is an application concern. The one Go transport that pools *for* you is
`net/http` — hence DoH is already covered. So a "plan B" connection manager
inside tdns is the realistic path for DoQ and DoT.

### 3.4 DoQ pool design (the easy one) — ~2–3 days

QUIC's native stream multiplexing does the hard part. The pool is small:

- **Keyed map.** `map[connKey]*pooledConn` guarded by a mutex, where `connKey`
  folds in the server address **and the TLS-config identity**. Connections with
  different verification policies (pin vs dane vs pkix, or different pin sets)
  must never be shared.
- **Acquire.** On a query: fetch a live connection for the key (or dial once and
  store it), then `OpenStreamSync` a new stream and run the *existing* framing
  from `exchangeDoQ` unchanged. The request/response body factors cleanly into a
  "given a stream, do the exchange" helper — so this is additive and `tryServer`
  call sites do not change.
- **Liveness + re-dial.** Detect a dead connection (`conn.Context().Done()`, or
  an error from `OpenStreamSync`) and transparently re-dial + retry once. This
  covers idle-timeout races, server restarts, and path changes.
- **Idle eviction.** Today an *unheld* connection dies on its own via
  `MaxIdleTimeout` (30s) / `KeepAlivePeriod` (15s) (cf. server side,
  `v2/doq.go:40-41`). A *pooled* connection that we keep alive with keepalives
  stays open indefinitely and consumes a trickle of bandwidth, so the pool needs
  an explicit idle-close policy (close connections unused for N seconds).
- **Concurrency.** Many IMR goroutines may want streams on the same connection
  at once; QUIC allows this, but honor the peer's `MaxIncomingStreams`
  (`OpenStreamSync` blocks when the flow-control limit is reached) and keep the
  map operations under the mutex.

Risk: low. The change is localized to the DoQ client; wire framing is already
written and tested.

### 3.5 DoT pool design (the harder one) — ~3–5 days done well

TCP/TLS has no streams, so a persistent connection multiplexes queries **by DNS
message ID**, and RFC 7766 permits the server to answer **out of order**. Proper
DoT reuse therefore needs:

- A persistent `*dns.Conn` (via `dns.Client.Dial`) per pooled connection instead
  of `dns.Client.Exchange` (which owns dial+close).
- A **read-demux loop** per connection that reads inbound messages and routes
  each to the waiting caller by message ID, plus ID allocation and
  collision/timeout handling.
- Per-connection write serialization and correct teardown on error.

If we instead **serialize** (one in-flight query per connection at a time) the
code is much simpler, but we forfeit most of the concurrency benefit and largely
just amortize the handshake. The full out-of-order design is what makes DoT
reuse genuinely useful — and it is roughly twice the DoQ effort, precisely
because QUIC gives us stream isolation that TCP does not.

### 3.6 Where it pays off

The dominant beneficiary is the **IMR**, which repeatedly queries the same
authoritative servers during iterative resolution — that is where per-query
handshakes hurt most and where a pool amortizes best. Because the per-transport
`DNSClient` is already a shared cached object, the pool lives entirely inside the
DoQ/DoT client and no caller changes. XoT/XoQ transfers are a lower-frequency
pattern that benefits far less.

### 3.7 Recommendation and sequencing

1. **DoQ pool first.** Best effort-to-payoff ratio, self-contained, and the
   transport where the per-query handshake is most wasteful.
2. **DoH:** verify HTTP/2 keep-alive and `MaxIdleConnsPerHost` are sane; likely
   no code change.
3. **DoT reuse:** treat as a separate, later decision. The ID-demux requirement
   doubles the work for a transport arguably being superseded by DoQ.

---

## 4. Part B — XFR-over-QUIC (XoQ), and why we defer it

### 4.1 Why XoT was cheap

The XoT branch is mostly **config + a verifying TLS-config builder**; the actual
AXFR/IXFR streaming came for free, because of two facts:

1. **The forked miekg/dns already implements TLS transfer.** The `replace` in
   `v2/go.mod:61` points at `github.com/johanix/dns`, whose `dns.Transfer` has a
   `TLS *tls.Config` field. Inbound transfer is just `transfer.TLS = tlsCfg;
   transfer.In(msg, addr)` (`v2/dnsutils.go:82,90`); the SOA probe sets
   `c.Net = "tcp-tls"` (`v2/zone_utils.go:146`).
2. **Outbound transfer is a stock miekg `dns.Server{Net:"tcp-tls"}`**
   (`v2/dot.go:63`) whose handler calls `dns.Transfer.Out(w, r, envChan)`
   (`v2/dnsutils.go:328`).

**TLS is transparent to AXFR framing** — it is a byte-stream wrapper around TCP,
and the library's envelope loop (multiple 2-byte-length-prefixed DNS messages,
TSIG signed every N envelopes) works unchanged over it. XoT reused ~100% of the
existing transfer machinery.

### 4.2 Why XoQ is not cheap by analogy

QUIC breaks both assumptions:

1. **The fork's `dns.Transfer` has no QUIC path.** It only knows
   `tcp`/`tcp-tls`. You cannot hand `Transfer.In`/`.Out` a QUIC connection at
   all.
2. **Our DoQ code is hard-wired to one-message-per-stream** in both directions —
   exactly what a multi-message AXFR violates:
   - **Client** (`exchangeDoQ`, `v2/core/dnsclient.go:353`): opens a stream,
     writes the query, does a single `io.ReadFull` for **one** length-prefixed
     response, returns. AXFR must loop reading many messages on the same stream
     until the terminating SOA.
   - **Server** (`doqResponseWriter.WriteMsg`, `v2/doq.go:208`): has a `wrote`
     guard that **rejects a second write** and closes the stream after one
     message. AXFR-out must write many envelopes on one stream.

So the reason XoT was a small branch is precisely the reason XoQ is not: nothing
in the AXFR data path is reusable.

### 4.3 What *is* reusable — the auth layer

The entire certificate-authentication layer is **transport-independent and drops
in unchanged**: `pin` / `dane` / `pkix`, the `VerifyConnection` gates,
`SPKISHA256`, `verifyPeerCertPins`, `verifyPeerCertDANE`, the config schema, and
`ClientTLSConfigForPeer` (`v2/xot.go:154`). QUIC uses the same `tls.Config`; the
only change is ALPN `"doq"` instead of `"dot"` in `NextProtos`. Peer identity is
already solved for QUIC.

### 4.4 Work breakdown

| Piece | Effort | Notes |
|-------|--------|-------|
| Config: allow `transport: doq`, port defaults, validation | Small (~½ day) | Extend `validatePeerXoT`, `defaultPortForPeer`, transport labels. Auth branches untouched. |
| Inbound SOA probe over DoQ | Small (~½ day) | `exchangeDoQ` already does single-message queries — route the probe through it. |
| **Inbound AXFR/IXFR over QUIC** | Medium (~1–2 days) | New transfer-in: dial QUIC, open stream, write query, loop-read length-prefixed messages, feed RRs into the existing `zd.SortFunc` accumulation until terminating SOA. |
| **Outbound AXFR/IXFR over QUIC** | Medium (~1–2 days) | Streaming `doqResponseWriter` (drop the single-write guard) **plus** re-implementing the envelope-batching that `dns.Transfer.Out` does today for free; branch `handleDoQStream` on AXFR/IXFR. |
| **TSIG across the transfer stream** | Large / risky (~2–4 days) or punt | See §4.5. |

### 4.5 The TSIG problem is the real decision point

On TCP/TLS, miekg performs per-envelope TSIG verify/sign (RFC 8945's "sign every
Nth envelope") for us. Hand-rolling XoQ means **re-implementing that
streaming-TSIG logic by hand** in both directions. Notably, the existing DoQ code
already **punts on TSIG entirely** — `doqResponseWriter.TsigStatus()` is a stub
with an explicit `TODO(tsig)` (`v2/doq.go:244-250`) arguing that encrypted
transports authenticate peers via TLS/mTLS instead. If we carry that same stance
into XoQ (peer auth via pin/dane/pkix/mTLS, no TSIG on the transfer), we delete
the largest and riskiest chunk and the feature drops to roughly **3–5 days**.
Full TSIG-over-XoQ parity pushes it to **~1.5–2 weeks**.

### 4.6 Where to put the streaming code: two options

- **Option A — hand-roll in tdns.** Build the multi-message read/write loops in
  `v2/doq.go` plus a new transfer file. Faster to a working prototype, but we
  reimplement envelope batching + (optionally) streaming TSIG that the library
  already solved for TCP.
- **Option B — extend the `johanix/dns` fork.** Teach `dns.Transfer` a QUIC path,
  mirroring how `.TLS` was added. More upfront work in the fork, but the
  envelope/TSIG logic lives where it already exists and both directions stay
  symmetric with the TCP/TLS code we already trust. Since we *already maintain
  the fork* specifically for transfer features, this is probably the cleaner
  long-term home.

### 4.7 Standardization and DANE caveats

- **XoQ is not standardized.** RFC 9103 is TLS-specific and there is no finished
  RFC for zone transfer over QUIC. In practice XoQ interoperates with
  **Knot DNS only** today (BIND and NSD do not implement DoQ/XoQ at all). Knot's
  `cert-key` PIN is the same base64 SHA-256 SPKI as our `pin`, so pin-based
  interop would be copy-paste — but the transport itself is a single-vendor axis.
- **DANE owner-name for QUIC is unsettled.** TLSA lives at `_853._tcp` by
  convention; there is no established `_quic` labelling, so `tls-auth: dane` over
  DoQ has a spec ambiguity that `pin`/`pkix` do not.

### 4.8 Decision

**Defer XoQ.** The auth half is genuinely free (already built,
transport-agnostic), but the transfer half is net-new because neither the fork
nor our DoQ code can stream a multi-message AXFR today, and the only interop
partner is Knot. Revisit if/when (a) a second implementation ships XoQ or the
IETF standardizes it, or (b) we have built the DoQ connection pool from Part A,
which removes a chunk of the foundational plumbing.

---

## 5. How the two efforts relate

Part A and Part B share a primitive: **"acquire a managed QUIC connection to this
peer."** The DoQ connection pool (§3.4) is that primitive. Building it first
means an eventual XoQ implementation starts from a managed-connection abstraction
rather than the current dial-and-discard, and it delivers standalone value to the
IMR immediately. This is the argument for sequencing DoQ pooling ahead of any XoQ
work.

---

## 6. Consolidated recommendations

| Item | Recommendation | Rough effort |
|------|----------------|--------------|
| DoH connection reuse | Already covered by `net/http`; verify settings only | ~0 |
| **DoQ connection pool** | **Do first** — contained, high IMR payoff | ~2–3 days |
| DoT connection reuse | Later; requires RFC 7766 ID-demux for real benefit | ~3–5 days |
| XoQ (no-TSIG, pin/dane/pkix auth) | Defer; single-vendor interop (Knot) | ~3–5 days when taken up |
| XoQ (full TSIG parity) | Defer | ~1.5–2 weeks when taken up |

*This document is analysis only; it proposes no code changes for merge.*
