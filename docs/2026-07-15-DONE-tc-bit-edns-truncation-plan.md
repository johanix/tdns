# Implementation plan — EDNS-aware UDP truncation / the TC bit (tdns-auth)

**Status:** ready for implementation. Self-contained — no prior context needed.
**Origin:** pq.axfr.net testbed bug TB2 (see
`docs/2026-07-14-snapshot-branch-signing-findings.md`, "pq.axfr.net testbed
bugs"). This doc is the cooked plan; implement against `main`.

Line numbers below are anchors as of 2026-07-15 and drift with commits — always
re-locate by the function/symbol name.

---

## 1. The problem

`tdns-auth` **never truncates UDP responses and never sets the TC bit.** There is
no `msg.Truncate()` call anywhere in the response path, and the client's
advertised EDNS UDP buffer size is ignored.

Consequence on the public internet (measured on the pq.axfr.net testbed, 135
PQ-signed leaf zones):

- a `bufsize=512` client gets a 1666-byte UDP answer;
- a DNSKEY query gets a 7747-byte UDP datagram (6 IP fragments);
- the 30 zones whose ZSK signatures exceed the fragmentation threshold
  (falcon512 / mayo3 ZSKs) **time out over UDP** (fragments dropped in the
  network) instead of the client falling back to TCP;
- UDP reachability: **105/135**; TCP: **135/135**.

A correct authoritative server must, for a UDP response that does not fit the
requestor's buffer, **remove records until it fits and set TC=1**, so the client
retries over TCP. This is a wire-correctness bug.

## 2. The bufsize rule (get this exactly right)

The truncation limit is the requestor's advertised UDP payload size:

```
if query has no EDNS(0) OPT:      bufsize = 512
else if opt.UDPSize() < 512:      bufsize = 512
else:                             bufsize = opt.UDPSize()   (optionally capped, see below)
```

Applies to **UDP only**. Over TCP there is a 2-byte length prefix (up to 65535
bytes) and you never truncate.

Rationale / pitfalls:

- **No OPT ⇒ 512, NOT 1232.** A query without an OPT is a bare RFC 1035 client
  that has signaled no EDNS capability; 512 is the only size it is guaranteed to
  accept. **DNS Flag Day 2020's 1232 is the value an EDNS-capable resolver
  advertises *inside its own OPT*, not a server-side fallback for OPT-less
  queries.** Do not assume 1232 for a query that carries no OPT.
- **UDPSize < 512 ⇒ clamp up to 512** (RFC 6891 §6.2.3: "Values lower than 512
  MUST be treated as equal to 512"). So the effective floor is always 512.
- **A response to a no-OPT query must itself carry no OPT** — never add EDNS to a
  response whose query didn't have it.
- **Optional server-side cap (DECISION FOR JOHAN):** you *may* cap the ceiling at
  **1232** even when a client advertises more (e.g. 4096), to avoid IP
  fragmentation (DNS Flag Day 2020). Given the entire motivation for this fix is
  PQ-signature fragmentation, a 1232 cap is a reasonable default — but it is a
  deliberate policy choice, not required by spec. Implement it as a single named
  constant (e.g. `maxUDPResponse = 1232`, or `0`/unset to disable) and confirm
  the value with Johan before enabling. The strictly-correct-without-a-cap
  behavior is to honor the advertised size.

## 3. Current code layout (what you need to know)

**Where responses are written.** Every response goes out via
`w.WriteMsg(m)`. Call sites (all in package `tdns`, `v2/`):
`defaultqueryhandlers.go` (×8), `dnsutils.go:442`, `do53.go:235`. Patching each
is fragile — instead wrap the `dns.ResponseWriter` once at the handler entry.
`QueryResponder` (the main query path) is handed the **same** `w`
(`defaultqueryhandlers.go:112` and `:172`: `zd.QueryResponder(ctx, w, r, …)`), so
one wrapper at the top catches every downstream write.

**Handler / transport wiring (`v2/do53.go`, in `DnsEngine`).**
- `authDNSHandler := createAuthDnsHandler(ctx, conf)` (`do53.go:209`) — returns
  `func(w dns.ResponseWriter, r *dns.Msg)`. It already has a top-level
  `recover()` that returns SERVFAIL on panic.
- `dnsMux := dns.NewServeMux()` and
  `dnsMux.HandleFunc(".", TsigSigningHandler(authDNSHandler))` (`do53.go:51`).
- The **Do53 UDP and TCP servers both use `dnsMux`** — a loop
  `for _, transport := range []string{"udp", "tcp"} { srv := &dns.Server{ … Net:
  transport, Handler: dnsMux, … } }` (`do53.go:60`).
- **DoH and DoQ receive the *unwrapped* `authDNSHandler`** (see the comment at
  `do53.go:51`). **DoT installs its own `TsigSigningHandler` inside
  `DnsDoTEngine`.** ⇒ none of DoT/DoH/DoQ go through `dnsMux`.

**TSIG (`v2/tsig_peer.go:126`).** `TsigSigningHandler(next)` returns a handler
that, **only when the request carries a TSIG** (`r.IsTsig() != nil` and it
verified), wraps `w = &tsigSignResponseWriter{…}` and calls `next(w, r)`. That
writer computes the TSIG MAC on `WriteMsg`. For ordinary (unsigned) queries `w`
is passed through unwrapped. (TSIG traffic in practice is replication —
NOTIFY / AXFR / IXFR — and AXFR is TCP, so it is rarely a UDP-truncation case,
but the ordering below must still be correct.)

**EDNS options (`v2/edns0/edns0.go:13`).** `type MsgOptions struct { RD, CD, DO,
CO, … }` — it carries flags but **not** the advertised UDP size.
`ExtractFlagsAndEDNS0Options(r *dns.Msg) (*MsgOptions, error)` builds it; it
already calls `opt := r.IsEdns0()`.

**Not the size you want.** The Do53 servers set `srv.UDPSize = dns.DefaultMsgSize`
(4096). That is the server's *inbound* receive buffer (UPDATEs can be large); it
does **not** cap outbound responses (miekg/dns never truncates on its own), which
is precisely why big answers fragment today. Do not confuse it with the client's
advertised bufsize.

**miekg/dns helper.** `func (m *dns.Msg) Truncate(size int)` removes trailing RRs
until the packed message fits `size` bytes and sets `m.Truncated = true` if it
had to drop anything; it preserves the OPT record. `m.Len()` returns the packed
length.

## 4. The fix — where and how

**Wrap on the Do53 mux, NOT in `createAuthDnsHandler`.** Wrapping inside
`createAuthDnsHandler` would also wrap the DoH/DoQ paths (which use it unwrapped).
**DoQ runs over QUIC, which is UDP** — so a wrapper keyed on
`w.RemoteAddr().Network() == "udp"` would truncate DoQ, a stream transport that
must **never** be truncated. `dnsMux` is used by *only* the Do53 UDP+TCP servers,
so on that mux `RemoteAddr().Network() == "udp"` unambiguously means plain
Do53-over-UDP; TCP on the same mux reports `"tcp"` and is never truncated.

Change `do53.go:51` from:

```go
dnsMux.HandleFunc(".", TsigSigningHandler(authDNSHandler))
```

to:

```go
dnsMux.HandleFunc(".", TsigSigningHandler(udpTruncate(authDNSHandler)))
```

Putting `udpTruncate` **inside** `TsigSigningHandler` gives the correct TSIG
order for free: for a TSIG request the chain becomes
`w → tsigSignResponseWriter → truncatingResponseWriter → authHandler`, so the
handler writes to the truncating writer, which **truncates first**, and only then
does the tsig writer MAC the already-truncated message. No MAC-over-untruncated
hazard.

### The two new pieces

```go
// udpTruncate installs a per-request truncating ResponseWriter. Placed on the
// Do53 mux only (do53.go), so "udp" here always means plain Do53-over-UDP —
// DoT/DoH/DoQ never reach this mux. Must sit INSIDE TsigSigningHandler so
// truncation precedes the TSIG MAC.
func udpTruncate(next func(dns.ResponseWriter, *dns.Msg)) func(dns.ResponseWriter, *dns.Msg) {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		tw := &truncatingResponseWriter{
			ResponseWriter: w,
			udp:            w.RemoteAddr().Network() == "udp",
			bufsize:        ednsUDPBufsize(r),
		}
		next(tw, r)
	}
}

type truncatingResponseWriter struct {
	dns.ResponseWriter
	udp     bool
	bufsize int
}

func (w *truncatingResponseWriter) WriteMsg(m *dns.Msg) error {
	if w.udp && m.Len() > w.bufsize {
		m.Truncate(w.bufsize) // drops trailing RRs to fit, sets TC=1, keeps OPT
	}
	return w.ResponseWriter.WriteMsg(m)
}

// ednsUDPBufsize implements the §2 rule. maxUDPResponse is the optional
// anti-fragmentation cap (see §2 — confirm with Johan; 0 = uncapped).
const maxUDPResponse = 1232 // or 0 to disable the cap — DECISION

func ednsUDPBufsize(r *dns.Msg) int {
	size := 512
	if opt := r.IsEdns0(); opt != nil {
		if u := int(opt.UDPSize()); u > size {
			size = u
		}
	}
	if maxUDPResponse > 0 && size > maxUDPResponse {
		size = maxUDPResponse
	}
	return size
}
```

Notes:
- `truncatingResponseWriter` embeds `dns.ResponseWriter`, so `Write`,
  `RemoteAddr`, `Close`, `TsigStatus`, `Hijack`, etc. pass through; only
  `WriteMsg` is overridden. (`do53.go:235`'s panic-path SERVFAIL uses `WriteMsg`
  too and is tiny, so it is never truncated — fine.)
- `ednsUDPBufsize` is the single source of truth for §2; do not duplicate the
  512/clamp/cap logic elsewhere. (You may optionally also stash the value on
  `edns0.MsgOptions` via `ExtractFlagsAndEDNS0Options` if other code wants it, but
  it is not required for this fix.)

## 5. Tests

**Unit** (`v2/…_test.go`):
- a message larger than `bufsize` written through `truncatingResponseWriter` with
  `udp=true` comes out with `TC=1` and `Len() <= bufsize`, and still has its
  question + OPT;
- the same message with `udp=false` is untouched (no TC, full length);
- `ednsUDPBufsize`: no OPT → 512; OPT 300 → 512; OPT 1232 → 1232; OPT 4096 →
  1232 if the cap is on, else 4096.

**Live** (against a PQ-signed zone, e.g. on the pq.axfr.net testbed):
- `dig +bufsize=512 @srv <zone> DNSKEY` → response has `flags: … tc`, small,
  answer dropped; `dig +tcp @srv <zone> DNSKEY` → full answer.
- Re-run the testbed UDP validation matrix → expect **135/135** (clients fall
  back to TCP) instead of 105/135.
- **Regression guard:** confirm a **DoQ** query on a large zone is NOT truncated
  (send over `:8853`/DoQ and check no TC, full answer) — this is the specific
  thing the mux-placement decision protects.

## 6. Effort & care-points

**Effort: moderate.** The wrapper + bufsize helper are small; the whole risk is
in two placement facts, both handled above:
1. install on `dnsMux` (do53.go:51), **not** in `createAuthDnsHandler` — else DoQ
   gets mis-truncated;
2. keep `udpTruncate` **inside** `TsigSigningHandler` — else truncation happens
   after the TSIG MAC and signed responses break.

**One decision to confirm with Johan:** the `maxUDPResponse = 1232`
anti-fragmentation cap (§2) — enable at 1232, or leave uncapped.
