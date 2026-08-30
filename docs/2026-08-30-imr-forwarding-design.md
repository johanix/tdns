# IMR: forwarding queries to upstream recursive resolvers

**Date:** 2026-08-30
**Status:** IMPLEMENTED (branch `feature/imr-forwarding`)

## 1. What and why

The IMR could resolve iteratively (from the root or from a stub zone's
authoritative servers) but had no way to hand a query to an upstream
**recursive** resolver and accept the final answer — the classic forwarder
configuration, where a resolver behaves like a stub resolver toward its
upstream. This adds it:

- forward all queries (`zone: .`) or selectively per zone,
- per-upstream transport (`do53`/`tcp`/`dot`/`doh`/`doq`) and port,
- multiple upstreams per zone, tried in order, first usable response wins.

Forwarding differs from the existing `stubs:` in exactly one semantic:
a stub pre-seeds the server map with authoritative servers and the resolver
still **iterates** (RD=0, referrals followed); a forward zone sends RD=1 and
treats the response as final.

## 2. Decisions

| Question | Decision |
|---|---|
| DNSSEC | Validate forwarded answers locally by default, same machinery as iterative answers. Forwarded queries carry CD=1 in this mode, so a validating upstream returns data (and RRSIGs) its own validator would suppress and the local verdict stays independent; the DNSKEY/DS chain is fetched lazily bottom-up through the forwarder and cached per zone. Per-zone `trust-ad: true` opts into accepting the upstream's AD bit instead (AD=1 → cache state Secure, else Insecure; queries then carry CD=0), for positives and negatives alike — and because a spoofed AD bit would be cached as Secure, trust-ad requires every upstream of the zone to be encrypted and verified (dot/doh/doq without `insecure`), enforced at config build. |
| Upstream failure | Forward-only. All upstreams failed → SERVFAIL. No fallback to iteration (predictable, and doesn't leak queries an operator confined to the upstream). |
| Upstream TLS | Verified by default. Per-upstream `tls-server-name` (SNI + certificate check; unset means the addr IP must be in a SAN), `insecure: true` as explicit opt-out for self-signed lab certs. Note the *iterative* path's shared clients still use `InsecureSkipVerify` — forward upstreams get their own clients and do not inherit that. |
| Config shape | Structured, mirroring `stubs:` — see `guide/config-tdns-imr.md` and the sample YAML. |
| Precedence | Most specific configured forward zone wins; a **more** specific configured stub wins over it. Cache-learned zone cuts never override a configured forward (the decision reads only configured entries, deliberately not `ServerMap`). |
| Reload | None, same as stubs: the forward table is built once in `InitImrEngine` and read-only afterwards. |

## 3. Where it sits

The forward decision lives at the top of
`IterativeDNSQueryWithLoopDetection` (`v2/dnslookup.go`), after the cache
check, replacing the whole iterative walk when a forward zone matches. That
single hook point covers every consumer of the iterative path: `ImrResponder`,
`ImrQuery`, the CNAME chase, NS-address resolution, and — critically — the
validator's `RRsetFetcher`, so the DNSKEY/DS chain queries needed to validate
a forwarded answer are themselves forwarded. It also runs *before* root
priming's fetcher queries: `InitImrEngine` installs the forward table before
`PrimeWithHints`, so a `zone: .` deployment primes through the upstream.

New code is in `v2/imr_forward.go`:

- `ImrForwardConf` / `ImrUpstreamConf` (config, in `v2/config.go`) →
  `BuildImrForwards` → `[]*ForwardZone` on the `Imr` struct, sorted
  most-specific first.
- Each `ForwardUpstream` owns a dedicated `core.DNSClient` carrying its
  transport, port and TLS settings. This sidesteps the shared
  `RRsetCacheT.DNSClient` registry, whose one-port-per-transport design
  cannot express a non-standard upstream port — and keeps forward upstreams
  out of the `AuthServer` backoff machinery entirely (the class of bug in
  `2026-08-11-imr-stub-resolution-broken.md` cannot reach them).
- `forwardZoneFor(qname)` — the match/precedence decision.
- `forwardQuery` — upstream loop; responses are processed by the *existing*
  `handleAnswer` (local validation, caching, CNAME chase) and
  `handleNegative` (negative caching), so forwarded data obeys the same
  cache/validation rules as iterative data. `trust-ad` answers instead go
  through `acceptForwardedAnswer`, which takes the answer (CNAME chain
  included) as-is and maps AD onto the cache validation state.
- The PR flag (encrypted-transport-only) is honored: unencrypted upstreams
  are skipped, and a forward zone with no encrypted upstream returns the
  same "PR flag requires encrypted transport" error the responder already
  turns into an EDE.

## 4. Tests

`v2/imr_forward_test.go`, all against local upstream doubles on ephemeral
ports (which by construction proves the per-upstream port plumbing). The
doubles log per-query header flags, and the encrypted ones present a
self-signed test certificate that the client verifies against an injected
`RootCAs` pool — verification stays on.

- Config decode (hyphenated keys), builder defaults, and builder rejections —
  including the four trust-ad-over-unauthenticated-channel cases.
- Match/precedence table, including same-zone stub + forward (forward wins).
- Wire flags: RD=1 always; CD=1 when validating locally, CD=0 under
  trust-ad (both asserted from the double's query log).
- trust-ad AD mapping over verified DoT: positives, NXDOMAIN and NODATA all
  cache Secure on AD=1; AD=0 caches Insecure. Without trust-ad, the same
  AD=1 responses must NOT cache Secure (positive and negative).
- Transport end-to-end: Do53 (UDP), DoT (name-SAN verification), DoH
  (IP-SAN verification, HTTPS POST /dns-query), DoQ (TLS 1.3, ALPN doq).
- Upstream failover, all-upstreams-dead SERVFAIL (forward-only), and root
  priming through a `zone: .` forward (`PrimeWithHints`' final `. NS` query
  must reach the upstream with RD=1).

## 5. Known limitations / follow-ups

- Upstream `addr` must be an IP literal; hostname upstreams would need
  bootstrap resolution.
- DoH path is fixed at `/dns-query`.
- No runtime visibility yet (`imr-show` does not list forward zones, no
  per-upstream stats) and no reload; both fit naturally into a later
  `imrengine:` reload/observability pass together with stubs.
- Upstream selection is ordered failover only — no RTT-based preference and
  no per-upstream backoff. With few upstreams this is fine; revisit if
  someone configures many.
- A cancelled context is checked between upstream attempts, not inside one:
  `DNSClient.Exchange` has no context (deliberate, documented in
  `core/dnsclient.go`), so a hung upstream holds the query for the client
  timeout (5s default) before failover moves on. Belongs to a later
  context-aware client pass, together with the iterative path.
- Under `trust-ad`, a CNAME-only answer (upstream returns the CNAME without
  the target RRset) is cached as-is and not chased. Validating recursives
  return the full chain, so this is theoretical; the local-validation
  default chases via `handleAnswer` as usual. If it ever matters, reuse the
  chase and overwrite the state from AD rather than growing a second
  packing path.

The 2026-08-30 external review (findings 1–3: CD bit, trust-ad channel
enforcement, trust-ad negatives) is addressed in the implementation; its
findings 4–5 are the two deferrals above.
