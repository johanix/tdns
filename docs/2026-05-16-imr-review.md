# IMR (Internal Recursive Resolver) Review — tdns/v2/

**Date:** 2026-05-16
**Scope:** `tdns/v2/` only — `tdns/tdns/` (v1) and `tdns/obe/`,
`tdns/music/` (frozen) deliberately excluded.
**Motivating symptom:** Provider→provider gossip is OPERATIONAL on
the lab testbed, but provider→auditor and auditor→auditor links are
stuck in NEEDED. Initial suspicion was AWS network filtering;
hypothesis is that the IMR itself fails to recover from per-transport
failures and keeps making the same bad choice on retry.

---

## a) Design overview

The IMR is an iterative recursive resolver embedded in every
tdns-mp binary (agent / combiner / signer / auditor). It is
built on top of `miekg/dns` plus a thin multi-transport client
wrapper (`core/dnsclient.go`) supporting Do53, DoT, DoH, and DoQ.

The public entry `Imr.ImrQuery`
([imrengine.go:293](tdns/v2/imrengine.go:293)) is fully reentrant
— callers from gossip, hsync, scanner, delegation analysis, the
on-the-wire `ImrResponder`, etc. invoke it directly from their
own goroutines and run concurrently. There is *one* legacy
serialization point: the engine loop at
[imrengine.go:211](tdns/v2/imrengine.go:211) reads from
`Conf.Internal.RecursorCh` and runs `ImrQuery` synchronously
inside the channel-read loop. In practice only `tdns-mpcli imr
query` ([cli/imr_cmds.go:57](tdns/v2/cli/imr_cmds.go:57)) uses
that channel — everything else bypasses it.

Within a *single* query, the resolver is sequential: `ImrQuery`
checks the cache, then loops up to 12 times following referrals.
Each iteration calls `IterativeDNSQuery`
([dnslookup.go:750](tdns/v2/dnslookup.go:750)), which picks an
NS+address+transport tuple via `prioritizeServers` /
`pickTransport`, fires the query through `tryServer`
([dnslookup.go:1603](tdns/v2/dnslookup.go:1603)), and processes
the response (answer / referral / negative). There is no
speculative in-query parallelism — candidates are tried one at
a time.

Shared state lives in a single `cache.RRsetCache` per process:
positive/negative RRset cache, per-zone state, a shared
`AuthServerMap` (NS-name → `*AuthServer`), and a DNSKEY cache.
`AuthServer` carries connection state (addresses, transport
weights, address backoffs, ALPN, connection mode). `Zone` carries
zone-scoped address backoffs (used for lame-delegation tracking).
Cache uses ConcurrentMap; `AuthServer` / `Zone` each have their
own per-instance mutex for short critical sections.

Transport choice is per-server, computed from a deterministic
weighted hash of `(qname, server.Name)`. Failure handling is
two-level: per-address (server-wide) and per-(zone, address)
(zone-scoped). DNSSEC validation is opt-in via
`ValidateRRsetWithParentZone`, which itself drives more IMR
lookups for parent DNSKEY/DS chains.

---

## b) Design choices, alternatives, trade-offs

For each choice: what was decided, the alternative(s), and the
trade-off as it plays out in practice — with file:line anchors so
the next person reading this can verify.

### 1. Failure state is keyed by IP only, not by (IP, transport)

**Choice:** `AuthServer.AddressBackoffs` is `map[string]*AddressBackoff`
keyed by IP ([authserver.go:566](tdns/v2/cache/authserver.go:566)).
A TCP timeout to `1.2.3.4` and a UDP timeout to `1.2.3.4` both
write to the same key.

**Alternative:** Key by `(addr, transport)` so DoT failures don't
poison Do53 viability and vice versa.

- ✅ *Pros of current:* simple, mirrors classic resolver semantics
  where "address is dead" is a single concept.
- ❌ *Cons of current:* **this is the most likely culprit behind
  the lab symptom.** When AWS drops DoT to 1.2.3.4 but UDP works
  fine, the first DoT timeout costs 2 minutes of backoff on the
  *whole* address, then the address comes back, `pickTransport`
  deterministically picks DoT again, fails again, and the cycle
  repeats. We never converge on a working transport.
- ✅ *Pros of alt:* directly addresses the convergence problem;
  small data-structure change.
- ❌ *Cons of alt:* somewhat more bookkeeping; need to decide
  when an *address* is wholly dead vs. one transport is.

### 2. Transport selection is a deterministic stable hash with no failure feedback

**Choice:** `pickTransport`
([dnslookup.go:1462](tdns/v2/dnslookup.go:1462)) computes
`fnv32(qname | server.Name) % 100` and picks the matching weighted
bucket. Pure function of inputs — same inputs always yield the
same transport.

**Alternative A:** Randomize per call (uniform over weights).
**Alternative B:** Sticky-good — remember the last transport that
*succeeded* for this server, prefer it on the next call, fall
back to weighted random only when no recent success is known.
**Alternative C:** Demote a transport on consecutive failures
(temporarily zero its weight for this server).

- ✅ *Pros of current:* deterministic — easy to reason about,
  load is predictably distributed across qnames.
- ❌ *Cons of current:* the determinism is exactly what makes
  failures persistent. Combined with #1, every retry on the same
  `(qname, server)` picks the same (possibly broken) transport.
  There is *no* feedback path from `RecordAddressFailure` into
  `pickTransport`.
- ✅ *Pros of B (sticky-good):* fast convergence after one
  success on any transport, minimal state (one enum per server).
- ❌ *Cons of B:* loses the per-qname load-balancing if you also
  want that property.
- ✅ *Pros of C (demote):* explicit and observable; aligns with
  how operators reason about "this transport is broken."
- ❌ *Cons of C:* more state, more knobs (how many failures =
  demote, how long stays demoted).

### 3. UDP→TCP fallback exists, but only for Do53 and only on transient errors

**Choice:** After 3 UDP retries (50ms / 150ms backoff), `tryServer`
([dnslookup.go:1688](tdns/v2/dnslookup.go:1688)) makes *one* TCP
attempt against the same address if the last error was transient.
Separately, `core.DNSClient.Exchange`
([core/dnsclient.go:185](tdns/v2/core/dnsclient.go:185)) handles
TC=1 truncation by retrying over TCP automatically. **Both
fallbacks are Do53-only.**

**Alternative:** A cascading transport ladder
(e.g. DoQ → DoT → Do53-UDP → Do53-TCP), configurable per server.

- ✅ *Pros of current:* simple, well-defined; TC=1 handling is
  correct.
- ❌ *Cons of current:* DoT/DoH/DoQ failures have *no* fallback
  at all. A DoT timeout just gives up on the address. This is
  exactly the kind of asymmetry that bites in cloud
  environments where one TCP-based transport is filtered while
  another is fine.
- ✅ *Pros of alt:* maximal resilience; one well-named knob.
- ❌ *Cons of alt:* fallback ladder needs careful sequencing
  (don't try the same wire format twice); risk of slow-failure
  cascades if every layer waits its full timeout.

### 4. Per-attempt timeouts are baked into the underlying DNS clients; no per-transport tuning

**Choice:** `tryServer` does not pass per-call deadlines — it
relies on (a) the caller's context for total wall time and (b)
the timeouts on the underlying `dns.Client` instances created in
`core.NewDNSClient`. UDP retry backoffs are hardcoded at
[dnslookup.go:1654](tdns/v2/dnslookup.go:1654).

**Alternative:** Per-transport, per-attempt deadlines (short for
UDP, longer for TCP/TLS handshake-bearing transports).

- ✅ *Pros of current:* simple call signature; no flag explosion.
- ❌ *Cons of current:* DoT/DoH/DoQ all share whatever default the
  underlying client has, which may not be tuned for handshakes
  failing fast. AWS-style "syn drops" can stall a query for a
  long time because the TLS handshake never starts.
- ✅ *Pros of alt:* fast failure → faster convergence to a working
  transport (assuming #1 and #2 are also fixed).
- ❌ *Cons of alt:* more config; harder to debug.

### 5. Backoff durations are coarse (2 min / 1 h) and not configurable

**Choice:** `categorizeError`
([authserver.go:528](tdns/v2/cache/authserver.go:528)) decides:
2 min for first/timeout failure, 1 h for repeat/routing errors,
1 h for REFUSED/NOTAUTH/SERVFAIL at the zone level
([zone_errors.go](tdns/v2/cache/zone_errors.go)). No exponential
backoff, no jitter, no config knob.

**Alternative:** Exponential backoff (e.g. 5s → 30s → 2m → 10m →
1h cap) with jitter, configurable globally.

- ✅ *Pros of current:* predictable; easy to explain.
- ❌ *Cons of current:* 2 minutes is *way* too long for transient
  AWS flaps. For a 30-second gossip BEAT cadence, a single
  packet drop hides a peer for ~4 beats. Combined with #1 and
  #2 this turns one bad packet into stuck NEEDED forever.
- ✅ *Pros of alt:* heals quickly from transient errors; still
  protects against persistent failures.
- ❌ *Cons of alt:* introduces unbounded state if not capped;
  harder to test deterministically.

### 6. Lame-delegation failures are scoped to (zone, address), not to the server

**Choice:** REFUSED/NOTAUTH/SERVFAIL/NOTIMP from server X for
zone Y record a backoff on `Zone[Y].AddressBackoffs[X]`
([dnslookup.go:910-924](tdns/v2/dnslookup.go:910)). The server
itself stays unblocked for other zones.

**Alternative:** Maintain server reputation across zones; many
consecutive lame answers downweight the server globally.

- ✅ *Pros of current:* correct in the common case — a misconfigured
  delegation pointing at a server that legitimately serves other
  zones shouldn't poison those other zones.
- ❌ *Cons of current:* no consolidation. A server that's broken
  in some general way keeps being picked over and over for
  every zone individually.
- ✅ *Pros of alt:* matches operator intuition.
- ❌ *Cons of alt:* "consecutive lame across N zones" needs a
  policy; risk of false-positive server-wide block.

### 7. Server prioritization order is random (Go map iteration), no RTT

**Choice:** `prioritizeServers`
([dnslookup.go:708](tdns/v2/dnslookup.go:708)) just iterates
`map[string]*AuthServer` — order is undefined per Go spec. There
is a TODO at [dnslookup.go:740](tdns/v2/dnslookup.go:740) ("Future:
Sort by RTT or other metrics") that's never been filled in.

**Alternative:** EMA RTT tracked per address, sort ascending.

- ✅ *Pros of current:* no state.
- ❌ *Cons of current:* in a geographically dispersed lab,
  always-pick-the-nearest gains are unrealised; first failure of
  a randomly picked far server costs us a 2-min backoff before
  we even *try* the near one.
- ✅ *Pros of alt:* better latency, fewer timeouts at the
  margin (a fast working server is preferred over a slow
  flapping one).
- ❌ *Cons of alt:* state per address; needs decay logic so a
  one-time slow query doesn't poison the server.

### 8. Transport signal discovery is fire-and-forget

**Choice:** `maybeQueryTransportSignal` /
`maybeQueryTLSA` ([imr_helpers.go:46](tdns/v2/imr_helpers.go:46))
spawn a `go func()` that issues an SVCB/TSYNC/TLSA query with a
5s timeout, then writes to the cache. There is no completion
signal, no retry on failure, and no way for the caller to know
whether discovery succeeded.

**Alternative:** Synchronous opportunistic lookup with a tight
deadline, or a per-server "discovery state machine" that retries
on a backoff.

- ✅ *Pros of current:* doesn't block the main query path on a
  discovery side-effect.
- ❌ *Cons of current:* if the SVCB query fails (which in the
  user's environment is *exactly* the kind of thing that
  happens), nothing tries again. The server stays on whatever
  Transports default it had at construction. If that default is
  also wrong, we're stuck.
- ✅ *Pros of alt (state machine):* explicit, observable, retried.
- ❌ *Cons of alt:* more code; risk of background-query storms.

### 9. Cache eviction is naive LRU, no separate budget per context

**Choice:** `evictOldestRRset`
([cache/rrset_cache.go:156](tdns/v2/cache/rrset_cache.go:156))
evicts oldest entries when the cache is full, regardless of
context (Answer vs Glue vs Hint vs Failure).

**Alternative:** Per-context budgets — protect Glue/Hint from
eviction by routine Answer traffic.

- ✅ *Pros of current:* simple, well-understood.
- ❌ *Cons of current:* a query storm for short-TTL answers can
  evict the long-lived NS / glue that the resolver needs to
  function. After eviction we re-prime, which is exactly when
  we hit the IMR's other weak points.
- ✅ *Pros of alt:* avoids the pathological re-priming cycle.
- ❌ *Cons of alt:* more knobs; risk of stale glue.

### 10. Concurrency: reentrant per-caller, no parallelism within a single query

**Choice:** `ImrQuery` is a plain method; concurrent callers run
in parallel and share only the cache (thread-safe via
ConcurrentMap and per-AuthServer / per-Zone mutexes). Within one
query, however, `IterativeDNSQuery` walks `prioritized` tuples
sequentially ([dnslookup.go:862](tdns/v2/dnslookup.go:862)).
A+AAAA NS-address lookups *are* spawned as goroutines
([dnslookup.go:1035-1051](tdns/v2/dnslookup.go:1035)).

There is one legacy serialization point: the `RecursorCh`
engine loop at [imrengine.go:211](tdns/v2/imrengine.go:211)
runs `ImrQuery` synchronously inside its channel read, so
requests delivered via that channel queue behind each other.
The only sender is the `imr query` CLI command — gossip and
hsync paths bypass it. See S11 below.

**Alternative:** Speculative query to top-N servers in parallel,
first valid answer wins (the "Happy Eyeballs" of DNS).

- ✅ *Pros of current:* simple, predictable load on auth servers;
  reentrancy is real — the lab gossip paths are not serialized.
- ❌ *Cons of current:* within one query, one slow server can
  block its full timeout before we move to the next.
- ✅ *Pros of alt:* significantly faster in failure scenarios.
- ❌ *Cons of alt:* multiplies query volume on auth servers;
  needs cancellation discipline; more complex.

### 11. maxiter = 12 hardcoded

**Choice:** [imrengine.go:295](tdns/v2/imrengine.go:295). No
configurability, no rationale in comments.

**Alternative:** Configurable; or rely entirely on the existing
`visitedZones` loop-detection map
([dnslookup.go:759](tdns/v2/dnslookup.go:759)).

- ✅ *Pros of current:* always terminates.
- ❌ *Cons of current:* magic number. Deep referral chains
  (e.g. some experimental delegations) hit the cap silently.
- ✅ *Pros of alt:* loop-detection is the right abstraction
  anyway.
- ❌ *Cons of alt:* dropping the cap requires trusting the
  visitedZones logic completely.

### 12. Cache-context semantics: re-query "indirect" hits to "upgrade quality"

**Choice:** Cache hits whose context is Referral / Glue / Hint /
Priming / Failure are *not* returned to the caller; the resolver
issues a fresh query to "upgrade" the data
([imrengine.go:349](tdns/v2/imrengine.go:349) and
[dnslookup.go:794](tdns/v2/dnslookup.go:794)). The comment notes
this is to get DNSSEC signatures.

**Alternative:** Return what we have if it's still valid, and
upgrade asynchronously.

- ✅ *Pros of current:* answers are always direct, always have
  signatures (when DNSSEC is on).
- ❌ *Cons of current:* every gossip BEAT triggers a fresh
  network query for the peer's address because the cached
  context is Glue, not Answer. In an environment where the
  network is the unreliable component, this multiplies the
  failure surface.
- ✅ *Pros of alt:* much less query volume in steady state.
- ❌ *Cons of alt:* harder to reason about; cached "Glue with
  short TTL" might serve stale.

---

## c) Suggestions for improvements

Ordered roughly by impact-to-effort ratio for the user's stated
problem (provider→auditor gossip stuck in NEEDED on AWS).

### S1. Make backoff per-(addr, transport), not per-addr [HIGH impact, MEDIUM effort]

**What:** Change `AuthServer.AddressBackoffs` key from `string`
(addr) to `addrTransportKey{addr, transport}`. Update
`RecordAddressFailure`, `RecordAddressSuccess`,
`GetAvailableAddresses`, and `pickTransport` to consult
per-transport state.

**Why:** Directly addresses the most likely failure mode — when
AWS drops one transport but allows another, the resolver should
converge on the working one within a few queries, not be stuck
in a 2-minute backoff cycle that keeps re-picking the broken
transport.

- ✅ Pros: small, surgical, observable change; obviously correct.
- ❌ Cons: need to re-think `AllAddressesInBackoff` semantics
  (is the address dead if *any* transport works?). Suggest:
  available if *any* transport is not in backoff.

### S2. Demote (zero-weight) a transport after N consecutive failures on the same server [HIGH impact, LOW effort]

**What:** When `RecordAddressFailure` fires for a `(server,
addr, transport)`, increment a per-(server, transport) counter.
At threshold (e.g. 3 consecutive without an intervening
success), temporarily set `TransportWeights[transport] = 0` for
some window (e.g. 5 min). `pickTransport` already handles zero
weights correctly.

**Why:** Lightweight version of S1 that's easier to implement
and gives a fast convergence signal without restructuring the
backoff map. Pair well with S1 (S1 prevents poisoning; S2
forces transport choice to adapt).

- ✅ Pros: minimal change; uses existing weight machinery; very
  observable in `imr show`.
- ❌ Cons: needs a "re-enable" path (success on another
  transport doesn't tell us the demoted transport is back).

### S3. Shorten first-failure backoff; add jitter; consider exponential [HIGH impact, LOW effort]

**What:** Reduce first-timeout backoff from 2 min to ~10–30s
with ±25% jitter; use exponential growth on repeat (10s, 30s,
2m, 10m, 1h cap). Make these constants configurable in
`ImrEngineConf`.

**Why:** 2 minutes is incompatible with a 30-second BEAT cadence.
A single dropped packet should not occlude a peer for 4 BEAT
cycles. Jitter avoids thundering-herd recovery.

- ✅ Pros: trivial code change; massive practical effect.
- ❌ Cons: shorter backoff = more retry traffic against truly-dead
  servers; the cap mitigates this.

### S4. Cross-transport fallback ladder in `tryServer` [HIGH impact, MEDIUM effort]

**What:** If the selected transport fails after its retries,
attempt the same query against one *other* transport from the
server's list before giving up on the address. Order: prefer
encrypted if requireEncrypted; otherwise prefer cheap (UDP).

**Why:** Today, a DoT timeout means we move to the *next server*,
not the next transport on the *same* server. In a deployment
where most peers expose DoT *and* Do53 from the same IP, this
strands working capacity. (Note: the existing Do53→TCP fallback
is a special case of this.)

- ✅ Pros: complements S1/S2 — even on the first query in a fresh
  state we get one cross-transport shot.
- ❌ Cons: more wall-clock per query on a broken server; harder
  to bound; risk of doubling timeout on already-slow paths.

### S5. Fix transport-signal discovery: synchronous, retriable, with state [MEDIUM impact, MEDIUM effort]

**What:** Replace `go func()` fire-and-forget with a
discovery-state machine on `AuthServer` (`DiscoveryState =
{NotAttempted, InProgress, Succeeded, Failed(retryAfter)}`). On
Failed, retry with backoff. On Succeeded, snapshot ALPN /
weights into AuthServer atomically.

**Why:** Right now an SVCB-query failure means the server is
permanently stuck with whatever Transports default it had —
silent and unrecoverable. This is exactly the kind of "IMR
doesn't learn from failures" the user described.

- ✅ Pros: matches operator intuition; observable in CLI dump.
- ❌ Cons: requires careful concurrency (multiple queries to the
  same server may all want to trigger discovery — debounce);
  more code.

### S6. Wire RTT collection and use it in `prioritizeServers` [MEDIUM impact, MEDIUM effort]

**What:** `DNSClient.Exchange` already returns RTT; pipe it back
via `tryServer` to `AuthServer.RecordRTT(addr, transport, rtt)`.
Maintain EMA per `(addr, transport)`. Sort `prioritizeServers`
tuples ascending by recorded RTT (default to mid value if
unknown).

**Why:** Completes the TODO at `dnslookup.go:740`. In a
distributed lab with peers across regions, this is the
difference between "try the closest peer first" and "try a
random peer and wait for its timeout."

- ✅ Pros: long-overdue; aligns with classic resolver design.
- ❌ Cons: requires the rtt return value to actually flow
  through (currently `tryServer` discards it,
  [dnslookup.go:1730](tdns/v2/dnslookup.go:1730)).

### S7. Configurable cache-upgrade policy [MEDIUM impact, LOW effort]

**What:** Add `ImrEngineConf.UpgradeIndirectCacheHits bool`. When
false, return cached Glue/Referral if the answer satisfies the
question (e.g. an A query whose name has cached glue). Default
to current behavior for safety.

**Why:** Cuts gossip-driven query volume substantially when peers
are addressed by their glue. In failure scenarios this is the
difference between "no answer at all" and "stale but usable
answer."

- ✅ Pros: huge query-rate reduction in steady state.
- ❌ Cons: stale-data risk if TTL is mis-set upstream; needs an
  explicit opt-in.

### S8. Observability: include per-(addr, transport) failure counts in `imr show` [LOW effort, ENABLES DIAGNOSIS]

**What:** Extend the `imr dump server` CLI to print, for each
`(addr, transport)`: success count, failure count, last error,
current backoff state. Even before S1 lands, this answers
"which transport is actually failing?" instead of forcing the
operator to guess from BEAT-level symptoms.

**Why:** Right now there is no way for an operator to confirm
the user's hypothesis. The data exists internally (especially if
Debug is on) but isn't surfaced.

- ✅ Pros: trivial; immediately useful even without code-path
  changes.
- ❌ Cons: per-(addr, transport) bookkeeping is needed if the
  underlying counters don't separate by transport yet (see S1).

### S9. Parallel A+AAAA NS resolution → first-success [LOW priority]

**What:** When resolving NS addresses, currently both A and AAAA
queries are spawned as goroutines into `respch`
([dnslookup.go:1035-1051](tdns/v2/dnslookup.go:1035)). The
calling loop in `resolveNSAddresses` could exit as soon as *one*
yields a usable address rather than waiting for both.

**Why:** In v6-broken environments, AAAA queries can take their
full timeout while a working A is already in hand.

- ✅ Pros: faster NS bootstrap in mixed-stack environments.
- ❌ Cons: need to make sure the late-arriving result still
  populates the cache for future use; cancellation can lose
  good data if mis-implemented.

### S11. Drop the `RecursorCh` serialization [TRIVIAL, cleanup]

**What:** The engine loop at
[imrengine.go:211-289](tdns/v2/imrengine.go:211) reads a request
from `RecursorCh` and runs `ImrQuery` synchronously before
reading the next. Wrap that call in `go func() { ... }()` (or
delete the channel path altogether — only `cli/imr_cmds.go:57`
uses it).

**Why:** Not the cause of the lab problem (gossip doesn't use
this path) but a real design smell: the underlying method is
reentrant, the channel-loop artifact pretends it isn't. Concurrent
`tdns-mpcli imr query` invocations are needlessly serialized.

- ✅ Pros: one-line change; removes a confusing inconsistency.
- ❌ Cons: none meaningful. Caller is responsible for the
  `ResponseCh` lifetime either way.

### S10. Cap retries' wall time with an explicit per-query budget [LOW priority]

**What:** Add `ctx, cancel := context.WithTimeout(ctx, budget)`
at the top of `IterativeDNSQuery` (configurable, default ~5s).
Today the only bound is the caller's context, which in some
call sites (gossip handlers) is effectively unbounded.

**Why:** Defense in depth — guarantees that an IMR pathology
can't stall a higher-level state machine indefinitely.

- ✅ Pros: tail-latency guarantee.
- ❌ Cons: needs the budget to be set conservatively or it'll
  break legitimately long DNSSEC chain walks.

### S12. Address-family reachability tracking [HIGH impact in mixed-stack envs, MEDIUM effort]

**What:** Track per-(address family) success/failure counts on
the `Imr` itself (it's a host-network property, not a per-server
property) in a sliding window — say last 10 minutes. Policy:
if `v6Successes == 0 && v6Failures ≥ N` across distinct
addresses in the window, mark v6 **suspect** and have
`prioritizeServers` push v6 candidates to the *bottom* of the
sort order. Don't drop them. After the suspect window expires,
allow a probe attempt — success clears the flag, failure
extends it. Same machinery symmetric for v4.

**Why:** RTT-as-timeout (S6) gives partial natural relief by
sinking v6 addresses to the back of the sort order, but only
*after* we've paid a 5s timeout to discover each fresh v6
address is unreachable. On a box with no global IPv6
connectivity, every newly-encountered AAAA address gets that
penalty independently — the IMR never draws the meta-conclusion
"this whole transport family is dead from this host right now."
S12 is that meta-conclusion.

Crucially, the deployment we care about (no *global* v6 but
working *local* v6) means **deprioritize, not drop**: hard
elimination would break local v6 too. Soft deprioritization
keeps v6 functional when it's the only path available, while
making v4 strictly preferred when both are.

This is a sibling of S2 (transport demotion per-server) and S6
(RTT-based selection) — all three are "meta-learning from
failure aggregates," which the IMR has none of today. Adding
the framework once means S2 and S12 share most of the
sliding-window / probe-recovery plumbing.

- ✅ Pros: directly fixes the no-global-v6 symptom; generalizes
  cleanly with S2; soft-deprioritization keeps partial v6
  working; observable in `imr show` (per-family success/fail
  counts).
- ❌ Cons: window/threshold tuning; risk of marking v6 suspect
  during a real outage that affects only some destinations;
  probe-recovery logic adds complexity. Kernel-routing
  introspection (`ip -6 route show default`) would give the
  same signal faster but adds OS-specific code — defer unless
  empirical detection proves too slow to recover.

---

## Cross-cutting observations

- The IMR has the *right shape* — failure state, transport
  selection, cache contexts — but the components don't talk to
  each other. `RecordAddressFailure` writes; nothing in the
  selection path reads. Fix that first (S1, S2, S8) and several
  symptoms resolve at once.
- The IMR has no *meta-learning* layer — it records per-address
  facts but never aggregates them into "this transport is
  dead", "this address family is dead", or "this server is
  generally bad." S2, S6, and S12 are all instances of this
  same missing layer; building the framework once means later
  members are cheap to add.
- "Take the AWS scenario seriously" is the dominant theme: the
  defaults are tuned for a world where most failures are
  permanent, but in the user's environment most failures are
  transient. The constants need to move and the architecture
  needs to learn faster.
- There is a notable amount of "Future:" / commented-out code
  (RTT sort, validation hooks, port allocation). A small
  follow-up sweep to either implement or delete those would
  improve confidence that what *is* there is what's intended.

## Suggested next steps

If implementing, the recommended order:

1. **S3** (constants/jitter) — one diff, hours of work, immediate
   relief at the lab.
2. **S8** (observability) — confirm hypothesis before deeper
   surgery.
3. **S2** (transport demotion) — incremental safety net.
4. **S1** (per-transport backoff) — the structural fix.
5. **S5** (discovery state machine) — fixes the silent-stuck
   failure mode.
6. Remaining items as time permits, prioritized by observed
   failures rather than speculation.
