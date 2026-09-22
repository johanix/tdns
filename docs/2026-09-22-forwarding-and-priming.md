# Forwarding and priming

**Written 2026-09-22.** Proposal. Follows from #722, where a resolver whose root
is forwarded lost its root NS for up to 15 s at a time, and a delegation sync that
fell into the gap failed. #723 fixes that by keeping a synthetic root alive. This
document argues that a forwarded root should not need one, and proposes the
shape of the resolver's start-up, refresh and lookup paths once forwarding is
treated as what it is: a replacement for delegation discovery.

## The principle

Priming bootstraps iteration: it tells the resolver where the delegation tree
starts. A forward zone replaces delegation discovery for its subtree. tdns
forwarding is forward-only (`v2/imr_forward.go:34`): when every upstream of the
matching zone fails, the query fails with SERVFAIL, and there is no fallback to
iteration.

So priming belongs to the part of the namespace that is iterated, not to the
resolver as a whole:

- **With `zone: .` forwarded, nothing is iterated.** The root NS is never used
  to send a query, and priming has nothing to do. Names under a stub zone that is
  more specific than the forward iterate from the stub's configured servers,
  which do not come from the root either.
- **With `zone: foo.` forwarded, everything outside `foo.` is iterated.** The
  root is primed and kept alive as usual, because of the rest of the tree. For
  `foo.` itself there is nothing to discover: the forward table is the answer to
  "where do queries for `foo.` go".

The rule: **prime if and only if `.` is not covered by a forward zone.**

## What goes wrong today

A forwarded root is primed from the hints file only (`v2/imrengine.go:295`),
without the live fetch, and then refreshed like any other root
(`v2/imrengine.go:416`, `v2/imr_root_refresh.go`).

1. **The refresh has nothing real to refresh against.** A `. NS` query for a
   forwarded root goes to the upstream, which answers from its own cache with a
   TTL that counts down. No refresh can buy more lifetime than the upstream has
   left. Observed: a tdns-agent forwarding `.` to a tdns-imr, which forwards `.`
   to an unbound with `cache-max-ttl: 10`. Downstream of the unbound, the root NS
   never had more than 10 s left, which is always inside the 60 s refresh lead.
   Each answer moved the expiry by the round trip, which counted as success, and
   the loop re-queried after 1 ms: about 70 queries in 1.3 s. When the upstream's
   TTL ticked down, the loop slept its 15 s retry interval while the copy
   expired.
2. **When the root NS expires, the root server map goes with it**
   (`v2/cache/rrset_cache.go:140`).
3. **Lookups treat "the closest cached cut has servers" as a precondition.** The
   forward decision is taken inside `IterativeDNSQuery` (`v2/dnslookup.go:1342`),
   but several callers look up the closest cut first and give up when it has no
   servers, before the forward is consulted:

   | caller | where |
   |---|---|
   | `imrQuery` | `v2/imrengine.go:702`, then `resolveNSAddresses` (`:834`): `no nameservers for zone ""` |
   | `ImrResponder` | `v2/imrengine.go:1114` |
   | `DefaultDNSKEYFetcher`, `DefaultRRsetFetcher` | `v2/dnslookup.go:3617`, `:3639` |
   | validator, signer DNSKEY fetch | `v2/cache/rrset_validate.go:170` |
   | validator, DS backfill | `v2/cache/rrset_validate.go:1009` |
   | delegation evidence for unsigned data | `v2/cache/unsigned_rrset.go:224` |
   | trust-anchor DNSKEY fetch | `v2/imrengine.go:2185`: `no known servers for "." to fetch DNSKEY` |

   Each falls back to the root server map when no closer cut is cached. The
   hint-seeded root exists only to keep these gates open; `PrimeFromHintsOnly`'s
   own comment says the forward outranks the root map in every lookup.

The result is not a start-up accident. With a hints file whose TTL is 900 s, one
forwarding tdns-imr logged "the root NS RRset is gone" 11 times in 90 minutes,
once per hints cycle (840 s, a burst, then 15 s). Everything that arrives through
the forward lives no longer than the upstream allows, so the closest cached cut is
often the root, and the gap hits ordinary lookups as well as internal ones.

## Proposal

### 1. Forward first, everywhere

Every path that picks servers for a question decides "forwarded?" before it
looks up a cut, and "no cut, no servers" is normal for a forwarded name.

- **`imrQuery`, `ImrResponder`:** check `forwardZoneFor` before
  `FindClosestKnownZoneFor` and send a forwarded question straight to
  `IterativeDNSQuery`, which forwards it.
- **The default fetchers:** the same check, and no "no servers" error for a
  forwarded name.
- **The cache package** does not know the forward table. It gets a hook in the
  style of `ConfiguredZone` (`v2/cache/cache_structs.go:91`):
  `Forwarded func(name string, qtype uint16) bool`. When it says true, the
  validator calls its fetcher without servers instead of skipping the fetch.
- **Trust-anchor processing** fetches the anchored DNSKEY through the forward
  instead of requiring the anchor's or the root's server map.
- **One decision function** for all of them, so the DS rule in section 5 is
  applied in one place.

### 2. Start-up

| configuration | priming | root refresh | per forward zone | trust anchors |
|---|---|---|---|---|
| no forward zones | hints + live `. NS` | yes | — | as today |
| `foo.` forwarded | hints + live `. NS` | yes | probe `foo.`'s upstreams | anchors at or below `foo.`: DNSKEY fetched through the forward |
| `.` forwarded | **none** | **none** | probe `.`'s upstreams | root anchor: `. DNSKEY` fetched through the forward; no `. NS` step |

- **No priming for a forwarded root**, not even the hints seed. `RefreshRoot`
  idles while `.` is forwarded.
- **Trust anchors.** `processTrustAnchorZone` fetches and validates the anchored
  DNSKEY RRset, then validates the NS RRset (`validateNSRRsetForAnchor`,
  `v2/imrengine.go:2122`, non-fatal). For an anchor zone under a forward, the
  DNSKEY comes through the forward, and the NS step is skipped: it validates a
  delegation the resolver never uses. Today this step is also what replaces the
  hint copy of the root NS with the upstream's short-lived one: it sends a forced
  `. NS` query, which is forwarded, and caches the answer.
- **Nothing blocks start-up.** The forward table is built, the probe runs
  concurrently, and the resolver serves.

### 3. Probing the upstreams

`ProbeForwardUpstreams` (`v2/imr_forward.go:981`) sends one recursive SOA query
for the forward zone to each upstream, concurrently. A failure warns and marks
`config status` DEGRADED; the resolver keeps serving. That stays, with two
changes:

- **Classify the probe's answer.** Today "reachable" means any DNS response,
  whatever its rcode (`v2/imr_forward.go:58`). An upstream that answers REFUSED
  or SERVFAIL to the SOA of the zone it is supposed to serve therefore looks
  healthy. The probe should report three outcomes: unreachable (no response),
  refusing (REFUSED, SERVFAIL, NOTAUTH, or NXDOMAIN for the apex), and answering
  (the zone's SOA). The first two are warnings with different wording. Live
  queries keep today's meaning of "reachable".
- **Optionally, re-probe idle zones.** Reachability only changes with traffic,
  so a zone nobody asks about keeps its start-up verdict forever. A slow re-probe
  (for example every 15 minutes, only for zones with no successful exchange in
  that window) keeps the status honest. The interval is an open question.

### 4. Reload, and status

- **Reload** (`v2/imr_reload.go`) swaps the forward table. The root state follows
  the new table:
  - `.` forward removed: prime now, and start refreshing. The reload nudges
    `RefreshRoot` rather than waiting for its next wake-up.
  - `.` forward added: stop refreshing. The old root data expires; nothing
    depends on it.
  - another forward zone added or removed: probe the new zone's upstreams. No
    effect on priming.
- **Status.** `imr config status` reports "root forwarded: not primed, no root
  NS kept" instead of a root NS expiry that means nothing for a forwarded root.

### 5. DS at a forward zone's apex (open question)

The forward decision uses the query name alone (`v2/dnslookup.go:1342`). A DS
query for `foo.` therefore goes to `foo.`'s upstream, although DS is parent-side
data (RFC 4035 §3.1.4.1). Iteration already honours that:
`FindClosestKnownZoneFor` (`v2/cache/rrset_cache.go:1151`) asks the parent's
servers for a DS.

**For sending it along the parent's path:**
- The DS is the parent's statement about the child. Asking the child's side for
  it is the mistake `FindClosestKnownZoneFor` was written to avoid (#150).
- An upstream that serves only an internal view of `foo.` may not know the public
  parent at all, or may answer from a local copy of `foo.`, giving NODATA or a
  wrong DS.
- It keeps forwarding and iteration consistent: the same question goes to the
  same side of the cut either way.

**For sending it to `foo.`'s upstream:**
- The upstream is a recursive resolver, and one with access to the public tree
  answers the DS correctly by asking the parent itself.
- With a split-horizon `foo.`, the operator's upstream is the authority for their
  view, and its DS may be the one that matches the keys that view serves.
- When the parent is not reachable from the resolver except through that upstream,
  it is the only path that works. (When everything is forwarded, `.` is forwarded
  too, and the question does not arise.)

**Proposed: the parent's path.** The maintainer's view is that sending it to
`foo.`'s upstream is wrong, though it can be argued both ways. The rule would
mirror `FindClosestKnownZoneFor`: for qtype DS, the forward decision looks at the
parent of the query name. A DS for `foo.` then follows `.`'s path (the `.`
forward if there is one, otherwise iteration), and a DS for `sub.foo.` still goes
to `foo.`'s upstream.

This does not change how tdns treats data from a forward zone: unsigned data from
a zone the operator configured is not held to a delegation proof from the public
tree (`ConfiguredZone`; `v2/cache/delegation_proof.go`). The rule matters for a
signed forward zone chained from a public trust anchor.

### 6. What stays from #723

Keep the hardening of the refresh for an **iterating** root:
- A refresh whose new expiry is still inside the lead window is not a refresh.
- After a turn that did not renew the root NS, the wait stops at the expiry
  instead of sleeping through it. Computed from the copy the cache holds after
  the attempt, with a floor of 1 s.

Drop what exists only to keep a synthetic root alive: re-seeding a forwarded root
from the hints, and the cache's `KeepServerMap` hook. Sections 1 and 2 remove the
need for both.

#724 (a failed proxy sync keeps its NS withdrawal) is independent of this and
unaffected.

## Tests

- A resolver with `.` forwarded, an empty cache and **no hints file**:
  - resolves through the forward;
  - validates an answer against a root trust anchor, fetching DNSKEY and DS
    through the forward;
  - `RefreshRoot` sends nothing, and the upstream never sees a `. NS` query that
    no client asked.
- The same resolver with the upstream's TTLs capped at 10 s: no lookup fails for
  want of a root NS, over several hints-length periods.
- `foo.` forwarded: the root is primed and refreshed; `foo.` names go to the
  upstream; the probe reports each of its three outcomes.
- Reload in both directions: `.` forward removed primes at once; added stops the
  refresh.
- Section 5, if adopted: a DS query for `foo.` goes to the parent's path, one for
  `sub.foo.` to `foo.`'s upstream.
- The iterating-root hardening, as in #723.

## Staging

| step | content | depends on |
|---|---|---|
| S1 | forward-first decision in the seven callers, the cache hook | — |
| S2 | no priming or refresh for a forwarded root; trust anchors through the forward; reload transitions; status | S1 |
| S3 | the iterating-root hardening from #723 | — |
| S4 | probe classification; optional idle re-probe | — |
| S5 | DS at a forward apex follows the parent's path | decision on section 5 |

S1 and S2 replace #723's forwarded-root half. S3 is #723's other half.

## Open questions

1. DS at a forward apex: parent's path (proposed) or the forward's upstream.
2. The idle re-probe: whether to have it, and at what interval.
3. Whether `root-hints` should be rejected or warned about when `.` is forwarded,
   since it is then unused.
