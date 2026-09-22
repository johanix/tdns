# Forwarding and priming

**Written 2026-09-22.** Proposal, revised the same day after three rounds of
review. Line
references are to main at `a3e2dae5`. Follows from #722, where a resolver whose root
is forwarded lost its root NS for up to 15 s at a time, and a delegation sync that
fell into the gap failed. #723 fixes that by keeping a synthetic root alive. This
document argues that a forwarded root should not need one, and proposes the
shape of the resolver's start-up, refresh and lookup paths once forwarding is
treated as what it is: a replacement for delegation discovery.

**Status:** adopted; merged as `f3af2129` (#725). Implemented in stages; each
stage's status is in the Staging table.

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

- **No priming for a forwarded root**, not even the hints seed. `InitImrEngine`
  neither calls `PrimeFromHintsOnly` nor reads `root-hints`, so a missing or
  unreadable hints file no longer stops a forwarded-root resolver from starting.
  Today a configured path that does not exist aborts init
  (`v2/cache/rrset_cache.go:883`, surfacing at `v2/imrengine.go:305`). A
  configured `root-hints` is kept for the reload that removes the `.` forward
  (section 4). If it is missing at start-up, that is a warning: that reload
  would fail to prime.
- **`RefreshRoot` waits for a notification**, with no timer, while `.` is
  forwarded (section 4).
- **Trust anchors.** `processTrustAnchorZone` fetches and validates the anchored
  DNSKEY RRset, then validates the NS RRset (`validateNSRRsetForAnchor`,
  `v2/imrengine.go:2122`, non-fatal). For an anchor zone under a forward, the
  DNSKEY comes through the forward, and the NS step is skipped: it validates a
  delegation the resolver never uses. Today this step is also what replaces the
  hint copy of the root NS with the upstream's short-lived one: it sends a forced
  `. NS` query, which is forwarded, and caches the answer.
- **Trust-anchor setup no longer holds back the listeners.** Today
  `initializeImrTrustAnchors` runs to completion before `StartImrEngineListeners`
  (`v2/imrengine.go:401`, `:406`). A validating resolver whose upstream is down
  therefore waits out those fetches before it binds: the leftover noted in
  `2026-08-31-imr-forward-startup-and-status.md` §5. S2 starts the listeners
  first and runs the online half of trust-anchor setup (fetching and validating
  the anchored DNSKEY RRsets) concurrently with the probe. The offline half
  (`loadConfiguredTrustAnchors`, `v2/imrengine.go:292`) still runs first, so the
  configured keys are in the cache before the first query. A query that arrives
  before the online half has finished has its DNSKEY fetched and validated
  against them on demand; S2's tests pin that. Neither the probe nor trust-anchor
  setup is a gate.

### 3. Probing the upstreams

`ProbeForwardUpstreams` (`v2/imr_forward.go:981`) sends one recursive SOA query
for the forward zone to each upstream, concurrently. A failure warns and marks
`config status` DEGRADED; the resolver keeps serving. That stays, with two
changes:

- **Classify the probe's answer.** Today "reachable" means any DNS response,
  whatever its rcode (`v2/imr_forward.go:58`). An upstream that answers REFUSED
  or SERVFAIL to the SOA of the zone it is supposed to serve therefore looks
  healthy. The probe should report three outcomes: unreachable (no response),
  answering (the zone's SOA), and refusing (every other response: REFUSED,
  SERVFAIL, NOTAUTH, NXDOMAIN or NODATA for the apex, FORMERR, NOTIMP, and so
  on). Unreachable and refusing are warnings with different wording. Live queries
  keep today's meaning of "reachable".
- **Optionally, re-probe idle zones.** Reachability only changes with traffic,
  so a zone nobody asks about keeps its start-up verdict forever. A slow re-probe
  (for example every 15 minutes, only for zones with no successful exchange in
  that window) keeps the status honest. Settled: yes, every 15 minutes, as a
  separate step after the classification (S4). It blocks nothing.

### 4. Reload, and status

- **`RefreshRoot` gets a wake-up channel.** Today its loop waits only on
  `ctx.Done` and `time.After` (`v2/imr_root_refresh.go:98`), so it can neither
  idle nor react to a reload; with no root NS it would spin at its 1 ms yield.
  On each wake it asks whether `.` is forwarded:
  - forwarded: it waits on the channel and `ctx` only, with no timer;
  - not forwarded: it runs its refresh pass as today, and waits on the channel,
    `ctx` and the pass's timer.

  The channel has a buffer of one, so a send never blocks and repeated sends
  collapse into one wake-up.
- **Reload** (`v2/imr_reload.go`) swaps the forward table and, when the answer to
  "is `.` forwarded?" changes, sends on the channel:
  - `.` forward removed: `RefreshRoot` wakes, finds an unforwarded root with no
    root NS, and primes the way start-up does (hints, then the live `. NS`).
  - `.` forward added: `RefreshRoot` wakes and goes idle. The old root data
    expires; nothing depends on it.
  - another forward zone added or removed: probe the new zone's upstreams. No
    effect on priming.

  **`RefreshRoot` owns priming after start-up.** The reload only notifies, so
  there is one place that primes and no race between the two.
- **Status.** `imr config status` reports "root forwarded: not primed, no root
  NS kept" instead of a root NS expiry that means nothing for a forwarded root.

### 5. DS at a forward zone's apex (settled: the parent's path)

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

**Settled: the parent's path.** The maintainer's view is that sending it to
`foo.`'s upstream is wrong, though it can be argued both ways; the review agrees.
The rule mirrors `FindClosestKnownZoneFor`: for qtype DS, the forward decision
looks at the parent of the query name. A DS for `foo.` then follows `.`'s path
(the `.` forward if there is one, otherwise iteration), and a DS for `sub.foo.`
still goes to `foo.`'s upstream. This is why the cache hook takes a qtype.

An operator whose split-horizon `foo.` needs the child's view has two ways out:
forward the parent too, or configure a trust anchor at `foo.`. The second only
works once a trust anchor takes precedence over the parent's DS, which today it
does not (section 6). S6 therefore depends on S5.

This does not change how tdns treats data from a forward zone: unsigned data from
a zone the operator configured is not held to a delegation proof from the public
tree (`ConfiguredZone`; `v2/cache/delegation_proof.go`). The rule matters for a
signed forward zone chained from a public trust anchor.

### 6. Trust anchors under a forward zone

The interesting case for section 5: `foo.` is forwarded **and** has a configured
trust anchor. The configuration then says "send everything at and below `foo.` to
this upstream, and trust `foo.` through this key". That is the operator's
statement of how `foo.` is trusted, and it has to beat anything a parent says.
It is the reason to configure one: a private `foo.` with no public delegation, a
split-horizon `foo.` signed with other keys than the public one, or a parent that
has not published the DS yet.

**The rule.** A configured trust anchor at `foo.` governs `foo.` and everything
below it, down to any more specific anchor:

- `foo.`'s DNSKEY RRset is validated against the anchor, and only against it.
- No DS for `foo.` is fetched for validation, and no parent-side data about
  `foo.` counts: not a parent DS, not a parent's proof that there is no DS, not
  an NXDOMAIN for `foo.` in the public tree. None of them can make `foo.`
  Insecure or Bogus.
- If `foo.`'s DNSKEY RRset does not validate against the anchor, `foo.` is Bogus.
  There is no fallback to the parent's DS.

**Today it is the other way round.** `ValidateDNSKEYs`
(`v2/cache/rrset_validate.go:668`) consults the parent's DS first, and the
configured anchor is only a fallback:

| line | what happens | result |
|---|---|---|
| 707 | look for a cached DS for the zone | |
| 721 | none cached: fetch one on demand (`backfillDS`) | |
| 728 | the DS denial proves an insecure cut | **Insecure** |
| 735 | a DS that is not Secure | its state |
| 756 | a Secure DS matching no DNSKEY (EDE 9 at 792) | **Bogus** |
| 803, 822 | only now: trust-anchor DNSKEYs, then a seeded DS | |

This does not show at start-up, because trust-anchor setup validates `foo.`'s
DNSKEY directly against the anchor. It shows when that DNSKEY RRset expires and
is validated again. The routing makes it worse: `backfillDS` picks the parent's
servers, but the forward hook decides by query name, so the DS query goes to
`foo.`'s upstream after all. Depending on what that upstream answers for
`foo. DS`, an anchored `foo.` can end up Insecure or Bogus. Not tested yet.

The code already follows the rule in one place: `proofNames`
(`v2/cache/unsigned_rrset.go:143`) leaves the zone out of the DS check when "a
trust anchor vouches for the zone, which no DS removal undoes". `ValidateDNSKEYs`
needs the same check, before anything about the DS. Three things stand in the
way today:

- **A DS-form anchor lives where parent data overwrites it.**
  `seedDSRRsetFromTrustAnchors` (`v2/imrengine.go:1901`) writes the configured DS
  into the cache's ordinary DS slot for the name, marked Secure. `backfillDS`, a
  CD=1 client query and S6's routing all write that same slot, and replace the
  seed with whatever the parent says.
- **`hasTrustAnchor` cannot see a DS-form anchor.** It only looks at trust-anchor
  flags in the DNSKEY cache (`v2/cache/unsigned_rrset.go:156`), which a DS-form
  anchor only gets once a key has been fetched and matched.
- **An earlier verdict short-circuits the check.** `ValidateDNSKEYs` returns
  early for a zone already marked Insecure or Indeterminate
  (`v2/cache/rrset_validate.go:696`–`703`), before any anchor is looked at. A
  parent's DS denial seen earlier therefore keeps an anchored zone Insecure.

So S5:

1. **Keeps the configured anchors in their own store**, DS-form and DNSKEY-form,
   filled from the configuration and changed only by a reload. Nothing learnt
   from the network writes to it. `seedDSRRsetFromTrustAnchors` fills this store
   instead of the cache's DS slot.
2. **`hasTrustAnchor` reads that store.**
3. **In `ValidateDNSKEYs`, an anchored zone is decided by its anchor first**:
   validate the DNSKEY RRset against the anchor's keys or DS, and stop. No cached
   or fetched DS, no DS denial, and no earlier Insecure or Indeterminate verdict
   applies. A zone marked Insecure before is validated again against its anchor.

**Why this must come before section 5.** With today's order, sending `foo. DS`
along the parent's path would make an anchored split-horizon `foo.` reliably
Bogus: the public parent's DS matches none of the internal keys. With the anchor
in charge, the routing of a DS query only matters where no anchor decides: a
client's own DS query, and a forward zone without an anchor that is chained from
the parent's.

**`trust-ad` and an anchor** contradict each other: one says "validate it
yourself with this key", the other "trust the upstream's AD bit". The anchor
wins, but that needs a mechanism: a `trust-ad` forward never reaches
`ValidateDNSKEYs`. `forwardQuery` sends CD=0 and takes the upstream's AD bit as
the cache verdict (`v2/imr_forward.go:694`, `:840`–`:860`). The rule:

- **Skip `trust-ad` when the closest configured anchor covering the query name
  is not the root and lies at or below the forward zone's apex.** Such names are
  queried with CD=1 and validated locally against the anchor, exactly as in a
  forward zone without `trust-ad`.
- **A root anchor never turns `trust-ad` off.** Practically every validating
  resolver has one, configured or the compiled-in IANA key; if it counted,
  `trust-ad` would never apply anywhere. The same goes for any anchor above the
  forward zone: the `trust-ad` forward is then the more specific statement. When
  a non-root anchor sits at the forward zone's own apex, the anchor wins.
- **The configuration gets a warning** when a non-root anchor lies at or below
  a `trust-ad` forward zone's apex, since the operator asked for both.

| configuration | result |
|---|---|
| root anchor only; `trust-ad` forward for `.` or `foo.` | `trust-ad` as today |
| anchor at `foo.`; `trust-ad` forward for `.` | `foo.` and below validated locally; everything else keeps the AD bit |
| anchor at `bar.foo.`; `trust-ad` forward for `foo.` | `bar.foo.` and below validated locally; the rest of `foo.` keeps the AD bit |
| anchor at `com.`; `trust-ad` forward for `foo.com.` | `trust-ad` as today: the forward is more specific |

### 7. Answering a DS query at an anchored zone

A client asks the resolver for `foo. DS`, and a trust anchor is configured at
`foo.`. The anchor is the resolver's statement of which key identifies `foo.`;
section 6 makes it the only thing that decides `foo.`'s validation. The DS answer
should say the same thing:

- **A trust anchor at `foo.`: answer from it.** A DS-form anchor is returned as
  configured. For a DNSKEY-form anchor the DS is computed with SHA-256, the
  digest every validator supports. With several anchors for `foo.`, as during a
  key roll, all of them are returned.
- **No trust anchor at `foo.`: the parent's path** (section 5).

This makes the answer agree with how the resolver itself trusts `foo.`. Without
it, a client could get AD=1 data for names under `foo.` (validated from the
anchor) together with an AD=1 answer from the public parent saying that `foo.`
has no DS, a different one, or does not exist at all.

**The CD bit decides which view a client gets.**

- **CD=0: the anchor's DS**, with AD=1 when the query had DO or AD set, AA=0,
  and no RRSIG. AA=0 because a recursive answer is not authoritative; AA=1 on a
  DS the resolver made up would look as if it owned `foo.`.
- **CD=1: the parent's path**, exactly as without an anchor. CD=1 asks for the
  data so that the client can judge it. A DS the resolver made up carries no
  signature from the parent, so a validating client would find it Bogus.

**What this does not do.** It does not let a downstream validating resolver that
knows nothing of the forward validate `foo.`. That resolver validates from its own
root anchor, and a DS with no parent signature under a signed parent is Bogus to
it. Such a downstream either trusts this resolver's AD bit (a tdns forward with
`trust-ad`), and then needs no DS, or carries the anchor itself. The clients that
benefit are stubs, resolvers that trust the AD bit, and diagnostics.

**Rules for the implementation:**

- **From the anchor store** (section 6), the same one the validator uses, so
  the answer is exactly what the resolver trusts.
- **Client-facing only.** The DS is built in the responder at answer time. It is
  never cached, and nothing inside tdns sees it: not the validator (which, after
  section 6, uses the anchor directly), and not any code that asks the IMR for a
  DS because it wants the parent's real one.
- **Marked.** The answer carries an EDE (Other, with extra text saying it comes
  from a configured trust anchor). As far as we know other resolvers do not
  answer DS queries from their trust anchors, so a tdns answer of "DS present"
  where the parent publishes none should say why.
- **TTL:** fixed at 3600 s, since the anchor has none of its own. Open to change
  in review of the implementation.
- **Scope:** any name below the root that has a configured anchor, whether it is
  forwarded or iterated. The root has no DS.
- **Configuration, not state.** The answer reflects the configured anchor, even
  when `foo.`'s DNSKEY RRset currently fails to validate against it.

### 8. What stays from #723

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
- Start-up with the only upstream down: the listeners bind without waiting for
  trust-anchor fetches, and a query that arrives before the online half of
  trust-anchor setup has finished still validates once the upstream is back. The
  test's parent publishes no DS that conflicts with the anchor, so that it does
  not depend on S5.
- `.` forwarded and `root-hints` pointing at a missing file: the resolver starts,
  with a warning.
- Reload in both directions, through the wake-up channel: removing the `.`
  forward primes at once, not on a timer; adding it makes `RefreshRoot` idle
  with no timer running.
- Section 5: a DS query for `foo.` goes to the parent's path, one for `sub.foo.`
  to `foo.`'s upstream.
- Section 6: `foo.` forwarded with a trust anchor at `foo.`. The upstream (or the
  parent's path, after S6) answers `foo. DS` with NODATA, with NXDOMAIN, with a DS
  that matches no DNSKEY, and with a matching DS. `foo.` stays Secure in all four,
  both at start-up and after its DNSKEY RRset expires and is validated again.
  With no anchor at `foo.`, the parent's answer decides, as today.
- Section 6, the anchor store:
  - a parent DS fetched after start-up (by `backfillDS`, or a CD=1 client query)
    does not displace a DS-form anchor, and `hasTrustAnchor` sees a DS-form
    anchor before any key has been matched;
  - a zone marked Insecure by an earlier parent denial is validated again against
    its anchor, and comes out Secure.
- Section 6, `trust-ad` plus an anchor:
  - a non-root anchor at or below the forward zone's apex: queries for names at
    or below it go out with CD=1 and validate locally; names elsewhere in the
    forward zone keep the upstream's AD bit; the configuration warns;
  - a root anchor with a `trust-ad` forward, for `.` and for `foo.`: the
    upstream's AD bit is taken, as today;
  - an anchor above the forward zone (at `com.`, forward for `foo.com.`): the
    upstream's AD bit is taken, as today.
- Section 7, with an anchor at `foo.`:
  - a DS-form anchor: `foo. DS` with CD=0 returns the configured DS, AD=1 when
    DO or AD was set, AA=0, no RRSIG, and the EDE; with CD=1 it returns the parent's
    path answer (a different DS, a denial or NXDOMAIN);
  - a DNSKEY-form anchor: CD=0 returns the SHA-256 DS of the key; CD=1 as
    above;
  - two anchors for `foo.`: both DS records are returned;
  - the cache never holds the synthesized DS, and an internal DS lookup through
    the IMR gets the parent's answer;
  - `sub.foo. DS`, with no anchor at `sub.foo.`: not synthesized.
- Section 7, with no anchor at `foo.`: CD=0 and CD=1 both get the parent's path
  answer.
- The iterating-root hardening, as in #723.

## Staging

| step | content | depends on | status |
|---|---|---|---|
| S1 | forward-first decision in the seven callers, the cache hook | — | implemented in #726 |
| S2 | no priming or refresh for a forwarded root; `root-hints` not read; `RefreshRoot` wake-up channel and reload notification; trust-anchor setup after the listeners, through the forward; status | S1 | not started |
| S3 | the iterating-root hardening from #723 | — | implemented in #727 |
| S4 | probe classification; then the idle re-probe | classification: —; re-probe: S1–S3 | not started |
| S5 | a configured trust anchor governs its zone; parent-side DS data cannot override it: the anchor store, anchor-first `ValidateDNSKEYs`, no `trust-ad` path under a non-root anchor inside the forward zone | — | not started |
| S6 | DS at a forward apex follows the parent's path | S5 | not started |
| S7 | a client's DS query at an anchored zone: the anchor's DS for CD=0, the parent's path for CD=1; responder only, marked with an EDE | S5, S6 | not started |

S1 and S2 replace #723's forwarded-root half. S3 is #723's other half. S1 alone
closes #722's lookup failures; S2 removes the synthetic root. S5 must land before
S6, and S7 after both.

## Size

Estimated lines added, in the codebase's style: production counts include the
comments, which run to a third or half of it, as in #723 (290 lines: about 150
production, 170 test). Test counts assume the fixtures that already exist: the
signed forward upstream (`startSignedForwardUpstream`,
`v2/imr_forward_validation_test.go:71`), the `ImrResponder` tests' writer, the
cache package's signed-zone helpers, and the reload tests.

| stage | production | tests | basis |
|---|---|---|---|
| S1 | 110–140 | 250–350 | Seven call sites at 10–20 lines each, the cache hook and its wiring (about 10), one decision function (about 20). One test per caller with no root server map, the validator paths through the signed upstream. |
| S2 | 120–170 | 180–250 | Start-up priming branch and `root-hints` warning (about 25); `RefreshRoot` wake-up channel and idle state (about 40); reload notification (about 15); trust-anchor setup after the listeners, without the NS step for a forwarded anchor (about 30); status in the API and the CLI (about 20). Tests: start with no hints file, idle with no timer, both reload transitions, a dead upstream at start-up, status. |
| S3 | 60–80 | 90–110 | Written already in #723 (`rootRefreshPass`, `rootRetryWait`, the lead-window check), plus the 1 s floor and the wait taken after the attempt (about 10). Mostly a cherry-pick, tests included. |
| S4 | 100–140 | 120–180 | Classifying the probe's answer and reporting it (60–80); the idle re-probe timer (40–60). Tests: one upstream double per outcome, and the timer. |
| S5 | 100–150 | 250–340 | The anchor store, filled from the configuration and read by `hasTrustAnchor` (40–60); move the trust-anchor branch of `ValidateDNSKEYs` (lines 803–938) ahead of the DS path and past the early return: mostly moved code, about 30 new; no `trust-ad` path under an anchor, and the warning (15–25). Tests: four DS answers at start-up and after re-validation, a control with no anchor, the store surviving parent fetches, re-validation of a zone marked Insecure, and `trust-ad`. |
| S6 | 20–40 | 60–90 | The DS rule in the decision function, and its callers passing the qtype. Tests: `foo.` and `sub.foo.`, with `.` iterated, with `.` forwarded, and with a nested forward. |
| S7 | 90–130 | 150–220 | Collecting the anchor's DS set, including DNSKEY to SHA-256 DS (about 30); the answer with CD, DO and AD handling, and the EDE (about 50); the hook in `ImrResponder` (about 15). Tests: the cases in the Tests section. |
| **total** | **600–850** | **1100–1540** | About 1700–2400 lines over seven PRs. |

S1 and S2 together, which close #722 and remove the synthetic root, are about
230–310 production lines and 430–600 test lines. Almost nothing is deleted: the
priming branch for a forwarded root (about 15 lines) is the only code that goes.

## Settled questions

Settled in review, 2026-09-22.

1. **DS at a forward apex:** the parent's path (S6), after trust-anchor
   precedence (S5). A split-horizon operator who needs the child's view forwards
   the parent too, or configures a trust anchor at the child.
2. **Idle re-probe:** yes, every 15 minutes, only for a zone with no successful
   live exchange in that window. It blocks nothing and comes after the start-up
   classification (S4).
3. **`root-hints` when `.` is forwarded:** warn, do not reject. The file is
   unused while `.` is forwarded, and it is what the reload that removes the
   forward primes from. A missing file must not stop start-up.
4. **A DS query at an anchored zone** (section 7, 2026-09-22): answered from the
   anchor for CD=0, and along the parent's path for CD=1.
