# What a delegation-sync proxy may synchronise, and why DS is different

**Status:** design agreed 2026-08-23, implementation outstanding. PR #382 is in
draft pending the rework described here. Recorded because the reasoning is
non-obvious and was arrived at by first getting it wrong twice.

## The question

A `delegation-sync-proxy` is a tdns-agent acting as secondary for a primary that
is unaware of DSYNC — it watches transfers and forwards the child's delegation
data to the parent. What delegation data is it entitled to assert?

The obvious answer, and the name of the subsystem, is "all of it: keep the
parent in sync with the child". That is right for NS and glue and wrong for DS,
and the reason it is wrong for DS generalises.

## The property that separates DS from NS

**DS is the only delegation element whose correct value at time T can differ
from what the child's current zone content implies.**

That is DNSSEC's TTL-bounded ordering. In a double-DS KSK rollover the child
publishes the new DS in the parent *first*, waits out the DS TTL, and only then
swaps the KSK in its own DNSKEY RRset. Between those steps the parent legitimately
holds a DS that maps to no published SEP DNSKEY. The state looks inconsistent
and is correct.

NS and glue have no such property. Every intermediate state of a nameserver
migration is valid on its face, so reflecting present state is always right.

## Why the proxy cannot participate in DS

From a snapshot of the child zone, these two are **the same observation**:

- the parent holds a DS with no matching DNSKEY, because a double-DS rollover is
  in progress and the child has not swapped yet;
- the parent holds a DS with no matching DNSKEY, because it is stale from a key
  that is gone.

Nothing in the zone distinguishes them. Only *intent* does, and intent is not in
the zone — it is in whatever is driving the rollover, on a clock.

The proxy has no access to it, and this is structural rather than an
implementation gap. It secondaries a zone whose keys belong to the primary's
operator: there is no keystore to consult, no policy, no target key set, no plan.
It sees exactly one thing, the zone as transferred, and a rollover is a sequence
of states with timing.

The consequence is stronger than "the proxy cannot help with rollovers". A proxy
that synchronises DS on present state **actively breaks** a rollover the primary's
operator is running out of band, by removing the DS they just placed. So the
proxy cannot be a lesser participant in DS; it has to be a non-participant. A
partial one is worse than none, because the primary is then unable to manage the
operation itself either — both are writing the same RRset with different answers.

## Three DS sources, one of which can see forward

The codebase already embodies the distinction, which is what makes the boundary
credible rather than merely convenient:

| driver | DS source | sees intent |
|---|---|---|
| KSK rollover engine | keystore + target key snapshot + policy | **yes** |
| tdns-auth child reconcile | published SEP DNSKEYs | no |
| delegation-sync proxy | published SEP DNSKEYs of another operator's zone | no, structurally |

`pushDSRRsetViaApi` sources its DS set from `dsSetFromSnapshot` /
`ComputeTargetDSSetForZone` — the keystore and the rollover target — not from
the DNSKEY RRset. That is precisely the knowledge of future intent: it can place
the DS for a key it has generated and not yet published.

`AnalyseZoneDelegation` and `proxyCurrentDelegationRRs` both derive DS by walking
the published DNSKEY RRset and taking SHA-256 of the SEP-flagged keys. For the
proxy that is the only thing available. For tdns-auth's own child path it is a
fixable gap, not a structural one — it *has* a keystore, and should use the same
helpers the rollover engine does.

## Agreed scope for the proxy

- **NS and glue** — synchronise present state. Stateless, always safe.
- **DS** — not a participant, with exactly one exception (below).
- **CDS/CDNSKEY** — forward the signal, do not interpret it. Already the
  behaviour: a CDS change drives NOTIFY(CDS) and the parent's scanner decides.

That last point keeps the restriction cheap rather than limiting. A primary
running a rollover behind a proxy still has a channel: publish CDS, and the
parent acts on it. The proxy stays a courier and never a decision-maker about DS.

## The one exception: an unsigned child

If the child has **no DNSKEY RRset at all**, the proxy must declare an empty DS
so the parent removes what it holds.

This is not a softening of the rule; it is the one state the rule does not cover,
for three independent reasons:

1. **There is no future intent to protect.** Pre-publishing a DS for a zone that
   is not signed breaks it immediately and buys nothing, so no rollover procedure
   produces this state deliberately.
2. **The state is an active outage.** A DS in the parent for a child that is not
   signed makes every validating resolver declare the whole child zone bogus.
   Leaving it is not caution — it preserves the breakage, and no later transfer
   repairs it, because the child never changes in a way that would trigger a
   removal.
3. **The child cannot signal for itself.** RFC 8078 CDS-delete is unavailable
   here: `ProcessCDSNotify` requires DNSSEC validation whenever a DS already
   exists, and an unsigned child has no key to validate with. The channel is shut
   exactly when it would be needed.

**The predicate is "no DNSKEY RRset", not "no DS derivable".** An empty derived
DS set means "no SEP-flagged DNSKEY", which is not the same thing: the SEP bit is
advisory and validators ignore it, so a zone signed with a KSK that does not set
it yields an empty derived set while being properly signed with a legitimate
parent DS. Keying the removal off the derived set would wipe that DS. The
distinction also cannot be made inside `CreateChildReplaceUpdate`, whose only DS
input is the derived set — the caller has to state the intent explicitly.

## Work outstanding

1. **PR #382, DS commit — rework.** `CreateChildReplaceUpdate` currently decides
   from `len(newDS)`. It must take explicit DS intent from the caller: *clear*
   when the child has no DNSKEY RRset, *hands-off* otherwise. The non-proxy caller
   keeps today's behaviour so the change stays proxy-scoped.
2. **PR #382, apex-SOA commit — split out.** Unrelated to any of this (a nil
   dereference on the transfer success path) and ready; it should not wait behind
   a design question.
3. **tdns-auth child path — separate issue.** `AnalyseZoneDelegation` derives DS
   from published DNSKEYs where the keystore is available, so double-DS is broken
   for tdns-auth's own child sync too. Unlike the proxy this is fixable: point it
   at the rollover engine's helpers.
4. **Verify the double-writer question before the rollover work lands.** For a
   zone with both rollover and delegation-sync enabled, the rollover engine
   publishes the *target* DS set while the reconcile path computes the *published*
   one. The reconcile would remove a pre-published DS during exactly the window
   the rollover created it. Whether the two are gated against each other is
   unknown and needs checking.

## How this was reached

Worth recording, because the first two answers were both wrong in instructive
ways.

The thread began with a review finding that the proxy could tell a parent to
delete a DS it never placed, and a proposal to make the proxy silent about DS
whenever it could not prove an un-signing. That was **backwards**: it treated
DS-retention as the safe default and removal as the dangerous act, when the state
being "protected" is an outage. Inaction is not neutral when the preserved state
is itself broken.

The correction — parent DS tracks child DS, empty included — was then applied too
broadly, in a form that would delete a DS during a legitimate double-DS rollover.
Synchronising present state is right only where present state determines the
correct answer.

A third argument, that the proxy should guard against acting on an incomplete
zone copy, was also wrong and is recorded here so it is not reintroduced: AXFR is
framed by its SOA, `dns.Transfer.In` reports a stream that ends without the
closing SOA as an error, and the data is discarded. A partial zone copy does not
reach the analysis. Guarding against one would mask a transfer bug rather than
fix it. (The separate nil-apex guard in `apexRRsetChanged` is still needed, but
for an unrelated reason: `new_zd` is a scratch zone, which carries `Ready=true`
with no published snapshot.)
