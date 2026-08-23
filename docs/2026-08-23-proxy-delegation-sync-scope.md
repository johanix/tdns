# Delegation synchronisation: who may assert what about DS, and on what evidence

**Status:** design agreed 2026-08-23. Implementation not started and not
authorised. PR #382 is superseded, #343 needs re-scoping, #384 tracks the
parent-side half. Recorded because the reasoning is non-obvious and was arrived
at through four wrong answers, each written down at the end so it is not
re-adopted.

(The filename says "proxy" because that is where the question surfaced. It
applies to every tdns component that asserts delegation data upward.)

## The question

Several tdns components push delegation data to a parent zone: tdns-auth acting
as primary for a child, the KSK rollover engine, and tdns-agent running as a
`delegation-sync-proxy` for a primary that is unaware of DSYNC. Each has to
decide what DS to assert and on what evidence.

NS and glue are easy: synchronise present state. DS is not, and the rest of this
document is about why, what each role should use instead, and what the parent
owes regardless.

## A scoping principle

tdns should be robust against states produced by **legitimate procedures**, not
against operator errors that have been known to be wrong for decades. Double-DS
rollovers are a legitimate procedure that deliberately produces a state that
looks inconsistent, so the code must not break them. Delegating to a nameserver
that is not yet serving the zone is not a procedure — it is an outage-causing
mistake with a thirty-year-old answer, which is "don't", and the right amount of
machinery to build for it is none.

The distinction matters because it decides what we owe. Where a legitimate
procedure creates an ambiguous state, we must not guess. Where an operator has
simply done something wrong, we neither prevent it nor design around it — with
one narrow exception, discussed under Role B, where the state is an unambiguous
outage that the party in question can repair for free and the child cannot
signal its way out of.

## The property that separates DS from NS

**DS is the only delegation element whose correct value at time T can differ
from what the child's current zone content implies.**

That is DNSSEC's TTL-bounded ordering. In a double-DS KSK rollover the child
publishes the new DS in the parent *first*, waits out the DS TTL, and only then
swaps the KSK in its own DNSKEY RRset. Between those steps the parent
legitimately holds a DS that maps to no published SEP DNSKEY. The state looks
inconsistent and is correct.

So from a snapshot of the child zone, these two are **the same observation**:

- a DS with no matching DNSKEY, because a double-DS rollover is mid-flight;
- a DS with no matching DNSKEY, because it is stale from a key that is gone.

Nothing in the zone content distinguishes them. Only *intent* does.

## The shared defect: DNSKEY-derived DS

Both child-side roles currently build the DS set by walking the child's DNSKEY
RRset and taking SHA-256 of the SEP-flagged keys — `proxyCurrentDelegationRRs`
on the proxy path, `AnalyseZoneDelegation` on tdns-auth's own child path. That
is the root mistake in both, and it is not fixable by making the derivation
cleverer.

**Publishing a DNSKEY is not a request for a DS. Publishing a CDS is.**

DNSKEY says "this key exists in my zone". CDS says "this is what I want my
parent to publish". They are different assertions and only the second is
addressed to the parent.

RFC 7344 §4 puts it directly: *"The CDS/CDNSKEY RRset expresses what the Child
would like the DS RRset to look like after the change; it is a 'replace'
operation"* — and, decisively for the no-signal case, *"If neither CDS nor
CDNSKEY RRset is present in the Child, this means that no change is needed."*

The derivation carries two further faults wherever it is used. It is SHA-256
only, so a parent holding SHA-384 never matches and looks permanently out of
sync. And it keys off the SEP bit, which is advisory and ignored by validators,
so a zone signed with a KSK that does not set it yields an empty derived set
while being properly signed with a legitimate parent DS.

## Three roles and the evidence each has

**DS content must come from the strongest available statement of intent, and
each role has a different strongest one.**

| role | strongest intent available | today |
|---|---|---|
| **A.** tdns-auth as primary for its own child zone | its keystore, rollover target and DNSSEC policy — it *is* the intent | rollover engine correct; reconcile path DNSKEY-derived, wrong |
| **B.** delegation-sync proxy | the child's CDS/CDNSKEY, read from transferred zone content | DNSKEY-derived, wrong |
| **C.** the parent | none of its own — it validates what arrives | authorization yes, coherence no (#384) |

The symptom is shared and the remedy is not, which is why this is one document
rather than two: anyone fixing the proxy would otherwise not discover that
tdns-auth has the same bug needing a different fix.

## Role A — tdns-auth as primary for the child

Here the daemon holds the keystore, the DNSSEC policy and the rollover engine.
It does not need to infer intent from zone content, because it *is* the thing
that formed the intent. Its problem is not blindness but inconsistency: it has
two sources of DS truth and uses the wrong one on one of its paths.

### Two writers, one RRset

The rollover engine sources its DS set from `dsSetFromSnapshot` /
`ComputeTargetDSSetForZone` — the keystore and the rollover target, not the
published DNSKEY RRset. That is exactly right, and it is what lets it place a DS
for a key it has generated and not yet published.

`AnalyseZoneDelegation` derives from published SEP DNSKEYs. For a zone with both
rollover and delegation-sync enabled, the two disagree about the same RRset
during precisely the window a double-DS rollover opens: the engine publishes the
target DS, and the reconcile path computes the published-key set, sees the extra
DS as surplus, and removes it.

Whether the two are gated against each other is **unknown and unverified**. It
needs checking before the rollover work lands, because that is the branch that
makes the pre-publish real.

### Should intent be expressed as CDS internally?

tdns-auth could go keystore → DS directly, which is what the rollover engine
does today. The argument for forming a CDS first and treating it as the single
internal contract:

- CDS is the interoperable form. A parent that is not tdns consumes CDS, so it
  has to be produced anyway for that case.
- It gives one representation every transport reads, instead of each transport
  deciding what the DS set is.
- It collapses Role A and Role B onto the same downstream code path.

The argument against is that it is an indirection where the daemon already has
the authoritative answer, and that CDS cannot express everything a policy can.
Open question, not settled here.

### Does un-signing propagate?

For Role B this needed a long justification (below). Role A needs none: the
daemon knows whether the zone is signed and whether the operator meant to stop.

But it is unverified whether it **acts**. If signing is turned off for a zone,
does tdns-auth withdraw the DS from the parent, or publish a CDS-delete? If it
does neither, the zone is left bogus by the same mechanism Role B has an
explicit rule for. This is the Role A analogue of that rule and it is currently
unwritten.

### The derivation faults apply here too

The SEP-bit and SHA-256-only problems described above are properties of the
shared derivation, so they affect `AnalyseZoneDelegation` verbatim.

## Role B — the delegation-sync proxy

A proxy secondaries a zone whose keys, policy and rollover plan belong to
another operator. There is no keystore to consult and no plan to read. It sees
exactly one thing, the zone as transferred — and a rollover is a sequence of
states with timing. Its blindness is structural, not an implementation gap.

Its evidence is therefore the child's own published statement: CDS/CDNSKEY.

| child state | proxy action |
|---|---|
| NS or glue differ from the parent | synchronise present state |
| **CDS/CDNSKEY present** | deliver it, over whichever scheme the parent advertises: NOTIFY(CDS), DS add/remove via UPDATE, or DS push via the DSYNC API |
| CDS absent, child signed | no DS opinion — per RFC 7344 §4, "no change is needed" |
| CDS absent, child unsigned (no DNSKEY RRset at all) | remove the parent's DS |

The second row is the substantive change. The proxy already *detects* a CDS
change (`ProxyDelegationAnalysis.CdsChanged`) but the only thing it does with one
is send NOTIFY(CDS) — which serves a parent that runs a scanner and does nothing
for one that does not. A parent advertising UPDATE or API is asking for the
*content*, not a nudge, and the proxy has the content.

An earlier version of this document had the proxy stay out of DS entirely and
forward CDS onward as NOTIFY. That quietly assumed the parent runs a CDS
scanner. Closing exactly that gap is why DSYNC exists.

### What falls out of using CDS as the source

- **The digest-algorithm problem disappears.** CDS states exactly which digests
  the child wants. Deriving stops, so SHA-256-only stops being a limitation.
- **The delete sentinel needs no special case.** `CDS 0 0 0 0` is simply another
  thing to deliver, and it is the child's own statement.
- **"In sync" gets a correct definition for DS**: parent DS versus *CDS-implied*
  DS. Idempotent and convergent — act while they differ, stop when they match.
- **Timing stays with the child.** CDS means "do this now"; an operator
  sequences a ceremony by choosing when to change CDS. The proxy needs no notion
  of rollover state. It delivers a set.
- **The conversion already exists.** CDS rdata is format-identical to DS, and
  the parent-side scanner already performs this translation.

### Standby keys and double-DS are expressible through CDS

Checked rather than assumed, because it decides whether a proxied primary can
run a KSK rollover at all.

**A CDS may request a DS for a key that is not yet in the child's DNSKEY
RRset.** RFC 7344 §4.1 gives exactly three acceptance rules — Location, Signer,
Continuity — and none constrains the CDS *content* to published keys. The Signer
rule constrains the signing key only: *"MUST be signed with a key that is
represented in both the current DNSKEY and DS RRsets, unless the Parent uses the
CDS or CDNSKEY RRset for initial enrollment."*

The RFC is explicit that this is deliberate. §1 points at RFC 6781 §4.1.2 and
notes it *"allows for publication of standby keys"*; §2.2.2 says the child
operator *"may want to publish a new DS record in the Parent, either because
they are changing keys or because they want to publish a standby key."*

**Continuity is what makes it safe:** *"MUST NOT break the current delegation if
applied to DS RRset."* A double-DS rollover publishes CDS = {old, new}; applying
that retains the old DS, the delegation still validates, and the parent accepts.
A child publishing CDS = {new} alone before the new DNSKEY exists would break
the delegation, and the parent MUST ignore it. The ordering enforces itself.

So double-DS carries through a proxy.

### The one remaining inference: an unsigned child

If the child has **no DNSKEY RRset at all**, the proxy removes the parent's DS
even without a CDS saying so. This is the only place any role acts on state
rather than on a statement, and it is the narrow exception to the scoping
principle above — the operator has done something wrong, and we repair it
anyway. Three independent grounds:

1. **No procedure produces this state deliberately.** Pre-publishing a DS for an
   unsigned zone breaks it immediately and buys nothing, so it is not a step in
   any ceremony. Every superficially similar case has a reading under which it
   is deliberate; this one has none, so there is nothing to guess.
2. **The state is an active outage.** A DS in the parent for an unsigned child
   makes every validating resolver declare the whole child zone bogus. Leaving
   it preserves the breakage, and no later transfer repairs it, because the
   child never changes in a way that would trigger a removal.
3. **The child cannot state it.** RFC 8078 CDS-delete requires a validation the
   child cannot provide: the parent-side scanner requires DNSSEC validation
   whenever a DS already exists, and an unsigned child has no key to validate
   with. The channel is shut exactly when it would be needed.

An operator who knows to publish an unsigned `CDS 0 0 0 0` is handled by the CDS
row anyway. This rule is the safety net for the operator who does not.

**The predicate is "no DNSKEY RRset", not "no derivable DS"**, for the SEP-bit
reason given above.

## Role C — the parent

**The parent verifies its own requirements on every channel, regardless of how
the change arrived** — its own CDS scanner, a NOTIFY(CDS), a DNS UPDATE, or the
DSYNC API. A child employing a proxy does not cause any check to be skipped,
because none of those checks were ever the child's to perform.

An earlier version of this document claimed the proxy inherits the parent's
§4.1 duties. That was wrong, and wrong in the same way as the DNSKEY/CDS error:
it put a parent-side responsibility onto a child-side client. Three reasons it
is not a matter of taste:

- **A check performed by the requester is not a check.** A parent relying on the
  proxy's verification is relying on a buggy or compromised proxy to refuse
  itself.
- **The client cannot know the requirements.** RFC 7344 §4.1 is a floor, not a
  ceiling. A parent may require a minimum algorithm, particular digest types, a
  DS count limit, or that a registrant is not on hold. None of that is
  discoverable by the child.
- **Pre-filtering is actively harmful.** A client whose idea of the rules
  differs from the parent's silently refuses changes the parent would have
  accepted. Sending the request and surfacing the parent's own rejection gives
  the operator the real reason.

Authorization already works this way: the DSYNC API handler applies the zone's
`updatepolicy.child` through `ApproveActionsForPrincipal`, the same function the
DDNS path uses, with the authenticated principal where the SIG(0) signer name
goes.

Coherence does not. `ApproveActionsForPrincipal` decides whether a principal may
touch an RRtype at a name and says nothing about whether the resulting
delegation still works. The scanner path has a validation gate; the UPDATE and
API paths have none, so an authorised principal can push a DS set that breaks
the delegation and the parent will publish it. Tracked as **#384**, including
the open question of whether the check should be mandatory or configurable.

## Same symptom, different remedy

| | Role A (tdns-auth primary) | Role B (proxy) |
|---|---|---|
| defect | DS derived from published DNSKEYs | DS derived from published DNSKEYs |
| double-DS broken | yes | yes |
| root cause | has the intent, uses the wrong source | has no access to intent at all |
| remedy | use the keystore/rollover target the engine already uses | read the child's CDS/CDNSKEY |
| un-signing | knows directly; does it act? unverified | explicit rule, three justifications |
| extra hazard | two writers disagreeing inside one daemon | none — single source once CDS is used |

## Work outstanding

Nothing here is authorised for implementation.

**Role A — tdns-auth as primary**

1. Replace the DNSKEY-derived DS in `AnalyseZoneDelegation` with the intent
   source the rollover engine already uses.
2. Verify whether the rollover engine and the reconcile path are gated against
   each other, before the rollover work lands.
3. Decide whether intent should be expressed as CDS internally as the single
   contract for all transports.
4. Verify whether turning off signing withdraws the DS or publishes a
   CDS-delete.

**Role B — the proxy**

5. Make CDS the DS source. `proxyCurrentDelegationRRs` should stop returning a
   DNSKEY-derived DS set; the UPDATE and API paths should take DS content from
   the child's CDS/CDNSKEY. NS and glue are unaffected.
6. Redefine "in sync" for DS as parent-DS versus CDS-implied-DS, so that a child
   with no CDS, or one using SHA-384, stops reading as permanently out of sync
   and re-sending NS and glue on every start with no DS change to show for it.
7. PR #382 is superseded — its DS commit is wrong on both predicate and source.
   Its unrelated apex-SOA panic fix was split out as #383.
8. PR #343 needs re-scoping onto CDS-as-source.

**Role C — the parent**

9. #384 — coherence checking on the UPDATE and API channels, and whether the
   scanner path's own gate should stop being a TODO.

## Four wrong answers, recorded

**First: "the proxy should stay silent about DS unless it can prove an
un-signing."** Backwards. It treated DS-retention as the safe default and
removal as the dangerous act, when the state being protected is an outage.
Inaction is not neutral when the preserved state is itself broken.

**Second: "parent DS tracks child DS, empty included."** Right for the unsigned
case, wrong as a general rule — applied literally it deletes a DS during a
legitimate double-DS rollover. Synchronising present state is correct only where
present state determines the correct answer.

**Third: "the proxy is a non-participant in DS, and forwards CDS as NOTIFY."**
Subtler: it conflated *inferring* DS intent from state, which no role should do,
with *acting* on DS at all, which the proxy must. Limiting it to NOTIFY assumes
the parent runs a CDS scanner, and a parent without one never notices — the very
gap DSYNC was created to close.

**Fourth: "the proxy inherits the parent's §4.1 obligations."** The same
category error as the second and third, one layer up: a parent-side duty placed
on a child-side client. Validation belongs where the resource is owned.

A fifth, on a different point, is recorded so it is not reintroduced:
**guarding against an incomplete zone copy.** AXFR is framed by its SOA,
`dns.Transfer.In` reports a stream that ends without the closing SOA as an
error, and the data is discarded — a partial zone copy never reaches the
analysis. Guarding against one would mask a transfer bug rather than fix it.
(The separate nil-apex guard in `apexRRsetChanged` is still needed, for an
unrelated reason: `new_zd` is a scratch zone, which carries `Ready=true` with no
published snapshot.)
