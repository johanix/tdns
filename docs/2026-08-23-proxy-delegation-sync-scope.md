# What a delegation-sync proxy may synchronise, and where DS comes from

**Status:** design agreed 2026-08-23, implementation not started and not
authorised. PR #382 is superseded; #343 needs re-scoping. Recorded because the
reasoning is non-obvious and was arrived at through three wrong answers, each of
which is written down below so it is not re-adopted.

## The question

A `delegation-sync-proxy` is a tdns-agent acting as secondary for a primary that
is unaware of DSYNC — it watches transfers and forwards the child's delegation
data to the parent. What delegation data may it assert, and on what evidence?

NS and glue are easy: synchronise present state. Every intermediate state of a
nameserver migration is valid on its face, so what the child currently serves is
always the right answer.

DS is not, and the rest of this document is about why, and what to do instead.

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

## The category error: DNSKEY is not a request for a DS

The proxy derived the DS set by walking the child's DNSKEY RRset and taking
SHA-256 of the SEP-flagged keys. That is the root mistake, and it is not fixable
by making the derivation cleverer.

**Publishing a DNSKEY is not a request for a DS. Publishing a CDS is.**

DNSKEY says "this key exists in my zone". CDS says "this is what I want my
parent to publish". They are different assertions and only the second is
addressed to the parent. The proxy was reading the first as though it were the
second.

RFC 7344 §4 puts it directly: *"The CDS/CDNSKEY RRset expresses what the Child
would like the DS RRset to look like after the change; it is a 'replace'
operation"* — and, decisively for the no-signal case, *"If neither CDS nor
CDNSKEY RRset is present in the Child, this means that no change is needed."*

Once DNSKEY and CDS are separated, the case analysis over "which SEP keys exist
versus which DS the parent holds" disappears. The proxy does not need to
classify those combinations, because none of them is a statement addressed to
it.

## Where DS content may come from

| source of DS content | verdict |
|---|---|
| derived from the child's DNSKEY RRset | the proxy inventing intent — forbidden |
| derived from the child's CDS/CDNSKEY | the proxy delivering the child's own assertion — correct |

This is the whole rule. It is not "the proxy stays out of DS", which was an
earlier and wrong version of this document: staying out assumes the parent will
notice the CDS by itself, and a parent with no CDS scanner never will. Removing
that assumption is precisely why DSYNC exists — the child *tells* the parent
something changed rather than waiting to be noticed.

## Agreed proxy behaviour

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

### What falls out of using CDS as the source

- **The digest-algorithm problem disappears.** CDS states exactly which digests
  the child wants — SHA-256, SHA-384, or both. Deriving stops, so SHA-256-only
  stops being a limitation and a parent holding SHA-384 stops looking
  permanently out of sync.
- **The delete sentinel needs no special case.** `CDS 0 0 0 0` is simply another
  thing to deliver. It is the child's own statement, so no inference is involved.
- **"In sync" gets a correct definition for DS**: parent DS versus *CDS-implied*
  DS, rather than versus DNSKEY-derived DS. Idempotent and convergent — act
  while they differ, stop when they match.
- **Timing stays with the child.** CDS means "do this now"; an operator
  sequences a ceremony by choosing when to change CDS, exactly as they would
  sequence a registrar submission. The proxy needs no notion of rollover state.
  It delivers a set.
- **The conversion already exists.** CDS rdata is format-identical to DS, and
  the parent-side scanner already performs this translation.

## Standby keys and double-DS are expressible through CDS

This was checked rather than assumed, because it decides whether a proxied
primary can run a KSK rollover at all.

**A CDS may request a DS for a key that is not yet in the child's DNSKEY
RRset.** RFC 7344 §4.1 gives exactly three acceptance rules — Location, Signer,
Continuity — and none of them constrains the CDS *content* to published keys.
The Signer rule constrains the signing key only: *"MUST be signed with a key
that is represented in both the current DNSKEY and DS RRsets, unless the Parent
uses the CDS or CDNSKEY RRset for initial enrollment."*

The RFC is explicit that this is deliberate. §1 points at RFC 6781 §4.1.2 and
notes it *"allows for publication of standby keys"*; §2.2.2 says the child
operator *"may want to publish a new DS record in the Parent, either because
they are changing keys or because they want to publish a standby key."*

**Continuity is what makes it safe:** *"MUST NOT break the current delegation if
applied to DS RRset."* In a double-DS rollover the child publishes CDS = {old,
new}; applying that retains the old DS, the delegation still validates, and the
parent accepts. A child publishing CDS = {new} alone before the new DNSKEY
exists would break the delegation, and the parent MUST ignore it. The ordering
constraint enforces itself.

So double-DS carries through a proxy, and the earlier conclusion that fancier
ceremonies require the primary to manage sync itself does not apply to it.

### Validation stays with the parent, on every channel

An earlier version of this document claimed the proxy inherits the parent's
§4.1 duties, on the grounds that consuming CDS directly bypasses the parent's
scanner. That is wrong, and wrong in a way worth naming, because it is the same
category error as the DNSKEY/CDS one: it put a parent-side responsibility onto a
child-side client.

**The parent verifies its own requirements, on every channel, regardless of how
the change arrived** — its own CDS scanner, a NOTIFY(CDS), a DNS UPDATE, or the
DSYNC API. A child employing a proxy does not cause any check to be skipped,
because none of the checks were ever the child's to perform.

Three reasons this is not a matter of taste:

- **A check performed by the requester is not a check.** The proxy is the party
  making the request. A parent relying on the proxy's verification is relying on
  a buggy or compromised proxy to refuse itself.
- **The proxy cannot know the requirements.** RFC 7344 §4.1 is a floor, not a
  ceiling. A parent may require a minimum algorithm, particular digest types, a
  DS count limit, or that a given registrant is not on hold. None of that is
  discoverable by the child, so "inherit the duties" is not implementable.
- **Pre-filtering is actively harmful.** If the proxy's idea of Continuity
  differs from the parent's actual policy, it silently refuses changes the
  parent would have accepted. Sending the request and surfacing the parent's own
  rejection gives the operator the real reason.

So the proxy delivers the child's stated intent faithfully and reports what the
parent says. A rejection is a normal outcome to be surfaced, not a failure the
proxy should have prevented.

The parent side already works this way for authorization: the DSYNC API handler
applies the zone's `updatepolicy.child` through `ApproveActionsForPrincipal`,
the same function the DDNS path uses, with the authenticated principal where the
SIG(0) signer name goes.

## The one remaining inference: an unsigned child

If the child has **no DNSKEY RRset at all**, the proxy removes the parent's DS
even without a CDS saying so. This is the only place the proxy acts on state
rather than on a statement, and it is justified on three independent grounds:

1. **No procedure produces this state deliberately.** Pre-publishing a DS for an
   unsigned zone breaks it immediately and buys nothing, so it is not a step in
   any ceremony. Every superficially similar case has a reading under which it
   is deliberate; this one has none.
2. **The state is an active outage.** A DS in the parent for an unsigned child
   makes every validating resolver declare the whole child zone bogus. Leaving
   it preserves the breakage, and no later transfer repairs it, because the
   child never changes in a way that would trigger a removal.
3. **The child cannot state it.** RFC 8078 CDS-delete requires a validation the
   child cannot provide: the parent-side scanner requires DNSSEC validation
   whenever a DS already exists, and an unsigned child has no key to validate
   with. The channel is shut exactly when it would be needed.

An operator who knows to publish an unsigned `CDS 0 0 0 0` is handled by the
CDS row anyway, on the proxy's own authenticated channel. This rule is the
safety net for the operator who does not.

**The predicate is "no DNSKEY RRset", not "no derivable DS".** An empty derived
DS set means "no SEP-flagged DNSKEY", which is a different thing: the SEP bit is
advisory and validators ignore it, so a zone signed with a KSK that does not set
it yields an empty derived set while being properly signed with a legitimate
parent DS. Keying the removal off the derived set would wipe that DS.

## Work outstanding

Nothing here is authorised for implementation yet.

1. **Make CDS the DS source on the proxy path.** `proxyCurrentDelegationRRs`
   should stop returning a DS set derived from DNSKEYs; the UPDATE and API paths
   should take their DS content from the child's CDS/CDNSKEY, with the
   Continuity check above. NS and glue are unaffected.
2. **Redefine "in sync" for DS** as parent-DS versus CDS-implied-DS, and stop DS
   differences that the proxy has no opinion about from marking the delegation
   out of sync — otherwise a child with no CDS, or one using SHA-384, is
   permanently out of sync and the reconcile re-sends NS and glue on every start
   with no DS change to show for it.
3. **PR #382 is superseded.** Its DS commit decided from `len(newDS)`, which is
   both the wrong predicate and the wrong source. Its unrelated apex-SOA panic
   fix has been split out so it can land on its own.
4. **PR #343 needs re-scoping.** Its current DS handling is DNSKEY-derived; that
   is pre-existing on the branch rather than introduced by the recent commits,
   but it is the thing this design replaces.
5. **tdns-auth's own child path** has the same DNSKEY-derived DS in
   `AnalyseZoneDelegation`. Unlike the proxy it has a keystore and a rollover
   engine, so the fix is different — point it at the same helpers the rollover
   engine uses — but the double-DS exposure is the same.
6. **The parent checks authorization but not coherence on its push paths.**
   `ApproveActionsForPrincipal` decides whether a principal may touch an RRtype
   at a name; it says nothing about whether the resulting delegation still
   works. The scanner path applies an RFC 7344/8078 gate, but the UPDATE and API
   paths have no continuity check at all, so a principal fully authorised to
   manage a child's DS can push a set that breaks the delegation and the parent
   will publish it. This is a parent-side gap on the parent's own channels, not
   something a proxy should compensate for, and whether the check should be
   mandatory or configurable is undecided.

7. **Verify the double-writer question before the rollover work lands.** For a
   zone with both rollover and delegation-sync enabled, the rollover engine
   publishes the *target* DS set while the reconcile path computes the
   *published* one. The reconcile would remove a pre-published DS during exactly
   the window the rollover created it. Whether the two are gated against each
   other is unknown.

## Three wrong answers, recorded

**First: "the proxy should stay silent about DS unless it can prove an
un-signing."** Backwards. It treated DS-retention as the safe default and
removal as the dangerous act, when the state being protected is an outage.
Inaction is not neutral when the preserved state is itself broken.

**Second: "parent DS tracks child DS, empty included."** Right for the unsigned
case, wrong as a general rule — applied literally it deletes a DS during a
legitimate double-DS rollover. Synchronising present state is correct only where
present state determines the correct answer.

**Third: "the proxy is a non-participant in DS, and forwards CDS as NOTIFY."**
The failure here was subtler: it conflated *inferring* DS intent from state,
which the proxy must not do, with *acting* on DS at all, which it must. Limiting
the proxy to NOTIFY silently assumes the parent runs a CDS scanner. A parent
without one never notices, which is the very gap DSYNC was created to close.

A fourth, on a different point, is recorded so it is not reintroduced: **guarding
against an incomplete zone copy.** AXFR is framed by its SOA, `dns.Transfer.In`
reports a stream that ends without the closing SOA as an error, and the data is
discarded — a partial zone copy never reaches the analysis. Guarding against one
would mask a transfer bug rather than fix it. (The separate nil-apex guard in
`apexRRsetChanged` is still needed, for an unrelated reason: `new_zd` is a
scratch zone, which carries `Ready=true` with no published snapshot.)
