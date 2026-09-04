# D-3b, step 2: the RFC 7477 rules on the UPDATE path

**Written 2026-09-02.** The second of D-3b's two PRs in
`docs/2026-07-16-ddns-delegation-keystate-draft-alignment-plan.md`: wire the
NS/glue acceptance rules extracted in step 1
(`docs/2026-09-02-ddns-keystate-d3b-csync-extraction.md`) into the UPDATE
path, alongside the DS check from #386. Branch
`feature/ddns-keystate-d3b-csync-wire`. Written stacked on the extraction
branch (#477); that has since merged, so the base is `main`.
(#477). This closes D-3b.

## The rule, and its scoping

ddns-02 §"Processing the UPDATE": a delegation change that arrives by DNS
UPDATE is subjected to the same correctness tests a CSYNC scanner would have
run. A scan *copies* the child's NS set and the addresses of its
in-bailiwick nameservers, from the child's nameservers, in agreement. So the
delegation a scan would produce is: NS = what the child serves; glue for each
in-bailiwick nameserver = what the child serves for it. That is what
`CheckDelegationNSCoherence` checks, **scoped to what the update touches**,
which is the DS check's discipline:

- If the update changes the NS set, the resulting set must be what the
  child's nameservers serve, in agreement; an empty resulting set is refused
  (RFC 7477 §3.2.1).
- A nameserver the update adds to the set, or whose glue it touches, must end
  up with the glue the child serves, per type. So adding an in-bailiwick
  nameserver without its addresses is refused: the scan would have carried
  them.
- A nameserver the update removes must not leave glue behind.
- An address record may only be added at an in-bailiwick nameserver of the
  resulting set. At the delegation point itself it is not glue; below the
  child but not a nameserver it is not glue; under no delegation at all it
  is an orphan.
- Glue the update does not touch, for nameservers it keeps, is **not**
  re-verified. Stale glue elsewhere is the scanner's to fix, not a reason to
  refuse this child's change. Likewise an update that touches neither NS nor
  glue never asks anyone.

Refusal is REFUSED with the same EDE the DS check uses. A dedicated
"delegation incoherent" EDE would be better for both; it is not added here
because the private EDE block was iota-numbered and #476 had two codes
in flight on its own branch, so a third from an unstacked branch would have
collided on merge. #476 is on `main` now, so the collision is historical and
appending after its codes is safe -- the deferral stands only because a
dedicated code is a separate, visible protocol change, not because it is
blocked. Add it, and switch both checks to it, once
merged.

## Whom the parent asks

The parent's **current** nameservers for the child, through the scanner's
`queryAllNSAndCompare` (every server, agreement required) — the same
fetcher the CSYNC path uses, now a `Scanner` method. That is RFC 7477's
child-first model: the child makes its current servers serve the change,
then asks the parent to publish it. tdns's own senders already work that
way (the UPDATE is computed from the child zone after it changed). For a
delegation that does not exist yet there are no current servers, so the ones
the update names are asked.

The scanner is the asker because it owns the auth-query engine. Without a
scanner instance the check refuses rather than guesses, like the DS check
does without a resolver — but only for updates that actually touch NS or
glue, so DS-only and KEY updates are unaffected.

## Where it is wired

`ApproveChildUpdate` (UPDATE) and the DSYNC API delegation handler, right
after the DS check in each, with the same refusal shape. `dsAfterActions`
became `rrsetAfterActions(owner, rrtype, …)` so both checks share the
RFC 2136 apply semantics.

## Not included

- The DS-duplication question (`CheckDelegationCoherence` vs
  `ProcessCDSNotify`): untouched, deliberately, as the plan required.
- Verifying that a *newly added* nameserver actually answers
  authoritatively for the child. RFC 7477 does not ask that of the scanner
  either; the check asks the current servers what the NS set is, not the new
  server whether it works.
- A live testbed run.

## Tests

`delegation_csync_update_test.go`, on a real parent `ZoneData` with a
map-backed asker: untouched updates ask nobody; an NS change the child
serves is accepted and the current servers are the ones asked; not served,
disagreement, lookup failure, empty result and no scanner each refuse; a
new in-bailiwick nameserver needs the served glue and is refused with none
or with wrong glue; address records at the delegation point, below the
child but not a nameserver, and under no delegation are refused; a removed
nameserver must not leave glue; untouched drifted glue is not re-verified
while touched glue is; a new delegation asks the nameservers it names; the
touched-set derivation; the generalised apply helper. The DS coherence
tests still pass over `rrsetAfterActions`.

## Stricter than the scanner, deliberately

Two places where the asserted check does NOT do what `computeCsyncDelta` does,
so that "the same tests a CSYNC scanner would run" is not over-read:

- **A glue fetch that fails, or on which the child's nameservers disagree,
  REFUSES the update.** The scanner skips that nameserver and carries on, which
  is right for a scan: it is an observation, and a partial one beats none. An
  UPDATE is a request to *change* the delegation, and accepting a change we
  could not verify is how the parent ends up publishing something the child
  does not serve.
- **Glue re-verification is owner-scoped, not per type.** Touching AAAA at a
  nameserver re-verifies its A as well. An in-bailiwick nameserver's addresses
  are one unit, and a nameserver whose A has drifted from what the child serves
  is a broken delegation whether or not this update touched the A. The cost is
  real: an operator adding an AAAA can be blocked by a pre-existing A drift they
  did not cause. Failing closed is the safer direction, and refusing to grow a
  delegation that is already incoherent is the point of the rule. Pinned by
  `TestCheckDelegationNSCoherenceGlueCheckIsOwnerScoped` so it reads as a choice
  rather than an accident.

A third, from the same principle: **a no-op NS edit is not checked at all** --
a duplicate add or a delete of something absent leaves the parent where it was,
so it neither queries the child nor is refused for lack of a scanner. That
mirrors the DS half's `sameRRsetContent` skip.
