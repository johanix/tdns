# D-3b, step 2: the RFC 7477 rules on the UPDATE path

**Written 2026-09-02.** The second of D-3b's two PRs in
`docs/2026-07-16-ddns-delegation-keystate-draft-alignment-plan.md`: wire the
NS/glue acceptance rules extracted in step 1
(`docs/2026-09-02-ddns-keystate-d3b-csync-extraction.md`) into the UPDATE
path, alongside the DS check from #386. Branch
`feature/ddns-keystate-d3b-csync-wire`, stacked on the extraction branch
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
because the private EDE block is iota-numbered and #476 has already
appended two codes on its branch, so a third from an unstacked branch would
collide on merge. Add it, and switch both checks to it, once the stack has
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
