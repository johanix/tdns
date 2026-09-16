# Removing a nameserver: the parent first

**Written 2026-09-17.** #665, fix 2. Branch `fix/665-parent-first-removal`,
stacked on fix 1 (`fix/665-correct-parent-transaction`), which makes both
senders build a correct transaction for a withdrawal.

## The rule

Adding and removing delegation data go in opposite orders:

- **Add**: make the change in the zone first, then update the parent. The
  parent checks that the child already serves what it is asked to publish.
- **Remove**: update the parent first, then the zone. The parent must never
  refer resolvers to a nameserver the child has stopped listing.

Until now tdns-auth did everything zone-first and built the parent's
transaction from the zone afterwards. For a removal that is the wrong order
however the transaction is built.

## Scope

- **Removals of an NS record from the apex NS RRset.** Additions, and glue
  changes for nameservers that stay, keep the zone-first order.
- **A zone's own tdns-auth** (`parentsync`, not `parentsync-proxy`). A proxy
  learns of a change by transfer, after it is public, so it cannot go first.
  Fix 1 is all it gets: a correct transaction, and success or failure logged
  with the payload.
- **Both update channels**: the management API (the CLI) and DNS UPDATE.
- DS is out of scope. The parent-first transaction says nothing about it, and
  a DNSKEY change in the same update is synced as before.

## Child: three steps

`applyParentFirst` (`v2/delegation_parent_first.go`):

1. **Here first:** what the update adds to the delegation (new NS, their
   glue), and glue changes for nameservers that stay. These are zone-first
   changes, and the parent checks that the child serves them.
2. **The parent:** the delegation as it will be after the update, over a
   scheme whose answer is a verdict: UPDATE (rcode) or API (status plus
   read-back). NOTIFY is dropped from the plan, because the parent acts on it
   later by reading what the child serves. A parent offering only NOTIFY
   cannot take a parent-first removal.
3. **Here:** the update exactly as sent.

On refusal, step 1 is undone. Step 1 only adds records that the final state
contains and removes records it does not, so applying the original update in
step 3 on top of step 1 reaches the same end state, and undoing step 1 is
exact.

The transaction comes from `planDelegationChange`. It applies the update to
the current NS and glue RRsets with `rrsetAfterActions`, the RFC 2136
semantics the parent's own coherence check uses, rather than from the
update-path delta producer. That producer does not handle `delrrset` or
`delname` at a glue owner.

- **Confirmed:** step 3 runs with `ParentSyncDone`, so the ZoneUpdater queues
  no zone-first sync to resend it.
- **Not confirmed:** nothing is applied.
  - API: an error naming the parent's reason and `--force`.
  - DNS UPDATE: REFUSED with the reason in `EDEZoneUpdateNotApplied`. It has
    no override.
- **`--force` (API only):** step 3 runs without `ParentSyncDone`, so the
  ordinary zone-first sync follows.

## Timing

The parent's answer is bounded at 60 seconds. UPDATE is tried twice, one
second apart: enough for one BADKEY re-bootstrap. Someone is waiting on the
answer, so a REFUSED is not retried with the background sync's backoff.

The three steps run detached from the caller's cancellation. A client that
hangs up after step 1 must not leave the zone half-changed with nobody to undo
it.

Every update to a zone that syncs its own delegation is applied holding the
zone's delegation lock (`lockDelegationChanges`), not only the removals. An
update that arrives while a removal waits for the parent is applied after it.
Otherwise it would change the delegation the removal's transaction was computed
from, and its own sync to the parent would race the removal's.

On DNS UPDATE, every update to such a zone therefore runs in its own goroutine
and answers the client itself. The UPDATE engine is one goroutine for every
zone, so neither the parent round trip nor the wait for the lock may happen on
it. When the parent is served by the same server, the round trip's own UPDATE
would queue behind it and deadlock.

## Parent: every resulting nameserver served

`CheckDelegationNSCoherence` used to require the resulting NS set to *equal*
what the child's nameservers serve. A correctly ordered withdrawal is one the
child still serves, so every one was refused. The rule is now that every
nameserver in the resulting set must be served. Additions are checked exactly
as before, and glue checks are unchanged. Recorded as an amendment in
`2026-09-02-ddns-keystate-d3b-update-wiring.md`.

## Tests

`v2/delegation_parent_first_test.go` drives `ApiZoneUpdate` against a running
ZoneUpdater, with a stand-in parent. The stand-in runs the real endpoint
action builder and coherence check against what the child zone serves at the
moment it is asked, so the order itself is under test. Covered:

- confirmed removal;
- refused replacement, undone;
- accepted replacement;
- `--force`;
- additions unchanged;
- zones without `parentsync` unchanged;
- a DNS UPDATE refusal and its EDE;
- the plan filter;
- the kept-nameserver glue split.

Also covered: an API update and a DNS UPDATE that arrive during the parent wait
are applied only after the removal.

Each piece was reverted in turn and at least one test fails for each. Not
covered by a test: the four-line hook in `UpdateResponder` that starts the
goroutine, which needs a fully validated SIG(0) UPDATE to reach.
