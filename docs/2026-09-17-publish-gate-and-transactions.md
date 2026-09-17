# One publish gate for every zone change, and transactions for changes that belong together

**Written 2026-09-17.** #653. **Status: PROPOSAL.** Nothing here is implemented.
Updates §1.3 and §1.6 of `2026-07-02-DONE-zone-mutation-snapshot-correctness.md`
("the July design"), which stays as it is.

## What went wrong

A multi-provider agent publishes its identity zone one record at a time. Each
`Publish*RR` call is its own internal ZONE-UPDATE, and the update path publishes
after every update: seven updates, seven serials and seven NOTIFYs inside one
second. The zone's secondary transferred an intermediate serial, 22 of 26
records, and served it for about a second. A peer looked the identity up in that
second and got a signed NODATA for a record that arrived a moment later. Its
resolver cached the denial for the zone's negative TTL, one hour, and the peer
was never discovered.

The same zone is visible even earlier. `CreateAutoZone` installs the first
snapshot while the zone holds only SOA and NS, before signing is turned on, so
the zone is Ready and answers NXDOMAIN, authoritatively, for everything it is
about to contain.

Publishing per change is also a cost. One publish is a serial bump, a signing
pass, an NSEC restitch, a whole-zone delta, a journal transaction, an IXFR link,
a snapshot copy that is O(names), and a NOTIFY to every downstream. A large zone
taking tens of thousands of single-record changes distributes tens of thousands
of IXFRs. One publish per ten seconds makes that about a hundred.

The July design already says changes are coalesced: §1.3 is "the publisher:
rate-limited, coalescing", and §1.6 says an accepted DNS UPDATE "is staged in
`workingSet` but NOT yet served until the next publish". The implementation
went another way. `2f666892` made the update path "publish synchronously on
commit", and `435db717` put the journal's durable-before-visible write, and its
error return, inside that synchronous publish. The coalescing publisher is
built and tested, and `parseconfig.go` is its only caller.

## The rules

1. **Every change is staged, and only the zone's publisher publishes.** This
   holds for every zone this server originates content for, and every writer:
   DNS UPDATE, the management API, the internal publishers, CHILD-UPDATE, the
   signing passes, the catalog, and the exported staging surface tdns-mp uses.
2. **The gate is the July design's §1.3, unchanged.** A change to an idle zone
   publishes at once. Otherwise the publish happens at `lastPublish + cadence`,
   and everything staged until then goes out with it. `publish-cadence` is per
   zone, default 5 s. One publish is one serial, one journal delta, one IXFR
   link and one NOTIFY.
3. **Changes that belong together are a transaction.** Grouping is declared by
   the writer, never inferred from timing.
4. **A zone's first content can be a transaction.** A zone holding only SOA
   and NS is never publicly visible when its creator says so.
5. **A zone that is not Ready is not rate-limited.** Nobody can query it,
   transfer it or be notified of it, so the gate has nothing to protect. A
   publish of such a zone happens at once, unless a transaction holds it.

## Transactions

```
{start tx  <zone> <id> <flags>}
   … changes …
{commit tx <zone> <id>}
```

- **A transaction is a publish hold on one zone.** While a zone has an open
  transaction, its publisher publishes nothing.
- **It is not isolation.** A zone has one working set. What other writers
  stage during the hold goes out with the commit. For an identity zone that is
  the wanted result: the DNSKEY RRset is staged by the signing path and the KEY
  by delegation sync, and both belong in the first publish.
- **Several may be open on one zone.** The zone publishes when the last one
  commits. A commit must not publish another transaction's half.
- **`urgent` is a flag on the start marker.** If any transaction of the hold
  carried it, the closing commit publishes at once. Without it the commit
  requests a publish through the gate: at once on an idle zone, otherwise at
  `lastPublish + cadence`. Wrapping every change in a transaction therefore
  does not bring the churn back.
- **No rollback.** A writer that fails part way commits what it has, or lets
  the hold run out, and logs it. Rollback needs a per-zone log of what each
  transaction staged, because restoring the working set saved at the start
  would also drop what other writers staged. Deferred, possibly for good. A
  failing action inside a multi-action update is skipped today and the rest
  applied; that does not change.
- **Internal writers only, one zone per transaction.** A DNS UPDATE message or
  an API call is already one `UpdateRequest`, staged as a unit. It publishes
  through the gate.
- **Durability follows.** The journal is written once per publish, so a
  transaction's changes are one journal delta. A crash cannot make half of
  them durable. A crash before the commit loses what was staged, as it loses
  any staged change; the writers concerned rebuild their content at start.

### The hold's limit

A commit marker can be lost: a full queue, a writer that failed, a bug.

- **A zone that has published before:** a hold older than the limit is
  released with a WARN, and what is staged publishes through the gate. Its
  previous content was valid, and so is each change added to it.
- **A zone that has never published: fail closed.** Releasing the hold would
  publish exactly the partial zone rule 4 forbids. The zone stays unpublished,
  logs an ERROR, and carries the error in its status until a commit arrives.
  Its creator is local start-up code; if that never commits, start-up failed.

The limit is a constant, 30 s. No knob until something needs one.

## First publish

A zone created inside a transaction is registered, so queued changes find it,
and has no snapshot.

- A query into it is SERVFAIL (`queryresponder.go` answers that for a zone with
  no published snapshot). A resolver does not cache SERVFAIL as a denial, and
  it is what a secondary says for a zone it has configured and not yet loaded.
- A transfer is refused and nothing is notified: the zone is not Ready.
- Changes stage as for any zone. `ensureWorkingSet` seeds the working set from
  `zd.Data` when there is no snapshot.
- The commit is the first publish: the complete zone, signed, then Ready, then
  one NOTIFY (`markReadyIfServableLocked` already notifies only when Ready
  flips). A secondary goes from SERVFAIL to the whole zone.

`CreateAutoZone` gets a held form that skips `InstallInitialSnapshot` and
returns the transaction. tdns-mp's `SetupAgentAutoZone` then sets its options
(signing, notify targets, the transfer ACL), publishes its records and commits.

**To prove first, by test:** that `ApplyZoneUpdateToZoneData` behaves on a
zone that has never published. The pieces exist (drafts, a working set seeded
from `Data`, silent pre-Ready publishes); they have not been run together.

## Mechanism

**Markers.** Two new `UpdateRequest` commands, `TX-BEGIN` (`ZoneName`, `TxID`,
`TxFlags`) and `TX-COMMIT` (`ZoneName`, `TxID`). `UpdateQ` is one ordered
channel with one consumer, so a writer's begin, changes and commit are applied
in the order sent. An in-process writer holding the `*ZoneData` gets
`BeginTx(flags) TxID` and `CommitTx(id)`. **The commit travels the way the
changes did:** a writer that queues its changes queues its commit, or the
commit overtakes them. The commit's send blocks until accepted; the 5 s
give-up the `ops_*` publishers use is wrong for it.

**Hold state.** On `ZoneData`, under `zd.mu`: the open transactions with their
start times, and whether any was urgent. `runPublisher` skips a zone with an
open transaction; the last commit wakes it, or publishes directly when urgent.

**The update path.** `ApplyZoneUpdateToZoneData` and
`ApplyChildUpdateToZoneData` stage, mark the delta for the journal, and call
`requestPublish(false)`. `wsPersistDelta` is assigned per update today; under
coalescing it accumulates (`||`), or a replayed update staged last would switch
the journal off for a publish that carries fresh changes.

**Waiters.** `UpdateRequest.Resp` promises an outcome "once the update has
been applied, persisted and published", and three senders use it: the DSYNC
API, the DS engine and the CSYNC publisher. The promise stays. Their channels
are collected on the zone and answered by the publish that carries their
change, with its error when the journal write refuses the publish. Every path
that drops a working set answers them too. They wait at most one cadence. The
DSYNC API gives up after 5 s today, which is the default cadence; it must wait
longer than the cadence. A commit marker may carry a `Resp` as well, so a
writer can learn that its transaction is published. A wire DNS UPDATE does not
wait today and does not start to.

**Observability.** `pendingChanges()` and `tdns-cli debug zone-txlog` exist
for exactly this: what is staged and not yet served. They gain the open
transactions and their age.

## Every publisher

| Where | Today | Under this design |
|---|---|---|
| `ApplyZoneUpdateToZoneData` (ZONE-UPDATE: DNS UPDATE, API, internal publishers) | publishes per update | stage, request publish |
| `ApplyChildUpdateToZoneData` (CHILD-UPDATE) | publishes per update | stage, request publish |
| `StageBatch`, and `StageRRset`/`StageDelete`/`StageOwnerDelete` + `Publish` (tdns-mp's combiner) | publishes per call, returns the new serial | stage as a unit, request publish. No new serial to return; tdns-mp only logs it |
| `ResignZone`, `SignZone`, `StripZoneRRSIGs`, `RenewZoneSignatures` | one publish per pass | stage, request publish. On a zone that is not Ready this is immediate (rule 5), so start-up is not delayed |
| `regenerateCatalogZone` | publishes per member change | stage, request publish |
| `BumpSerial` / `BumpSerialOnly` (operator) | publishes | stays immediate: an explicit operator action. `Publish` stops being the same call |
| `requestPublish(false)` from `parseconfig.go` | the gate | unchanged |
| `initialLoadZone`, `applyRefreshReplacementLocked`, `applyOutboundSerialAfterRefresh`, `RepopulateDynamicRRs` | publish a load or refresh | unchanged: the content and serial are a file's or an upstream's |
| `ReplayPersistedDeltas` | publishes at start | unchanged: before Ready |
| `commitTransportSignalLocked` | republishes, no serial change | unchanged |
| `handleCatalogCreate` | `CreateAutoZone`, then stages the version record and republishes: the catalog is visible as SOA and NS first | create held, stage, commit |

`requestPublish(true)` goes to `publishSync` today. After this, the only
sources of an immediate publish of a Ready zone are an urgent transaction and
the operator's bump. No automated path sets `urgent` without a stated reason.

## A refresh must not drop what is staged

`applyRefreshReplacementLocked` replaces the working set wholesale
(`zd.workingSet = snapshotMapFromData(new_zd.Data)`). Today a staged change
waits for microseconds, so nothing is there to lose. Under the gate a change can
wait a cadence, and a refresh or reload arriving in that window would drop it
without a trace, waiters included.

Proposed: a refresh or reload that finds staged changes publishes them first.
If a transaction is open it waits for the commit, up to the hold's limit.
tdns-mp's combiner is already safe: its contributions are re-staged onto every
refresh by the pre-refresh callbacks.

## tdns-mp

- `SetupAgentAutoZone`, the only `CreateAutoZone` caller in tdns-mp, creates
  the identity zone held, publishes its records and commits. Every role that
  sets its identity up through it is covered.
- The combiner's `StageBatch` logs `NewSerial != OldSerial`; that line changes.
- Re-pin after this lands. With a `Resp` on its commit, an agent can hold its
  first hello until its identity is published. Today the hello leaves in the
  second the publishing starts, which is what sends the peer's lookup into the
  window.

## Not in this design

- **The identity zone's negative TTL.** `CreateAutoZone` writes `$TTL 3600` and
  an SOA minimum of 3600, while the SVCB it serves has TTL 120. A zone that is
  important and rarely asked wants a minimum near 60 s. A separate, small fix.
- **The transport gives up on a peer whose discovery found a URI and no
  address** (tdns-mp, tdns-transport). Separate.
- `ImrQuery` returns a cached denial's SOA RRset as the answer RRset. Separate.

## Tests

- **One serial.** A secondary of a zone created held sees SERVFAIL, then one
  transfer of the complete zone. The harness that reproduced #653 (a secondary
  double serving SERVFAIL, an intermediate serial, the full zone) becomes this
  test, run through the real `SetupAgentAutoZone`-shaped producer.
- **Coalescing.** A burst of N updates to a Ready zone is one publish when
  idle plus at most one per cadence; an urgent transaction publishes at once; a
  plain one on a busy zone waits for the gate.
- **The hold.** Two transactions: nothing publishes until the second commits.
  Another writer's change staged during the hold goes out with the commit.
- **The limit.** A lost commit on a published zone releases with a WARN. On a
  never-published zone it does not, and the zone reports the error.
- **Waiters.** Answered by the publish that carries their change; answered
  with the error when the journal refuses it; answered when a working set is
  dropped.
- **Refresh.** A change staged before a refresh is served after it.
- **Journal.** A transaction is one delta; `wsPersistDelta` survives a replayed
  update staged after a fresh one.

## Open

- Whether a refresh that meets an open transaction waits, as proposed, or
  refuses and retries.
- Whether the signing passes belong behind the gate from the start or in a
  second step. They are one publish per pass already; the gain is a pass and an
  update sharing a serial.
