# One publish gate for every zone change, and transactions for changes that belong together

**Written 2026-09-17.** #653. **Status: r4.** r3 was merged with #695. Nothing
here is implemented yet, which is why r4 revises the text in place and is not
an amendment.
Updates §1.3 and §1.6 of `2026-07-02-DONE-zone-mutation-snapshot-correctness.md`
("the July design"), which stays as it is.

**Revisions.** r1: first draft. r2, after review: queries follow the snapshot and
not Ready, so rule 5 and "First publish" are rewritten around the two gates; the
gate is no longer called "§1.3 unchanged", because RFC 2136 loses its bypass;
signing is behind the gate from the start, the hold is enforced where every
publish passes, and a zone that signs gets a signed first snapshot or none; a
refresh that meets an open transaction is refused and retried; the waiter margin
has a number; an idle zone's publish stays in the caller; new sections on risks,
size and order of work, and what must not regress. **r1 was wrong about one
fact:** it said a wire DNS UPDATE does not wait for its change. It does, and so
do seven other senders, not three. "What NOERROR promises" is new because of it.
r3: that question is decided, option A for the first implementation. Nothing is
left open. r4, before any code, from the implementer's read of r3 against the
code. **r3 was wrong about three things:** a publish stopped by a hold is not
"marked queued", which would spin the publisher; the publish does not sign what
an update staged, so the first-snapshot rule is stated on its own and sits where
every publish passes, not in the commit; and held creation's commit goes through
the queue only for a creator that queues its changes. New in r4: a zone created
held is never a draft; where a commit publishes and how its `Resp` is answered;
what retries a first content that could not be signed; a known limit of steps 1
and 2; the "one serial" test is the producer's half; `CreateAutoZoneHeld`; where
the hold check sits. The decisions of r1 to r3 stand.

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
the zone answers NXDOMAIN, authoritatively, for everything it is about to
contain.

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

## Two gates, as the code has them

What is visible, and to whom, is decided in two places. The rules below lean on
both, so they are stated first.

- **Queries follow the snapshot.** `QueryResponder` answers from
  `publishedSnapshot()` and says SERVFAIL when there is none. It never reads
  `Ready`, and neither does `FindZone`. A zone with a snapshot is queryable,
  Ready or not.
- **Transfers and NOTIFY follow Ready**, and so does `GetOwner`
  (`ErrZoneNotReady`). For a zone that signs, Ready also wants a signed apex SOA
  (`snapshotContentIsServableLocked`).

So "not yet visible" means **no snapshot**. "Not Ready" only means no
downstreams.

## The rules

1. **Every change is staged, and only the zone's publisher publishes.** This
   holds for every zone this server originates content for, and every writer:
   DNS UPDATE, the management API, the internal publishers, CHILD-UPDATE, the
   signing passes, the catalog, and the exported staging surface tdns-mp uses.
2. **The gate's timing is the July design's §1.3.** A change to an idle zone
   publishes at once. Otherwise the publish happens at `lastPublish + cadence`,
   and everything staged until then goes out with it. `publish-cadence` is per
   zone, default 5 s. One publish is one serial, one journal delta, one IXFR
   link and one NOTIFY.
   **What changes is who goes through it.** §1.3 let an RFC 2136 update bypass
   the gate as urgent, and the implementation never coalesced updates at all.
   Here a DNS UPDATE, an API change and an internal publish all go through the
   gate. Whoever runs a dynamic zone sees, for the first time, a busy zone take
   up to one cadence to serve a change, and to answer the UPDATE that made it
   (see "What NOERROR promises").
3. **Changes that belong together are a transaction.** Grouping is declared by
   the writer, never inferred from timing.
4. **A zone's first content can be a transaction.** Such a zone has no snapshot
   until the commit, so a zone holding only SOA and NS is never visible.
5. **A zone that is not Ready is not rate-limited, unless a transaction holds
   it.** It has no downstreams, so there is no distribution to spare, and a
   partial state is a transaction's business, not the gate's. Without this rule
   a signed zone becomes Ready a cadence late at every start: the load publishes
   first, and the signing pass that makes the zone Ready would wait behind it.
   ("Never published" would be too narrow a test for that reason: the zone
   waiting for its signing pass has published once already.)

## Transactions

```
{start tx  <zone> <id> <flags>}
   … changes …
{commit tx <zone> <id>}
```

- **A transaction is a publish hold on one zone.** While a zone has an open
  transaction, nothing publishes it.
- **It is not isolation.** A zone has one working set. What other writers
  stage during the hold goes out with the commit.
- **Several may be open on one zone.** The zone publishes when the last one
  commits. A commit must not publish another transaction's half.
- **`urgent` is a flag on the start marker.** If any transaction of the hold
  carried it, the closing commit publishes at once. Without it the commit
  requests a publish through the gate: at once on an idle zone, otherwise at
  `lastPublish + cadence`. Wrapping every change in a transaction therefore
  does not bring the churn back. A zone that is not Ready is not rate-limited
  (rule 5), so the commit of a zone's first content publishes at once too; see
  "Where a commit publishes".
- **No rollback.** A writer that fails part way commits what it has, or lets
  the hold run out, and logs it. Rollback needs a per-zone log of what each
  transaction staged, because restoring the working set saved at the start
  would also drop what other writers staged. Deferred, possibly for good.
  `StageBatch` keeps its own unwind, which is safe because it runs under one
  hold of `zd.mu`. A failing action inside a multi-action update is skipped
  today and the rest applied; that does not change.
- **Internal writers only, one zone per transaction.** A DNS UPDATE message or
  an API call is already one `UpdateRequest`, staged as a unit. It publishes
  through the gate.
- **Durability follows.** The journal is written once per publish, so a
  transaction's changes are one journal delta. A crash cannot make half of
  them durable.

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
and has **no snapshot**. That, and not Ready, is what keeps it out of sight.

- A query into it is SERVFAIL. A resolver does not cache SERVFAIL as a denial,
  and it is what a secondary says for a zone it has configured and not loaded.
- A transfer is refused and nothing is notified: the zone is not Ready either.
- Changes stage as for any zone. `ensureWorkingSet` seeds the working set from
  `zd.Data` when there is no snapshot.
- **A zone created held is never a draft.** The exported staging surface
  (`StageRRset`, `StageDelete`, `StageOwnerDelete`, `StageBatch`) takes a zone
  with no snapshot for a draft, the scratch zone a pre-refresh callback gets:
  it writes `zd.Data` and publishes nothing, because the refresh that consumes
  the draft is the publish. A held zone has no snapshot either, and no refresh
  is coming. Once its working set is seeded, a write to `zd.Data` reaches
  nothing and is lost without a trace. So held creation sets a flag on the zone,
  and a zone that carries it stages into the working set, from creation on.
  The flag, and not "has an open hold": a first content that could not be signed
  (below) leaves the zone with no hold and no snapshot, and it is still not a
  draft.
- **The commit installs the first snapshot, and it is the complete zone.** Then
  Ready, then one NOTIFY (`markReadyIfServableLocked` notifies only when Ready
  flips). A secondary goes from SERVFAIL to the whole zone.

### The first snapshot of a zone that signs: signed or none

For a zone that signs its own content the first snapshot is the complete
*signed* zone. A publish does not make it so by itself. What a publish signs is
the apex SOA, the NSEC chain, the ZONEMD and a signing scope somebody staged
(`wsNeedsFullSign`, `wsSignOwners`), which today only a refresh does. A record
staged by an update is signed by the update's applier, and the identity zone is
signed today because its creator calls `SignZone`. A creator that did not, or
whose records were staged before its keys resolved, would get a signed SOA, a
signed chain and unsigned answers. And "cannot sign yet" today means "publish
unsigned and stay not Ready", which is queryable.

**The rule sits in `publishWorkingSetLocked` and is keyed on the zone, not on
the commit.** On a zone that was created held, has never published and signs
its own content, *whichever* publish would install the first snapshot

1. stages a full signing scope (`wsNeedsFullSign`, not forced: a working set
   that is signed already costs a walk), and
2. installs **nothing** when signing resolves to "not yet"
   (`resolveSigningMaterialLocked`: no policy bound, no key store, or keys held
   back by the key lifecycle hooks). The working set stays staged, the serial is
   restored, and no publish stays queued.

It cannot sit in the commit alone. After a commit that could not sign, the hold
is closed, and the next publisher to arrive would install the first snapshot:
an update's own publish, for one. With keys present by then it would install a
zone whose earlier records are unsigned; with none, the unsigned zone.

**What a commit that could not sign does.** It closes the hold: the transaction
is over, and nothing more is coming from its writer. It logs an ERROR, puts the
error in the zone's status, and answers its `Resp` with it. The zone has no
snapshot and answers SERVFAIL: fail closed, as for a commit that never came.

**What retries it.** Two events. No timer, and not the publisher's loop, which
the refusal clears on purpose, because a zone that cannot sign used to retry
hot.

- **The next signing pass.** `SignZone`, `ResignZone` and
  `RenewZoneSignatures` end in a publish. With the hold closed it reaches the
  rule above, and passes it once signing material exists. These passes are what
  runs when the missing thing arrives: a policy binding, the policy apply, the
  resigner.
- **The creator commits again.** `TX-COMMIT` (or `CommitTx`) on a zone whose
  first content is committed and unsigned is accepted and tries the publish
  again; its `Resp` carries the outcome. A creator that wants a schedule has one
  it controls.

**The refusal has its own error category, and it is not `DnssecError`.**
`SignZone`, `ResignZone` and `RenewZoneSignatures` all refuse a zone that
carries `DnssecError`, and only the policy and rollover validation clear it: a
"not yet" that set it would switch its own retry off. The category gates
nothing, and the publish that succeeds clears it. A *real* signing failure (keys
that do not resolve for a reason other than "not yet", a signing error) keeps
today's behaviour, `DnssecError` included: that is a fault.

In #653 the intermediate serial was signed: the denial that did the damage
carried a valid RRSIG. A signing pass that published during the hold would
recreate exactly that, which is why the hold is enforced where every publish
passes (next section) and not in the publisher's loop alone.

### Held creation

`CreateAutoZone` gets a held form beside it, `CreateAutoZoneHeld`, which opens
the transaction before the zone is registered, skips `InstallInitialSnapshot`,
marks the zone as created held, and returns the zone and the transaction.
`CreateAutoZone` itself keeps its signature and its behaviour, so no caller
changes until it chooses to. tdns-mp's `SetupAgentAutoZone` then sets its
options (signing, notify targets, the transfer ACL), publishes its records and
commits.

**What must be inside the identity's hold:** everything discovery reads, which
is what `SetupAgentAutoZone` itself publishes (URI, address records, SVCB, JWK,
TLSA), and the DNSKEY RRset, which the signing path stages directly into the
working set when the zone first signs, at the commit's publish at the latest.
The SIG(0) KEY that delegation sync publishes from its own goroutine may arrive
after the commit and go out with the next publish; the zone is valid without it.

**To prove first, by test:** that `ApplyZoneUpdateToZoneData` behaves on a
zone that has never published. The pieces exist (drafts, a working set seeded
from `Data`, silent pre-Ready publishes); they have not been run together.

## Mechanism

**Markers.** Two new `UpdateRequest` commands, `TX-BEGIN` (`ZoneName`, `TxID`,
`TxFlags`) and `TX-COMMIT` (`ZoneName`, `TxID`). `UpdateQ` is one ordered
channel, buffered 50, with one consumer (`ZoneUpdaterEngine`), so a writer's
begin, changes and commit are applied in the order sent. An identity's begin,
seven or so updates and commit fit; a queue that is full is the hold's-limit
case. The commit's send blocks until accepted; the 5 s give-up the `ops_*`
publishers use is wrong for it. (The buffer is the daemon's: a key store made
by `NewKeyDB` alone has an unbuffered queue, so a test runs the engine or
buffers the queue as the daemon does.)

**The commit travels the way the changes did.** A writer that queued any of its
changes queues its commit, or the commit overtakes them and publishes an empty
hold. The in-process pair, `BeginTx(flags) TxID` and `CommitTx(id)` on
`*ZoneData`, is for a writer that also stages in-process, `StageBatch`'s kind.
It is not a shortcut for a writer that queues. Held creation always opens its
transaction in-process, because the zone must be held before it is registered.
Its commit follows the same rule as any other: through the queue, behind the
creator's updates, for a creator that queues its changes (`SetupAgentAutoZone`);
in-process for a creator that stages in-process (`handleCatalogCreate`, whose
key store has no queue at all).

**The hold is enforced at the choke point.** Every publish of a working set
passes `publishWorkingSetLocked`. That is where an open transaction stops it:
the caller's changes stay staged, the hold records that a publish is wanted,
and the call returns. `SignZone`, `StageBatch`, the catalog and the rest call
`publishLocked` directly today, so a check in `runPublisher` alone would let
them through. No publisher installs a snapshot on a held zone.

- **A stopped publish changes nothing.** The check sits after the two early
  exits (no working set; a zone that is no longer live, which drops its working
  set held or not) and before the apex check and the serial bump. The serial,
  `lastPublish` and every `ws*` flag are as they were.
- **"Wanted" is not `publishQueued`.** `runPublisher` republishes for as long
  as `publishQueued` is set and the cadence has run out, and a publish that a
  hold stopped would leave both true: a hot loop on `zd.mu`, the one
  `clearQueuedPublishAfterRefusalLocked` exists to stop. So the want is part of
  the hold state, `runPublisher` stands down on a held zone, and the commit
  that closes the hold wakes it.

**Hold state.** On `ZoneData`, under `zd.mu`: the open transactions with their
start times, whether any was urgent, whether a publish is wanted, and the
commits waiting for their outcome.

**Where a commit publishes.** The commit that closes the hold publishes **in
the caller** (the updater's goroutine, or `CommitTx`'s caller) when the zone is
not Ready (rule 5; a zone's first content always is) or when the hold was
urgent, and answers its `Resp` there, with the refusal if there was one.
Otherwise it asks the gate, and the publish happens in the publisher's
goroutine, where the commit's handler cannot see its outcome. So a commit's
`Resp` on that path is kept on the zone and answered by the publish that
carries it, or by the refusal that drops it. This is the gate's entry, below,
arrived at early, and that list of waiting commits is the seed of "Waiters"; in
the first step it holds commits only. A commit that leaves other transactions
open publishes nothing, and its `Resp` waits for the commit that closes the
hold.

**The gate's entry.** One call replaces the direct `publishLocked` in every
writer. With no hold, on a zone that is idle or not Ready, it publishes **in
the caller, under the `zd.mu` the caller already holds**, exactly as today.
Otherwise it marks the publish queued and wakes `runPublisher`, which publishes
at `lastPublish + cadence`. Keeping the idle publish in the caller matters
twice: a waiter on an idle zone is answered at once, with the journal's error if
there is one, as today; and a test that applies one change and reads the zone
back does not start racing a goroutine.

**The update path.** `ApplyZoneUpdateToZoneData` and
`ApplyChildUpdateToZoneData` stage, mark the delta for the journal, and call the
gate. `wsPersistDelta` is assigned per update today; under coalescing it
accumulates (`||`), or a replayed update staged last would switch the journal
off for a publish that carries fresh changes. A hold is coalescing already, so
the plain assignment matters from the first step on. It is left alone until the
gate reaches updates all the same: replay runs at start, before anything can
open a transaction, the zones held before then have no journal, and the
assignment is on the path of every zone that opens no transaction.

**Waiters.** `UpdateRequest.Resp` promises an outcome "once the update has
been applied, persisted and published". Eight senders wait on it: the wire DNS
UPDATE responder (`answerAfterApply`, and the parent-first submitter), the
management API (`queueApiZoneUpdate`), the DSYNC API, the DS engine, the CSYNC
publisher, the scanner's child update and the signal republisher. Only the
`ops_*` publishers (URI, address, SVCB, JWK, TLSA, KEY) send and forget. The
promise stays. The waiters' channels are collected on the zone and answered by
the publish that carries their change, with its error when the journal write
refuses the publish. Every path that drops a working set answers them too:
four refusals inside `publishWorkingSetLocked`, the unsignable and
unrepairable-chain refusals, and a refresh. On an idle zone the publish is in
the caller, so the answer is as prompt as today. On a busy zone it takes up to
a cadence. Most waiters give up after `UpdateApplyTimeout`, 10 s; the DSYNC API
and the CSYNC publisher after 5 s, which *is* the default cadence. All of them
wait **the larger of `UpdateApplyTimeout` and twice the zone's cadence**: a wait
equal to the cadence loses the race. A commit marker may carry a `Resp` with
the same bound, so a writer can learn that its transaction is published.

**A known limit until the waiters are on the zone (steps 1 and 2).** An
update's applier publishes and the updater answers the update's `Resp` straight
after. Under a hold that publish installs nothing, so the waiter is told
"applied" when its change is staged, before anything serves it. The only holds
in those steps are start-up holds of well under a second on auto zones that
have never published, have no journal and are written by the send-and-forget
publishers. An identity zone does allow updates, though, so a wire UPDATE that
arrives inside its hold is answered NOERROR early. Step 3 closes it. Doing it
sooner would put step 3's plumbing on the updater's path for every zone.

**Observability.** `pendingChanges()` and `tdns-cli debug zone-txlog` exist
for exactly this: what is staged and not yet served. They gain the open
transactions and their age.

## What NOERROR promises

RFC 2136 section 3.5 wants a change committed to nonvolatile storage before the
response is sent, and allows a server to store only the update records, provided
a restart folds them into the zone. tdns keeps that today by answering an UPDATE
only after the publish, because the journal is written by the publish. Under the
gate that has a price on a busy zone: the answer waits for the next publish, so
a client that sends one UPDATE, waits for the answer and sends the next runs at
**one update per cadence**. A UDP client also retransmits in the meantime
(`nsupdate` after 3 s), and the copy arrives while the first is staged.

| | NOERROR means | Cost |
|---|---|---|
| **A** | applied, durable and served, as today | Nothing new to build. A serial client is throttled to one update per cadence on a busy zone; parallel sessions and multi-record UPDATE messages are not. That throttle is the churn protection doing its work |
| **B** | applied and durable, served within a cadence | A stage-time journal of update records, replayed into the working set at start, beside the per-publish delta journal. About 250–350 lines and a second durability path to keep right. The answer is prompt again and nothing accepted is ever lost (R2 goes away) |
| **C** | accepted | What July's §1.6 implied. Breaks section 3.5. Not proposed |

**Decided (2026-09-17): A for the first implementation.** It is correct, it is
what the code promises today, and `UpdateApplyTimeout` already covers twice the
default cadence. B is the follow-up if a bulk dynamic-update load turns up; the
design leaves room for it, since it changes when a waiter is answered and
nothing about the gate or the transactions.

## Every publisher

Names as of `8db21168`.

| Where | Today | Under this design |
|---|---|---|
| `ApplyZoneUpdateToZoneData` (ZONE-UPDATE: DNS UPDATE, API, internal publishers) | publishes per update | stage, ask the gate |
| `ApplyChildUpdateToZoneData` (CHILD-UPDATE) | publishes per update | stage, ask the gate |
| `StageBatch`, and `StageRRset`/`StageDelete`/`StageOwnerDelete` + `Publish` (tdns-mp's combiner) | publishes per call, returns the new serial | stage as a unit, ask the gate. A new serial only when the publish happened in the caller; tdns-mp only logs it |
| `ResignZone`, `SignZone`, `StripZoneRRSIGs`, `RenewZoneSignatures` | one publish per pass | stage, ask the gate, from the start. Immediate on a zone that is not Ready (rule 5); stopped by a hold like everything else |
| `regenerateCatalogZone` | publishes per member change | stage, ask the gate |
| `BumpSerial` / `BumpSerialOnly` (operator) | publishes | stays immediate: an explicit operator action. `Publish` stops being the same call |
| `requestPublish(false)` from `parseconfig.go` | the gate | unchanged |
| `initialLoadZone`, `applyRefreshReplacementLocked`, `applyOutboundSerialAfterRefresh`, `RepopulateDynamicRRs` | publish a load or refresh | unchanged in timing: the content and serial are a file's or an upstream's. See the next section for what they do about staged work |
| `ReplayPersistedDeltas` | publishes at start | unchanged: before anything can open a transaction |
| `commitTransportSignalLocked` | republishes, no serial change | unchanged, and like every publisher it installs nothing on a held zone |
| `handleCatalogCreate` | `CreateAutoZone`, then stages the version record and republishes: the catalog is visible as SOA and NS first | create held, stage in-process, commit in-process (`CommitTx`). A catalog does not sign. The commit bumps the template's serial once, on a zone nothing has seen |

`requestPublish(true)` goes to `publishSync` today. After this, the only
sources of an immediate publish of a Ready zone that is not idle are an urgent
transaction and the operator's bump. No automated path sets `urgent` without a
stated reason.

## A refresh must not drop what is staged

`applyRefreshReplacementLocked` replaces the working set wholesale
(`zd.workingSet = snapshotMapFromData(new_zd.Data)`). Today a staged change
waits for microseconds, so nothing is there to lose. Under the gate a change can
wait a cadence, and a refresh or reload arriving in that window would drop it
without a trace, waiters included.

- **No transaction open:** the refresh publishes what is staged first, then
  replaces.
- **A transaction open: the refresh is refused and retried.** Waiting would tie
  an inbound transfer to a local writer's hold. A hold on a published zone ends
  within its limit, so the refresh is late by that much at most, and a zone that
  has never published has nothing to refresh.

tdns-mp's combiner is already safe: its contributions are re-staged onto every
refresh by the pre-refresh callbacks.

## tdns-mp

- `SetupAgentAutoZone`, the only `CreateAutoZone` caller in tdns-mp, creates
  the identity zone held, publishes its records and commits. Every role that
  sets its identity up through it is covered.
- The combiner's `StageBatch` logs `NewSerial != OldSerial`; that line changes.
- With a `Resp` on its commit, an agent can hold its first hello until its
  identity is published. Today the hello leaves in the second the publishing
  starts, which is what sends the peer's lookup into the window.
- **tdns-mp must use the transaction before it re-pins onto a tdns where
  updates go through the gate.** Without one, the gate would publish the
  identity's first record at once and the rest a cadence later: the partial
  zone of #653, served for five seconds instead of one.

## Risks

| | Risk | How bad | What holds it |
|---|---|---|---|
| R1 | **A busy zone serves a change up to a cadence late**, and answers the UPDATE or API call that made it as late. A script that fires a second change and reads the zone at once, without waiting for the answer, reads the old data | Certain to be noticed; harmless to data | An idle zone publishes in the caller, so a single change behaves as today. Every external channel is a waiter already, so a client that waits for its answer never reads stale data. `publish-cadence` per zone. The guide says so |
| R2 | **A crash loses what was staged and not yet published.** Under option A that is never something a client was told had succeeded: every external channel is answered after the publish. What can be lost is the `ops_*` publishers' fire-and-forget records, which their owners rebuild at start | Low under A | Option A itself. Option B removes it altogether |
| R10 | **A serial DNS UPDATE client runs at one update per cadence** on a busy zone, and a UDP client retransmits while its first copy is staged; a retransmitted update with a prerequisite can fail where the first succeeded | Medium for bulk loaders, none for the occasional update | Multi-record UPDATE messages and parallel sessions are not throttled. Option B if it matters. The duplicate is an old problem made a little more likely; RFC 2136 updates are idempotent apart from prerequisites |
| R3 | **A refresh drops staged changes** if "publish staged first" is wrong or missed on one path (refresh, reload, first load, dynamic-RR repopulation) | High: silent data loss, and a waiter never answered | A test per path. Every working-set drop answers its waiters, so a miss is an error somebody sees |
| R4 | **A zone stuck unpublished.** Fail closed means a creator that never commits leaves its zone at SERVFAIL for good: for an agent, an identity that never appears. The same for a first content that cannot be signed and whose signing material never arrives | High for that daemon, and loud | ERROR log, the zone's status, a commit send that blocks, the commit's `Resp`. It fails at start, in front of whoever started it. An unsigned first content is retried by the next signing pass and by a repeated commit, and its error category does not stop either |
| R5 | **The test suite assumes a synchronous publish.** About 130 call sites in 40 test files apply an update, stage a batch or sign, and read the zone back (`ApplyZoneUpdateToZoneData` 35, `SignZone` 57, `Publish` 13, `StageBatch` 8, …) | Certain; a cost, not a hazard | The idle publish stays in the caller, which covers a test that makes one change. A test that makes several in a row sets the zone's cadence to zero; one package-level default in `TestMain` does it for all of them |
| R6 | **Locking.** A deferred publish runs in the publisher's goroutine: signing, the journal write and the waiters' answers all under `zd.mu` there. This tree has deadlocked before on paths that re-enter zone locking from a publish (`PublishDnskeyRRs`) | Medium | The deferred publish is the code `runPublisher` runs today for `parseconfig.go`. Waiters are answered with the non-blocking send `respond` already uses. `-race` on every step |
| R7 | **A signing pass no longer means "published" when it returns**, on a Ready zone that is busy. A caller that reads the snapshot straight after `SignZone` sees the previous one | Low to medium; needs a read of each caller | Not Ready and idle zones publish in the caller, which is every start-up and first-sign path. The rollover and resign callers are the ones to read |
| R8 | **tdns-mp re-pins onto the gate without the transaction** (see above) | High, and easy to do by accident | Order of work below: the transaction ships first, and tdns-mp adopts it before the gate reaches updates |
| R9 | One delta per publish is larger than one per change. The IXFR chain holds fewer, bigger links | Low | `ixfr-chain-max-bytes` already bounds it, with AXFR as the fallback |

## Size and order of work

Rough, from reading the code; not from a prototype. Non-test lines added or
changed.

| Piece | tdns `v2` | tests |
|---|---|---|
| Markers, `UpdateRequest` fields, the two `ZoneUpdater` cases | 80 | 100 |
| Hold state, `BeginTx`/`CommitTx`, the check in `publishWorkingSetLocked`, the limit, fail closed and its status | 180 | 300 |
| Held `CreateAutoZone`, a signed first snapshot or none, `handleCatalogCreate` | 110 | 250 |
| The gate's entry; the update and CHILD-UPDATE paths; `wsPersistDelta` | 90 | 200 |
| Waiters: collected on the zone, answered at the publish and at every drop site; one bound for all eight senders | 170 | 250 |
| Refresh: publish staged first, refuse and retry | 90 | 200 |
| `StageBatch`/`Publish`/`BumpSerial` apart; the catalog; four signing passes | 90 | 150 |
| `pendingChanges`, the API struct, `debug zone-txlog` | 70 | 50 |
| Guide: `publish-cadence` now governs updates; what an operator sees | 40 (docs) | |
| Existing tests adapted (R5) | | 100–300 |
| **tdns** | **about 850–1000** (option B: 250–350 more) | **about 1600–1900** |
| tdns-mp: `SetupAgentAutoZone` held and committed, the hello on the commit's `Resp`, the combiner's log line | 100–150 | 150–250 |

In four steps, each a PR that is green on its own:

1. **Transactions and held creation** (rows 1–3). Nothing changes for a zone
   that opens no transaction, so the blast radius is the zones that opt in.
   This is the half that closes #653. It brings one piece of row 5 with it, the
   list of commits waiting for their publish, and leaves one known limit for
   step 3 (an update's `Resp` under a hold; see "Waiters").
2. **tdns-mp adopts it** and re-pins. #653 can be verified on a fleet here.
3. **The gate for every update** (rows 4–6): the churn half, and the one with
   R1, R2, R3 and R5 in it. The hold is already enforced at the choke point by
   step 1, so a signing pass cannot publish through a hold even before step 4.
4. **The remaining publishers behind the gate** (row 7), observability, guide.

Signing is "behind the gate from the start" in the sense that matters for
correctness from step 1: no pass publishes a held zone. Step 4 adds the rate
limit, which is the smaller matter of a pass and an update sharing a serial.

## Must not regress

- The journal is durable before visible; a refused persist drops the working
  set, restores the serial, and answers waiters with the error.
- `StageBatch` unwinds a failed callback without dropping other writers' staged
  work.
- `commitTransportSignalLocked` republishes without a serial bump.
- The operator's `BumpSerial` / `BumpSerialOnly` is immediate.
- A wire DNS UPDATE is answered NOERROR only once its change is durable (RFC
  2136 section 3.5), and SERVFAIL when that cannot be established in time.
- No snapshot means SERVFAIL; Ready gates transfers and NOTIFY.
- The combiner's contributions are re-staged on every refresh.
- `parseconfig.go`'s publish uses the gate.
- A signing zone's first Ready snapshot has a signed apex SOA.
- Wrapping every change in its own transaction does not bring per-record
  publishing back: without `urgent`, a commit asks the gate.

## Not in this design

- **The identity zone's negative TTL**: #697, merged (the SOA minimum, 3600 to
  60 s), and #699 for the two places that still make it an hour.
- **tdns-mp#84**: an inbound hello promotes a mechanism that has no address,
  and the peer is never discovered again.
- **#698**: `ImrQuery` answers a cached denial with the proof SOA as the answer
  RRset.
- **A zone that signs can hold an unsigned snapshot before it is Ready today**,
  and queries follow the snapshot. Read, not tested. This design closes it for
  a zone created held and leaves the load path as it is.

## Tests

- **One serial.** A secondary of a zone created held sees SERVFAIL, then one
  transfer of the complete zone. This is the producer's half of #653. The
  harness that reproduced #653 is the resolver's half (a double of the
  secondary, serving SERVFAIL, an intermediate serial and the full zone to a
  resolver) and drives no producer, so it is a model for the double and not the
  test. The producer is `SetupAgentAutoZone`-shaped and goes through the real
  joins: held creation, the signing and notify options, `SignZone`, the
  `Publish*RR` calls through a real `UpdateQ` with `ZoneUpdaterEngine` running,
  and `TX-COMMIT` through the same queue. tdns cannot import tdns-mp, so the
  producer is the test's own here, and step 2 runs the same test against the
  real one. The observer is a secondary double that records every serial it can
  transfer. Before the change it sees the zone as SOA and NS and then a serial
  per record; after, SERVFAIL and then one serial, complete and signed.
- **Signed or nothing.** On a held zone that signs, a signing pass during the
  hold installs no snapshot; the commit's snapshot is signed, records staged
  before the keys resolved included; a commit that cannot sign installs nothing,
  reports it on its `Resp` and in the zone's status, and the zone stays
  SERVFAIL. After such a commit, an update's own publish installs nothing
  either. A signing pass once the policy is bound installs one signed snapshot,
  flips Ready and sends one NOTIFY; so does a repeated commit. The refusal does
  not set `DnssecError` and does not spin the publisher.
- **Not a draft.** A change staged in-process (`StageRRset`, `StageBatch`) on a
  zone created held is in the first snapshot: staged before the working set is
  seeded, after it, and after a commit that could not sign.
- **Coalescing.** A burst of N updates to a Ready zone is one publish when
  idle plus at most one per cadence; an urgent transaction publishes at once; a
  plain one on a busy zone waits for the gate.
- **The hold.** Two transactions: nothing publishes until the second commits.
  Another writer's change staged during the hold goes out with the commit. A
  direct `publishLocked` caller does not get through it, and the publish a hold
  stopped leaves the serial, `lastPublish` and the `ws*` flags as they were.
  The publisher does not spin on a held zone. A commit's `Resp` is answered in
  the caller for a first content and for an urgent hold, and by the gate's
  publish otherwise. A zone that opens no transaction publishes as before.
- **The limit.** A lost commit on a published zone releases with a WARN. On a
  never-published zone it does not, and the zone reports the error.
- **Waiters.** Answered by the publish that carries their change; answered
  with the error when the journal refuses it; answered when a working set is
  dropped; answered at once on an idle zone.
- **Refresh.** A change staged before a refresh is served after it. A refresh
  that meets an open transaction is refused, and succeeds after the commit.
- **Journal.** A transaction is one delta; `wsPersistDelta` survives a replayed
  update staged after a fresh one.
