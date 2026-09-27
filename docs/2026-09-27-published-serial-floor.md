# A restart must not reuse a served serial: the published-serial floor

**Written 2026-09-27.** For #655. Line references are to main at `2cf0ffa2`.

**Status:** proposal, revision 1, not implemented.

## Summary

- **What goes wrong.** After a restart, a primary can publish serials it
  already served before the restart, with different content. #655 shows two
  cases:
  - the zone came back below the serial it served;
  - the zone came back below it and then reached it again with a change (the
    DS engine's CDNSKEY).

  A secondary that already holds the serial never transfers. It keeps the
  old image until the primary passes it, and the change published at a reused
  serial reaches the secondary only by AXFR.
- **Why.** The only record of how far a zone got that survives a restart is
  the journal's tail. Most publishes write nothing to the journal: re-signs,
  DNSKEY publishes, serial bumps, signal synthesis. Only the zone updater's
  changes are journaled (§2). So the tail lags the served serial, and:
  - the replay lifts the serial past the tail, not past what was served (§2.1);
  - with an empty journal, nothing lifts it at all (§2.2);
  - the zone-file merge trusts a record of the served serial that is only
    written in `outbound-soa-serial: persist` mode (§2.3).
- **The fix already exists, for one mode.** `persist` mode records the served
  serial on every publish and restores one past it at first load. That is the
  floor #655 asks for. It is missing only because it is tied to a mode.
- **Proposal.**
  - Record the published serial for every zone that originates content, in
    every mode, before the new snapshot becomes visible.
  - At first load, lift the serial past that record whenever the record is
    newer than what the zone loaded.
  - Make the replay and the merge use the record as well.
  - Report the record in `zone journal status` (§3).
- **Cost.** One small database write per publish, which `persist` mode pays
  today. A restart burns one serial, and gives each secondary one transfer,
  when the zone published anything after its file was last written. That
  transfer is needed anyway: the content differs.

## 1. What goes wrong

Two observations are recorded on #655.

**2026-09-14.** The zone served `2026092659` before the restart. The replay
logged `file_serial=2026092545 last_published_serial=2026092656
serial=2026092657`, and the zone came back at `2026092657`. It had published
`2026092652` to `2026092659` since the previous restart, but only two of
those publishes reached the journal.

**2026-09-24.** Before the restart the zone served `2103839817`. The replay
landed at `2103839816`, and the first publish after the restart (a CDNSKEY,
#769) took the zone to `2103839817` again, with different content. The
secondary held `2103839817` already and never transferred. An IXFR from
`2103839817` at the next change would carry only that change, so the CDNSKEY
reaches the secondary only by AXFR.

The replay states the rule itself (`zone_delta_replay.go:191`): the published
serial must end up strictly greater than the highest serial the zone ever
published. There are two reasons:
- **Secondaries transfer only on a serial increase.** One below or equal to
  what they hold is ignored.
- **One serial must name one zone image.** `updateIxfrChainLocked` treats a
  serial with two contents as an error.

Why it matters now: after #769, a signed zone's first run on a new build
publishes a CDNSKEY, usually right after the upgrade restart. If that restart
reuses a serial, the primary and its secondaries disagree on the CDNSKEY at
one serial, and a parent that checks consistency across the nameservers
(RFC 9975 §3.1, as #769's scan does) refuses the CDS.

## 2. Why

**Only the zone updater journals.** `wsPersistDelta` is set in two places,
the two update appliers (`zone_updater.go:773` and `:1004`). A delta is then
written only if the change, minus derived records (NSEC, ZONEMD), is not
empty (`zone_mutation.go:641`). All other publishes advance the serial and
journal nothing:

- **Re-signs:** `SignZone` and the resigner. The RRs are identical and the
  RRSIGs are new (`zone_delta_store.go:70`).
- **DNSKEY publishes:** `publishDnskeyRRsLocked`. The DNSKEY set is rebuilt
  from the keystore at load, so journaling it would be redundant.
- **Serial-only publishes:** `zone bump`, and the `unixtime` and `persist`
  applications (`zone_delta_store.go:77`).
- **Transport signal synthesis, and the NSEC and ZONEMD repairs.**

The design is right about content: none of these needs replaying, because the
zone regenerates them. It is wrong about the serial. Every one of them hands
secondaries a new serial, and nothing durable records it.

**The journal's tail is not the served serial.** The tail is the ToSerial of
the last journaled change. Every publish after that is invisible to it. So is
anything published after `zone journal truncate` shortened the chain, or
after `zone journal purge` emptied it.

### 2.1 The replay compares against the tail

`ReplayPersistedDeltas` takes the floor from the tail
(`zone_delta_replay.go:128`):

```go
lastSerial := deltas[len(deltas)-1].ToSerial
...
if !serialNewer(zd.CurrentSerial, lastSerial) {
        zd.CurrentSerial = lastSerial
        ...publishWorkingSetLocked(..., true)
}
```

It then logs the tail as `last_published_serial` (`:226`). Both #655
observations show that label reporting a serial below the one served.

### 2.2 An empty journal lifts nothing

The replay returns before the floor when the journal is empty
(`zone_delta_replay.go:37`). An empty journal is the normal state after
`write-zone`/`sync`/`freeze`: the write drops every delta the file now holds
(`zone_utils.go:1372`). Then the zone re-signs, and publishes S+1 … S+k
without journaling any of them. On a restart:

- the file loads at S;
- the load signs it if it needs signing, which publishes S+1;
- there is no replay and no floor.

The zone serves S or S+1 again. The first change after that lands at or below
S+k, where #655's second case begins. `zone journal purge` gets to the same
state without a write. It adopts the file and empties the journal, so the
next restart has no floor.

The load itself publishes before the replay runs
(`completeFirstZonePolicyAndLoad`, `refreshengine.go:414`–`437`):
`InstallInitialSnapshot`, then the policy bind (which can publish the DNSKEY
set), then `signOnceAfterPolicyBind`. Each publish that bumps lands just past
the file's serial. So a floor applied inside the replay comes too late even
when the journal holds deltas: the load has already published reused serials
by then, and for a moment they are servable.

### 2.3 The merge relies on a record that is written only in one mode

`MergeJournalOverNewFile` lifts the merged zone past
`LoadOutgoingSerial`, described as "the durable record of what secondaries
have been handed" (`zone_merge.go:421`–`446`). That row is written only in
`persist` mode:
- by the publish (`zone_mutation.go:737`–`744`);
- by the refresh replacement (`:965`–`969`).

In the default mode, `keep`, the row is missing. `sql.ErrNoRows` is then read
as "nothing has been served yet", and the floor falls back to the file, the
journal's head and `CurrentSerial`. That is #655's wrong number again, on the
reload path.

### 2.4 `persist` mode already does the right thing

In `persist` mode:
- every publish writes the served serial to `OutgoingSerials`
  (`zone_mutation.go:740`);
- the first load reads it back and starts one past it when it is newer than
  what was loaded (`zone_mutation.go:863`–`908`).

That is the floor, at the right point: before any publish of the load.

The guide describes the mode as protection against serial regression on
restart (`guide/config-tdns-auth.md:899`). The schema comment says the same
(`db_schema.go:108`). Nothing about that protection is specific to one serial
scheme. A zone in `keep` or `unixtime` mode needs it just as much.

## 3. Proposal: record the published serial, and floor on it

### 3.1 The rule

After a restart, a zone that originates content never publishes a serial at
or below the highest serial it published before the restart.

A reload keeps this rule today. The refresh replacement lifts past
`max(served, file)` (`zone_mutation.go:952`–`964`, from #362). A restart
lacks only the served serial. The record supplies it.

The rule needs no operator step. A plain restart and a crash are covered
alike: the record is written before a serial becomes visible (§3.2), and it
is read at load before anything publishes (§3.3). The one exception is the
first restart onto a build with this change (§4).

### 3.2 The record

- **Where:** reuse `OutgoingSerials`, not a new table. It already means "the
  serial secondaries have been handed". The merge already reads it as that,
  and `persist` mode already writes it. A second table would hold the same
  number twice.
- **Which zones:** every zone with `zoneMayOriginateContent(zd)` and a KeyDB,
  in every `outbound-soa-serial` mode. Mirroring secondaries are unchanged:
  their row is deleted and their serial is upstream's (MUST-NOT-MODIFY).
- **When:** in `publishWorkingSetLocked`, after the delta has been persisted
  and before `updateIxfrChainLocked` and the snapshot swap
  (`zone_mutation.go:720`–`724`). That is the same durable-then-visible order
  the journal follows. Today the write runs after the swap (`:737`), so a
  crash between the two can leave a served serial unrecorded. Written but not
  served, which is the reverse, costs one extra serial at the next restart.
- **On failure:** log it and raise a zone error (`SetError`), then publish
  anyway. Refusing would stop re-signing, which takes the zone bogus when its
  signatures expire, a worse failure than a possible regression at a later
  restart. The next publish writes the current serial again, so one failed
  write corrects itself.
- **Not tied to `journal: active`.** The record is about serial
  monotonicity, not content. The kill-switch stops deltas, not this.
- **Redundant write:** the refresh replacement's own `persist` write
  (`zone_mutation.go:965`–`969`) is covered by the publish it performs and
  can go.

### 3.3 The floor at first load

This is the `persist` branch of `applyRefreshReplacementLocked`
(`zone_mutation.go:863`–`908`), for every mode. Read the record before the
load changes anything, exactly as that branch does:
- a missing row means nothing was recorded;
- any other read error fails the load, as it does today.

Then:

```
high := record
if the zone is file-backed and the journal's tail is newer than high:
        high = tail            // a deployment upgraded from a build without the record
if serialNewer(high, CurrentSerial):
        CurrentSerial = high + 1
```

- **Clean restarts burn nothing.** If nothing was published since the file
  was written, the record equals the file's serial and no lift happens.
- **An edited file is honoured.** A file whose serial is newer than the
  record, in RFC 1982 order, keeps that serial. So the RFC 1982 procedure
  for changing a serial scheme works as it does today.
- **Transferred zones:** an inline-signing secondary loads at the upstream's
  serial. It gets the same floor, and the same reason applies: its serial is
  its own space, as the refresh replacement already treats it (`:944`–`951`).

**The apex SOA signature.** The first load publishes before the DNSSEC policy
binds, so that publish cannot sign (`resolveSigningMaterialLocked`,
`zone_mutation.go:1134`). A lifted serial rewrites the SOA while it still
carries the file's RRSIG, which covers the old serial.
`snapshotContentIsServableLocked` counts any SOA RRSIG as signed, so:
- the zone can go Ready with that signature;
- `signOnceAfterPolicyBind` then skips signing;
- nothing replaces the signature until the next publish.

This proposal does not establish whether `persist` mode does that today. It
would, for every signed zone, once the lift applies to all modes. So
`setWorkingSetSOASerial` must drop the SOA's RRSIGs when:
- it changes the serial;
- the zone signs its own content;
- the publish has no signing material.

The zone then stays not Ready until the policy binds and
`signOnceAfterPolicyBind` signs it, which the servable gate already enforces.
Test T8 checks this.

### 3.4 `unixtime` moves forward only

Two places set `CurrentSerial = now` unconditionally:
- `initialLoadZone` (`refreshengine.go:242`);
- `applyOutboundSerialAfterRefresh` (`refresh_run.go:154`).

With a floor in place, "now" can be older than the lifted serial. That
happens when the clock steps back, or after a burst of publishes pushed the
serial past the wall clock (`nextOutboundSerial` then falls back to +1,
`zone_utils.go:1764`). Both places must keep the newer of the two, as
`nextOutboundSerial` does.

### 3.5 The replay and the merge

- **Replay:** the floor becomes the newer of the record and the tail. After
  §3.3 this does not fire at first load, since the load has already lifted
  past both. It covers a reload, and a record that could not be written. Log
  both numbers under honest names, `journal_tail_serial` and
  `published_serial`, instead of `last_published_serial`.
- **Merge:** no code change. The row it reads now exists in every mode.
  Update its comment to say so.

### 3.6 `zone journal status`

Add `PublishedSerial` (the record) next to `HeadSerial` in `ZoneJournalInfo`
(`zone_journal.go:39`), and print it. If it is ahead of the file's serial, a
restart will lift past it. Say that in the status output, so an operator can
see before a restart what serial the zone will come back at. #655 asks for
this.

### 3.7 What `persist` then means

At a restart, all three modes floor on the record. `persist`'s restore logic
(`zone_mutation.go:901`, `refreshengine.go:246`, `refresh_run.go:158`) then
finds nothing newer than the served serial and never fires. The value stays
accepted. The guide should say that the restart protection now applies to
every mode. Whether to deprecate `persist` is a separate decision (§9).

## 4. Upgrade, and until then

- **The first restart onto a build with this change still lacks the record**
  for `keep` and `unixtime` zones. The floor then falls back to the journal's
  tail, which is today's behaviour. The record is written from the first
  publish on.
- **Before that restart, and before any planned restart until then:** run
  `tdns-cli auth zone sync -z <zone> --force` immediately before stopping.
  This writes the published snapshot, so the file's serial is the served
  serial, the journal is emptied through it, and the restart loads at the
  serial last served. It is safe as long as nothing publishes between the
  write and the stop.

## 5. Stages

One PR, two commits.

1. **The record and the floor.**
   - `publishWorkingSetLocked`: write in every mode, before the swap.
   - `applyRefreshReplacementLocked`: the first-load floor for every mode,
     with the journal tail as the pre-upgrade fallback.
   - `setWorkingSetSOASerial`: the dropped stale SOA RRSIG.
   - The two `unixtime` assignments: forward only.

   This commit alone is enough for both of the cases in #655.
2. **Visibility.**
   - The replay's floor and log fields.
   - The merge comment.
   - `zone journal status` and its CLI output.
   - The guide paragraph on `outbound-soa-serial`.

## 6. Alternatives

- **Journal serial-only publishes as empty deltas** (#655's second
  suggestion). Rejected:
  - Every re-sign would grow the journal, which it is explicitly designed not
    to do (`zone_delta_store.go:70`).
  - The chain would be full of rows that `zone journal list`, `truncate` and
    `purge` show an operator, none of which change content.
  - `purge` and `truncate` would still lower the floor.
  - A zone with `journal: active: false` would have none at all.
  - The merge's re-anchor would reduce the chain to one delta and lose the
    history anyway.
- **Floor inside the replay only** (#655's first suggestion, placed where the
  issue places it). Not enough:
  - it misses the empty journal (§2.2);
  - it misses the publishes the load makes before the replay runs.

  §3.5 keeps it as a second line of defence.
- **A new table for the record.** It would hold the same number as
  `OutgoingSerials` (§3.2).
- **Write the zone file on shutdown.** A crash skips it, and a crash is the
  restart that needs it most.
- **Default to `unixtime`.** It changes every deployment's serial scheme to
  fix a bookkeeping gap, and still needs §3.4.

## 7. Relation to other work

- **#769 (CDNSKEY with the CDS):** its first-run publish is what turns a
  serial regression into different content at the same serial (§1).
- **#362 (reload floor):** the refresh replacement's `max(served, file) + 1`
  is the same rule for a reload. This proposal gives a restart the served
  serial that a reload already has.
- **Journal overlay on transfer (#732, #746):** an overlay zone journals
  from the serial it serves and skips the replay. It gets the first-load
  floor like any other originating zone.
- **Secondary serial mirroring (MUST-NOT-MODIFY):** unchanged. A mirror
  writes no record, and its row is still deleted.
- **Derived apps:** `zoneMayOriginateContent` is true for every zone outside
  tdns-auth (`zone_origination.go:46`), so tdns-agent and tdns-mp zones get
  the record and the floor too (§9).

## 8. Tests

Unit tests, in the files that already cover each path:

- **`zone_delta_roundtrip_test.go`**
  - **T1:** publish a journaled change (N), then two unjournaled publishes
    (N+1, N+2). Restart and replay. The served serial is newer than N+2. This
    is #655's own test.
  - **T2:** as T1, with an empty journal (a zone write at S, then two
    unjournaled publishes). The first served serial after the load is newer
    than S+2.
  - **T3:** after the replay, a publish that changes content lands on a
    serial never served before the restart. This is the test the 2026-09-24
    comment asks for.
- **`first_load_post_refresh_test.go`** (extend the
  `TestFirstLoadRestoresThePersistedSerial…` tests to all three modes)
  - **T4:** the floor applies in `keep` and `unixtime` as in `persist`.
  - **T5:** a clean restart, with the record equal to the file's serial,
    lifts nothing.
  - **T6:** RFC 1982 order: a file serial newer than the record by
    wrap-around is kept.
  - **T7:** a mirroring secondary writes no record and gets no floor.
  - **T8:** a signed zone whose first-load serial was lifted does not go
    Ready with an SOA RRSIG over the old serial. Once Ready, its SOA RRSIG
    validates against the served SOA.
  - **T9:** in `unixtime` mode, with the record ahead of the clock, the
    serial never moves backwards.
- **`zone_merge_test.go`**
  - **T10:** in `keep` mode, a merged zone lands past the record.
- **`zone_journal_test.go`**
  - **T11:** `zone journal status` reports the record and the tail.
  - **T12:** after a failed record write, the publish goes ahead, the zone
    error is set, and the next publish writes the record.
  - **T13:** with no record but a journal tail (a pre-upgrade database), the
    floor is the tail.

**Test deployment:** a signed primary with one secondary:
- publish unjournaled changes (re-signs) past the last journaled one;
- restart the primary;
- publish a content change.

The secondary must transfer it without an AXFR being forced.

## 9. Questions

1. **Deprecate `persist`?** After this change it differs from `keep` in
   nothing an operator can observe at a restart. The recommendation is to
   keep it accepted and documented as equivalent for now, and decide later.
2. **Derived apps.** tdns-mp zones would get the floor in every mode (§7).
   Is there a zone there that must follow its upstream's serial across a
   restart? If so, tdns-mp opts out through its own origination predicate,
   not through a mode.
3. **An operator who wants a lower serial on purpose.** The RFC 1982
   procedure works through the floor, because each step is "newer". A plain
   step backwards is refused, silently lifted past the record. The
   recommendation is no new command in this change. Such an operator also
   has to force every secondary to AXFR, which is a manual procedure in any
   case.

## 10. Not in scope

- **A zone that moves to tdns from another signer.** Its serial can go
  backwards at the move, when the zone file tdns loads carries a serial below
  the one the previous signer published. This proposal does not touch that
  case. The record holds only serials this server published, and for such a
  zone it has none. Two ways to handle it:
  - the operator gives the file a serial past the old signer's before the
    move;
  - the load asks the zone's served nameservers for their SOA and uses that
    as a floor.

  The second is a separate design.
- **A zone deleted and created again under the same name.** The record
  survives the delete (only mirrors delete it), so the new zone starts past
  the old one's serial. That is harmless, and helpful to secondaries that
  still hold the old zone. This proposal does not change it.
