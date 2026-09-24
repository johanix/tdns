# The journal over every transfer: a signing secondary keeps its own records

**Written 2026-09-24.** For #732. Line references are to main at `ff4c4b1a`.

**Status:** merged as #746, after an external review (sound) and a re-review
(merge). Implemented in #747; §11 records what the implementation settled.
L1 has not been run. The review is applied: the overlay is limited to
the server's own records (Q1, decided), the journal read, publish and
compaction are pinned to one lock (4.3, 4.4), and Q2 and Q3 are answered
(§10).

## Summary

- **What goes wrong.** A signing secondary adds records of its own on top of
  what it transfers: the DS engine's CDS, delegation sync's CSYNC, anything
  else applied through the zone updater. A full transfer replaces the zone and
  drops them. The CDS is the serious one: under `rollover.method: none` (the
  default) a CDS once lost is not published again (§1).
- **The journal already holds those records.** Every zone-updater change is
  written to the delta journal, on a secondary as on a primary. But on a
  secondary nothing reads the journal back:
  - a transfer never consults it;
  - the replay at startup refuses it once the upstream has moved on, and
    raises a warning that the zone file "has been edited or replaced", on a
    zone with no file (§2).
- **A second defect, found while checking this.** The journal anchors to the
  upstream's serial, while a signing secondary publishes in its own serial
  space. When the two disagree, the next local change is refused outright, so
  no CDS or CSYNC can be published. Confirmed for an empty journal behind an
  upstream whose serial is ahead and, with a stand-in for a restart, for a
  journal left ahead of the served serial (§3).
- **Proposal: the journal as an overlay.** On a signing secondary the journal
  holds exactly what this server added to its upstream's zone, because
  transfers are never journalled. So:
  - apply the net effect of its own records (CDS, CDNSKEY, CSYNC) to every
    full transfer, before the one publish that transfer makes;
  - keep the journal in the zone's own serial space, and compact it at every
    full transfer;
  - skip the file-oriented replay and merge for such zones (§4).

  It keeps those records across transfers and restarts (#732), and ends the
  refused publishes. Local edits to the upstream's data are still lost at a
  full transfer, as today.
- **Size:** about 165 lines of non-test code and 450–550 of tests, in one PR
  (§9). It touches neither the keystore nor DS intent, so it is independent of
  key lifecycle ownership (KLO).

## 1. What is lost, and what that costs

A full transfer rebuilds the working set from the transferred data
(`applyRefreshReplacementLocked`, `v2/zone_mutation.go:811`) and then adds back
what `CollectDynamicRRs` returns (`v2/zone_utils.go:2054`): the DNSKEY RRset and
the apex SIG(0) KEY from the keystore, and the transport signals from the
served zone. The CDS is added back only for an owned multi-provider zone
(`ownedZoneCDS`, `v2/zone_utils.go:2090`). Nothing else the server added
survives.

"Full transfer" covers more than it sounds like:

- an upstream that answers IXFR with the whole zone, for example one serving a
  zone file with no journal;
- the fallback from IXFR to AXFR;
- a forced retransfer;
- `no-request-ixfr`;
- the first transfer after a restart.

An applied IXFR keeps them, since it is a delta on the published snapshot.

What it costs, per record:

| Record | Put there by | After a full transfer |
|---|---|---|
| CDS, `rollover.method: none` | the DS engine, when delegation sync asks (`ensureCDS`, `v2/ds_engine.go:352`) | **gone for good.** `followKeysWithCDS` leaves a zone that serves no CDS alone (`v2/ds_engine.go:448`), and nothing else asks again: #742's refresh sync never carries DS. Only a delegation sync with a DS difference over NOTIFY brings it back. |
| CDS, `multi-ds` | the rollover engine's NOTIFY push, through the DS engine | gone until the next push. The rollover tick already logs the gap (`v2/ksk_rollover_automated.go:265`). |
| CSYNC | delegation sync's NOTIFY scheme, with `allow-updates` (#557) | gone. Harmless once the parent has read it. |
| SIG(0) KEY, DNSKEY, transport signals | the keystore, the served zone | kept, by `CollectDynamicRRs` |

## 2. Why the journal does not bring them back

**Written: yes.** The DS engine publishes through an internal ZONE-UPDATE
(`publishCDSAndWait`, `v2/ds_engine.go:489`). The publish writes the change to
the journal (`v2/zone_mutation.go:584`) for any zone, gated only by
`journal: active: false`. Only zone-updater changes are journalled
(`wsPersistDelta` is set only in `v2/zone_updater.go:742` and `:948`). On a
secondary the journal therefore holds exactly what this server added to its
upstream's zone.

**Read back: only for a zone loaded from a file.** The journal is replayed at
first load (`replayZoneDeltasOnLoad`, `v2/refreshengine.go:437`), and merged
when a primary reloads a changed file (`MergeJournalOverNewFile`,
`v2/zone_merge.go:358`). That is why a signing primary keeps its CDS. The
transfer path does not consult it (`v2/zone_utils.go:1203`).

**At restart it is refused.**
- The journal's first delta anchors to `zd.fileSerial` (`v2/zone_mutation.go:629`),
  and a transfer sets that to the upstream's serial (`v2/dnsutils.go:287`,
  `v2/zone_mutation.go:839`).
- The replay requires the chain to start at the serial just loaded
  (`validateDeltaChain`, `v2/zone_delta_replay.go:268`).
- Once the upstream has moved on, the whole journal is refused, and the zone
  gets a ConfigWarning that the zone file "has been edited or replaced"
  (`v2/refreshengine.go:648`).

The comment at `v2/zone_mutation.go:909-914` says nothing anchors a journal to a
transferred zone's received serial. The publish path does exactly that.

Checked with a scratch test (inline-signing secondary with a keystore, test
upstream, not committed):

| Step | fileSerial | served | CDS served | journal |
|---|---|---|---|---|
| start | 7 | 8 | 0 | empty |
| CDS published through the zone updater | 7 | 9 | 1 | `7 → 9: add CDS` |
| AXFR, upstream at 20 | 20 | 10 | **0** | `7 → 9: add CDS` (still there) |
| replay, as at restart | | | | refused: "deltas start at serial 7, file is at serial 20" |

## 3. A second defect: local changes refused

The publish path refuses a change it cannot journal, and the zone "continues to
serve its previous content" (`v2/zone_mutation.go:649-673`). `PersistZoneDelta`
refuses a delta that does not advance the serial (`v2/zone_delta_store.go:117`).
A signing secondary's served serial is its own, not the upstream's
(`v2/zone_mutation.go:909`), so the two go wrong together:

- **Empty journal, upstream ahead.** The delta runs from `fileSerial` (the
  upstream's) to the next served serial. Scratch test: AXFR from an upstream at
  2026092401, served serial 9, then a CDS publish: refused,
  "2026092401 -> 10". An upstream whose serial runs ahead of the signer's does
  this; a date-based serial does it at the first day boundary. It lasts until
  the served serial overtakes the upstream's again.
- **Journal tail ahead of the served serial.** The delta runs from the
  journal's tail. After a restart in the default `outbound-soa-serial: keep`,
  the first load serves the upstream's serial (`v2/zone_mutation.go:843-844`).
  That is below the tail whenever the signer's own serial had run ahead. The
  scratch test with a fresh zone on the same keystore as a stand-in for a
  restart: refused, "11 -> 9". A real restart is still to be run.

Either way the DS engine cannot publish a CDS, and delegation sync cannot
publish a CSYNC. A SIG(0) KEY already served is not taken away:
`CollectDynamicRRs` puts the keystore's KEY back at every refresh, so #742's
UPDATE scheme keeps its key. A newly created key waits for the next refresh.
CDS and CSYNC have no second source.

## 4. Proposal: the journal as the zone's overlay

### 4.1 Which zones

An **overlay zone** is one whose content arrives by transfer and which adds
records of its own:

- `AppTypeAuth`, as #742's predicate: tdns-auth and tdns-signer;
- `type: secondary`;
- `inline-signing`, which is what lets a secondary originate content
  (`zoneMayOriginateContent`, `v2/zone_origination.go:42`);
- not `multi-provider`. There the combiner's zone and KLO's arrow 1
  (`ownedZoneCDS`) decide the CDS, and the journal could hold an older one.

Primaries, plain secondaries, multi-provider zones and other apps keep today's
behaviour.

The overlay needs the journal. With `journal: active: false` nothing is
journalled, so nothing is overlaid and the CDS is lost at a full transfer as
today; §3 does not occur either.

### 4.2 What is overlaid

**The server's own records only** (Q1, decided 2026-09-24): CDS, CDNSKEY and
CSYNC at the apex. These are the records this server originates for its
parent, and nothing else puts them back.

- **An allowlist, not a filter.** Every other type in the journal is left out.
  That covers:
  - DNSKEY and KEY, which `CollectDynamicRRs` supplies from the keystore. An
    overlay of the journal's copy could bring back a key the keystore has
    since retired;
  - derived and serial records;
  - local edits to the upstream's data, through the API or DNS UPDATE. These
    stay as today: lost at a full transfer, kept across an applied IXFR. Making
    them survive every transfer would be a new feature, not #732.
- **CDNSKEY is not generated today** (#730 D4). It is on the list so that a
  later DS-engine change that journals one is covered without another change
  here.
- **Net effect.** One instruction per record: the last one wins, compared as
  `rrKey` does (`v2/zone_merge.go`: owner, type, canonical RDATA, TTL ignored).
  Three CDS publishes overlay as one CDS, not as three adds and two deletes.
- **The server's copy wins for these types.** Its journalled deletes remove
  the transfer's record, and its adds are applied. No conflict policy is
  involved: the zone's `on-conflict-*` option stays a primary's file-merge
  setting. When the transfer carried a record of these types that the overlay
  removed, one log line per zone names it (Q2).

### 4.3 Where

Inside `applyRefreshReplacementLocked`, before the working set is built from
the transferred data (`v2/zone_mutation.go:930`). The overlay is applied to
the scratch zone with the IXFR applier's primitives (`applyIxfrRemove`,
`applyIxfrAdd`, `v2/ixfr_in.go:351, 436`). An add already present and a
delete of an absent record are skipped first, since those primitives refuse
both.

- **One publish.** The overlaid records are part of the content the
  replacement publishes. There is no window without the CDS, no second serial
  and no second NOTIFY: the costs #514 removed from this path.
- **Signed with the rest.** A full replacement on a signing zone signs
  everything (`wsNeedsFullSign`, `v2/zone_mutation.go:978-982`).
- **One lock for all of it.** Read the journal, apply the overlay, publish
  (`publishWorkingSetLocked`), compact (4.4): all inside
  `applyRefreshReplacementLocked`, under the `zd.mu` its caller already holds.
  Journal writes happen under the same lock (`v2/zone_mutation.go:576-583`),
  so no local change can fall between the read and the compaction.
- **Not for an applied IXFR.** Its scratch zone is the published snapshot plus
  the delta, so it already carries the overlay. Overlaying it again could
  reach owners outside the touched set, which that path signs alone
  (`wsSignOwners`). A whole-zone answer to an IXFR request is not an applied
  IXFR: `adoptFullZoneRRs` (`v2/ixfr_in.go:782`) leaves `ixfrDerived` unset,
  so it is a full replacement and gets the overlay.

### 4.4 The journal in the zone's own serial space

For an overlay zone the journal is a set of instructions, not a chain from a
file. Its serials only order its rows. Two changes follow:

- **A local change is journalled from the served serial it was computed from**
  (`oldSnap.Serial`), not from `fileSerial` or the journal's tail
  (`v2/zone_mutation.go:629-646`). The delta then always advances, which is
  what ends §3.
- **Every full replacement compacts the journal**, right after its publish,
  under the same lock (4.3).
  - **The result:** one delta holding the net effect of the overlaid types
    (4.2), from `CurrentSerial`−1 to `CurrentSerial`, written with
    `ReplaceZoneJournal` (`v2/zone_delta_store.go:472`) and bounded by the row
    id the overlay read.
  - **When nothing is left,** the journal is cleared with
    `DeleteZoneDeltasThroughID`, bounded the same way. `ReplaceZoneJournal`
    refuses an empty replacement (`v2/zone_delta_store.go:506`).
  - **What is kept:**
    - adds, even an add the transfer already has. That is local intent: if
      the upstream later withdraws the same record, the next full transfer
      must put it back;
    - deletes of records the transfer has.
  - **What is dropped:**
    - deletes of records the transfer does not have. They do nothing now, and
      must not delete the record if the upstream adds it again later;
    - rows of every other type, which the transfer has superseded.

  This bounds the journal, and no old row can collide with a later serial. A
  first load compacts the same way. It anchors to `CurrentSerial` whether or
  not that publish installed a snapshot yet.

### 4.5 First load and restart

For an overlay zone, `replayZoneDeltasOnLoad` and the reload arm of
`reconcileZoneFileWithJournal` (`v2/zone_utils.go:798`) do not replay or
merge. The replacement has already applied the overlay, whether the content
came from the first transfer or from a persisted copy at first bind
(`adoptPersistedCopyAtFirstBind`, `v2/zone_utils.go:71`). Applying the overlay
to a copy that already holds it changes nothing (§4.3). The false
ConfigWarning goes with the replay.

### 4.6 `zone journal status`

`Replayable` and its diagnosis (`v2/zone_journal.go:48`) describe a chain from
a file. For an overlay zone they say instead that the journal is applied to
every transfer. `zone journal purge` keeps its meaning: the zone's own records
disappear at the next full transfer. For a CDS under `none` that is the case
§1 describes, so the status output should warn about it.

## 5. What changes

| Zone | Today | With this |
|---|---|---|
| tdns-auth or tdns-signer, inline-signing secondary | CDS and CSYNC lost on full transfer; journal refused at restart with a false warning; local changes refused when the serials disagree | CDS, CDNSKEY and CSYNC kept across transfers and restarts; local changes accepted; local edits to the upstream's data still lost at a full transfer |
| primary (signed or not) | journal replayed or merged over its file | unchanged |
| plain secondary | nothing journalled | unchanged |
| multi-provider zone | arrow 1 restores an owned zone's CDS | unchanged |
| tdns-agent and other apps | as today | unchanged |

## 6. Alternatives

- **A. Carry the served CDS over a full transfer**, in `CollectDynamicRRs`, as
  it does for transport signals. About 20 lines. It covers the running server
  only: at restart the zone is transferred afresh, so it depends on a
  persisted copy, and a config-declared secondary has none. It fixes neither
  §3 nor the false warning.
- **B. A keystore table holding the last CDS the DS engine published**,
  restored in `CollectDynamicRRs`. It survives restart, but it duplicates the
  journal for one record type. It adds a table to the keystore KLO is
  redesigning, and leaves CSYNC and §3 as they are.
- **C. Recompute the CDS from the DS model at every transfer**, which is what
  #732's text suggests. Under `none` a CDS is served only once delegation
  sync has asked, so recomputing needs B's stored state anyway. It can also
  produce a CDS other than the one the parent was told about.

The journal is already written, already transactional, and already what a
primary relies on. What is missing is reading it back.

## 7. Relation to other work

- **KLO.** Independent: nothing here reads DS intent or touches the keystore.
  Multi-provider zones are excluded (4.1), so arrow 1 stays the only thing
  that sets an owned zone's CDS. #734 §8 had tied #732 to arrow 1 because of
  the recompute options (B, C). The overlay needs no such tie.
- **Pure signer (#730).** A pure signer drops API and UPDATE edits. Its journal
  then holds only the DS engine's and delegation sync's records, and this is
  still needed.
- **#742.** A signing secondary now syncs NS and glue after every transfer,
  over UPDATE or API. The SIG(0) KEY that UPDATE needs is kept by
  `CollectDynamicRRs`, even when §3 refuses its publish (§3).
- **#557.** Unchanged. The CSYNC is overlaid like any local record, but it is
  still published only with `allow-updates`.
- **#736.** Unchanged. Under `none` nothing publishes a first CDS on its own.
  This only keeps the one a delegation sync did publish.
- **#730 D2.** Its suggestion, restoring the CDS in `CollectDynamicRRs`, is
  alternative A, superseded here. D3 (#557) and D4 (CDNSKEY) stay as they are.
- **`childsync` on a signing secondary.** Out of scope, same kind of loss.
  `SetupZoneSync` publishes the DSYNC advertisement into the zone's own copy
  (`v2/zone_utils.go:1933`), and a full transfer drops it. The code warns
  about this only for an agent secondary. The childsync-proxy design (§3.1)
  says where a secondary's advertisement belongs. DSYNC is not on the
  allowlist (4.2).

## 8. Tests

| # | Test |
|---|---|
| T1 | A CDS published on an inline-signing secondary survives an AXFR from an upstream without one; the transfer publishes once (§2's table, inverted). |
| T2 | Restart stand-in: a new zone on the same keystore, first loaded by transfer from an upstream that has moved on, serves the CDS; no ConfigWarning. L1 is the real restart. |
| T3 | Empty journal, upstream serial ahead of the served one: a local change is applied (§3, first case, inverted). |
| T4 | Journal tail ahead of the served serial: a local change is applied (§3, second case, inverted). |
| T5 | Net effect: three CDS publishes, one AXFR: one CDS served, and the journal is one delta with one add. |
| T6 | Allowlist: a DNSKEY or KEY in the journal that the keystore no longer has is not overlaid, and a journalled local edit of an upstream A record is not overlaid either. |
| T7 | The server's copy wins for its own types: an upstream CDS is replaced by the journal's, and logged. A local delete of an upstream A record does not survive a full transfer. |
| T8 | Unchanged: primary reload merge and replay (the existing `zone_reload_reconcile` tests), plain secondary, multi-provider zone, non-auth app. |
| T9 | IXFR: the CDS survives as today, no overlay applied, only the touched owners re-signed. |
| T10 | Persisted copy at first bind: the overlay is not doubled; no ConfigWarning. |
| T11 | Compaction with an empty net effect clears the journal (`DeleteZoneDeltasThroughID`), and one with rows of other types drops them. |
| T12 | An add the transfer already has is kept in the compacted journal, and the record is back after the upstream withdraws it. |
| T13 | `journal: active: false`: nothing is overlaid, and nothing is refused. |
| L1 | Live: a signing secondary behind an upstream that answers IXFR with the whole zone. The CDS stays across upstream changes and across a restart after one, and the DS engine's publishes succeed after the restart. |

The harness exists: `ixSigningSecondary`, `ixfrTestPrimary` and a real keystore
(`newTestKeyDB`), as in §2's scratch test.

## 9. Size

| Part | Non-test lines |
|---|---|
| overlay-zone predicate (4.1) | ~10 |
| net effect of the allowlisted types, log (4.2) | ~35 |
| apply to the scratch zone in the replacement (4.3) | ~40 |
| journalled from the served serial (4.4) | ~10 |
| compaction after a full replacement and at first load (4.4) | ~40 |
| skip replay and merge (4.5) | ~10 |
| `zone journal status` (4.6), and the comment at `v2/zone_mutation.go:909` | ~20 |
| **total** | **~165** |

Tests: T1–T13, about 450–550 lines.

One PR. §3's fix and the overlay depend on each other: without compaction,
journalling from the served serial collides with old rows after a restart; and
without the overlay, compacting would discard what the journal is for.

## 10. Decided

- **Q1 (2026-09-24).** Overlay only the server's own records: CDS, CDNSKEY
  and CSYNC (4.2). A local change to the upstream's own data does not survive
  a full transfer, as today. The external review argued for this: the primary's
  `on-conflict-db-wins` default would make a local delete of an upstream
  record survive every later transfer. That would be a new feature, not #732.
- **Q2.** No ConfigWarning. A primary's warning points at a `.rejected` file
  the operator can edit. Here there is no such file, and the warning would
  repeat at every full transfer. One log line per zone, and
  `zone journal status`.
- **Q3.** Overlay the CSYNC, as a primary keeps it. A stale CSYNC is harmless,
  and the next NS sync replaces it.

## 11. Amendment, 2026-09-24: what the implementation settled

Implemented in #747. These points were not settled above. Johan answered the
first four; the last two are the implementation's choices.

- **`zone journal purge` asks for `--force` on an overlay zone.** The journal
  is the only copy of the zone's own records, as a replaying journal is for a
  primary. The refusal says what purging costs and does not point at
  `zone sync`. `zone journal status` reports the journal as applied to every
  full transfer, with the same warning, in place of the replay lines (4.6).
- **`journal: active: false` with rows from before the switch.** They are
  still overlaid and compacted. Reads are not gated, as the replay is not, and
  the primary's merge rewrites the journal whatever the switch says.
- **No compaction after a refused publish.** Compaction follows a publish that
  installed the content, or one that an open transaction holds staged (a zone
  created held, at its first load). A publish refused because the zone cannot
  be signed, its chain cannot be repaired, it has no apex or it is no longer
  live leaves the journal as it was, for the next full replacement.
- **`zone write`, `zone sync` and freeze keep an overlay zone's journal.**
  `WriteZone` drops a primary's journalled changes once its file holds them. An
  overlay zone's journal is not relative to a file, and dropping it would take
  the zone's own records out at the next full transfer.
- **An unreadable journal row** is not applied, and the journal is not
  compacted, since compacting would drop it.
- **The Q2 log line** is at Warn.

The tests are in `v2/journal_overlay_test.go`: T1–T13, a CSYNC through the
same path as the CDS, an unreadable row, `zone journal status` and purge, and
`zone write`.
