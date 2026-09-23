# The journal over every transfer: a signing secondary keeps its own records

**Written 2026-09-24.** For #732. Line references are to main at `ff4c4b1a`.

**Status:** proposal. Nothing implemented.

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
  space. When the two disagree, the next local change is refused outright: no
  CDS, no CSYNC, no SIG(0) KEY. Confirmed for an empty journal behind an
  upstream whose serial is ahead and, with a stand-in for a restart, for a
  journal left ahead of the served serial (§3).
- **Proposal: the journal as an overlay.** On a signing secondary the journal
  holds exactly what this server added to its upstream's zone, because
  transfers are never journalled. So:
  - apply its net effect to every full transfer, before the one publish that
    transfer makes;
  - keep the journal in the zone's own serial space, and compact it at every
    full transfer;
  - skip the file-oriented replay and merge for such zones (§4).

  It keeps the records across transfers and restarts (#732), and ends the
  refused publishes.
- **Size:** about 200 lines of non-test code and 450–550 of tests, in one PR
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

Either way the DS engine cannot publish a CDS, delegation sync cannot publish a
CSYNC, and the SIG(0) KEY cannot be published.

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

### 4.2 What is overlaid

The journal's **net effect**, not its history:

- **Net effect.** One instruction per record: the last one wins, compared as
  `rrKey` does (`v2/zone_merge.go`: owner, type, canonical RDATA, TTL ignored).
  Three CDS publishes overlay as one CDS, not as three adds and two deletes.
- **Filtered.** Types that have a source of their own are left out, whatever
  the journal says about them:
  - the types `CollectDynamicRRs` supplies from the keystore or the served
    zone (DNSKEY, KEY, transport signals);
  - derived and serial records (SOA, RRSIG, NSEC, NSEC3, NSEC3PARAM, a managed
    ZONEMD). Most never reach the journal.

  Without this filter the overlay could bring back a DNSKEY or SIG(0) KEY the
  keystore has since retired.
- **Conflicts, as a primary's merge decides them.** A conflict is a record the
  upstream has and the journal deletes (`findMergeConflicts`,
  `v2/zone_merge.go:123`). The zone's existing option decides it
  (`applicableInstructions`, `v2/zone_merge.go:551`):
  - `on-conflict-db-wins` (the default): the local delete stands;
  - `on-conflict-zonefile-wins`: the upstream's record stays.

  There is no zone file to write a `.rejected` artefact beside, so the
  conflicts are logged, one line per zone with the records.

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
- **The journal is read under `zd.mu`.** Journal writes happen under the same
  lock (`v2/zone_mutation.go:576-583`), so no local change can fall between
  the read and the replacement.
- **Not for an applied IXFR.** Its scratch zone is the published snapshot plus
  the delta, so it already carries the overlay. Overlaying it again could
  reach owners outside the touched set, which that path signs alone
  (`wsSignOwners`).

### 4.4 The journal in the zone's own serial space

For an overlay zone the journal is a set of instructions, not a chain from a
file. Its serials only order its rows. Two changes follow:

- **A local change is journalled from the served serial it was computed from**
  (`oldSnap.Serial`), not from `fileSerial` or the journal's tail
  (`v2/zone_mutation.go:629-646`). The delta then always advances, which is
  what ends §3.
- **Every full replacement compacts the journal**, after its publish. The
  journal becomes one delta holding the net effect (§4.2) from served−1 to
  served (`ReplaceZoneJournal`, `v2/zone_delta_store.go:472`, bounded by the
  row id it read), or it is cleared when nothing is left. Deletes of records
  the upstream no longer has are dropped: they do nothing now, and must not
  delete the record if the upstream adds it again later. This bounds the
  journal, and no old row can collide with a later serial.

A first load whose publish installs nothing yet compacts where the replay runs
today, after the policy binds (`completeFirstZonePolicyAndLoad`,
`v2/refreshengine.go:413`).

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
| tdns-auth or tdns-signer, inline-signing secondary | own records lost on full transfer; journal refused at restart with a false warning; local changes refused when the serials disagree | own records kept across transfers and restarts; local changes accepted |
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
  `CollectDynamicRRs`, but §3 could refuse its first publish.
- **#557.** Unchanged. The CSYNC is overlaid like any local record, but it is
  still published only with `allow-updates`.
- **#736.** Unchanged. Under `none` nothing publishes a first CDS on its own.
  This only keeps the one a delegation sync did publish.

## 8. Tests

| # | Test |
|---|---|
| T1 | A CDS published on an inline-signing secondary survives an AXFR from an upstream without one; the transfer publishes once (§2's table, inverted). |
| T2 | Restart: a new zone on the same keystore, first loaded by transfer from an upstream that has moved on, serves the CDS; no ConfigWarning. |
| T3 | Empty journal, upstream serial ahead of the served one: a local change is applied (§3, first case, inverted). |
| T4 | Journal tail ahead of the served serial: a local change is applied (§3, second case, inverted). |
| T5 | Net effect: three CDS publishes, one AXFR: one CDS served, and the journal is one delta with one add. |
| T6 | Filter: a DNSKEY or KEY in the journal that the keystore no longer has is not overlaid. |
| T7 | Conflict: a local delete of an upstream record stands under db-wins, the upstream's record stays under zonefile-wins; both logged. |
| T8 | Unchanged: primary reload merge and replay (the existing `zone_reload_reconcile` tests), plain secondary, multi-provider zone, non-auth app. |
| T9 | IXFR: the CDS survives as today, no overlay applied, only the touched owners re-signed. |
| T10 | Persisted copy at first bind: the overlay is not doubled; no ConfigWarning. |
| L1 | Live: a signing secondary behind an upstream that answers IXFR with the whole zone. The CDS stays across upstream changes and across a restart after one, and the DS engine's publishes succeed after the restart. |

The harness exists: `ixSigningSecondary`, `ixfrTestPrimary` and a real keystore
(`newTestKeyDB`), as in §2's scratch test.

## 9. Size

| Part | Non-test lines |
|---|---|
| overlay-zone predicate (4.1) | ~10 |
| net effect, filter, conflicts, log (4.2), reusing `findMergeConflicts` and `applicableInstructions` | ~70 |
| apply to the scratch zone in the replacement (4.3) | ~40 |
| journalled from the served serial (4.4) | ~10 |
| compaction after a full replacement and at first load (4.4) | ~40 |
| skip replay and merge (4.5) | ~10 |
| `zone journal status` (4.6), and the comment at `v2/zone_mutation.go:909` | ~20 |
| **total** | **~200** |

Tests: T1–T10, about 450–550 lines.

One PR. §3's fix and the overlay depend on each other: without compaction,
journalling from the served serial collides with old rows after a restart; and
without the overlay, compacting would discard what the journal is for.

## 10. Open questions

- **Q1.** For an overlay zone, should a local change to the upstream's own data
  win (db-wins, the default, as for a primary)? Or should the upstream always
  win for types the server does not originate? This proposes the existing
  option, so an operator can choose.
- **Q2.** Should the conflict log also become a ConfigWarning, as a primary's
  merge makes it (`v2/refreshengine.go:627, 636`)? It would repeat at every full
  transfer while the conflict lasts.
- **Q3.** Should a CSYNC be overlaid at all, or dropped once the parent has
  read it? Overlaying keeps the primary's behaviour. A stale CSYNC is
  harmless, and the next NS sync replaces it.
