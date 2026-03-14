# SIG(0) KEY Publication via Combiner: Design

**Date:** 2026-03-14
**Status:** Implemented

## Problem

When an agent wins leader election for a multi-provider zone (e.g. `whisky.dnslab.`), it needs
to publish its SIG(0) public key so that the parent zone can validate DNS UPDATE messages from
it. There are two publication locations, depending on what the parent supports:

- **`at-apex`**: KEY RR at the zone apex (`whisky.dnslab. KEY ...`)
- **`at-ns`**: KEY RR at the RFC 9615 `_signal` name for each NS record the local provider
  contributes: `_sig0key.<customerzone>._signal.<nstarget>.`

The agent knows which locations the parent supports (via DSYNC RRset lookup). The combiner
knows which NS records each agent has contributed, has persistent storage, and manages the
provider zone where `_signal` records live. Therefore the **combiner** should own all KEY
publication logic once instructed by the agent.

The same mechanism will later be used for CDS publication (same location choices).

## Design

### Protocol: PublishInstruction piggybacked on UPDATE

A new `PublishInstruction` struct is added. It is carried as an optional field on the existing
UPDATE message. The agent sends it alongside (or instead of) regular zone data contributions.

```go
// core/messages.go
type PublishInstruction struct {
    KEYRRs    []string `json:"key_rrs,omitempty"`    // KEY RRs in text format (plural: supports rollover)
    CDSRRs    []string `json:"cds_rrs,omitempty"`    // CDS RRs in text format (future use)
    Locations []string `json:"locations"`             // ["at-apex"], ["at-ns"], both, or [] (retract)
}
```

`Locations` values:
- `"at-apex"` — publish at zone apex of the MP zone
- `"at-ns"` — publish at `_sig0key.<zone>._signal.<nstarget>.` for each NS the local agent contributed
- `[]` (empty) — retract: remove all published KEYs (apex + all `_signal` names)

`PublishInstruction` is added to:
- `AgentMsgPost` (core/messages.go) — wire format
- `CombinerSyncRequest` (combiner_chunk.go) — combiner processing
- `ZoneUpdate` (syncheddataengine.go) — agent-side construction
- `ConvertZoneUpdateToSyncRequest` — copies the field through
- `combiner_msg_handler.go` — copies from `AgentMsgPost` to `CombinerSyncRequest`

### Agent side (main_initfuncs.go: onLeaderElected)

Replace the current `PublishSignalKeyToCombiner` call with a normal `EnqueueForCombiner`
carrying `PublishInstruction` with `Locations: ["at-apex", "at-ns"]` (always both for now;
parent-capability filtering is future work).

```go
zu := &ZoneUpdate{
    Zone:      zone,
    ZoneClass: "mp",
    Publish: &PublishInstruction{
        KEYRRs:    []string{keyRR.String()},
        Locations: []string{"at-apex", "at-ns"},
    },
}
sigDistID, err := tm.EnqueueForCombiner(zone, zu, "")
```

Delete `PublishSignalKeyToCombiner` from `parentsync_leader.go`. Keep `Sig0KeyOwnerName` as
a package-level helper (referenced in `GetParentSyncStatus`).

### Combiner side: processing PublishInstruction

In `CombinerProcessUpdate`, after handling regular Operations/Records: if `req.Publish != nil`,
call `combinerApplyPublishInstruction(req, zd, kdb, tm)`.

`CombinerProcessUpdate` gains two new parameters: `kdb *KeyDB` and `tm *TransportManager`.
Both are available at all call sites in `combiner_msg_handler.go`. `CombinerState.ProcessUpdate`
is updated to thread them through.

`combinerApplyPublishInstruction` logic:

```
load storedInstr = kdb.GetPublishInstruction(zone, senderID)  // may be nil

if Locations == []:
    if storedInstr != nil:
        remove apex KEY (ReplaceCombinerDataByRRtype with empty slice)
        for each ns in storedInstr.PublishedNS:
            send provider UPDATE: DELETE KEY at _sig0key.<zone>._signal.<ns>.
    kdb.DeletePublishInstruction(zone, senderID)
    return

if "at-apex" in Locations:
    parse KEYRRs → []dns.RR
    zd.ReplaceCombinerDataByRRtype(senderID, zone, TypeKEY, parsedRRs)
else if storedInstr had "at-apex":
    zd.ReplaceCombinerDataByRRtype(senderID, zone, TypeKEY, nil)  // remove

if "at-ns" in Locations:
    currentNS = NS targets from AgentContributions[senderID][zone][TypeNS]
    prevPublished = storedInstr.PublishedNS (or [])
    for each ns in currentNS not in prevPublished:
        send provider UPDATE: REPLACE KEY at _sig0key.<zone>._signal.<ns>.
    for each ns in prevPublished not in currentNS:
        send provider UPDATE: DELETE KEY at _sig0key.<zone>._signal.<ns>.
    publishedNS = currentNS
else if storedInstr had "at-ns":
    for each ns in storedInstr.PublishedNS:
        send provider UPDATE: DELETE KEY at _sig0key.<zone>._signal.<ns>.
    publishedNS = []

kdb.SavePublishInstruction(zone, senderID, instr, publishedNS)
```

### Combiner side: NS change side-effect

Add `combinerResyncSignalKeys(senderID, zone, zd, kdb, tm)`:
- Load stored instruction for (zone, senderID); if none or Locations empty: no-op
- If `"at-ns"` in Locations: diff currentNS vs storedPublishedNS, add/remove `_signal` KEYs,
  update storedPublishedNS in kdb

Call it at the end of `combinerProcessOperations` when any NS records changed (dataChanged &&
ns was among the changed types).

### Database: CombinerPublishInstructions table

New table in `db_schema_hsync.go`, initialized via `InitCombinerEditTables`:

```sql
CREATE TABLE IF NOT EXISTS 'CombinerPublishInstructions' (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    zone              TEXT NOT NULL,
    sender_id         TEXT NOT NULL,
    key_rrs_json      TEXT NOT NULL DEFAULT '[]',
    cds_rrs_json      TEXT NOT NULL DEFAULT '[]',
    locations_json    TEXT NOT NULL DEFAULT '[]',
    published_ns_json TEXT NOT NULL DEFAULT '[]',
    updated_at        INTEGER NOT NULL,
    UNIQUE(zone, sender_id)
)
```

Index: `CREATE INDEX IF NOT EXISTS idx_publish_instr_zone ON CombinerPublishInstructions(zone)`

New file `db_combiner_publish_instructions.go`:

```go
type StoredPublishInstruction struct {
    Zone        string
    SenderID    string
    KEYRRs      []string
    CDSRRs      []string
    Locations   []string
    PublishedNS []string  // NS targets with currently active _signal KEYs
    UpdatedAt   time.Time
}

func (kdb *KeyDB) SavePublishInstruction(zone, senderID string, instr *PublishInstruction, publishedNS []string) error
func (kdb *KeyDB) GetPublishInstruction(zone, senderID string) (*StoredPublishInstruction, error)
func (kdb *KeyDB) DeletePublishInstruction(zone, senderID string) error
func (kdb *KeyDB) LoadAllPublishInstructions() (map[string]map[string]*StoredPublishInstruction, error)
```

### NS records: migration to Operations style

The agent currently sends NS records via `ZoneUpdate.RRsets` (legacy). Migrate
`syncheddataengine.go` to build NS (and all non-DNSKEY RRtypes) using
`Operations: []core.RROperation{{Operation: "replace", ...}}`.

The `RRsets` field is kept in `ZoneUpdate` with a TODO comment for future removal once
the Operations path is trusted.

## Files to modify

| File | Change |
|------|--------|
| `v2/core/messages.go` | Add `PublishInstruction` struct; add `Publish *PublishInstruction` to `AgentMsgPost` |
| `v2/syncheddataengine.go` | Add `Publish` field to `ZoneUpdate`; migrate NS to Operations; set `Publish` in onLeaderElected path |
| `v2/combiner_chunk.go` | Add `Publish` to `CombinerSyncRequest`; add `combinerApplyPublishInstruction`; `combinerResyncSignalKeys`; copy in `ConvertZoneUpdateToSyncRequest`; add kdb+tm params to `CombinerProcessUpdate` |
| `v2/combiner_msg_handler.go` | Copy `Publish` field; thread kdb+tm to `CombinerProcessUpdate` |
| `v2/db_schema_hsync.go` | Add `CombinerPublishInstructions` table + index |
| `v2/db_combiner_publish_instructions.go` | New file: Save/Get/Delete/LoadAll |
| `v2/main_initfuncs.go` | Replace old publication code with `ZoneUpdate{Publish: ...}` |
| `v2/parentsync_leader.go` | Delete `PublishSignalKeyToCombiner` |

## Helper functions

- `sig0KeyOwnerName(zone, nsTarget string) string` — keep in `parentsync_leader.go`
- `publishSignalKey(zone, nsTarget string, keyRRs []string, tm *TransportManager) error`
  — internal combiner helper; builds provider ZoneUpdate with `Zone=""` and calls
  `EnqueueForCombiner("", update, "")` (zone auto-discovery already implemented)

## Extensibility for CDS

`PublishInstruction.CDSRRs` is already present. When CDS publication is implemented:
- Add `"at-apex"` and `"at-ns"` handling for CDS in `combinerApplyPublishInstruction`
- The `_signal` name for CDS will follow the same pattern (TBD per spec)
- No struct or table changes needed

---

## Complexity Assessment

**Overall: Medium**

The struct additions and field threading are mechanical and low-risk. The non-trivial parts are:

- **`combinerApplyPublishInstruction`**: Must correctly handle all 4 Locations combinations,
  diff old vs new published NS set, and drive provider zone updates asynchronously via the
  existing reliable message queue. Moderate complexity (~60–80 LOC).

- **`combinerResyncSignalKeys`**: Triggered on NS changes; must be idempotent and handle the
  case where no instruction is stored. Low-moderate complexity (~30 LOC).

- **Parameter threading** (`kdb`, `tm` into `CombinerProcessUpdate`): Mechanical but touches
  several call sites — `combiner_msg_handler.go` (main call), `CombinerState.ProcessUpdate`
  (wrapper), and the `SendToCombiner` in-process path. All straightforward.

- **NS migration to Operations**: Mechanical refactor. The Operations path is already exercised
  by DNSKEY and KEY; NS is just another RRtype going through the same code.

---

## Risk Analysis

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Provider zone update races (combiner sends _signal update while NS is being changed) | Low | Medium | `publishedNS` is updated atomically in kdb after the provider updates are enqueued; idempotent REPLACE ops mean replays are safe |
| `AgentContributions[senderID][zone][TypeNS]` empty at instruction time (NS not yet synced) | Medium | Low | `at-ns` with zero NS targets is a no-op; `combinerResyncSignalKeys` will pick it up when NS arrives |
| NS migration breaks existing combiner update handling | Low | High | `combinerProcessOperations` already handles "replace" for all RRtypes; NS is no different. Test with AXFR after deploy. |
| kdb+tm parameter threading breaks `CombinerState.ProcessUpdate` (used by in-process `SendToCombiner`) | Low | Medium | `SendToCombiner` has access to the CombinerState; either pass nil (skip publish logic) or store kdb+tm in CombinerState |
| Empty Locations retract removes wrong records if PublishedNS is stale | Low | Medium | `PublishedNS` is the authoritative list — always compare against it, never re-derive |

---

## Code Estimate

| Component | Est. lines |
|-----------|-----------|
| `PublishInstruction` struct + field additions (4 files) | ~15 |
| `combinerApplyPublishInstruction` | ~80 |
| `combinerResyncSignalKeys` | ~35 |
| `ConvertZoneUpdateToSyncRequest` + handler copy | ~5 |
| kdb+tm parameter threading | ~10 |
| `db_combiner_publish_instructions.go` (new file) | ~130 |
| `db_schema_hsync.go` table + index | ~20 |
| `main_initfuncs.go` replacement | ~15 (replaces ~12) |
| NS migration to Operations in `syncheddataengine.go` | ~20 (replaces ~30) |
| Delete `PublishSignalKeyToCombiner` | −25 |
| **Total new/changed** | **~330 lines** |
| **Net change** | **~+295 lines** |

---

## Verification

1. `cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make` — clean build
2. Deploy combiner + agent to lab; agent wins election
3. Combiner log: `[INFO/combiner] publish instruction applied zone=whisky.dnslab. sender=agent.alpha.dnslab. locations=[at-apex at-ns]`
4. `dogv2 @combiner whisky.dnslab axfr | grep " KEY "` → KEY at zone apex
5. `dogv2 @combiner alpha.dnslab axfr | grep " KEY "` → `_sig0key.whisky.dnslab._signal.ns2.alpha.dnslab. KEY ...`
6. Remove NS contribution → verify corresponding `_signal` KEY disappears from provider zone
7. Send empty Locations (or simulate via restart without re-election) → both apex KEY and all `_signal` KEYs removed
8. `daemon restart --clear ...` → on re-election, instruction re-sent, all publication restored
