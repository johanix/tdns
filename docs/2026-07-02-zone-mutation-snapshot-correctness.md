# Project B — Zone-Mutation Correctness via an Immutable Snapshot

**Status:** **B3 enforcement pending** — B1 **done** (`98e50fa`); B2 **done** (`c76dfc4`);
B3 reader cut-over **done** (uncommitted); unexported published type **remaining**.
**Date:** 2026-07-02 (plan); **implementation log:** 2026-07-08
**Scope:** replace direct-write-then-bump-serial mutation with an **immutable
snapshot published atomically**, in **tdns core (`v2/` + `cmdv2/`) only**. A
**standalone correctness fix** (repairs a serial-invariant violation that bites
*queries* today), independent of A and C. Project C (IXFR) is scheduled **after** B.
**tdns-mp is OUT of scope** — see the constraint below.
**Prerequisite:** Project A **step 0 retires SliceZone**, so the whole store is
MapZone (`zd.Data`) — B's snapshot is **map-only, no store normalization**.

> **HARD SCOPE CONSTRAINT — do NOT touch `tdns-mp` in this project.** tdns-mp is
> undergoing a major refactor of its interface to tdns-transport; changing it here
> would collide with that in-flight work. tdns-mp is a **separate module pinned to
> a known-good tdns/v2 version** and stays on that pin throughout B — it keeps
> compiling and serving unaffected by B1→B3, because it never re-pins to the changed
> core during B. Migrating tdns-mp's mutators to the staging API is a **separate
> follow-on mini-project (“B-MP”, see §9)**, run *after* the tdns-mp↔transport
> refactor, which does the migration **and** the re-pin together. Because MP never
> sees post-B3 tdns/v2 during B, **B3 uses full-strength enforcement** (unexported
> published type + grep gate) with no compatibility softening; its grep gate is
> scoped to the tdns-core tree only.
**Reference:** the sibling POP component solved the same problem the same way —
`tapir/docs/2026-06-02-pop-149-snapshot-concurrency-design.md` (*POP §n*).
**Review folded in:** `…-zone-mutation-snapshot-correctness-review.md`.
Anchors as of 2026-07-02; verify before editing.

---

## Implementation status (2026-07-08)

Branch: `feature/zone-snapshot-correctness` (off `main`).

### B1 — done (`98e50fa`)

| Deliverable | Status |
|---|---|
| `ZoneSnapshot`, `atomic.Pointer`, `PendingChanges` | `v2/zone_snapshot.go` |
| Staging API, coalescing publisher | `v2/zone_mutation.go` (dual-write removed in B3) |
| `publish-cadence` on `ZoneConf` / `TemplateConf` | `v2/structs.go`, `v2/parseconfig.go` |
| `InstallInitialSnapshot()` after first load / `SetupZoneSigning` | `v2/refreshengine.go`, `v2/zone_utils.go` |
| B1 tests (`TestSnapshotImmutability`, dual-write, coalescing, generation guard) | `v2/zone_snapshot_test.go` — pass `-race` |

### B2 — done (`c76dfc4`)

| Mutator / deliverable | Status | Notes |
|---|---|---|
| Query-path write-backs removed | **done** | `signedApexRRsets`, `soaForResponse`; no `Set`-after-sign |
| `SignZone` / `ResignZone` / `GenerateNsecChain` / `StripZoneRRSIGs` | **done** | stage + `publishLocked` under `zd.mu` |
| `PublishDnskeyRRs` | **done** | `publishDnskeyRRsLocked` |
| `BumpSerial` / `BumpSerialOnly` | **done** | `publishSync()` |
| RFC2136 `ApplyZoneUpdate` / `ApplyChildUpdate` | **done** | `stagedOwner`, sync `publishLocked` on commit |
| Refresh flips (`FetchFromFile` / `FetchFromUpstream`) | **done** | `applyRefreshReplacementLocked` — no hard `Data` flip |
| `RepopulateDynamicRRs` | **done** | `repopulateWorkingSetLocked`; folded into refresh publish |
| `CreateTransportSignalRRs` | **done** | `commitTransportSignalLocked` |
| Catalog (`regenerateCatalogZone`, create version TXT) | **done** | working-set rebuild + publish |
| Post-refresh serial override (`outbound_soa_serial`) | **done** | republish instead of `setApexSOASerial` on served data |
| `PublishCsyncRR` | **unchanged** | already routes via internal `ZONE-UPDATE` → staged RFC2136 |
| `dnsutils.SortFunc` (zone file load into `new_zd`) | **intentionally unchanged** | draft build target; consumed by refresh publish |
| `tdns-cli debug zone-txlog` + `/debug` handler | **done** | `pendingChanges()` → `zone-txlog` command + JSON view |
| `TestConcurrentServeAndUpdate` (B2 variant) | **done** | superseded by B3 variant in same commit |
| `pendingChanges` test | **done** | `TestPendingChanges` |

**B2 gate:** all B1 tests + `TestPendingChanges` + `TestConcurrentServeAndUpdate` (B2 variant) pass `-race`.

### B3 — reader cut-over done; enforcement remaining

| Deliverable | Status | Notes |
|---|---|---|
| Readers via `publishedSnapshot()` | **done** | `GetOwner`, `GetOwnerNames`, `NameExists`, `GetSOA`, `soaForResponse` |
| Query transport signal | **done** | `queryresponder.go` → `publishedTransportSignal()` |
| `ZoneTransferOut` / `WriteZoneToFile` | **done** | `GetOwnerNames`/`GetOwner`; no transfer-time SOA serial override |
| Mutators use working set | **done** | `stagedOwner`, `workingOwnerNamesLocked` in sign/tsignal/ops_dnskey |
| Drop dual-write | **done** | `syncLegacyFromSnapshot` removed; publish stores snapshot only |
| Dead code cleanup | **done** | `setApexSOASerial`, `AddOwner` removed |
| `check-no-mutators` grep gate | **done** | `utils/Makefile.common`; wired into `lint` |
| B3 tests | **done** | `TestPublishedSnapshotAfterPublish`; B3 `TestConcurrentServeAndUpdate` — pass `-race` |
| Unexported published type | **remaining** | `ZoneSnapshot` still exported; rename → `zoneSnapshot` |
| `PrintOwners` | **remaining** | still walks draft `zd.Data`; should use `GetOwnerNames` |

**B3 gate (partial):** B1 + B2 + B3 snapshot tests pass `-race`. Full sign-off blocked on unexported type.

---

## 0. The bug and the fix
**Bug.** Every mutating site writes **directly into published zone data**
(`OwnerData.RRtypes.Set(...)`) and bumps the SOA serial **later**, separately —
violating "a zone's serial uniquely identifies its content." Verified:
`signApexRRsets` writes RRSIGs back to the apex on **every DO query**
(queryresponder.go:103-108, called from 638, 212-213, 277); positive answers
persist signed RRsets (771-776); query SOA stamps (339-340, 403, 747, 791); RFC2136
mutates then bumps in defer (zone_updater.go:562-567); signing passes Set per-RRset
then bump once (sign.go:874-898). Two secondaries can serve **different content for
the same serial**. (tdns's `zd.Data` is a `core.ConcurrentMap`, so the symptom is a
logical inconsistency, not POP's uncatchable `fatal error: concurrent map read/
write` — same disease, quieter symptom.)

**Fix (POP-proven).** Mutators never touch the served view. A writer builds a
**fresh** `ZoneSnapshot` and swaps it behind an `atomic.Pointer`; readers `Load()`
lock-free. Content changes only at a serial boundary, atomically. IXFR (C) later
retains the delta publish already computes.

---

## 1. Design

### 1.1 The snapshot type (map-only; bundle everything consistent)
```go
type ZoneSnapshot struct {
    Serial          uint32
    SOA             *dns.SOA     // single source of truth; Serial == CurrentSerial
    Apex            *OwnerData   // apex incl. NS / DNSKEY
    Data            map[string]*OwnerData // read-only after publish (map-only; SliceZone gone)
    TransportSignal *core.RRset  // parallel field the query path reads (see §1.5)
    IxfrChain       []Ixfr       // read-only; empty in B, populated by C
}
```
On `ZoneData` (structs.go:108): add `snapshot atomic.Pointer[ZoneSnapshot]`.
Reuse the dead `Ixfr` (structs.go:509) / `IxfrChain` (structs.go:140) scaffolding.

### 1.2 Stage vs publish
- **Stage** — immediate; a mutator applies its change into a per-zone **working
  set** (the *next* zone) so the next mutator reads current-including-pending
  state. Readers never see the working set.
- **Publish** — a **request** to a per-zone publisher which, under the **per-zone
  publish mutex** (`zd.mu`), runs:
  1. `old := zd.snapshot.Load()`
  2. build a **fresh** `ZoneSnapshot` from the working set (fresh `Data` map; one
     fresh `*dns.SOA` with `Serial=CurrentSerial`; fresh `IxfrChain` slice — copy,
     don't append onto `old`'s backing array); compute the delta
  3. **generation guard** — verify `zoneStillLive(zd, gen)` (refreshengine.go:18-28)
     before `Store`, so a publish racing a zone-delete doesn't resurrect it
  4. `zd.snapshot.Store(new)`
  5. persist serial if configured (`SaveOutgoingSerial`, db_outgoing_serial.go:5)
  6. **NOTIFY downstreams once** (subsumes the `BumpSerial`→`NotifyDownstreams`
     path, zone_utils.go:823-829)

### 1.3 The publisher: rate-limited, coalescing
- **idle ⇒ publish immediately** (zero latency for a lone change);
- **under load ⇒ ≤ 1 publish per configurable per-zone cadence** (default **5 s**;
  10 s fine), folding all pending changes into one snapshot (a 50/s trickle ⇒ one
  publish/cadence, one serial bump, one delta). **urgent** flag lets an RFC 2136
  update bypass. Mechanism: publish now if `now-lastPublish >= cadence`, else
  schedule at `lastPublish+cadence` and absorb further requests.
- **NOTIFY fires once per *completed publish*, not per stage.** Under coalescing,
  downstreams see serial lag up to the cadence — intentional; document in the
  config knob. The `ResignerEngine` whole-zone resign (a whole pass) is **one**
  publish, not per-RRset.

### 1.4 Copy strategy A + the immutability invariant
**Full-copy-on-publish**, cost **O(number of names)** (copy `name→*OwnerData`
slots; unchanged owners share pointers; PQ signature bytes live in the shared
`*RRTypeStore`, never copied). `ZoneSnapshot` is the reader-facing boundary, so a
persistent map (B, e.g. HAMT) can replace A later with no reader changes; not
building it. **Critical invariant this depends on:**

> Staging **never** mutates any `OwnerData`/`*RRTypeStore` reachable from the
> currently published snapshot. A staged change always **allocates fresh**
> RRset/owner structures; publish copies the map shell and swaps pointers.

Without this, "unchanged owners share pointers" (§1.4) would let a stage mutate a
live snapshot in place (`GetOwner` returns a struct copy sharing the same
`*RRTypeStore`, zone_utils.go:475-485).

### 1.5 Multi-writer — per-zone publish mutex (option i)
POP had a single writer goroutine (POP §1.1); tdns has several — `RefreshEngine`,
**`ResignerEngine`** (resigner.go:14, main_initfuncs.go:280; `SignZone(..,true)` on
`triggerResign` resigner.go:58), update handlers, and today query goroutines. So
`atomic.Pointer` makes **readers** lock-free, but the `load→build→guard→swap→notify`
sequence runs under the **per-zone publish mutex** or two writers clobber each
other (lost update). `TransportSignal` (query path reads `zd.TransportSignal`,
queryresponder.go:370-371; set by `RepopulateDynamicRRs` zone_utils.go:1228-1230
and `CreateTransportSignalRRs` tsignal.go:307) is **part of the snapshot bundle**
so it flips atomically with `Data`.

### 1.6 Staging API + working-set structure (concrete)
Data-structure facts (verified): `RRTypeStore` (rrtypestore.go:7-50) =
`struct{ data ConcurrentMap[uint16, core.RRset] }`, methods
`Get/GetOnlyRRSet/Set/Delete/Keys/Count`, **no Copy/Clone**; `core.RRset`
(core/core_structs.go:10-23) = `{Name,Class,RRtype,RRs []dns.RR,RRSIGs []dns.RR,
UnclampedTTL}` (slices are references, no Copy); `GetOwner` returns an `OwnerData`
copy **sharing the same `*RRTypeStore`** (zone_utils.go:469/475) — so a stage must
never write through such a handle. No zone/owner clone helper exists.

Working set on `ZoneData`: `workingSet map[string]*OwnerData` (nil between
publishes) + `wsTransportSignal *core.RRset`, guarded by **the same `zd.mu` as
publish** (one lock for stage + publish avoids a stage-lock↔publish-mutex deadlock
when `requestPublish` flushes mid-stage; writers already serialize on it per §1.5):
```go
func (zd *ZoneData) ensureWorkingSet() {              // O(names) shallow clone, once per publish cycle
    if zd.workingSet == nil {
        snap := zd.snapshot.Load()
        zd.workingSet = make(map[string]*OwnerData, len(snap.Data))
        for k, v := range snap.Data { zd.workingSet[k] = v }   // share *OwnerData for unchanged owners
    }
}
func (zd *ZoneData) cloneOwner(name string) *OwnerData {       // fresh-alloc (no Copy helper exists)
    src := zd.workingSet[name]
    nod := &OwnerData{Name: name, RRtypes: NewRRTypeStore()}
    if src != nil { for _, t := range src.RRtypes.Keys() { rs, _ := src.RRtypes.Get(t); nod.RRtypes.Set(t, rs) } }
    zd.workingSet[name] = nod; return nod                       // COW: replace shared pointer with a fresh owner
}
func (zd *ZoneData) stageRRset(name string, rs core.RRset)       { zd.ensureWorkingSet(); zd.cloneOwner(name).RRtypes.Set(rs.RRtype, cloneRRset(rs)) }
func (zd *ZoneData) stageDelete(name string, t uint16)          { zd.ensureWorkingSet(); zd.cloneOwner(name).RRtypes.Delete(t) }
func (zd *ZoneData) stageOwnerReplace(name string, od *OwnerData){ zd.ensureWorkingSet(); zd.workingSet[name] = od }
func (zd *ZoneData) requestPublish(urgent bool)                  // enqueue to the coalescing publisher

// Read-only observability of the pending (staged-but-unpublished) state,
// for the `tdns-cli debug zone-txlog` command (§4 B2). Returns nil when no
// changes are staged. It is a VIEW, not a mutation path — it does not
// break the "no exported mutators" invariant (§4 B3).
func (zd *ZoneData) pendingChanges() *PendingChanges              // under zd.mu; snapshot of workingSet vs published
```
- `publish()` hands the working-set map to the new snapshot (`Data: zd.workingSet`)
  and sets `zd.workingSet = nil` — the published map is never mutated again (next
  stage re-clones). This **is** copy-strategy-A: the O(names) cost is the one
  `ensureWorkingSet` shallow clone per publish cycle.
- **Fresh-alloc rule + `cloneRRset` helper:** `stageRRset` always passes
  `cloneRRset(rs)` — fresh `RRs`/`RRSIGs` slices with `dns.Copy` per RR. But
  `cloneOwner` copies RRset *headers* for unchanged types — those slices stay
  aliased to the published snapshot — so **append paths (RFC2136 add) must clone
  before appending** onto an existing RRset. **Whole-RRset replace** must also use
  `cloneRRset` when `rs` was built from a handle obtained via `GetOwner` (in-place
  signing mutates shared slices). Never append onto or reuse slice backing arrays
  reachable from the published snapshot.
- **Whole-zone passes** (SignZone/GenerateNsecChain/combiner) stage many owners,
  then **one** `requestPublish` — one delta, one serial bump.
- **Pending-change observability (`pendingChanges`).** Because publish is
  coalesced (§1.3, 5 s cadence), an accepted change (e.g. a DNS UPDATE) is staged
  in `workingSet` but NOT yet served until the next publish. Unlike today's
  direct-write model, "just query the zone" no longer confirms a change landed
  during that window. `pendingChanges()` returns a read-only diff of `workingSet`
  vs the currently-published snapshot (added/replaced/deleted owners+types), plus
  the published serial and whether a publish is already queued. It is the data
  source for the `tdns-cli debug zone-txlog` command (§4 B2). Scope note: this is
  the *pending, unpublished* delta only; the retained history of *already-published*
  deltas is Project C's `IxfrChain` (§8), out of scope here.

### 1.7 Serial semantics
- **`ZoneSnapshot.Serial == CurrentSerial`** at publish (via `nextOutboundSerial`,
  zone_utils.go:736-748). `IncomingSerial` (structs.go:135) stays on `ZoneData` as
  **upstream-sync metadata only — never served** in a SOA.
- Refresh flip (today `IncomingSerial ← upstream`, `CurrentSerial++`,
  zone_utils.go:343-348; post-flip `setApexSOASerial` without lock,
  refreshengine.go:150,709) becomes **`publish(fullReplacement)`** — the serial
  logic moves inside publish.
- **`CurrentSerial` migration (enumerated — smaller than "dozens"):** keep
  `zd.CurrentSerial` as a **cached mirror written only inside `publish()`** and the
  refresh serial-init (refreshengine.go:132-145/694-704). The ~15 *write* sites
  collapse into publish()/refresh. The served SOA comes from `snapshot.SOA`, not
  the field, so the query/transfer stamps (queryresponder.go:339/403/747/791;
  dnsutils.go:267) are **deleted, not migrated**. Only ~4 *genuine* readers remain
  and just read the mirror (consistent because publish is the sole writer): CSYNC
  serial (ops_csync.go:17), `WriteZoneToFile` stamp (dnsutils.go:670), ParentSerial
  (zone_utils.go:844), a log line (zone_utils.go:160). A transitional
  `zd.CurrentSerial == snapshot.Load().Serial` assertion catches drift during B1's
  dual-write.

---

## 2. Invariants
- **Serial ⇒ content**; published content changes only at a serial boundary via one
  atomic swap.
- **A published snapshot is never mutated**; staging never touches memory aliased
  by it (§1.4); publish builds fresh `Data`/`IxfrChain`.
- **Readers lock-free** — queries, AXFR, SOA all `snapshot.Load()`.
- **Writers serialize per zone** via the publish mutex.
- **Responses never write back** — inline RRSIGs from the snapshot; online/compact
  RRSIGs signed into the response and discarded.
- **NOTIFY once per publish**; **`Serial == CurrentSerial`**; **served store
  writable only via `publish()`** (enforced, §4).

---

## 3. Current state to convert
### 3.1 Mutators

| Mutator / path | file:line | writer | note |
|---|---|---|---|
| `SignZone`/`ResignZone`/`GenerateNsecChain`/`StripZoneRRSIGs` | sign.go:749/580/918/702 | **ResignerEngine** | whole pass → one publish |
| RFC2136 `ApplyZoneUpdate`/`ApplyChildUpdate` | zone_updater.go:540/386 | update | delta-shaped already; convert first |
| `PublishDnskeyRRs`/`PublishCsyncRR` | ops_dnskey.go:26 / ops_csync.go:13 | engine | |
| `RepopulateDynamicRRs` (+ `TransportSignal`) | zone_utils.go:1170-1230 | post-flip, **no lock** | fold into the post-refresh publish; ordering vs `SetupZoneSigning` (refreshengine.go:713-716) must be fixed |
| `CreateTransportSignalRRs` | tsignal.go:307,420 | engine | into `snapshot.TransportSignal` |
| Catalog | apihandler_catalog.go:167,524,565 | API | |
| Refresh flips + `OnZonePreRefresh` | zone_utils.go:236-260/340-364; :231-233/335-337 | RefreshEngine | flip → `publish(fullReplacement)`; PreRefresh callbacks mutate a **draft snapshot** |
| `BumpSerialOnly`/`BumpSerial` | zone_utils.go:782-830 | engine | generalised by `publish()` |
| **Query-path signing** — `signApexRRsets` (def 92-115; calls 638, 212-213, 277); positive 771-776; CNAME 449/514/534; `signRRsetForZone` 134-183 | queryresponder.go | **query goroutines** | **B2:** delete all `Set`-after-sign write-backs (not only 771-776). **B3:** read inline RRSIGs from snapshot; online/compact stays ephemeral |
| Query SOA stamps | queryresponder.go:339,403,747,791 | query | **B2:** delete (with other query write-backs) |
| `WriteZoneToFile` stamp | dnsutils.go:669-670 | API | export reads snapshot |
| **`tdns-mp`** signing/combiner | mp_signer.go:142,356 (+`BumpSerial` :151); combiner_utils.go:163,165,170 (`mpzd.Data.Set`) | MP | **OUT of scope for B — deferred to §9 (B-MP).** `MPZoneData` embeds `tdns.ZoneData` (same `Data` field, so the future `stage*`/`publish()` receivers are promoted for free), which is exactly *why* the migration is mechanical later — but tdns-mp is mid-refactor and stays on its current tdns/v2 pin through B, so these Set-sites are NOT touched here. B-MP routes them and re-pins together. |

`addCDEResponse` (queryresponder.go:940-944) already signs NSEC into the **response
only** — matches the ephemeral-online split; leave it.

### 3.2 Reuse: `nextOutboundSerial`, `setApexSOASerial`, `Save/LoadOutgoingSerial`,
`zoneStillLive` (B5b guard), `Zones` registry (global.go:55), `ModifyDynamicZone`
pointer-swap + `generation.Add(1)` (dynamic_zones.go:934,981 — epoch reset in C).

---

### 3.3 Refresh-flip recipe (H4) + PreRefresh callbacks (H5)
Today: hard flip copies `zd.Data` under mutex (zone_utils.go:257) →
`RepopulateDynamicRRs` (no lock) → post-refresh callbacks → RefreshEngine
`SetupZoneSigning`→`SignZone`→`BumpSerial` (refreshengine.go:713-716). Under the
publish model this becomes one ordered, single-writer sequence:
1. Build a **working set** from `new_zd` (the freshly loaded/transferred zone) —
   replaces the hard-flip field copy.
2. Stage the dynamic RRs + `TransportSignal` (`RepopulateDynamicRRs`'s content).
3. If the zone signs: stage the signing pass (`SignZone`/NSEC) into the **same**
   working set.
4. **One** `publish()` (full replacement) — one snapshot, one serial bump, one
   NOTIFY (chain epoch reset for Project C happens here).

**`OnZonePreRefresh` callbacks** (zone_utils.go:231-233/335-337) today receive
`(zd, new_zd)` and mutate `new_zd` before the flip. Migration: **`new_zd` becomes
the working-set build target** — callbacks stage into it (combiner contributions,
MP pre-refresh hooks, delsync-proxy analysis parseconfig.go:1043-1049), and the
single `publish()` in step 4 makes it live. No callback writes served data
directly. **This migration is core-side only:** MP's pre-refresh hooks
(`tdns-mp/v2/config.go`, `hsync_utils.go MPPreRefresh`) keep mutating `new_zd`
exactly as today and are NOT modified here — B changes only how *core* consumes
`new_zd` (as the working set). MP's callbacks meet the new working-set contract
when MP re-pins, in B-MP (§9). Preserve a working `new_zd` mutation surface through
B so the pinned MP keeps compiling.

## 4. Implementation — milestoned (NOT one PR), **writers before readers**
At ~1800+ LOC across `v2` + `cmdv2` + QueryResponder (tdns-mp excluded, §9), one PR
is too risky. Use a
**dual-write / strangler** transition, `-race`-gated at each milestone. **Order is
load-bearing: writers cut over before readers.** If readers moved to the snapshot
while legacy mutators still bypassed `publish()`, the snapshot would freeze while
served data changed underneath — worse than today. So:

- **B1 — engine (dormant, dual-write ready).** Add `ZoneSnapshot`, `snapshot
  atomic.Pointer`, `publish()` (§1.2, incl. generation guard), the coalescing
  publisher (§1.3, 5 s), the staging API (§1.6). **Dual-write definition:** each
  `publish()`, under `zd.mu`, (1) stores the new snapshot AND (2) replaces
  `zd.Data`'s content to match it — converting the snapshot's
  `map[string]*OwnerData` back into the legacy `ConcurrentMap[string, OwnerData]`
  (values). Both stores stay byte-identical. Build the initial snapshot **before**
  the zone serves (closes the `Ready=true` "lie", zone_utils.go:223-225; POP §5).
  Nothing reads the snapshot yet; legacy writers unchanged. `-race` gate: publisher
  + immutability tests.
- **B2 — writers cut over (dual-write keeps legacy current for readers).** Route
  every §3.1 **tdns-core** mutator — refresh flips, RFC2136, signing passes, the
  **ResignerEngine**, DNSKEY/CSYNC/transport/catalog — through `stage*` +
  `requestPublish`. (**`tdns-mp` is excluded** — deferred to §9 B-MP.) **Also at
  the start of B2:** delete all query-path write-backs
  (`signApexRRsets`, positive/CNAME `Set`-after-sign, query SOA stamps) — readers
  still use legacy `GetOwner`, but legacy must only change via `publish()` so
  dual-write stays consistent. `publish()` still dual-writes, so legacy `zd.Data`
  stays current AND the snapshot advances. After B2 both stores are always current;
  **no path may mutate served data except via `publish()`**. `-race` gate:
  `TestConcurrentServeAndUpdate` (see §5 — B2 variant). Online-signing: the
  resigner must produce signed snapshots via publish before DO queries rely on them.
  **Ship `tdns-cli debug zone-txlog --zone X`** in this milestone: with publish now
  coalesced, an accepted change is staged but unserved for up to a cadence, so
  "query the zone" no longer confirms it landed. The command calls
  `pendingChanges()` (§1.6) and prints the pending (staged-but-unpublished) delta —
  added/replaced/deleted owners+types — plus the currently-published serial and
  whether a publish is queued. B2 is where it first has anything to show (staging
  begins here) and where it is most needed (the publish window opens). It is a
  read-only view; it must not become a mutation path (§4 B3 enforcement).
- **B3 — readers cut over + drop legacy + enforce.** Switch QueryResponder
  (`GetOwner`/`GetRRset` → `snap.Data`), `ZoneTransferOut`, and the SOA responder
  to `snapshot.Load()`. Query-path signing split: inline RRSIGs **read** from the
  snapshot; online/compact signed into the response and discarded (write-backs
  already removed in B2). **Remove the dual-write** (publish stores the snapshot
  only). **Enforce structurally:** an unexported published type (no exported
  mutators) + a CI grep gate rejecting `RRtypes.Set`/`Data.Set` outside an
  allowlist (`zone_mutation.go`, the staging file). `-race` gate: full
  serving+update path (see §5 — B3 variant); the serial-invariant guarantee holds
  here.

---

## 5. Test plan (acceptance gate)
- **`TestConcurrentServeAndUpdate` (`-race`)** — would fail today. Two variants:
  - **B2:** N reader goroutines iterate via legacy `GetOwner`/`Data` while writers
    publish a delta stream; assert legacy ≡ snapshot after each publish (dual-write
    consistency). Query write-backs must be gone before this runs.
  - **B3:** same load under `snapshot.Load()`; full serial-invariant gate.
- **`TestSnapshotImmutability`** — publish, mutate the working set, assert the
  published snapshot unchanged (catches the §1.4 aliasing trap and the `IxfrChain`
  slice-header trap).
- **`TestPublishCoalescing`** — burst ⇒ ≤1 publish/cadence (one serial bump); idle
  stage ⇒ immediate publish; urgent ⇒ bypass.
- **Per-writer** — each tdns-core mutator class produces the right served zone.
  (tdns-mp writers are out of scope — tested in B-MP, §9.)
- **`pendingChanges` / `debug zone-txlog`** — stage a change without publishing,
  assert `pendingChanges()` reports it (added/replaced/deleted) and the published
  serial is unchanged; after publish, assert it reports empty. Smoke-test the CLI
  command against a running auth.
- **CI grep gate** — no `Set` outside the allowlist, scoped to the tdns-core tree
  (`v2/*`, `cmdv2/*`); tdns-mp is not in the gate (out of scope).

## 6. Risk / effort / LOC (revised)
**Risk: high** — multi-writer serialization, QueryResponder surgery, ~15 tdns-core
mutator classes, structural enforcement. Mitigated by dual-write milestones +
`-race` gates + the CI enforcement. **Effort: multi-day agent** — the earlier 6–9 h
estimate undercounted QueryResponder + enforcement by ~3–5×. (Excluding tdns-mp,
now deferred to §9, trims the earlier ~20–40 h estimate somewhat, but core alone
is still multi-day.) **LOC (core only): ~1200–1600 impl + ~600 test.**
Parallelizable by mutator class within B2 (writer routing) and B3 (enforcement
cleanup).

## 7. Decisions (settled)
map-only snapshot (SliceZone retired by A) · copy strategy **A** · **5 s** coalescing
cadence (per-zone, urgent bypass, NOTIFY once/publish) · transfer-time signing
deleted (serve verbatim) · **`tdns-mp` OUT of scope — deferred to §9 (B-MP)** ·
**`Serial == CurrentSerial`**, `IncomingSerial` = metadata · **milestoned
B1→B2→B3 (dual-write), `-race` gate each** · **B3 full-strength enforcement
(unexported published type + grep gate), no MP-compat softening** (MP re-pins only
in B-MP, after B3).

## 8. What B hands to Project C
`publish()` already **computes** the per-publish delta; C **retains** it in the
byte-bounded `IxfrChain`, adds the serial-space chain spec, the downstream tracker,
and inbound/outbound IXFR. See `…-ixfr-support.md`.

## 9. Deferred follow-on: Project B-MP (tdns-mp migration)
**Not part of B. Runs AFTER the tdns-mp↔transport refactor completes**, as its own
mini-project. Until then tdns-mp stays on its current (known-good) tdns/v2 pin and
is unaffected by B.

Scope, when it runs:
- Route tdns-mp's mutators through the staging API that B built: the `mpzd.Data.Set`
  sites in `combiner_utils.go:163,165,170` and `mp_signer.go:142,356` (+ `BumpSerial`
  :151). Because `MPZoneData` embeds `tdns.ZoneData`, the `stage*`/`publish()`
  receivers are already promoted — the migration is mechanical (combiner = one
  publish at end), the same pattern as a B2 core mutator.
- **Re-pin tdns-mp to the post-B3 tdns/v2** in the same change (this is the point at
  which MP first meets B3's unexported published type / no exported `Data.Set`, so
  routing and re-pin must land together or MP won't compile).
- Extend the grep gate to the tdns-mp module; add MP per-writer tests (the §5
  per-writer test, MP variant).

Because migration + re-pin happen together here and MP never re-pins during B, B
itself needs no MP-compatibility concessions.
