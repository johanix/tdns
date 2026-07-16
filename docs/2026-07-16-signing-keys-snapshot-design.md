# Design proposal — per-zone signing-keys snapshot (G3)

**Status:** architecture approved; M1–M3 / R1–R4 incorporated — ready to implement.
**Defaults:** D1 = N-caller discipline + R4 freshness matrix; D2 = big-bang delete
(grep-clean). §16: active-only yes; lazy = CAS-if-unbuilt (not plain Store);
clear mid-tx strip = out of G3 (follow-up ticket).
**Branch / worktree:** `feature/signing-keys-snapshot` @
`/Users/johani/src/git/tdns-project/tdns-signing-keys-snapshot` (cut from
`main` @ `bdc6450`).
**Origin:** G3 in
`docs/2026-07-15-transactional-policy-reload-decisions.md`; sketch in
`docs/2026-07-14-snapshot-branch-signing-findings.md` §Signing pipeline item 2;
CodeRabbit on #288 (keystore post-commit invalidation). Same race class as the
config-map crashes fixed by the RuntimeConfig snapshot (#287).
**Sequencing:** lands **before** Plan B PR-2 (refresh-engine wiring), which will
read keys lock-free on the reload path via this accessor.

Line numbers below are anchors as of `bdc6450` and drift — re-locate by symbol.

---

## 1. Problem

`KeyDB.KeystoreDnskeyCache` (`structs.go:820`) is a plain
`map[string]*DnssecKeys` keyed `zone+"+"+state`. It is read and written from many
goroutines — signer hot path, config reload, key mutations — with **inconsistent
locking**:

| Access | Locked? |
|--------|---------|
| Cache hit / fill in `GetDnssecKeys` (`keystore.go:1071–1155`) | **No** |
| Most invalidations (`add`/`generate`/`setstate`/`delete`, `PromoteDnssecKey`, `UpdateDnssecKeyStateTx`, `RolloverKey`, `sign.go` deletes) | **No** |
| Prefix wipe in `clear` / `purge` / `forceZoneKeysToPolicyRoles` | Yes (`kdb.mu`) — and `clear` still wipes **mid-tx** |

`kdb.mu` is a **single-tx context gate** (`Begin`/`Commit`), not a cache lock.
Unlocked concurrent map read vs write is a Go runtime `fatal error`. Rare
(exact-timing), but real — the same class as the #287 config races.

**Decision (locked — do not re-litigate):**

- Do **not** fix by sprinkling locks on every reader.
- Do **not** fold keys into the zone-data snapshot (#279).
- Give each zone its own **copy-on-write signing-keys snapshot** — a `zd`-held
  `atomic.Pointer` — separate from the zone-data snapshot (#279) and the
  runtime-config snapshot (#287). Same "guard the rare writer, not the many hot
  readers" model.

**Why this shape (recap):**

1. Keys change rarely → reads are lock-free ~always.
2. A mass re-sign (10⁴–10⁵ zones) rewrites RRSIGs but **not** keys → keys
   snapshots do not republish → **zero cross-zone contention** (vs a global lock
   serializing every signer).
3. The snapshot is **keystore-derived**, not served-data-derived → **no
   zone-Ready ordering dependency** (unlike the zone-data snapshot).

---

## 2. Principle — mirror #279 / #287

| Precedent | Pattern |
|-----------|---------|
| Zone-data snapshot (#279) | `zd.snapshot atomic.Pointer[zoneSnapshot]`; writers build immutable copy under `zd.mu`, `Store`; readers `Load()` lock-free |
| RuntimeConfig (#287) | `liveConfig atomic.Pointer[RuntimeConfig]`; `ConfLive()` never nil (seeded empty in `init`); publish under `confMu` at reload end |

G3 applies the same pattern to **per-zone active signing keys**:

- One rare writer path: **build from DB after keystore commit → atomic Store**.
- Many hot readers: `Load()` and sign, no lock.
- Nil-safe accessor (seeded empty sentinel), cf. `ConfLive()`.

---

## 3. Type + placement

### 3.1 Snapshot struct (M2 — `built` distinguishes keyless vs unbuilt)

```go
// signingKeysSnapshot is an immutable, keystore-derived view of the keys a
// zone signs with. Published snapshots are never mutated in place; a key-set
// change builds a fresh one and swaps the pointer.
type signingKeysSnapshot struct {
    // built is true iff this snapshot was produced by a successful DB build
    // (eager republish or CAS-if-unbuilt lazy fill). false means unbuilt —
    // either the package sentinel or a post-failed-republish marker.
    // Keyless-but-loaded zones have built=true with empty Active slices
    // (negative-cached; no per-call DB re-query).
    built  bool
    Active *DnssecKeys // never nil; slices may be empty when built && keyless
}
```

Reuse `DnssecKeys` / `PrivateKeyCache` (`structs.go:792–811`). After `Store`,
neither the snapshot nor its `DnssecKeys` / slices / `PrivateKeyCache` entries
are mutated. `PrepareKeyCache` sets `CS` eagerly (`readkey.go:330`); `SignRRset`
only reads `CS`/`DnskeyRR` — sharing `*DnssecKeys` lock-free is race-free.

### 3.2 Placement on `ZoneData`

```go
signingKeys atomic.Pointer[signingKeysSnapshot] // NOT on KeyDB
```

### 3.3 Lock-free accessors (never nil)

```go
// Package sentinel: built=false. Returned when Load() is nil. NEVER Store this
// shared instance onto a zone (ABA hazard with CAS-if-unbuilt — M3).
var emptySigningKeys = &signingKeysSnapshot{built: false, Active: &DnssecKeys{}}

func (zd *ZoneData) SigningKeys() *signingKeysSnapshot { /* Load or emptySigningKeys */ }
func (zd *ZoneData) ActiveDnssecKeys() *DnssecKeys     { /* SigningKeys().Active */ }
```

Never `Store(emptySigningKeys)`. On republish failure, `Store` a **fresh**
allocation `{built:false, Active:&DnssecKeys{}}` so CAS expected-values stay unique.

---

## 4. Which key states go in the snapshot

### Decision (signed off): **active only**

| State | Today | Proposal |
|-------|-------|----------|
| **Active** | Cached in `KeystoreDnskeyCache` (only state that *reads* the cache) | **In snapshot** — every signer / QR / updater / `EnsureActiveDnssecKeys` |
| Published / standby / retired / created / removed | `GetDnssecKeysByState` → **DB-direct** (no cache read); occasional `GetDnssecKeys(Published)` in Ensure bootstrap | **Stay DB-direct** via `GetDnssecKeysByState` / a thin DB loader |

**Justification:**

1. `GetDnssecKeys` only **hits** the cache for `state == Active`
   (`keystore.go:1071`). Non-active fills are write-only noise.
2. Rollover / KeyStateWorker already use `GetDnssecKeysByState` (metadata, no
   private keys) — cold, infrequent, correct without a snapshot.
3. Snapshotting every state would enlarge the republish surface (every
   published→standby tick would republish) for no hot-path win.
4. Favor the smaller change that eliminates the crash class and the global map.

**Consequence for Ensure's published lookup** (`sign.go:463`): keep a DB-direct
load (extract today's SQL path into `loadDnssecKeysFromDB`). Do not put
published keys in the snapshot.

If a later rollover-path race appears on cold states, that is a separate
follow-up — not G3.

---

## 5. Build + republish

### 5.1 Build (DB → immutable snapshot)

```go
// Always returns built=true on success (including keyless empty Active).
func buildSigningKeysSnapshot(kdb *KeyDB, zone string) (*signingKeysSnapshot, error)
```

### 5.2 Republish — post-commit only + M3 loud failure / self-heal

```go
// Call ONLY after the keystore tx that changed this zone's keys has COMMITTED.
// Generation-gated: bump signingKeysGen at entry; Store (success or unbuilt
// marker) only if that generation is still current — prevents an older
// overlapping republish from clobbering a newer snapshot.
func (zd *ZoneData) republishSigningKeys(kdb *KeyDB) error {
    gen := zd.signingKeysGen.Add(1)
    snap, err := buildSigningKeysSnapshot(kdb, zd.ZoneName)
    if err != nil {
        lgSigner.Error("republishSigningKeys: build failed, retrying", "zone", zd.ZoneName, "err", err)
        snap, err = buildSigningKeysSnapshot(kdb, zd.ZoneName) // one retry
    }
    if err != nil {
        // M3: do NOT leave the old built snapshot installed silently.
        // Invalidate with a FRESH unbuilt marker (never the shared sentinel —
        // ABA with CAS-if-unbuilt). Next reader rebuilds via CAS.
        if zd.signingKeysGen.Load() == gen {
            zd.signingKeys.Store(&signingKeysSnapshot{built: false, Active: &DnssecKeys{}})
        }
        lgSigner.Error("republishSigningKeys: failed after retry; marked unbuilt",
            "zone", zd.ZoneName, "err", err)
        return err
    }
    if zd.signingKeysGen.Load() == gen {
        zd.signingKeys.Store(snap) // snap.built == true
    }
    return nil
}

// R3: always FQDN via Zones.Get(dns.Fqdn(zone)) — never keyname-shaped strings.
func republishSigningKeysForZone(kdb *KeyDB, zone string) error {
    zone = dns.Fqdn(strings.TrimSpace(zone))
    if zone == "." { return nil }
    zd, ok := Zones.Get(zone)
    if !ok || zd == nil { return nil }
    return zd.republishSigningKeys(kdb)
}
```

`delete(map)` could not fail; a DB-build republish can. Returning the error keeps
failures loud (callers / logs); the unbuilt marker prevents silent signing with
removed keys via a stale `built=true` snapshot.

### 5.3 Own-tx vs external-tx (R1)

| Mutator | Owns commit? | Republish |
|---------|--------------|-----------|
| `DnssecKeyMgmt` (local tx) | yes | **Once** post-commit in defer, keyed by `dns.Fqdn(kp.Zone)` (R2) — not per-subcommand |
| `PromoteDnssecKey` | yes | self-republish after Commit |
| `UpdateDnssecKeyState` | yes | self-republish after Commit |
| `RolloverKey` (tx==nil) | yes | self-republish after Commit |
| `GenerateKeypair` (tx==nil, DNSKEY) | yes | self-republish after Commit |
| `forceZoneKeysToPolicyRoles` | yes | `zd.republishSigningKeys` after Commit |
| `GenerateKeypair` (external tx) | no | delete any cache op; **caller** republishes post-commit |
| `UpdateDnssecKeyStateTx` | no | no inline cache/republish; **caller** republishes |
| `RolloverKey` (external tx) | no | no inline cache/republish; **caller** republishes |

**External-tx callers that must republish after their Commit (enumerate):**

- **`APIkeystore` (`apihandler_funcs.go`)** — the production caller of `DnssecKeyMgmt`; always
  passes a non-nil (external) tx. After a successful Commit, if
  `resp.NeedsSigningKeysRepublish`, call `republishSigningKeysForZone` **before**
  `triggerResign`. The `DnssecKeyMgmt` localtx/R2 republish path is never taken here.
- `AtomicRollover` (`ksk_rollover_atomic.go` after `tx.Commit`)
- KSK observe advance that uses `UpdateDnssecKeyStateTx` (created→ds-published — active set unchanged; republish optional/harmless; still call for uniformity if cheap)
- Any future helper that passes a non-nil `*Tx` into `DnssecKeyMgmt` or the three external-tx mutators

`DnssecKeyMgmt` with `tx==nil` (local tx) still self-republishes once post-commit (R2).
That path is for direct/own-tx callers only — not the API.

**KeyStateWorker / reconcile / most rollover pipeline** call `UpdateDnssecKeyState`
(own-tx) — covered by self-republish. `EnsureActiveDnssecKeys` calls
`PromoteDnssecKey` / `GenerateKeypair(nil)` — covered by those self-republish paths;
`refreshActiveDnssecKeys` becomes an explicit `republishSigningKeys`.

### 5.4 Mid-tx ban

NEVER republish (or invalidate) mid-tx. Same D4 window as the old mid-tx map wipe.

## 6. Republish sites## 6. Republish sites (complete list)

Every keystore mutation that can change a zone's **active** set must republish
**after commit**. Sites today that touch `KeystoreDnskeyCache` (replace each
delete/wipe with `republishSigningKeys` / `republishSigningKeysForZone`):

| Site | Symbol / path | Trigger |
|------|---------------|---------|
| Keystore CLI/API add | `DnssecKeyMgmt` `add` | post-commit republish |
| Keystore generate | `DnssecKeyMgmt` `generate` (after `GenerateKeypair`) | post-commit |
| setstate | `DnssecKeyMgmt` `setstate` | post-commit (active set may change) |
| delete | `DnssecKeyMgmt` `delete` | post-commit |
| clear | `DnssecKeyMgmt` `clear` | **move** invalidate to post-commit; then republish (fixes mid-tx wipe) |
| purge | `dnssecKeyPurge` | post-commit republish per affected zone |
| policy-reset force | `forceZoneKeysToPolicyRoles` | replace cache wipe with `zd.republishSigningKeys` post-commit (zd already in hand) |
| Promote | `PromoteDnssecKey` | after *that* tx commits |
| State transitions | `UpdateDnssecKeyState` / `UpdateDnssecKeyStateTx` | after owning tx commits — covers **KeyStateWorker**, KSK/ZSK rollover promotions, reconcile retires |
| ZSK roll | `RolloverKey` | post-commit |
| Ensure bootstrap gen | `EnsureActiveDnssecKeys` after `GenerateKeypair` / `PromoteDnssecKey` | republish on zd after those commits (today's explicit cache deletes at `sign.go:507,537`) |
| refresh after mutation | `refreshActiveDnssecKeys` | becomes `zd.republishSigningKeys` (or Load after publish) — not a blind cache delete |
| ZSK active_at heal | `zsk_rollover.go` cache delete | metadata-only (`GetDnssecKeysByState`); **drop** the cache line — no snapshot republish |
| KSK pipeline create | `GenerateKskRolloverCreated` | created-only → **no** active republish required; skip unless it also touches active |

**`GenerateKeypair`:** own-tx (nil) self-republishes for DNSKEY after Commit;
external-tx does not — caller republishes (R1).

**Mass re-sign must NOT republish:** `SignZone`, `SetupZoneSigning`, resigner
ticks, QR online-sign, zone-updater signing — these rewrite RRSIGs only. They
**read** `zd.ActiveDnssecKeys()` and leave the pointer alone. That is the
scalability property this design exists for.

---

## 7. Accessor resolution — `GetDnssecKeys` after G3 (M1 + M2)

**M1 — never plain `Store` from the read path.** A lazy `Store(built)` can
clobber a concurrent post-commit republish (reader builds during a wide
`PrepareKeyCache` window; mutator republishes `{new}`; reader's Store lands
last with `{old}` → silent stale until next mutation). Use **CAS-if-unbuilt**:

```
loaded := zd.signingKeys.Load()
if loaded != nil && loaded.built {
    return loaded.Active, nil          // includes built&&keyless (M2 negative cache)
}
built, err := buildSigningKeysSnapshot(kdb, zone)   // built=true always on success
if err != nil { return nil, err }
if zd.signingKeys.CompareAndSwap(loaded, built) {   // loaded may be nil
    return built.Active, nil
}
return zd.signingKeys.Load().Active, nil            // lost the race — take winner
```

`GetDnssecKeys` resolution:

```
if state != Active:
    return loadDnssecKeysFromDB(...)                 // cold; no snapshot

zone = dns.Fqdn(zone)
if zd, ok := Zones.Get(zone); ok && zd != nil:
    return zd.activeKeysCAS(kdb)                     // § above

return loadDnssecKeysFromDB(kdb, zone, Active)       // unloaded — no zd
```

Hot callers with `*ZoneData` prefer `zd.ActiveDnssecKeys()` when `built`
(Ensure still generates when empty). Pre-Ready OK — no Ready dependency.

---

## 8. Bootstrap — eager + lazy (CAS-if-unbuilt)

| When | What |
|------|------|
| `ZoneData` created | Leave pointer nil (accessor falls back to `emptySigningKeys`); **do not** Store the shared sentinel |
| First successful `EnsureActiveDnssecKeys` / `SetupZoneSigning` | **Eager** `republishSigningKeys` → `Store({built:true, ...})` |
| First read while `!built` | **Lazy CAS-if-unbuilt** (§7) — never plain Store |
| Package sentinel | Return-only when `Load()==nil`; `built=false` |

Keyless zones: eager/lazy build succeeds with empty slices and `built=true` —
subsequent reads do not re-query the DB (M2; matches today's non-negative-cache
gap at keystore.go:1136/:1142 which returned before fill — we now negative-cache
correctly via `built`).

---

## 9. Removal of the global cache

**Confirm:** this PR **deletes** `KeyDB.KeystoreDnskeyCache` and every access:

- Field on `KeyDB` (`structs.go:820`)
- Init in `NewKeyDB` (`db.go:359`)
- All `delete(...)` / range-wipe sites listed in §6
- Cache hit + fill in `GetDnssecKeys` (`keystore.go:1071–1155`)
- Test `policy_reset_cache_test.go` — rewrite to assert **snapshot** freshness
  after clear/force (stale global cache scenario goes away; new assertion:
  post-commit snapshot matches DB active set)

**No residual global map.** No "compat shim" that keeps a map behind the
snapshot. Grep-clean for `KeystoreDnskeyCache` at PR end.

---

## 10. Consistency note — keys vs RRSIG snapshots

Keys and RRSIGs live in **separate** snapshots (`signingKeys` vs
`zoneSnapshot`). They are **not** published atomically together.

**Existing discipline (unchanged, still required):**

```
keystore Commit
  → republishSigningKeys          // new G3 step (was: cache invalidate)
  → stripStaleRRSIGsForKeySet     // stages + publishes zone-data snapshot
  → SignZone / apply transactional // adds RRSIGs; publishes zone-data again
```

Canonical reference: `forceZoneKeysToPolicyRoles` + `resetZonePolicy`
(`apihandler_zone.go` after force) and D7 in the policy-reload decisions doc.

**Torn-state window:** between keystore commit+keys-republish and the later
zone-data publish, a reader can see **new keys + old RRSIGs** (or, during strip,
briefly fewer RRSIGs). That window **already exists today** (decoupled
`KeystoreDnskeyCache` vs zone snapshot). G3 does **not** widen it:

- Readers never see a half-updated Go map (the crash class).
- They see one immutable keys snapshot XOR the next — same as #279/#287.
- Orphan/DNSKEY RRSIG correctness still rests on strip-after-commit → re-sign,
  not on atomic co-publication of keys+RRSIGs.

**Mass re-sign:** zone-data snapshot republishes many times; keys snapshot stays
put → no cross-zone keys contention, and no extra torn windows from keys.

---

## 11. Call-site migration (implementation sketch)

| Phase | Work |
|-------|------|
| A | Add type, field, accessors, `build`/`republish`, seed sentinel |
| B | Wire post-commit republish at every §6 site; delete cache ops |
| C | Rewrite `GetDnssecKeys` per §7; extract `loadDnssecKeysFromDB` |
| D | Hot callers with `*ZoneData` → `zd.ActiveDnssecKeys()` (+ Ensure still generates) |
| E | Delete `KeystoreDnskeyCache` field + init; grep-clean |
| F | Tests (§12) |

PR-2 (refresh-engine) then consumes `zd.ActiveDnssecKeys()` / `SigningKeys()` on
reload without touching any global map.

---

## 12. Test plan (freshness matrix — R4)

### 12.1 `-race` regression (mandatory)

`TestSigningKeysSnapshotNoRace` — mirror `runtime_config_race_test.go`:
many readers on `ActiveDnssecKeys` / `SigningKeys` vs one mutator that commits +
republishes. Must stay clean under `-race`
(`GOROOT=/opt/local/lib/go CGO_ENABLED=1`).

### 12.2 Mass re-sign does not Store

Publish keys snapshot; record pointer; `SignZone` without key mutation → same
pointer. Contrast: real key mutation → pointer changes.

### 12.3 Freshness matrix (per mutation path)

For each path, after successful commit assert
`zd.ActiveDnssecKeys()` keyids match DB active keyids (`GetDnssecKeysByState`
or direct SQL):

| Path | Test |
|------|------|
| setstate | DnssecKeyMgmt setstate → active |
| generate | DnssecKeyMgmt generate / GenerateKeypair(nil) |
| delete | DnssecKeyMgmt delete (active → removed) |
| rollover | RolloverKey(nil) / ZSK roll |
| promote | PromoteDnssecKey |
| clear | DnssecKeyMgmt clear (+ regen) |
| force | forceZoneKeysToPolicyRoles |

Plus:

- **M1:** concurrent lazy-read (force unbuilt) + mutation → ends with **fresh**
  (new) keys, never the pre-mutation set.
- **M3:** force republish build failure (inject / close DB) → error returned /
  logged; snapshot `!built` (or next read rebuilds); never silently serve the
  pre-failure built snapshot as if current.

Rewrite `policy_reset_cache_test.go` into this matrix (stale global-cache
scenario is gone).

### 12.4 Nil-safety / built semantics

- Fresh `ZoneData`: `SigningKeys()` non-nil, `built==false`.
- Keyless zone after build: `built==true`, empty slices; second read no DB
  round-trip (optional: count queries).

### 12.5 Full suite gate

`build` / `vet` / full `v2 -race` green before each commit.

## 13. Non-goals## 13. Non-goals / out of scope

- Folding keys into `zoneSnapshot` or `RuntimeConfig`.
- Snapshotting published/standby/retired (see §4).
- Per-zone sign coalescing / worker pool (findings doc items 1 and 3) — separate.
- SIG0 key caches (`KeystoreSig0Cache`) — separate race class if any.
- Widening `kdb.mu` into a general cache lock.

---

## 14. Implementation rules (when signed off)

- Work only in the `tdns-signing-keys-snapshot` worktree on
  `feature/signing-keys-snapshot`.
- GPG-sign every commit (**never** `--no-gpg-sign`).
- No `Co-Authored-By` / AI bylines.
- Implement → commit → push → open PR → **stop** (do not merge).
- `build` / `vet` / full `v2 -race` green before each commit.

---

## 15. Success criteria

- Zero remaining references to `KeystoreDnskeyCache`.
- Hot signer / QR path reads `zd.ActiveDnssecKeys()` lock-free.
- Every active-set mutation republishes **post-commit** only.
- Mass re-sign does not `Store` a new keys snapshot.
- `-race` regression in §12.1 clean; freshness matrix §12.3 green (incl. M1/M3).
- No wider torn-state window than today's cache vs zone-snapshot decoupling.
- Ready for Plan B PR-2 to consume the accessor on reload.

---

## 16. Sign-off answers + method defaults

| Item | Decision |
|------|----------|
| Active-only (§4) | **Yes** |
| Lazy fill | **CAS-if-unbuilt** (M1) — not plain Store; return-without-store also acceptable |
| clear mid-tx RRSIG strip | **Out of G3** — follow-up ticket (D7-ordering violation) |
| **D1** choke-point vs N-caller | **N-caller (R1) + freshness matrix (R4)** unless Johan overrides. Note: the APIkeystore external-tx gap showed N-caller still misses real callers; a tx-registered deferred republish remains an optional structural alternative. |
| **D2** shadow-map vs big-bang | **Big-bang**, grep-clean at PR end |

## 17. References## 17. References

- `docs/2026-07-15-transactional-policy-reload-decisions.md` — G3, D4, D7
- `docs/2026-07-14-snapshot-branch-signing-findings.md` — per-`zd` active-key cache sketch
- `docs/2026-07-15-runtime-config-snapshot-plan.md` — #287 pattern to mirror
- `v2/runtime_config.go` — `ConfLive` / seed / publish
- `v2/zone_snapshot.go` / `zone_mutation.go` — #279 publish path
- `v2/keystore.go` — `GetDnssecKeys`, `forceZoneKeysToPolicyRoles` post-commit
- `v2/policy_reset_cache_test.go` — stale-cache regression to retarget
- `v2/runtime_config_race_test.go` — race-test template
