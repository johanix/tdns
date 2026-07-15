# Implementation plan — persist effective DNSSEC policy + transactional config-reload (P0-2 / Plan B)

**Status:** ready for implementation. Self-contained — no prior context needed.
**Origin:** Finding 2 / Decision 2 in
`docs/2026-07-14-snapshot-branch-signing-findings.md` (Plan B / P0-2).
**Base branch — branch off `main` (a96cc79 or later).** All three prerequisites
are merged; this plan assumes them:

- **PR #285 (CLI relocation) — MERGED (22424ff).** The policy CLI verbs moved
  under `zone dnssec`, and `set-policy` was renamed to `policy-set` — **CLI verb
  and wire command**. So throughout this plan, read `zone set-policy` as
  **`zone dnssec policy-set`**, the wire command as **`policy-set`** (not
  `set-policy`), and the escape hatch (§6.7) lands as **`zone dnssec policy-reset`**.
  The server handlers `setZonePolicy` / `changeZonePolicy` keep their names.
- **PR #286 (Finding 4) — MERGED (in a96cc79).** The synchronous reload
  `SetupZoneSigning` at `parseconfig.go:995` is deleted; the refresh engine
  (`triggerResign` + post-refresh sign) is the sole reload signer, off `confMu`.
  §6.5 is DONE; the old §3.2 "parseconfig signs synchronously" gap and its
  ordering race are gone.
- **PR #287 (runtime-config snapshot) — MERGED (in a96cc79). ⚠ READ THIS — it
  changes how you read config policy.** The reloadable runtime config is now an
  immutable **copy-on-write snapshot** (`RuntimeConfig`, `v2/runtime_config.go`),
  published atomically at the end of every reload path and read **lock-free** via
  `ConfLive()`:
  - **Read config policy structs from `ConfLive().DnssecPolicies[name]`** (and
    MultiSigner from `ConfLive().MultiSigner`), **not** from
    `conf.Internal.DnssecPolicies`, and **do not take `confMu`** for policy
    lookups. The CLI handlers already do this (`setZonePolicy`
    `apihandler_zone.go:371`, `changeZonePolicy` `:470`), as do all three
    refresh-engine policy blocks (`:273 / :413 / :617`). `conf.Internal.DnssecPolicies`
    is now parse-scratch, copied into the snapshot at publish — do not read it at
    runtime.
  - The snapshot is **read-only for this project.** A config reload republishes it
    with the new policies (a reader always sees the current epoch); this project's
    *applied-policy* state lives in the DB (§4), separate from the snapshot. You do
    **not** add fields to `RuntimeConfig`.
  - Wherever this plan still says "resolve the policy struct under `confMu`" or
    reads `conf.Internal.DnssecPolicies`, substitute
    "`ConfLive().DnssecPolicies[name]`, lock-free."

The *minimal refuse-keeping-old guard* for incompatible algorithm changes on
reload is also merged (`c57a564`, `applyReloadedPolicyLocked` in
`refreshengine.go`). This plan completes the full Decision 2: persist last-applied
policy for every signed zone, extract a shared transactional apply core from the
CLI path, and wire config reload/restart through it.

Line numbers below are anchors as of 2026-07-15 and drift with commits — always
re-locate by the function/symbol name.

---

## 1. The problem

Changing a zone's DNSSEC policy via **`zone set-policy` / `change-policy`** is
transactional today:

1. Rebind in-memory policy (`zd.DnssecPolicy` / `zd.DnssecPolicyName`)
2. `UpdateSigValidityFloor`
3. `SignZone(kdb, force=true)`
4. **On failure:** revert in-memory binding, return error
5. **On success:** persist override (`SetZonePolicyOverride`) so the change
   survives restart

See `setZonePolicy` (`apihandler_zone.go:363`) and `changeZonePolicy`
(`apihandler_zone.go:465`).

Changing policy via **config-file edit + reload** is **not** transactional:

| Step | What happens | Gap |
|------|--------------|-----|
| ~~`parseconfig.go:995`~~ | *Removed in #286 — reload no longer signs synchronously in `parseconfig`; the refresh engine is the sole reload signer.* | — |
| `refreshengine.go:406-453` | Rebind via `applyReloadedPolicyLocked`; async `triggerResign` on benign apply | **No revert** if re-sign fails — the remaining transactional gap this plan closes |
| DB | `ZonePolicyOverride` only written by CLI | Config-only zones have **no last-applied record** — a config change cannot be detected as a change across restart |

**Symptom (Finding 1 instance):** operator edits `dnssec_policy` in YAML to a
policy whose KSK algorithm differs from active keys. Reload rebinds the new
policy; `SignZone` refuses (KSK algorithm rollover not built). The zone is left
bound to an unusable policy. Queries may still look signed ephemerally while
stored RRSIGs (AXFR, secondaries) are absent or stale.

**Goal:** config reload and restart must behave like the CLI path: refuse or
apply transactionally, never half-bind an unusable policy, and persist what the
zone was **last successfully signed under** so intent vs reality is always
comparable.

---

## 2. Design principles

1. **Operator intent ≠ keystore keys.** A keystore may hold retired or
   multi-algorithm keys during a rollover. The authoritative policy choice is
   a single named policy — do not infer it from key material.
2. **Intent vs last-applied.** At load/reload/restart, compare what the
   operator *wants* (YAML `dnssec_policy`, or a live CLI override if set) against
   what was *last successfully signed* (the DB `applied_*` record). Only apply a
   diff through the transactional core. **Never classify against the in-memory
   binding alone** — on restart the binding is freshly loaded from config and
   equals intent, which would hide a pending change (see Phase 0 ①).
3. **Single source of truth.** Extract `applyZonePolicyTransactional` from
   `setZonePolicy` and call it from CLI **and** config paths so they cannot
   drift.
4. **Fail closed on incompatible algorithm change.** Refuse, keep last-applied
   policy bound, log a warning. When the auto-rollover engine lands, route here
   instead of refusing. Surfacing warnings in `config status` is **item 9**
   (P1-4) and can follow.
5. **Do not conflate CLI override with last-applied.** Today
   `ZonePolicyOverride.policy` is sparse CLI *intent*. Plan B adds separate
   `applied_*` columns so config-only zones get a durable record without implying
   a CLI override.

---

## 3. Current code layout

### 3.1 CLI transactional path (reference implementation)

```
setZonePolicy / changeZonePolicy (apihandler_zone.go)
  → resolve pol := ConfLive().DnssecPolicies[name]   (snapshot, lock-free — #287)
  → snapshot old binding
  → rebind zd.DnssecPolicy / DnssecPolicyName
  → UpdateSigValidityFloor
  → SignZone(kdb, true)
  → on error: revert binding
  → on success: SetZonePolicyOverride (CLI intent persistence)
```

`changeZonePolicy` adds entry guards **before** rebind (CSK, both-role alg
change, in-flight ZSK roll, strict mode, KSK-only alg) — these stay outside the
shared core and are **CLI-only today** (see Phase 0 minor item ⑤).

### 3.2 Config reload path (gaps)

```
ParseZones (parseconfig.go)
  → on reload (!FirstZoneLoad): NO synchronous sign (removed in #286)
  → queue ZoneRefresher to refresh engine

RefreshEngine — existing zone, ConfigUpdate (refreshengine.go:406-453)
  → EffectiveDnssecPolicyName (intent)
  → applyReloadedPolicyLocked (alg refuse only — compares in-memory old vs new)
  → if applied: UpdateSigValidityFloor + triggerResign (async, no revert)   ← the gap this plan closes
```

**Ordering race — already resolved (#286).** The prior race (`parseconfig` signs
under the **old** binding before the refresh engine rebinds to the **new**
policy) is gone: with the synchronous `parseconfig` sign deleted (Finding 4 /
#286), the refresh engine is the sole reload signer. The remaining gap is purely
transactional — the refresh-path `triggerResign` still has **no revert** if the
re-sign fails, which is what Phase 3 fixes.

### 3.3 Policy storage today

Table `ZonePolicyOverride` (`db_schema.go:188`):

```sql
zone    TEXT PRIMARY KEY
policy  TEXT NOT NULL
set_at  TEXT
```

API (`db_zone_policy_override.go`):

- `SetZonePolicyOverride` / `GetZonePolicyOverride` / `ClearZonePolicyOverride`
- `EffectiveDnssecPolicyName(kdb, zone, configName)` — override wins over YAML

Only CLI paths write this table. Config-only signed zones have no row.

### 3.4 Algorithm guards (reuse, do not duplicate)

| Location | Role |
|----------|------|
| `applyReloadedPolicyLocked` (`refreshengine.go:184`) | Refuse KSK/ZSK alg change on reload (in-memory old vs new config) — **replaced** by applied-vs-intent classifier in Phase 3 |
| `changeZonePolicy` entry guards (`apihandler_zone.go:495-543`) | CSK, both-role, in-flight ZSK, strict, KSK-only — CLI only |
| `reconcileActiveKeyAlgorithms` (`sign.go:297`) | Backstop inside `SignZone`; refuses unsafe swaps |

### 3.5 Integration sites (plan seam)

Three `EffectiveDnssecPolicyName` call sites in `refreshengine.go`:

- **:264** — pre-registered zone first bind (restart / initial load)
- **:409** — existing zone config reload
- **:610** — dynamic zone first bind

### 3.6 Out of scope (Plan B v1)

**Signed ↔ unsigned transitions via config** (e.g. toggling
`online-signing`/`inline-signing`, or setting `dnssec_policy: default` ↔ removing
signing options) are **not** covered by this plan. They continue to follow
today's `parseconfig` option handlers and `SetupZoneSigning` / unsigned publish
logic. Plan B applies only to zones that remain signed across the reload or
restart.

---

## 4. Schema change

Extend `ZonePolicyOverride` with last-applied columns. Keep existing `policy` /
`set_at` semantics for **CLI override intent** (sparse).

```sql
-- New columns (added by dbMigrateSchema — see below)
applied_policy  TEXT    -- last policy name the zone was successfully signed under
applied_source  TEXT    -- 'config' | 'command'
applied_at      TEXT    -- ISO timestamp of last successful apply
```

**Row shapes after migration:**

| Scenario | `policy` (override) | `applied_*` |
|----------|---------------------|-------------|
| Config-only signed zone | NULL / absent row initially | backfilled without re-sign on first post-upgrade reload (see §5.5) |
| CLI `set-policy` success | target name | same name, source=`command` |
| YAML changed, reload refused | unchanged | unchanged (still last-applied) |
| Override cleared | row deleted or override NULL | applied columns retained |

**Migration — two facilities, do not conflate:**

| Step | Facility | Location | What |
|------|----------|----------|------|
| Add columns | `dbMigrateSchema` | `db.go:175` | Idempotent `ALTER TABLE ZonePolicyOverride ADD COLUMN applied_policy …` (and `applied_source`, `applied_at`). Same pattern as existing column migrations. |
| Backfill CLI rows | `dbMigrateData` | `db.go:131` | For existing rows where `policy` is set: copy `policy` → `applied_policy`, set `applied_source = 'command'`, `applied_at = set_at`. CLI always wrote after successful sign. |
| Runtime backfill (config-only zones) | refresh engine | §5.5 / §6.2 | No data migration — silent DB write on first reload after upgrade when zone is already signed under intent. |

**New API** (extend `db_zone_policy_override.go` or add `db_zone_policy_state.go`):

```go
func GetZoneAppliedPolicy(kdb *KeyDB, zone string) (name string, source string, ok bool, err error)
func SetZoneAppliedPolicy(kdb *KeyDB, zone, policy, source string) error
// Optional aggregate:
func GetZonePolicyState(kdb *KeyDB, zone, configName string) (intent, applied string, overridden bool, err error)
```

`EffectiveDnssecPolicyName` — **unchanged** (reads override `policy` column only).

---

## 5. Transactional core

**New file:** `v2/zone_policy_apply.go`

### 5.1 Types and classification

**Design lock (blocking ①):** classification is always **applied (from DB) vs
intent**, never current in-memory binding vs intent. On a live reload,
applied-policy struct equals the old binding anyway; on restart the binding is
freshly loaded from config (= intent) and comparing against it would return
`PolicyChangeNone` and silently miss the YAML edit.

```go
type PolicyApplySource string

const (
    PolicyApplySourceConfig  PolicyApplySource = "config"
    PolicyApplySourceCommand PolicyApplySource = "command"
)

type PolicyChangeClass int

const (
    PolicyChangeNone           PolicyChangeClass = iota // same name, same effective algs
    PolicyChangeBenignInternals                         // same name, lifetimes/sigvalidity/ttls/rollover params
    PolicyChangeCompatibleName                          // different name, same KSK+ZSK algs
    PolicyChangeIncompatibleAlg                         // KSK or ZSK algorithm differs — refuse (v1)
)
```

```go
// classifyPolicyChange compares the LAST-APPLIED policy (from DB, resolved to
// a struct via ConfLive().DnssecPolicies) against INTENT (operator wants).
// Do NOT pass zd.DnssecPolicy as the "old" side — that breaks restart detection.
// Precondition: appliedPol != nil. The applied-missing case is resolved in §6.2
// Branch 0 (backfill or first apply) BEFORE the classifier runs.
func classifyPolicyChange(
    appliedPol *DnssecPolicy, appliedName string,
    intentPol *DnssecPolicy, intentName string,
) PolicyChangeClass
```

Resolution helper (used uniformly at all three refresh-engine sites):

```go
// resolvePolicyPair loads intent via EffectiveDnssecPolicyName and applied via
// GetZoneAppliedPolicy, then looks up both policy structs from the ConfLive()
// snapshot (lock-free — no confMu).
func resolvePolicyPair(kdb *KeyDB, conf *Config, zone, configPolicyName string) (
    intentName string, intentPol *DnssecPolicy,
    appliedName string, appliedPol *DnssecPolicy, appliedOK bool,
    err error,
)
```

Rules (v1):

- Compare effective `KSKAlgorithm` / `ZSKAlgorithm` on **appliedPol** vs
  **intentPol** (same fields as `applyReloadedPolicyLocked` and `setZonePolicy`).
- Alg mismatch → `PolicyChangeIncompatibleAlg` (delegate to auto-rollover engine
  later; refuse for now).
- Same name → benign internals or none (cheap re-sign path).
- Different name, same algs → `PolicyChangeCompatibleName` (transactional apply).

For incompatible changes on the **config path**, refuse (same as c57a564).
Gradual ZSK roll remains CLI `change-policy` only. Config reload during an
in-flight CLI ZSK roll is handled separately (Phase 0 minor ⑤).

### 5.2 Core function

```go
// applyZonePolicyTransactional rebinds, re-signs, persists applied policy.
// On SignZone failure it reverts the in-memory binding and returns an error
// without updating applied_*.
//
// When source is PolicyApplySourceCommand, also calls SetZonePolicyOverride
// on success (CLI intent).
func applyZonePolicyTransactional(
    zd *ZoneData,
    kdb *KeyDB,
    newPol *DnssecPolicy,
    newName string,
    source PolicyApplySource,
) (newRRSIGs int, err error)
```

Body lifted from `setZonePolicy` (`apihandler_zone.go:363`, the rebind → sign →
persist block):

1. Require signed zone (`OptOnlineSigning` or `OptInlineSigning`).
2. Snapshot `oldPol`, `oldName` under `zd.mu` (for revert only — not for classify).
3. Rebind `zd.DnssecPolicy = newPol`, `zd.DnssecPolicyName = newName`.
4. `UpdateSigValidityFloor(...)`.
5. `newRRSIGs, err = zd.SignZone(kdb, true)`.
6. On error: revert binding; return err.
7. On success: `SetZoneAppliedPolicy(kdb, zone, newName, string(source))`.
8. If `source == PolicyApplySourceCommand`: `SetZonePolicyOverride(...)`.

### 5.3 Refuse helper (config path)

```go
// refusePolicyChange keeps the zone signing under appliedName. Re-binds
// appliedPol when it can be resolved from ConfLive().DnssecPolicies;
// see §5.6 when the applied policy name is no longer in config.
func refusePolicyChange(zd *ZoneData, intentName, appliedName string, appliedPol *DnssecPolicy, reason string)
```

Used when `classifyPolicyChange` returns incompatible, or entry guards block
apply on the config path.

### 5.4 Intent vs applied diff

```go
func zonePolicyNeedsApply(kdb *KeyDB, zone, intentName string) (needsApply bool, appliedName string, appliedOK bool, err error)
```

- `appliedOK == false` → applied record absent; **does not** automatically mean
  `needsApply == true` (see §5.5 — backfill path).
- `appliedOK && intentName == appliedName` → `needsApply = false` for
  name-level changes; classifier still runs for benign-internal edits (same
  name, changed struct fields in config map).

### 5.5 Applied missing — backfill without thundering herd (blocking ②)

**Problem:** on first post-upgrade reload, every config-only signed zone has no
`applied_*` row. Treating "missing applied" as `needsApply = true` would force a
full `SignZone(force=true)` on each zone — a thundering-herd re-sign of every PQ
zone that is already correctly signed.

**Decision:** distinguish three states:

| State | Condition | Action |
|-------|-----------|--------|
| **Applied present** | `GetZoneAppliedPolicy` ok | Normal intent vs applied flow (§6.2) |
| **Applied missing, eligible backfill** | No applied row; zone already has active keys whose algorithms match **intent** policy; zone is serving stored RRSIGs (or equivalent "already signed under intent" predicate) | **Silent backfill only:** `SetZoneAppliedPolicy(zone, intentName, "config")` — **no** forced re-sign. Bind in-memory to intent (already the case on restart). |
| **Applied missing, needs sign** | No applied row; zone is newly signed, keys missing, or intent algs ≠ active key algs | Normal `SetupZoneSigning` / transactional apply; write applied on success |

```go
// backfillAppliedIfEligible writes applied=intent when the zone is already
// correctly signed under intent and no applied row exists. Returns true if
// backfill happened (caller skips re-sign for policy purposes).
func backfillAppliedIfEligible(kdb *KeyDB, zd *ZoneData, intentName string, intentPol *DnssecPolicy) (backfilled bool, err error)
```

**Critical:** the backfill branch must be reachable **independently** of
`intentName == appliedName` — when applied is absent, that equality check never
fires. §6.2 lists backfill as its own first branch.

After backfill, subsequent reloads use the normal cheap path.

### 5.6 Applied policy deleted from YAML (minor ③)

If `appliedName` is set in DB but `ConfLive().DnssecPolicies[appliedName]` no
longer exists (operator removed the policy definition):

- **Do not** nil-deref `appliedPol` or refuse-bind into a missing struct.
- **Fallback:** keep the zone's current in-memory binding and existing active
  keys signing; log a warning; set a non-service-impacting DNSSEC warning on
  the zone (same philosophy as Decision 2 / item 9 deferral).
- Do not attempt transactional apply toward intent if intent policy is also
  missing — quarantine with `SetError(DnssecError, …)` only when intent itself
  is unresolvable (existing behaviour at refreshengine.go:276-280).

---

## 6. Wiring — call graph after Plan B

### 6.1 CLI handlers (refactor only)

| Handler | Change |
|---------|--------|
| `setZonePolicy` | Entry validation + `applyZonePolicyTransactional(..., PolicyApplySourceCommand)` + response formatting |
| `changeZonePolicy` | Keep entry guards; replace inline rebind/sign/revert with core call |

No behaviour change expected for CLI — tests should pass unchanged.

### 6.2 Refresh engine — existing zone reload (`refreshengine.go:406-453`)

Replace:

```
applyReloadedPolicyLocked → reapplyPolicy → triggerResign
```

With (pseudocode — **applied vs intent throughout**):

```
intentName, intentPol, appliedName, appliedPol, appliedOK := resolvePolicyPair(...)

// Branch 0 — applied missing (blocking ②). BOTH sub-branches RETURN, so every
// branch below runs only when appliedOK == true (i.e. appliedPol is non-nil).
// This is what makes the appliedPol dereference in Branch 1b safe.
if !appliedOK {
    // 0a — already correctly signed under intent: record applied, no re-sign.
    if backfillAppliedIfEligible(kdb, zd, intentName, intentPol) {
        return
    }
    // 0b — genuine first apply (newly signed / keys missing / active-key algs
    // differ from intent). There is NO appliedPol to classify against, so apply
    // toward intent directly; the SignZone alg backstop (reconcileActiveKeyAlgorithms,
    // sign.go:297) still refuses an unsafe swap. The core writes applied on success.
    if _, err := applyZonePolicyTransactional(zd, kdb, intentPol, intentName, PolicyApplySourceConfig); err != nil {
        log warning (core reverted the binding); applied unchanged
    }
    return
}

// appliedOK == true from here on ⇒ appliedPol is non-nil.
class := classifyPolicyChange(appliedPol, appliedName, intentPol, intentName)

// Branch 1 — no name-level change (or benign internals only)
if intentName == appliedName &&
   (class == PolicyChangeNone || class == PolicyChangeBenignInternals) {

    rebind zd to intentPol (same name, struct may have changed in config map)
    UpdateSigValidityFloor(zd, intentPol, ...)   // pick up sig-validity/TTL edits
    cheap re-sign (triggerResign) if zone data or policy internals changed
    return
}

// Branch 1b — in-flight CLI ZSK roll (minor ⑤): skip config re-apply.
// appliedPol.ZSKAlgorithm is safe to read — appliedOK guaranteed above.
if zskAlgRollInFlight(kdb, zone, appliedPol.ZSKAlgorithm).InFlight {
    log debug; keep current binding; do not treat intent≠applied as config apply
    return
}

// Branch 2 — compatible name change
if class == PolicyChangeCompatibleName {
    applyZonePolicyTransactional(zd, kdb, intentPol, intentName, PolicyApplySourceConfig)
    on error: log warning (revert inside core); applied unchanged
    return
}

// Branch 3 — incompatible alg change
if class == PolicyChangeIncompatibleAlg {
    refusePolicyChange(zd, intentName, appliedName, appliedPol, ...)
    re-bind appliedPol when resolvable (§5.6 fallback if not)
    return
}
```

**Remove `applyReloadedPolicyLocked`** once the classifier covers its cases;
update `reload_policy_alg_guard_test.go` to target `classifyPolicyChange` +
refuse helper with **applied vs intent** fixtures (including a restart scenario
where in-memory binding equals intent but applied differs).

Because classification uses DB applied — not in-memory binding — this path is
correct on both live reload and restart, and does not depend on parseconfig
signing before the refresh engine runs.

### 6.3 Refresh engine — first bind / restart (`refreshengine.go:260-308`)

Use the **same** `resolvePolicyPair` → backfill → classify → apply/refuse flow
as §6.2. Do **not** bind `intentPol` into `zd.DnssecPolicy` before running the
diff — on restart that pre-bind is exactly what hides the change.

Suggested order:

1. Resolve intent + applied via `resolvePolicyPair` (policy structs from the `ConfLive()` snapshot, lock-free).
2. Run Branch 0 (backfill) if applied missing.
3. Classify **appliedPol vs intentPol** (not `zd.DnssecPolicy`).
4. On refuse: bind `appliedPol` / `appliedName` when resolvable (§5.6 fallback).
5. On apply or cheap path: bind intent (or applied on refuse) **then**
   `initialLoadZone` if zone data not yet loaded, then sign/backfill as needed.

Zone data must be loaded before `SignZone`; backfill-only (Branch 0) may run
before `initialLoadZone` if the eligibility predicate only needs keystore keys.

### 6.4 Dynamic zone path (`refreshengine.go:608+`)

Same intent/applied/backfill/classify flow as §6.3.

### 6.5 parseconfig reload ordering (`parseconfig.go:987-998`) — Finding 4 ✅ DONE

**Already on `main` (via #286) — nothing to implement here.** The synchronous
`SetupZoneSigning` on reload (`!FirstZoneLoad`) formerly at `parseconfig.go:995`
has been **deleted** (Finding 4). The refresh engine now receives the
`ZoneRefresher` from `ParseZones` and is the sole reload signer, off `confMu` — so
this project starts from a tree where the removal is already in place. No gated
partial fix, no second signing path: verify the deletion is present in your base,
then build on it.

**First load:** the `OnFirstLoad → SetupZoneSigning` deferral for genuinely new
zones was kept by #286; refresh-engine backfill (§5.5) handles post-upgrade
config-only zones without a herd re-sign.

### 6.6 Cheap no-change path

When applied is present, intent == applied, and class is none/benign:

- Rebind to refreshed `intentPol` struct from config map (same name)
- **`UpdateSigValidityFloor`** — required so sig-validity / TTL / KASP edits apply
- `triggerResign` if zone data or policy internals changed
- Do **not** write applied again unless backfilling (name unchanged)

Helper:

```go
func recordAppliedPolicyOnSignSuccess(kdb *KeyDB, zd *ZoneData, source PolicyApplySource) error
```

Called from transactional core and from first-sign paths — **not** from silent
backfill (backfill calls `SetZoneAppliedPolicy` directly).

### 6.7 Escape hatch — `zone dnssec policy-reset` (test/lab; dangerous)

Once `applied_*` is persisted, an *abrupt* policy switch is refused by design (an
incompatible KSK/ZSK algorithm change needs a rollover that is not built). That is
correct for production but blocks iteration on **test zones**, so this project
must also ship a forced reset. **Clearing the `applied_*` row alone is not enough:**
the zone's active keys are still the old algorithm, so the next `SignZone` hits
`reconcileActiveKeyAlgorithms` (`sign.go:297`) and refuses. The reset must also
**drop the keys** so fresh ones are generated under the config policy.

**Operation — `tdns-cli auth zone dnssec policy-reset --zone <name> --confirm`:**

1. Refuse without `--confirm`; require an explicit single zone (no wildcard / no
   bulk).
2. **Delete the zone's DNSSEC keys** from the keystore (reuse the
   `keystore dnssec clear` path: clear keys → the sign path regenerates them).
3. **Clear the persisted policy rows:** `ClearZoneAppliedPolicy` (new) **and**
   `ClearZonePolicyOverride` (existing) — wipe both the CLI intent-override and
   the last-applied record, so the zone falls back to its **config**
   `dnssec_policy`.
4. **Trigger a fresh sign** (`triggerResign` / `SetupZoneSigning`):
   `EnsureActiveDnssecKeys` generates new keys under the config policy, `SignZone`
   re-signs, and the transactional core records `applied = config`.
5. **Log a loud WARN:** this is an *abrupt* switch that **breaks the chain of
   trust** — the parent DS will not match the new KSK until re-published, so
   validators go bogus until the operator updates DS.

**Not for production.** No server-level gate beyond `--confirm` + naming the zone
+ the warning (same posture as `rm -f`); the operator owns the consequences.

Wiring:

- **Server:** new `case "policy-reset":` in `apihandler_zone.go` (beside
  `policy-set` / `change-policy`) → `resetZonePolicy(zd, kdb)` doing steps 2–4.
- **CLI:** `policy-reset` under the `zone dnssec` group (from #285), `--confirm`
  required — sibling of `policy-set` / `policy-change`.
- **DB:** new `func ClearZoneAppliedPolicy(kdb *KeyDB, zone string) error`.

---

## 7. Implementation phases

### Phase 0 — Design lock (~30 min)

Baseline confirmations:

- Schema: separate `applied_*` columns; `policy` stays CLI override.
- v1 refuse scope: all effective alg changes on **config path** (same as c57a564);
  gradual ZSK roll stays CLI `change-policy` only.
- Signed ↔ unsigned config toggles: **out of scope** (§3.6).

#### Phase 0 addendum — decisions gating Phase 3

| ID | Severity | Decision | Sections |
|----|----------|----------|----------|
| **①** | **BLOCKING** | Classify **applied (DB) vs intent** everywhere via `classifyPolicyChange(appliedPol, appliedName, intentPol, intentName)`. Never use `zd.DnssecPolicy` as the "old" side. Use `resolvePolicyPair` at all three refresh-engine sites. | §2, §5.1, §6.2, §6.3 |
| **②** | **BLOCKING** | **Applied missing → backfill without re-sign** when zone is already signed under intent (`backfillAppliedIfEligible`). Branch 0 in §6.2 is independent of `intent == applied`. Do not route every config-only zone through forced re-sign on first post-upgrade reload. | §5.4, §5.5, §6.2 |
| ③ | minor | Applied policy name deleted from YAML: refuse-bind fallback keeps existing keys signing + warning; no nil-deref. | §5.6 |
| ④ | ✅ done | Remove reload `SetupZoneSigning` (Finding 4 `confMu` fix) — **already done in #286**; not part of this project. Just verify it's present in the base. | §6.5 |
| ⑤ | minor | Config reload during in-flight CLI ZSK roll: config path checks `zskAlgRollInFlight` and **skips** treating intent≠applied as a config-driven re-apply (Branch 1b). Does not duplicate full `change-policy` entry guards on config path. | §6.2 |
| ⑥ | minor | Benign-internals cheap path must call `UpdateSigValidityFloor`. | §6.2 Branch 1 |
| ⑦ | minor | Signed ↔ unsigned via config: **out of scope** for Plan B v1. | §3.6 |

**Phase 3 must not start until ① and ② are reflected in code and tests.**

### Phase 1 — Schema + persistence (small)

| Task | Files |
|------|-------|
| Add `applied_policy`, `applied_source`, `applied_at` via `dbMigrateSchema` | `v2/db.go` |
| Backfill existing CLI override rows via `dbMigrateData` | `v2/db.go` |
| Update schema comment | `v2/db_schema.go` |
| `GetZoneAppliedPolicy`, `SetZoneAppliedPolicy` | `v2/db_zone_policy_override.go` |
| Unit tests | `v2/db_zone_policy_override_test.go` |

**Exit criteria:** schema migration idempotent; data backfill idempotent; applied
CRUD tested; existing override tests still pass.

### Phase 2 — Transactional core (medium)

| Task | Files |
|------|-------|
| `resolvePolicyPair`, `classifyPolicyChange` (applied vs intent), `applyZonePolicyTransactional`, `zonePolicyNeedsApply`, `backfillAppliedIfEligible` | `v2/zone_policy_apply.go` (new) |
| Refactor `setZonePolicy` | `v2/apihandler_zone.go` |
| Refactor `changeZonePolicy` rebind/sign block | `v2/apihandler_zone.go` |
| **Escape hatch** (§6.7): `resetZonePolicy` handler + `case "policy-reset"`, `ClearZoneAppliedPolicy`, and the `zone dnssec policy-reset --confirm` CLI command | `v2/apihandler_zone.go`, `v2/db_zone_policy_override.go`, `v2/cli/zone_cmds.go` |
| Unit tests (revert on sign failure, applied persist, classify with applied≠intent while binding=intent) | `v2/zone_policy_apply_test.go` (new) |

**Exit criteria:** CLI behaviour unchanged; classifier tested with restart-shaped
fixtures (applied ≠ intent, binding would equal intent); backfill eligibility
tested; `policy-reset` drops keys + clears applied/override → zone re-signs under
the config policy and records `applied = config`.

### Phase 3 — Refresh engine wiring (medium/large) — **requires Phase 0 ①②**

| Task | Files |
|------|-------|
| Replace reload rebind/resign with resolve → backfill → classify → apply/refuse | `v2/refreshengine.go` |
| First-bind / restart path (same flow, no pre-bind before classify) | `v2/refreshengine.go` |
| Dynamic zone path | `v2/refreshengine.go` |
| Remove `applyReloadedPolicyLocked` | `v2/refreshengine.go` |
| ~~Remove reload `SetupZoneSigning` (Finding 4)~~ — **already done in #286**, not a task here | ~~`v2/parseconfig.go`~~ |
| Branch 1b in-flight ZSK roll skip | `v2/refreshengine.go` |
| §5.6 deleted-policy fallback | `v2/zone_policy_apply.go` |

**Exit criteria:** reload with same-alg policy rename applies transactionally;
reload with incompatible alg refuses and keeps last-applied; sign failure reverts
in-memory binding; restart with YAML policy edit detected via applied≠intent;
first post-upgrade reload backfills without mass re-sign.

### Phase 4 — Tests (medium)

| Test | File | Covers |
|------|------|--------|
| Alg refuse classifier (applied vs intent) | extend `v2/reload_policy_alg_guard_test.go` | incompatible → refuse; restart fixture |
| Transactional revert | `v2/zone_policy_apply_test.go` | SignZone error → old binding restored, applied unchanged |
| Backfill eligibility | `v2/zone_policy_apply_test.go` | missing applied + signed under intent → no SignZone |
| Applied vs override independence | `v2/db_zone_policy_override_test.go` | CLI override without clobbering applied semantics |
| Intent/applied diff on reload + restart | new or extend `v2/zsk_alg_rollover_test.go` | YAML change detected after restart |
| CLI parity | existing set-policy tests | override + applied both set |
| Deleted applied policy name | `v2/zone_policy_apply_test.go` | no nil-deref; warning path |

### Phase 5 — Follow-on (deferred, item 9 / P1-4)

- Surface refused policy changes in `config status` / zone status API
- Wire auto-rollover engine into `refusePolicyChange` replacement when built

---

## 8. PR slicing strategy

Recommended two PRs:

**PR 1 — Foundation (Phases 1–2):**

- Schema + applied CRUD + migration (`dbMigrateSchema` + `dbMigrateData`)
- `zone_policy_apply.go` + CLI refactor
- Unit tests for DB + core (including ①② semantics in classifier/backfill tests)

Low risk; CLI path is the reference behaviour; no reload behaviour change yet.

**PR 2 — Reload/restart (Phases 3–4):**

- Refresh engine wiring (①② enforced)
- Integration / guard tests

*(The parseconfig Finding-4 removal is **not** in PR 2 — it already landed in
#286, which is part of this project's base.)*

Higher risk; validate with live reload testbed (edit `dnssec_policy` in YAML,
`config reload`, inspect zone signing state and DB applied row).

---

## 9. Test plan (manual / live)

After PR 2, on a signed PQ zone:

1. **No change reload:** `config reload` → zone stays signed; `applied_policy`
   unchanged in keystore DB.
2. **First post-upgrade backfill:** upgrade binary on a config-only signed zone
   with no `applied_*` row → single `config reload` → `applied_policy` backfilled
   to intent **without** a full PQ re-sign storm (watch logs / sign duration).
3. **Benign policy edit:** change sig-validity or TTL in same-named policy →
   reload → `UpdateSigValidityFloor` picks it up; zone re-signed if needed;
   `applied_policy` unchanged.
4. **Compatible rename:** two policies with same KSK/ZSK algs; change YAML
   `dnssec_policy` → reload → transactional apply; `applied_policy` updated;
   zone signed on wire and AXFR.
5. **Incompatible alg change:** edit YAML to policy with different KSK alg →
   reload → refused; zone keeps old applied policy; warning in logs;
   `applied_policy` unchanged.
6. **Restart detection:** edit YAML policy (compatible rename), **restart daemon**
   (not just reload) → change detected via applied≠intent, transactional apply
   runs (①).
7. **CLI override + YAML drift:** `set-policy` to X; edit YAML to Y (same alg) →
   restart → override (intent X) wins; applied updated only on successful apply.
8. **Sign failure simulation:** break policy (e.g. point at removed policy name)
   → reload → no half-bound state; applied unchanged.
9. **In-flight ZSK roll:** mid `change-policy` gradual roll, `config reload` →
   no spurious config re-apply (Branch 1b).

---

## 10. Risks and open questions

| Risk | Mitigation |
|------|------------|
| Restart misses policy change | **①** applied vs intent classify; never pre-bind intent before classify |
| Thundering herd on upgrade | **②** silent backfill when already signed under intent |
| parseconfig vs refresh engine double-sign | **④** ✅ already removed in #286 (reload sign deleted; refresh engine is the sole reload signer) |
| Applied policy removed from YAML | **③** keep signing with existing keys + warning |
| Config reload during CLI ZSK roll | **⑤** `zskAlgRollInFlight` skip on config path |
| `change-policy` gradual ZSK roll vs config refuse | v1: config path refuses alg change; gradual roll stays CLI-only |
| Concurrent CLI set-policy during reload | Existing `confMu` / zone mutex patterns; transactional core holds `zd.mu` for rebind |
| DB error reading applied | Fail safe: log; prefer backfill eligibility check; refuse intent change if applied unknown and change would be destructive |

**Resolved in Phase 0:**

- Remove reload `SetupZoneSigning` entirely (Finding 4 — §6.5): **already done in #286** (delete-only); this project starts with it gone.
- On refuse at restart: keep signing under last-applied policy + warning (Decision 2); do not quarantine unless intent policy name is entirely unresolvable.

---

## 11. Files touched (estimate)

| File | Change |
|------|--------|
| `v2/zone_policy_apply.go` | **new** — core + classifier + backfill + resolve |
| `v2/zone_policy_apply_test.go` | **new** |
| `v2/db_zone_policy_override.go` | applied CRUD + `ClearZoneAppliedPolicy` (§6.7) |
| `v2/db_zone_policy_override_test.go` | applied tests |
| `v2/db.go` | `dbMigrateSchema` + `dbMigrateData` |
| `v2/db_schema.go` | comment |
| `v2/apihandler_zone.go` | CLI refactor + `resetZonePolicy` / `case "policy-reset"` (§6.7) |
| `v2/cli/zone_cmds.go` | `zone dnssec policy-reset --confirm` command (§6.7) |
| `v2/refreshengine.go` | reload/restart wiring |
| `v2/reload_policy_alg_guard_test.go` | retarget to applied-vs-intent |

*(`v2/parseconfig.go` is **not** touched here — the reload `SetupZoneSigning`
removal (Finding 4) is already done in #286.)*

**Estimated size:** ~450–800 LOC across ~9–11 files (the `policy-reset` escape
hatch adds ~50–100).

---

## 12. Success criteria

- Config reload policy change is as safe as `set-policy`: no half-bound unusable
  policy after failed sign.
- Every successfully signed zone has `applied_policy` / `applied_source` /
  `applied_at` in the keystore DB (backfill counts for already-signed zones).
- Intent (YAML + CLI override) vs last-applied diff drives apply/refuse on reload
  **and** restart (**①** — not foiled by fresh in-memory binding).
- First post-upgrade reload backfills config-only zones without a mass forced
  re-sign (**②**).
- Incompatible effective algorithm change on config reload: refused, old applied
  policy kept, zone continues signing on the wire.
- CLI `set-policy` / `change-policy` behaviour unchanged (modulo shared core).
- Unit tests cover classifier (applied vs intent), revert, backfill, applied
  persistence; reload guard tests updated.

---

## 13. References

- `docs/2026-07-14-snapshot-branch-signing-findings.md` — Finding 2, Decision 2,
  Plan B summary; **Finding 4** (`confMu` / reload signing)
- `docs/2026-06-16-dnssec-policy-change-handling.md` — earlier policy change /
  override design (CLI path)
- `v2/reload_policy_alg_guard_test.go` — merged c57a564 guard tests
- `v2/zsk_alg_rollover_test.go` — `EffectiveDnssecPolicyName` + override patterns
