# PR-2 transactional policy reload — live/practical test plan

- **Scope:** validating `feature/transactional-policy-reload-pr2` (PR #292) *in
  practice*. Unit + `-race` are green and all reviews passed; this doc covers the
  behaviour only a running signer, a real keystore DB, and a real
  reload/restart can exercise.
- **Companion docs:** plan `2026-07-15-transactional-policy-reload-plan.md` (§9 is
  the seed of this matrix), decisions `…-decisions.md`, guardrail
  `2026-07-17-config-reload-policy-guardrail-plan.md`, origin
  `2026-06-16-dnssec-policy-change-handling.md`.
- **Code under test:** `v2/zone_policy_apply.go` (the core + `syncZoneDnssecPolicyFromConfig`),
  the three refresh-engine sites in `v2/refreshengine.go`
  (existing-zone reload `:417`, pre-registered first-bind `:314`, dynamic add `:640`,
  plus the ticker completion retries `:706`/`:722`).

---

## 1. Why live testing at all — what the unit/race suite cannot prove

The unit tests construct `ZoneData` in-process and assert branch selection. Five
properties are *structurally* invisible to them, and every one is a way PR-2 can
be wrong on real hardware:

1. **Ordering of the backfill GATE.** `zoneServesIntentSOASig`
   (`zone_policy_apply.go:282`) reads the *served* apex SOA RRSIG via
   `zd.GetRRset`, which needs a Ready MapZone snapshot. PR-2 moved the sequence to
   `InstallInitialSnapshot → syncZoneDnssecPolicyFromConfig → drainAndRunOnFirstLoad`
   (SetupZoneSigning post-Ready). Only a real first-bind proves the GATE reads a
   *populated* snapshot and backfills instead of falling through to a re-sign.
2. **The ② thundering herd, at scale.** "No mass re-sign on first post-upgrade
   reload" is a claim about N already-signed zones. It only means something with
   many real zones and real (PQ) signing cost.
3. **Restart detection (① design lock).** On a true daemon restart the in-memory
   binding is reloaded = intent; only the DB `applied_*` record detects a YAML
   edit. A reload does not exercise this — you must stop and start the process.
4. **Refuse-and-keep-serving.** Branch 3 must leave the zone serving *valid*
   signatures under the old algorithm — on the wire **and** in AXFR (the Finding-1
   symptom was "stored RRSIGs absent or stale"). Needs real keys + a validator.
5. **First-load failure retention / ticker retry.** OnFirstLoad is retained on a
   sync failure and finished later by `finishFirstLoadPolicy` on the ticker. This
   is timing/state that no unit test drives end-to-end.

---

## 2. Environment

Two environments, complementary — run both:

| Env | Role in this plan | Why |
|-----|-------------------|-----|
| **nox** (auth signer) | The focused single-zone **matrix** (Groups A–E, G, H) and the **restart** cases | Where PR-1/#288 round-2 and #289 were live-validated; known-good single-signer baseline |
| **pq.axfr.net testbed** (foffe/NetBSD behind hetz DNAT :53, ~135 combo zones) | The **scale / thundering-herd** case (A2) and PQ **incompatible-alg** cases (C) | Real PQ signing cost makes "no re-sign storm" and alg-rollover refusal meaningful; config-only zones are already in the `applied_*`-missing state |

**Build prerequisites** (from memory): `GOROOT=/opt/local/lib/go CGO_ENABLED=1`;
PQ algorithms need `WITH_LIBOQS/SQISIGN/QRUOV=1` and the sourced env scripts.
Incompatible-alg cases (Group C) need two algorithms available — ED25519 ↔ a PQ
alg is the cheapest, or MAYO5 ↔ FALCON512 for a pure-PQ pair.

**DB state matters — set it up deliberately:**
- **"Applied missing" (backfill, A1/A2):** a config-only signed zone with
  `applied_policy` NULL. This is the natural state of any zone that never went
  through a CLI `policy-set`. To re-arm it on a DB that already has the row, clear
  it: `UPDATE ZonePolicyOverride SET applied_policy=NULL, applied_source=NULL,
  applied_at=NULL WHERE zone='<z>';` (server stopped).
- **"Applied present":** normal steady state after one successful sync.

---

## 3. Observability toolkit — the five signals

`applied_*` used to have no CLI surface — the single biggest testing-friction
point. **Now solved:** `auth zone desc -z <zone>` (merged to `main`, PR #301;
already in the #292 branch via forward-merge) prints, for one zone, everything
`zone list -v` shows plus two DNSSEC sections not otherwise visible from the CLI:
the last-applied record (`Applied policy: <name>  Source: config|command  Applied
at: <ts>`, or `(not recorded)` / `(lookup failed: …)`), and the bound policy's
detail (`Mode`, KSK/ZSK or CSK algorithm, key lifetimes, `SigValidity`). Read-only;
degrades gracefully for an unsigned zone or unresolvable policy. This is the
standard S1 readback; the direct sqlite query remains as a fallback.

| # | Signal | How to read it | Proves |
|---|--------|----------------|--------|
| **S1** | `applied_*` record | **preferred:** `tdns-cli auth zone desc -z <z>` (shows `applied_policy/source/at` + policy alg detail). **fallback:** `sqlite3 "$KEYSTORE" "SELECT zone,policy,set_at,applied_policy,applied_source,applied_at FROM ZonePolicyOverride ORDER BY zone;"` | which branch ran; source=config vs command |
| **S2** | **RRSIG inception** (the re-sign discriminator) | `dig @server SOA <z> +dnssec` → RRSIG `inception`; capture before/after | **whether a synchronous re-sign happened.** Backfill/None → inception UNCHANGED at reload; CompatibleName apply → inception JUMPS at reload; refuse → UNCHANGED |
| **S3** | Wire validation | `dog @server <z> SOA --dnssec` / `delv @server <z> SOA +root=<trust>` / `dog +sigchase` | zone still SECURE (or deliberately BOGUS after a DS break) |
| **S4** | Stored sigs (AXFR) | `dig @server AXFR <z>` → RRSIGs present, correct alg | secondaries/stored data are signed, not just ephemeral wire answers |
| **S5** | Zone warning/error + logs | `zone list -v` → `State: serving Warning[dnssec-policy-warning]: …` or `State: ERROR …`; server log lines (`refused incompatible…`, `backfilled applied…without re-sign`, `skipping config… ZSK roll in flight`) | soft-keep vs quarantine; refuse; branch taken |

S2 is the workhorse: it turns "did a herd happen?" into an objective per-zone
yes/no instead of eyeballing CPU. For A2 at scale, snapshot SOA-RRSIG inception
for all N zones before the reload and diff after — expect **~0 changed**.

---

## 4. Scenario matrix

Legend: **Trigger** = reload (`config reload` / `reload-zones` / `zone reload -z`
/ SIGHUP) or **restart** (stop+start daemon). Branch = the `syncZoneDnssecPolicyFromConfig`
path. Every row: precondition → trigger → expected branch → pass criteria (signals).

### Group A — backfill & no-op (prove ② / no herd)

| ID | Precondition | Trigger | Branch | Pass |
|----|--------------|---------|--------|------|
| **A1** | 1 config-only signed zone, `applied_*` NULL, correctly signed | reload | 0a backfill | S1: `applied_policy=intent, source=config`. **S2: inception UNCHANGED.** S5 log: "backfilled…without re-sign". S3 SECURE |
| **A2** | **all ~135 pq.axfr.net zones**, `applied_*` NULL, signed | single reload | 0a ×N | S2: inception UNCHANGED for ~all zones (only genuinely-changed ones move). No sign-duration spike / quiet sign log. S1: every zone backfilled |
| **A3** | applied present, same name | reload | 1 None | S2 UNCHANGED; S1 unchanged |
| **A4** | same-name policy, edit **sig-validity** | reload | 1 None | S2: **not** re-signed synchronously; floor moved → resigner re-signs on its *next tick* (inception moves later, on cadence). S1 unchanged. Separately: **TTL** edit → not applied until full sign; `zone dnssec resign -z <z>` applies immediately |

### Group B — compatible rename (prove transactional apply)

| ID | Precondition | Trigger | Branch | Pass |
|----|--------------|---------|--------|------|
| **B1** | policies FOO,BAR same KSK+ZSK alg; zone applied=FOO; edit YAML FOO→BAR | reload | 2 CompatibleName | S1 `applied_policy=BAR, source=config`. **S2 inception JUMPS** (synchronous force-sign). S3 SECURE, S4 AXFR sigs fresh |
| **B2** | same as B1 | **restart** | 2 at first-bind | Same as B1, driven by applied≠intent after a fresh binding (**① lock** — reload-style in-memory compare would miss it) |

### Group C — incompatible alg (prove refuse-and-keep-serving)

| ID | Precondition | Trigger | Branch | Pass |
|----|--------------|---------|--------|------|
| **C1** | zone applied=FOO (KSK=ED25519); edit YAML → policy with KSK=MAYO/FALCON | reload | 3 refuse | S5 log "refused incompatible…keeping applied". S1 `applied_policy` UNCHANGED (=FOO). **S3 still SECURE under old alg**, **S4 AXFR sigs present + old alg**. S2 UNCHANGED |
| **C2** | same | **restart** | 3 refuse at first-bind | Zone comes up **signed, not SERVFAIL/unsigned** (the exact Finding-1 symptom PR-2 must prevent). S3 SECURE, S1 unchanged |
| **C3** | ZSK-only alg differs | reload | 3 refuse | Config path refuses **all** alg changes in v1 (gradual ZSK roll stays CLI-only). Confirm refused, not applied |

### Group D — deleted / broken policy fallback (§5.6; prove no nil-deref)

| ID | Precondition | Trigger | Branch | Pass |
|----|--------------|---------|--------|------|
| **D1** | live signed zone; **delete its intent policy** from YAML | reload | keepBinding | S5: `Warning[dnssec-policy-warning]` "keeping bound policy"; zone keeps serving (S3 SECURE); **no crash** |
| **D2** | applied policy name deleted from YAML, intent still resolves & differs | reload | appliedPol==nil keep | keep current binding + warning; no nil-deref |
| **D3** | **first-bind/restart**, intent policy missing, nothing healthy to keep | restart | quarantine | `State: ERROR [dnssec-error]`; zone not signed; **no crash** |
| **D4** | intent policy present but `Error` set (broken) | reload | keep-or-quarantine | soft-keep if healthy binding, else quarantine — same as D1/D3 |

### Group E — policy-reset break-glass (regression smoke; core is shared with PR-2)

`policy-reset` was live-validated in PR-1 round-2 on nox; run a light smoke here
since PR-2 wires the same `applyZonePolicyTransactionalLocked`.

| ID | Action | Pass |
|----|--------|------|
| **E1** | `zone dnssec policy-reset -z <z>` (no `--confirm`) | dry-run preview only; S1 + keys UNCHANGED |
| **E2** | ZSK-only change, `--confirm` | drops+regens ZSK, keeps KSK; **no DS-break warning**; S1 `applied=config`, override cleared; S3 SECURE (DS intact) |
| **E3** | KSK/CSK change, `--confirm` | new KSK keytag; **DS-break warning fires**; S3 BOGUS until DS re-publish (expected) |
| **E4** | keys already match, `--confirm` | "no key roll", additive re-sign, `applied=config` |

### Group F — dynamic-zone site (c) parity

| ID | Action | Pass |
|----|--------|------|
| **F1** | add a signed dynamic/API zone at runtime | first-bind flows through sync post-Ready; SetupZoneSigning runs post-Ready; S1 applied recorded; S3 SECURE |
| **F2** | catalog-member auto-config of a signed zone | same as F1 via the catalog path |

### Group G — failure/retry & concurrency (the hard-to-unit-test edges)

| ID | Action | Pass |
|----|--------|------|
| **G1** | induce a first-load sync failure (e.g. broken intent policy), then fix it via reload | OnFirstLoad retained (zone not signed yet); ticker completion retry (`finishFirstLoadPolicy`) later finishes it — SetupZoneSigning runs, S1 recorded. Verify no permanent strand |
| **G2** | send a plain NOTIFY / refresh (**not** ConfigUpdate) to a signed zone | sync does **not** run (no reclassify/apply); S1 unchanged. Then `zone reload -z` (ConfigUpdate) → sync **does** run. Validates the `zr.ConfigUpdate` gate (`refreshengine.go:416`) |
| **G3** | concurrent CLI `policy-set` during a `config reload` of the same zone, under query load | serialized by `policyApplyMu`; no torn binding; final S1 consistent with the winner; no half-bound/SERVFAIL window |
| **G4** | first-bind of a signed zone while it is answering queries | backfill GATE reads a consistent served SOA RRSIG; zone answers SECURE throughout (ties to merged snapshot-correctness work) |

### Group H — acceptance / merge gate

- **H1** — one scripted pass of the full §9 matrix on a single signed PQ zone on
  nox: no-change → internals edit → compatible rename → incompatible refuse →
  **restart** detection → CLI override + YAML drift → sign-failure → in-flight ZSK
  roll (Branch 1b: mid CLI `change-policy` gradual roll, `config reload` → S5 log
  "skipping config… ZSK roll in flight", no spurious apply).
- **H2** — throughout H1, an external validating resolver stays **SECURE** for
  every case *except* the deliberate DS breaks (E3), where **BOGUS-until-DS-republish**
  is the expected, documented outcome.

---

## 5. Execution sequence

1. **Smoke (nox, 1 zone):** A1 → A3 → B1 → C1 → D1. Confirms all five signals wired
   and the four live branches behave before investing in scale/restart.
2. **Restart cases (nox):** B2, C2, D3 — the ① lock. Stop+start, not reload.
3. **Scale/herd (pq.axfr.net):** A2 with the SOA-RRSIG-inception diff over all zones.
   This is the headline ② guarantee and the case most likely to surprise.
4. **PQ incompatible-alg (pq.axfr.net):** C1/C3 with a real PQ pair; verify S3+S4
   still signed under the old alg after refuse.
5. **Chaos/edges (nox):** G1–G4, then the E-group smoke.
6. **Acceptance:** H1 scripted + H2 validator.

## 6. Pass/fail gate for merge

Merge-ready when: every A/B/C/D row passes with its listed signals; the A2 herd
diff shows no unexpected re-signs; B2/C2/D3 prove restart detection and
**C2 comes up signed, not SERVFAIL**; G1 shows no permanent first-load strand;
G3 shows no torn/half-bound window; H1+H2 pass end-to-end. Any BOGUS outside the
deliberate DS-break cases (E3) is a hard fail.

## 7. Tooling

- **applied_* readback (S1) — DONE:** `auth zone desc -z <zone>` shipped (merged
  to `main`, PR #301; present in the #292 branch). S1 is now self-serve; sqlite is
  the fallback.

Open:
- **A2 automation:** hand-run the inception diff, or extend the `tdns-debug`
  churn tool (the snapshot branch's live merge gate) with a policy-reload mode so
  the herd check is scriptable and repeatable?
- **Fault injection for G1:** is a "broken-then-fixed policy" reload a reliable
  enough way to force a first-load sync failure, or do we want a test hook?
