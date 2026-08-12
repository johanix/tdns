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
- **Live status (2026-07-20):** executed on the **pq.axfr.net testbed (foffe)**, not
  nox. The core rows are done (A2/B1/B2/C1/C2/C3/D1 + first-bind at scale), and all
  of them have been **re-validated on the branch tip** (`13dfd47`); **four defects
  were found and fixed**, including a **daemon SIGSEGV**, all now merged into #292.
  **Per-row status is the `Status` column in §4** — that column is the answer to
  "what still needs running". Detailed outcomes, findings and the ratified
  follow-ups live in `…-pr2-live-results.md`; the agent-run procedure is in
  `…-pr2-selfdriven-runbook.md`.

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

**Status legend:** ✅ passed live · ⚠️ ran, outcome differs from spec (see results
doc) · ◐ partially / implicitly covered · ⬜ not run — each ⬜ carries its reason
(*ready now* = no missing tooling, just needs running; or the specific fixture,
harness, or pending decision that gates it).

### Group A — backfill & no-op (prove ② / no herd)

| ID | Precondition | Trigger | Branch | Pass | Status |
|----|--------------|---------|--------|------|--------|
| **A1** | 1 config-only signed zone, `applied_*` NULL, correctly signed | reload | 0a backfill | S1: `applied_policy=intent, source=config`. **S2: inception UNCHANGED.** S5 log: "backfilled…without re-sign". S3 SECURE | ◐ subsumed by A2 (each of the 136 backfills *is* an A1); no dedicated single-zone capture |
| **A2** | **all ~135 pq.axfr.net zones**, `applied_*` NULL, signed | single reload | 0a ×N | S2: inception UNCHANGED for ~all zones (only genuinely-changed ones move). No sign-duration spike / quiet sign log. S1: every zone backfilled | ✅ **PASS** (foffe) — 136/136 backfilled, **zero re-signs**, inceptions byte-identical. **Re-run on the tip build 2026-07-20: 140/140**, `applied.backfilled=140` (coverage guard silent → backfill genuinely exercised), `a2.no-resign=140` at `--tolerance 0`, exit 0 |
| **A3** | applied present, same name | reload | 1 None | S2 UNCHANGED; S1 unchanged | ◐ implicit — repeated `reload-zones` during B–D never produced a re-sign storm, but no dedicated before/after S1+S2 capture |
| **A4** | same-name policy, edit **sig-validity** | reload | 1 None | S2: **not** re-signed synchronously; floor moved → resigner re-signs on its *next tick* (inception moves later, on cadence). S1 unchanged. Separately: **TTL** edit → not applied until full sign; `zone dnssec resign -z <z>` applies immediately | ⬜ **ready now** — needs a sig-validity edit + one resigner-tick wait |

### Group B — compatible rename (prove transactional apply)

| ID | Precondition | Trigger | Branch | Pass | Status |
|----|--------------|---------|--------|------|--------|
| **B1** | policies FOO,BAR same KSK+ZSK alg; zone applied=FOO; edit YAML FOO→BAR | reload | 2 CompatibleName | S1 `applied_policy=BAR, source=config`. **S2 inception JUMPS** (synchronous force-sign). S3 SECURE, S4 AXFR sigs fresh | ✅ **PASS** (foffe) — applied on the reload path, inception advanced (real synchronous re-sign). Needed the **two-step** `config reload` + `reload-zones` at the time; single-step now works via fix **#2** |
| **B2** | same as B1 | **restart** | 2 at first-bind | Same as B1, driven by applied≠intent after a fresh binding (**① lock** — reload-style in-memory compare would miss it) | ✅ **PASS** (foffe) — applied≠intent detected across a fresh binding, still SECURE. **The ① lock is proven live** |

### Group C — incompatible alg (prove refuse-and-keep-serving)

| ID | Precondition | Trigger | Branch | Pass | Status |
|----|--------------|---------|--------|------|--------|
| **C1** | zone applied=FOO (KSK=ED25519); edit YAML → policy with KSK=MAYO/FALCON | reload | 3 refuse | S5 log "refused incompatible…keeping applied". S1 `applied_policy` UNCHANGED (=FOO). **S3 still SECURE under old alg**, **S4 AXFR sigs present + old alg**. S2 UNCHANGED | ✅ **PASS** (foffe, tip build) — `e.preload` ED25519 → `mldsa44-falcon512`: S1 applied **unchanged** + `applied_at` unchanged, **S2 byte-identical** (SOA `20260719231032/56675`, DNSKEY `20260719231012/57993`), S3 still alg 15 serving signed, S5 `zone_policy_apply.go:516` "refused incompatible…keeping applied policy". `config check` **predicted it** pre-flight (KSK+ZSK named, 0 FAIL) |
| **C2** | same | **restart** | 3 refuse at first-bind | Zone comes up **signed, not SERVFAIL/unsigned** (the exact Finding-1 symptom PR-2 must prevent). S3 SECURE, S1 unchanged | ✅ **PASS** (foffe) — applied unchanged, SOA RRSIG still alg 15 (not MLDSA44), refuse-log fired, **zone came up signed, not SERVFAIL** — Finding-1 prevented |
| **C3** | ZSK-only alg differs | reload | 3 refuse | Config path refuses **all** alg changes in v1 (gradual ZSK roll stays CLI-only). Confirm refused, not applied | ✅ **PASS** (foffe, tip build) — `b.preload` `preload-b` → `ed25519-falcon512` (KSK identical ED25519, **only ZSK** differs FALCON512): refused, S1 applied **unchanged** `preload-b`, **S2 byte-identical** (SOA `20260719231102/38015`, DNSKEY `20260719231011/46686`), S5 refuse log with `applied_zsk_alg=ED25519`. Confirms v1 refuses ZSK-only changes too |

### Group D — deleted / broken policy fallback (§5.6; prove no nil-deref)

| ID | Precondition | Trigger | Branch | Pass | Status |
|----|--------------|---------|--------|------|--------|
| **D1** | live signed zone; **delete its intent policy** from YAML | reload | keepBinding | S5: `Warning[dnssec-policy-warning]` "keeping bound policy"; zone keeps serving (S3 SECURE); **no crash** | ⚠️ **RAN — outcome differs.** `parseconfig` quarantines the zone (`State: ERROR`) **before** PR-2's §5.6 soft-keep can run: the zone **stopped signing** (fail-closed) and was **not reload-recoverable** — restoring the policy + `reload-zones` did not rescue it, only a **restart** did. **No crash.** Not a PR-2 defect (PR-2 never got the chance to run); see results Finding 4 + ratified decisions (1)(2)(3) |
| **D2** | applied policy name deleted from YAML, intent still resolves & differs | reload | appliedPol==nil keep | keep current binding + warning; no nil-deref | ⬜ **deferred by decision** — mechanically testable (intent resolves, so `parseconfig` won't quarantine), but the D-group's *expected* behaviour is in flux pending decisions (2)/(3); worth re-running once the reload guardrail lands |
| **D3** | **first-bind/restart**, intent policy missing, nothing healthy to keep | restart | quarantine | `State: ERROR [dnssec-error]`; zone not signed; **no crash** | ◐ the expected outcome (`State: ERROR`, unsigned, no crash) was observed during D1 — but on the **reload** path; the **restart** variant is still unrun |
| **D4** | intent policy present but `Error` set (broken) | reload | keep-or-quarantine | soft-keep if healthy binding, else quarantine — same as D1/D3 | ⬜ **blocked** — no clean way to induce a policy `Error`; gated by the DNSSEC error-classification restructure (`2026-07-19-dnssec-error-classification-restructure.md`) |

### Group E — policy-reset break-glass (regression smoke; core is shared with PR-2)

`policy-reset` was live-validated in PR-1 round-2 on nox; run a light smoke here
since PR-2 wires the same `applyZonePolicyTransactionalLocked`.

| ID | Action | Pass | Status |
|----|--------|------|--------|
| **E1** | `zone dnssec policy-reset -z <z>` (no `--confirm`) | dry-run preview only; S1 + keys UNCHANGED | ⬜ **ready now** — read-only, zero blast radius |
| **E2** | ZSK-only change, `--confirm` | drops+regens ZSK, keeps KSK; **no DS-break warning**; S1 `applied=config`, override cleared; S3 SECURE (DS intact) | ⬜ mutates keys — wants a throwaway fixture, not a showcase zone |
| **E3** | KSK/CSK change, `--confirm` | new KSK keytag; **DS-break warning fires**; S3 BOGUS until DS re-publish (expected) | ⬜ deliberately breaks DS — needs a **delegated** throwaway fixture (DS in `pq.axfr.net`) to be observable end-to-end |
| **E4** | keys already match, `--confirm` | "no key roll", additive re-sign, `applied=config` | ⬜ ready after E2 (it is E2's follow-on state) |

### Group F — dynamic-zone site (c) parity

| ID | Action | Pass | Status |
|----|--------|------|-------|
| **F1** | add a signed dynamic/API zone at runtime | first-bind flows through sync post-Ready; SetupZoneSigning runs post-Ready; S1 applied recorded; S3 SECURE | ⬜ needs an API/dynamic-zone fixture on the testbed. **Partially de-risked:** the site-(c) first-bind path is what the SIGSEGV fix hardened, and a brand-new signed zone now loads cleanly (validated at 140 zones incl. 3 keyless) |
| **F2** | catalog-member auto-config of a signed zone | same as F1 via the catalog path | ⬜ needs a catalog fixture (no catalog configured on foffe) |

### Group G — failure/retry & concurrency (the hard-to-unit-test edges)

| ID | Action | Pass | Status |
|----|--------|------|-------|
| **G1** | induce a first-load sync failure (e.g. broken intent policy), then fix it via reload | OnFirstLoad retained (zone not signed yet); ticker completion retry (`finishFirstLoadPolicy`) later finishes it — SetupZoneSigning runs, S1 recorded. Verify no permanent strand | ⬜ **needs fault injection** — the D1 episode showed the obvious lever (a missing policy) trips `parseconfig` quarantine *first*, so it never reaches the retained-first-load state. Wants a test hook (§7 open question) |
| **G2** | send a plain NOTIFY / refresh (**not** ConfigUpdate) to a signed zone | sync does **not** run (no reclassify/apply); S1 unchanged. Then `zone reload -z` (ConfigUpdate) → sync **does** run. Validates the `zr.ConfigUpdate` gate (`refreshengine.go:416`) | ⬜ **ready now** — NOTIFY then `zone reload -z`, diff S1/S2 across both |
| **G3** | concurrent CLI `policy-set` during a `config reload` of the same zone, under query load | serialized by `policyApplyMu`; no torn binding; final S1 consistent with the winner; no half-bound/SERVFAIL window | ⬜ **needs a concurrency harness** — the tdns-debug A2 mode drives reloads but not a *competing* `policy-set` under query load. Closest existing tool: `tdns-debug test churn` (the snapshot branch's merge gate) — extending it is the likely path |
| **G4** | first-bind of a signed zone while it is answering queries | backfill GATE reads a consistent served SOA RRSIG; zone answers SECURE throughout (ties to merged snapshot-correctness work) | ⬜ **needs a query-load harness** (same tool as G3). Adjacent ground already covered by merged #279 (1112 snapshot swaps under UDP+TCP flood, 0 SERVFAIL/torn) |

### Group H — acceptance / merge gate

- **H1** — one scripted pass of the full §9 matrix on a single signed PQ zone on
  nox: no-change → internals edit → compatible rename → incompatible refuse →
  **restart** detection → CLI override + YAML drift → sign-failure → in-flight ZSK
  roll (Branch 1b: mid CLI `change-policy` gradual roll, `config reload` → S5 log
  "skipping config… ZSK roll in flight", no spurious apply).
  - ⬜ **not run as a single scripted pass.** The constituent rows were executed
    piecemeal on foffe instead of scripted on nox, and **two H1 legs have no
    coverage at all**: *CLI override + YAML drift*, and the **Branch-1b in-flight
    ZSK roll** (the "skipping config… ZSK roll in flight" case). Those two are the
    substantive H1 gap; the rest is re-packaging.
- **H2** — throughout H1, an external validating resolver stays **SECURE** for
  every case *except* the deliberate DS breaks (E3), where **BOGUS-until-DS-republish**
  is the expected, documented outcome.
  - ◐ **unblocked, partially proven.** The `pq.axfr.net` delegation is live and the
    chain validates end-to-end (verified 2026-07-20: `ad` flag from 8.8.8.8, `delv`
    "fully validated", DS `10549 15 2`). Two caveats for the *leaves*: (a) standard
    validators only implement the ED25519 links, so a pure-ED25519 leaf reads
    SECURE but **any leaf with a PQ alg in KSK/ZSK reads INSECURE to them** — PQ
    leaves need a **PQ-aware validator** (`dog +sigchase` / `tdns-imr` built with
    the algs); (b) the throwaway `*.preload` fixtures have **no DS in
    `pq.axfr.net`**, so they are outside the chain until one is added.

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

### Where we stand against that gate (2026-07-20)

**Met:** the two headline guarantees — ② no herd (A2) and ① restart detection (B2)
— plus **C2 comes up signed, not SERVFAIL**, and no crash in any D case. First-bind
at scale (137 PQ zones, 0 errors) also passed. **The refuse branch is now proven on
both paths**: C2 at first-bind/restart, C1 and C3 on the reload path, C3 covering
the ZSK-only case.

**Re-validated on the branch tip (2026-07-20).** Everything above had been run on
intermediate fix builds, so the tip binary itself had never run on the testbed.
Rebuilt foffe from `13dfd47` and re-ran: startup clean (140 zones, **0 panics**,
`applied_*` preserved with timestamps unchanged, 0 real errors — the 15 warnings
are the expected large-algorithm advisories), A2 **140/140 with zero re-signs**,
C1 and C3 both refusing correctly. This closes the one gap that mattered — the
CodeRabbit **CSK-as-ZSK guard** (fix 1's follow-up) had until then been covered
only by unit tests, on the exact path that already produced a SIGSEGV. No new
defects surfaced. Sharpest single artifact: a sample zone's `applied_at` advanced
to the reload while its SOA RRSIG inception stayed at the *previous* restart's
value — policy record written, signature untouched.

**Not yet met:** G1 and G3 are unrun (both need harness/fault-injection work), H1
has two uncovered legs (CLI-override drift, Branch-1b in-flight ZSK roll), and D1
returned a *different* outcome than specified — fail-closed quarantine rather than
§5.6 soft-keep. **D1 is not a PR-2 defect** (the quarantine happens in
`parseconfig`, upstream of PR-2's classifier, which never runs), so it does not
block this PR on its own terms; it is tracked as ratified decisions (1)(2)(3) and
is the live motivator for the reload guardrail.

**Found and fixed while testing** (all merged into #292, each live-validated):

| # | Defect | Fix |
|---|--------|-----|
| 1 | 🔴 **daemon SIGSEGV** — new online-signed zone with no keys crashed at first load (nil `zd.DnssecPolicy`, PR-2 defers binding past the load-time resign) | two guards + regression tests; CSK-as-ZSK hole later closed after CodeRabbit review |
| 2 | `reload-zones` never re-read the `zones:` block — zone→policy mapping changes needed a restart (pre-existing, **orthogonal** to PR-2) | `reloadZonesFromFile()` + test; B1 is now single-step |
| 3 | `config check` reported 134 false FAILs on PQ policies (CLI has no PQ alg registry), burying the one real FAIL | online + role-aware check that asks the **server** for its algorithms |
| 4 | `config check` alg **correlation** compared a name against a codepoint-derived string | correlate on the server-reported name |

## 7. Tooling

- **applied_* readback (S1) — DONE:** `auth zone desc -z <zone>` shipped (merged
  to `main`, PR #301; present in the #292 branch). S1 is now self-serve; sqlite is
  the fallback.

- **A2 automation (S2 herd diff) — DONE:** `tdns-debug` gained a policy-reload
  mode (PR #302, merged) that snapshots per-zone apex SOA+DNSKEY RRSIG inceptions,
  drives `reload-zones`, and diffs. This is what produced the 136/136 A2 result;
  it is repeatable, and the result was independently cross-checked with `dig`.
- **`config check` as pre-flight — DONE (fixes 3+4):** usable on PQ configs now
  that it asks the server for its algorithm set. This matters beyond tidiness: it
  is the **only pre-flight lifeline before a restart**, and it *did* correctly
  predict the D1 breakage — the prediction was just buried under 134 false FAILs.

Open:
- **Fault injection for G1:** a "broken-then-fixed policy" reload turns out **not**
  to work — D1 showed `parseconfig` quarantines the zone first, so the retained
  first-load state is never reached. G1 needs a real test hook.
- **Concurrency harness for G3/G4:** competing `policy-set` + `config reload`
  under query load. Likely path is extending `tdns-debug test churn`.
- **PQ-aware validation for H2:** external SECURE proof on PQ leaves needs
  `dog +sigchase` / `tdns-imr` built with the algorithms; stock `delv`/8.8.8.8
  cannot verify PQ signatures.
- **Delegating the throwaway fixtures:** `*.preload` zones need DS records in
  `pq.axfr.net` before E3-style DS-break cases are observable end-to-end.
