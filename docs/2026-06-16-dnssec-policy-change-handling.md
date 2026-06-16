# DNSSEC policy change handling: reconcile, live override, visibility

Status (2026-06-16): IN PROGRESS. Phases 1, 2, 3, 4, 5a, 5 DONE on branch
dnssec-policy-change-phase1-2; Phases 1+2 and 4 live-verified on the nox
auth signer. Phases 6 and 7 remaining. Per-phase status + commit hashes
below.
The originally-reported orphan-RRSIG bug turned out to be one symptom of a
larger gap (DNSSEC policy changes are not applied), and is folded in here
as Phase 2.

Branch context: built on PR #259 (per-role KSK/ZSK algorithms + config
restructure), now merged to main. This is the natural continuation:
making a policy that SAYS "KSK=MAYO5, ZSK=MAYO2" actually take effect.


## 1. Problem

The per-role algorithm work lets a policy specify different algorithms
for KSK and ZSK, and the keystore/signer support it. But changing a
zone's policy does NOT apply:

- **A policy algorithm change is a silent no-op.** EnsureActiveDnssecKeys
  (sign.go) gates on "does ANY active KSK and ANY active ZSK exist?" — it
  does not check their ALGORITHM against the policy. So a zone with
  active ED25519 keys, switched to a MAYO5/MAYO2 policy, keeps signing
  with ED25519. No new keys, no error, no warning. (Verified.)
- **The only way to apply new-algorithm keys today is `keystore dnssec
  clear`** — a destructive hard-delete of ALL keys that regenerates one
  KSK + one ZSK with the policy algorithms.
- **`clear` (and any key removal) leaves orphan RRSIGs.** clear
  hard-deletes keys but does not strip the signatures they made; the
  served zone keeps RRSIGs whose DNSKEY is gone (unvalidatable). This is
  the originally-reported bug. It is NOT clear-specific: removal does not
  strip RRSIGs anywhere (verified: retired→removed transition does not
  strip sigs either), so ZSK rollover already produces transient orphans.


## 2. Design

### 2.1 Core principle — reconcile active keys against the policy

EnsureActiveDnssecKeys becomes algorithm-aware. The invariant:

> The set of ACTIVE keys must match the set the policy specifies. For
> each (role, algorithm) the policy wants, an active key of that
> algorithm must exist (generate if missing). Any active key whose
> (role, algorithm) is NOT wanted by the policy is RETIRED (not deleted).

The number of active keys per role is whatever the policy specifies —
NOT hardcoded to one. Today's policies specify one algorithm per role,
so one active KSK + one active ZSK; a future multi-active policy
(e.g. ksks: [MAYO5, FALCON1024]) yields four active keys, two per role.
The reconcile logic iterates over the policy's "wanted (role, alg) set",
so multi-active slots in later without a rewrite. (The DnssecPolicy
struct's scalar KSKAlgorithm/ZSKAlgorithm becomes the single-element
wanted-set today; widening to lists later is localized.)

### 2.2 Why retire (not delete) — graceful, almost-rollover

Retiring an old-algorithm key, rather than deleting it:

- Keeps the old DNSKEY PUBLISHED and its existing RRSIGs valid (verified:
  retired keys stay in the DNSKEY RRset but stop signing).
- New keys are generated active and sign the zone. The zone is briefly
  DOUBLE-SIGNED (old sigs + new sigs) and stays fully validatable
  throughout — no outage.
- The existing KeyStateWorker carries retired→removed after
  propagation_delay (+ maxTTL margin for ZSKs); at removal the old sigs
  are stripped (Phase 2). Cleanup is automatic, on the right schedule.

This gives us the ZONE-SIDE of an algorithm rollover for free. The piece
we are NOT building now is the parent-side DS/CDS coordination (full RFC
6781 algorithm rollover) — explicitly deferred.

### 2.3 The persistence constraint — why live `set-policy` is required

RRSIGs are NOT persisted (in-memory only, regenerated each run). So a
policy change applied only at RESTART can never be graceful: at restart
there are no old sigs in memory to retain, so retiring the old keys would
leave the zone with only new-algorithm sigs (the old keys' sigs are gone,
never having been saved). The graceful retire+double-sign transition can
only happen in a RUNNING process, where the old sigs are live in memory.

Therefore:

- **`set-policy` (live, running server)** is the CORRECT path for a policy
  change. It runs reconcile in-process: old sigs retained, old keys
  retired, new keys generated and double-sign, KeyStateWorker cleans up.
- **Restart, and the zone-reload commands (`config reload-zones` /
  `zone reload -z`)** must still CONVERGE to the policy (no crash, keys
  eventually match) but accept a HARD cutover when the config base itself
  changed — they cannot be graceful (zone data, including its in-memory
  RRSIGs, is reloaded). An ORDINARY restart/reload with no policy change
  is unaffected. See Phase 5 for the exact commands and the single
  convergence point.

### 2.4 Persistence — DB override table, never rewrite YAML

The server must never rewrite the operator's YAML (comments, formatting,
includes). Instead:

- **Config (YAML)** = declared BASE zone→policy mapping. Operator-owned.
- **DB override table** = dynamic zone→policy mapping, written ONLY by
  `set-policy`. Server-owned.
- **Effective policy** = override if present, else config base. Resolved
  wherever a zone's policy is read.

This closes the persistence gap AND removes the revert-on-restart hazard:
after `set-policy`, the override persists, so a restart loads the zone
with the already-changed policy and its already-correct keys — no reverse
rollover. The config base and override can differ; that difference is made
VISIBLE (2.6), and reconciling it is the operator's choice.

### 2.5 set-policy warning

`set-policy` returns a stark warning that the zone's YAML config and the
live state now differ and the operator should reconcile when convenient.
(Exact wording is a detail, tweak later.)

### 2.6 Visibility

Two gaps, both closed:

- **`zone list` (-v) does not show a zone's DNSSEC policy at all.** Add a
  policy column: effective policy name + whether it matches config (flag
  overrides, e.g. `pq-mayo (override; config: default)`). Makes the
  base/override distinction observable — without which the override table
  would be a foot-gun.
- **The transient double-signed state** (post policy change, before
  KeyStateWorker removes the old keys) is surfaced via the EXISTING
  `keystore dnssec auto-rollover status` command (it already shows
  per-key state + timing for KSK and ZSK), NOT a new generic framework.
  A zd.SetStatus() framework is explicitly DEFERRED — not yet clear it's
  the right abstraction; the key-state machine + this command may carry
  all the needed signal.


## 3. Deferred (explicitly NOT in this work)

- Full RFC 6781 algorithm rollover: parent DS/CDS coordination, the
  multi-DS pipeline for algorithm changes.
- Multi-active-key policies (lists of algorithms per role). The reconcile
  engine is written to ACCOMMODATE them but the policy schema stays scalar
  per role for now.
- zd.SetStatus() generic zone-status framework.
- set-policy --persist writing back to YAML (rejected outright).


## 4. Implementation plan

Sequenced; checkpoint between phases (build + testbed where it matters).
LOC = net source lines (±), excluding tests unless noted. Agent time =
rough wall-clock for an implementing agent incl. build/iterate, not
counting testbed deploys (operator-gated).

Risk legend: LOW = localized, well-understood, easy to test; MED =
touches signing/key-state behavior or multiple call sites; HIGH =
changes core signing/serving semantics, needs testbed validation.

---

### Phase 1 — Reconcile engine in EnsureActiveDnssecKeys

STATUS: DONE (commit 1144928), live-verified on nox. Implemented as
reconcileActiveKeyAlgorithms in sign.go (retire wrong-alg active keys via
UpdateDnssecKeyState; CSK mode skipped; defensive RolloverInProgress
guard). No new retire helper needed — UpdateDnssecKeyState already stamps
retired_at. Tested: TestReconcileActiveKeyAlgorithms.

Make EnsureActiveDnssecKeys ensure active keys of the policy's wanted
(role, alg) set, generating missing ones and RETIRING active keys whose
algorithm the policy no longer wants. Add a general "retire this active
key" helper (today active→retired exists only inside AtomicRollover, KSK-
specific — F1). Write the reconcile loop over a wanted-set abstraction.

- Files: sign.go (EnsureActiveDnssecKeys), a new retire helper (near
  ksk_rollover_atomic.go's transition or keystore.go), key_state_worker
  interplay.
- Risk: HIGH. This changes when/whether keys are generated and retired on
  every zone load and re-sign. Must not regress the common "keys already
  correct" path, and must not retire keys mid-legit-KSK-rollover (the
  RolloverKeyState pipeline has its own active set). Needs testbed.
- LOC: +120 / −20.
- Agent time: ~60–90 min (careful; lots of edge cases — CSK mode, KSK-
  reused-as-ZSK flags=257, rollover pipeline interaction).
- Verify: a zone with ED25519 active keys + MAYO policy, on re-sign,
  generates MAYO active keys, retires ED25519, double-signs. A zone
  already matching its policy is a no-op (no new keys).

---

### Phase 2 — Strip RRSIGs of removed keys (fixes orphans generally)

STATUS: DONE (commit 1144928), live-verified on nox. Implemented as
StripZoneRRSIGs(remove func) in sign.go — one subtractive, per-RRset-
atomic pass; called at the retired→removed transition (strip the removed
key's keytag) and on `clear` (strip everything not in the regenerated
keyset). Tested: TestStripZoneRRSIGs.

At the retired→removed transition (key_state_worker.go) and on `clear`,
strip the served RRSIGs whose keytag belongs to no surviving key. One
subtractive pass over the zone (GetOwnerNames→GetOwner→RRtypes; filter
rrset.RRSIGs; Set back only if changed). This fixes the original orphan-
RRSIG bug AND the latent ZSK-rollover orphan case — both stem from F2
(removal doesn't strip sigs today).

- Files: key_state_worker.go (after retired→removed), keystore.go (clear),
  a shared stripSignaturesNotIn(zd, keepKeytags) helper in sign.go.
- Risk: MED. Subtractive only, but must compute the "keep" set correctly
  (surviving keys' keytags, matched by keytag+algorithm to avoid the rare
  16-bit keytag collision) and must run post-commit / on consistent state.
  Must NOT strip sigs of still-published retired keys (only removed ones).
- LOC: +70 / −5.
- Agent time: ~45–60 min.
- Verify: after retired→removed, the removed key's RRSIGs are gone from
  served data; active + still-retired keys' sigs remain. After `clear`,
  no orphan sigs.

---

### Phase 3 — DB override table + effective-policy resolution

STATUS: DONE (commit 85b8451). ZonePolicyOverride table in db_schema.go;
Set/Clear/Get + EffectiveDnssecPolicyName resolver in
db_zone_policy_override.go. Resolver wired into all four read sites: the
three refreshengine paths (first-load, existing-zone refresh,
dynamic/catalog) and the CLI dnssecPolicyForZone helper. Tested:
TestZonePolicyOverride.

Add a ZonePolicyOverride table (zone TEXT PRIMARY KEY, policy TEXT,
set_at TEXT). Read/write helpers. Introduce a single
zd.EffectiveDnssecPolicyName() / resolution used at every site that
currently reads conf.Internal.DnssecPolicies[name] for a zone (F4: the
refreshengine load + refresh sites are the main ones). On zone load,
override wins over config base.

- Files: db_schema.go (+table, ~15 LOC), a new db_zone_policy_override.go
  (helpers), refreshengine.go (resolution at load + refresh).
- Risk: MED. New table is LOW; the risk is finding ALL policy-read sites
  and routing them through one resolver so override is honored everywhere
  (signing, rollover, status). Miss one and behavior is inconsistent.
- LOC: +110 / −10.
- Agent time: ~50–70 min.
- Verify: set an override row by hand, restart, zone loads with the
  override policy not the config base.

---

### Phase 4 — set-policy command (live reconcile + persist override)

STATUS: DONE (commit fa4d163), live-verified on nox. setZonePolicy in
apihandler_zone.go (validate → persist override → rebind → ADDITIVE
SignZone so retired keys' sigs stay = graceful double-sign). CLI
`zone set-policy -z -p` in zone_cmds.go; ZonePost.Policy field added.
Returns the YAML-divergence warning.

`tdns-cli auth zone set-policy -z <zone> -p <policy>`. API handler:
validate policy exists and is healthy (Error==""), write the override
row, rebind zd.DnssecPolicy, run reconcile (Phase 1) live, trigger
re-sign. Return the stark warning (2.5).

- Files: cli/agent_zone_cmds.go (or a new auth zone cmd file) + the zone
  API handler (apihandler_zone.go switch, F6), reusing Phase 1 reconcile +
  Phase 3 override write.
- Risk: MED. Orchestration of existing pieces; the live reconcile is
  Phase 1's risk, already paid. Main new risk: ensure the old sigs are
  retained at the moment of switch (don't wipe before new keys sign).
- LOC: +100 / −0.
- Agent time: ~45–60 min.
- Verify (testbed): set-policy on a live ED25519 zone to a MAYO policy →
  zone immediately double-signed (ED25519 retired + MAYO active), warning
  printed, override persisted, survives restart.

---

### Phase 5a — extract parseDnssecConfig() helper

STATUS: DONE (commit d25b398). Config.parseDnssecConfig() in
parseconfig.go; ParseConfig calls it; behavior identical. Tested:
TestParseDnssecConfig.

Pull the parsing of the ENTIRE `dnssec:` block out of ParseConfig into a
standalone helper — parseDnssecConfig(conf) — that resolves policies +
split_algorithms + large_algorithms + kasp into the conf.Internal.*
structures (including the broken-policy error states from Phase 4 /
already-landed work). ParseConfig calls it; nothing else changes there.

Two payoffs:
1. Testability — the dnssec parse becomes a pure function over YAML →
   resolved structures, unit-testable without driving full ParseConfig.
   (We could not test the policy-loading loop directly before because it
   was buried in ParseConfig.)
2. Reuse on zone reload — Phase 5 calls this helper from the zone-reload
   path so reloading zones ALSO re-parses the dnssec block they depend
   on, closing the "forgot to reload policies before zones" gap.

It also makes the policies-before-zones dependency an explicit invariant
of the reload path rather than an accident of call order in ParseConfig.

- Scope: ENTIRE dnssec: block (policies + split_algorithms +
  large_algorithms + kasp). They are parsed and validated together — a
  policy's validity depends on split_algorithms — so they cannot be split.
- Files: parseconfig.go (extract), a new test file.
- Risk: LOW. Pure refactor + tests; behavior identical, just relocated.
  One caveat: confirm ParseConfig does nothing BETWEEN the dnssec parse
  and ParseZones that the zone-reload path would miss (trace the seam).
- LOC: +40 / −20, plus ~+60 test LOC.
- Agent time: ~30–40 min.
- Verify: ParseConfig behavior unchanged (existing flows); new unit tests
  exercise parseDnssecConfig directly (good/broken policies, split gate,
  large-alg names, kasp).

---

### Phase 5 — zone reload re-parses dnssec + reconciles (convergence)

STATUS: DONE (commit d25b398). ReloadZoneConfig and ReloadZone call
parseDnssecConfig before re-applying zones (two-step dance eliminated).
Per-zone refresh block rebinds + re-signs on every reload of a signed
zone (not just on name change); reconcile is idempotent. Override still
wins over config base on reload.

The three reload CLI commands (verified):
- `config reload` — reloads GENERAL config only (calls ParseConfig →
  parseDnssecConfig + the rest); does NOT touch zones. NOT on the
  per-zone path.
- `config reload-zones` — re-runs ParseZones for ALL zones.
- `zone reload -z <zone>` — re-reads ONE zone's config.

The last two CONVERGE: both push a ZoneRefresher into the RefreshEngine
channel and flow through the SAME per-zone block at
refreshengine.go:315-346. Logic is added ONCE, there.

DESIGN (uses Phase 5a): the zone-reload entry points CALL
parseDnssecConfig FIRST, so reloading zones ALSO refreshes the dnssec
block (policies etc.) they depend on. Decision (confirmed): re-parse the
dnssec block on EVERY zone reload — including `zone reload -z <one>`.
Policies are few and small; the parse is cheap; doing it "sometimes"
would be more confusing than always. Side effect accepted: a single-zone
reload updates the server-wide policy structs. Blast radius for
re-APPLICATION stays scoped — only the reloaded zone(s) get reconciled
against the refreshed policies; other zones are untouched until they too
are reloaded.

This ELIMINATES the old two-step "config reload then reload-zones" dance:
`reload-zones` (or `zone reload -z`) now picks up edited policy
definitions by itself.

Remaining gap to close in the per-zone block:
- The existing detection fires only on a policy NAME change
  (zd.DnssecPolicyName != zr.DnssecPolicy). It misses "same name, internal
  details changed" (operator edits policy `pq-mayo`'s KSK alg; zone still
  references `pq-mayo`). Resolution: always re-run the Phase 1 reconcile
  on reload (idempotent — a no-op when keys already match the freshly
  parsed policy), rather than gating on a name compare. Simpler and
  correct: the reconcile itself is the change detector.

On reload the convergence is a HARD cutover when the config BASE changed
(can't be graceful — RRSIGs are not persisted across a reload of zone
data; 2.3). An ordinary reload with no policy change is a no-op (reconcile
generates/retires only when keys don't match). Effective policy =
override (Phase 3) else config base; reload must NOT clobber a live
override with the config base — the override wins until explicitly cleared
(confirm the clear path at impl).

- Files: the zone-reload entry points (config.go ReloadZoneConfig /
  zone_utils.go ReloadZone) call parseDnssecConfig before pushing
  ZoneRefreshers; refreshengine.go (~315-346) calls Phase 1 reconcile
  unconditionally instead of only on name change.
- Risk: MED. The reconcile-always approach removes the fiddly field
  compare but must be genuinely idempotent (no thrash on repeated
  reloads) and must respect override precedence.
- LOC: +50 / −15.
- Agent time: ~40–60 min.
- Verify: edit a policy's algorithm in YAML, then `reload-zones` (one
  step) → affected zones reconcile to the new algorithm (hard cutover OK).
  `zone reload -z` of an unchanged zone → no key churn. A zone with a live
  override is not reverted to the config base by a reload.

---

### Phase 6 — policy-cleanup command (collapse double-signing early)

STATUS: DONE (uncommitted as of this writing). `policy-cleanup` subcommand
in keystore.go DnssecKeyMgmt: transitions the zone's retired keys to
removed and strips their RRSIGs by keytag (reusing StripZoneRRSIGs), keeps
active keys; triggers a re-sign. CLI command in keystore_cmds.go (with
confirmation prompt); added to the resign-trigger list in
apihandler_funcs.go.

`tdns-cli auth keystore dnssec policy-cleanup -z <zone>`: remove RETIRED
keys no longer wanted by the policy and their sigs NOW, keeping active
keys — for operators who don't want to wait out the double-signed window
(large zone). Distinct verb from `clear` (which stays the sledgehammer:
delete ALL keys + regenerate). Reuses Phase 2's sig-strip.

- Files: keystore.go (new subcommand), cli registration, reuse Phase 2.
- Risk: LOW–MED. Destructive but well-scoped (only retired-unwanted keys).
  Must never touch active keys.
- LOC: +70 / −0.
- Agent time: ~40 min.
- Verify: after a policy change leaves the zone double-signed,
  policy-cleanup drops the retired old-alg keys + sigs immediately; zone
  stays validatable with the active new-alg keys.

---

### Phase 7 — Visibility (zone list -v only)

Surface a zone's DNSSEC policy where it is currently invisible. ONLY the
verbose listing changes:

- `zone list` (no -v): output UNCHANGED. The default terse listing stays
  exactly as today.
- `zone list -v`: add the zone's effective DNSSEC policy name, and — when
  the effective policy came from a DB override (Phase 3) and differs from
  the config base — a note that the live policy overrides config (so the
  operator sees the YAML and live state have diverged and which zones).

DEFERRED (explicitly not in this phase): hooking the transient
double-signed-after-policy-change state into the `auto-rollover status`
command. That needs status-struct changes and is better done alongside
the actual rollover work. For now, the key states themselves (visible via
existing key-listing commands) carry the signal; we are not building a
dedicated presentation of the transition window yet.

- Files: cli/zone_cmds.go (the -v branch of the list renderer only) +
  apihandler_zone.go (list-zones response carries effective policy name +
  an "overridden" flag).
- Risk: LOW. Presentation behind -v + one or two response fields. No
  behavior change; default output untouched.
- LOC: +45 / −5.
- Agent time: ~30–40 min.
- Verify: `zone list` output is byte-identical to before; `zone list -v`
  shows each zone's policy and flags zones whose live policy overrides
  config.

---

## 5. Totals (rough)

| Phase | Risk | LOC (±)      | Agent time | Status |
|-------|------|--------------|------------|--------|
| 1 reconcile engine      | HIGH    | +120 / −20 | 60–90m | DONE 1144928 (live) |
| 2 strip removed sigs    | MED     | +70 / −5   | 45–60m | DONE 1144928 (live) |
| 3 override table + read | MED     | +110 / −10 | 50–70m | DONE 85b8451 |
| 4 set-policy            | MED     | +100 / −0  | 45–60m | DONE fa4d163 (live) |
| 5a parseDnssecConfig    | LOW     | +40 / −20  | 30–40m | DONE d25b398 |
| 5 reload convergence    | MED     | +50 / −15  | 40–60m | DONE d25b398 |
| 6 policy-cleanup        | LOW–MED | +70 / −0   | 40m    | DONE (uncommitted) |
| 7 visibility (-v only)  | LOW     | +45 / −5   | 30–40m | remaining |
| **Total**               |         | **~+605 / −75** | **~5.5–7h** | |

Plus tests (~+250 LOC across phases) and testbed validation cycles for
Phases 1, 4, 5 (operator-gated builds, not in the agent-time figures).

Sequencing note: Phases 1+2 are the engine and are independently
valuable (reconcile + orphan-sig fix) even without the live UI. 3→4 add
persistence + the live path. 5a (pure refactor) can land anytime and is a
prerequisite for 5; 5 is the reload safety net that also closes the
"reload policies before zones" gap. 6+7 are operability. Recommend
checkpoints after 1, after 2, after 4, after 7. Phase 1 is the riskiest
and gates everything — do it first, testbed it before proceeding. 5a is
the lowest-risk and could even be done early/standalone (it's the
testability refactor that was deferred during the config-restructure
work).
