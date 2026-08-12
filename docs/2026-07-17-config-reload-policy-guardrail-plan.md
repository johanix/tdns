# Config-reload policy-change guardrail — design & sequencing plan

- **Status:** **PR-B IMPLEMENTED 2026-07-24** (branch
  `feature/config-reload-policy-guardrail`). §1–§7 below are the original design
  thread of 2026-07-16/17 (tags **[DECIDED]** / **[LEANING]** / **[OPEN]**); the
  code has since drifted (PR-2 merged, other parts already landed). **§9 is the
  authoritative "what was verified and built" layer — read it first.** Inline
  `[UPD 2026-07-24]` notes mark where the historical design no longer matches main.
- **Relationship to other work:** builds on PR-2 (transactional policy reload,
  `docs/2026-07-15-transactional-policy-reload-plan.md`, PR #292 — **now MERGED to
  main**, so this guardrail's precondition is met).
- **Intended home:** `tdns-project/tdns/docs/2026-07-17-config-reload-policy-guardrail-plan.md`.

---

## 1. Problem

The DNSSEC keystore persists only the **zone→policy-name mapping**, not policy
content. The reload classifier (`classifyPolicyChange` in `zone_policy_apply.go`)
compares applied-vs-intent by resolving both names against the *current*
`ConfLive()` policies. Consequences:

- A **policy-name change** for a zone (`example.com`: FOO→BAR) *is* detected, and
  an incompatible algorithm change is currently **refused**
  (`reconcileActiveKeyAlgorithms`, `sign.go:302`; also `key_state_worker.go:305`).
- A **same-name content change** — operator edits policy FOO's `ksk` algorithm
  Ed25519→FALCON512 in the YAML, zone stays on FOO — is **invisible** to the
  classifier: applied and intent both resolve to the *new* FOO, so
  `classifyPolicyChange` returns `None`. Branch 1 rebinds the zone to the new FOO
  and does **not** re-sign or roll keys. The mismatch only surfaces later, at the
  next sign, when `reconcileActiveKeyAlgorithms` **refuses** (KSK) — leaving the
  zone stuck: active keys are Ed25519, policy wants FALCON512, re-signs fail,
  stale sigs served until expiry → eventual bogus. Nothing performs the rollover
  (the KSK-algorithm-rollover engine is "not yet built").

This is the Finding-A blind spot made concrete: **a same-name algorithm edit is
the one change no existing path detects-and-handles.**

## 2. Governing axiom **[DECIDED]**

> **The YAML config is the single source of truth. The DB persists only the
> zone→policy-*name* mapping (for change detection across restart), never policy
> content. On conflict, YAML wins and the server converges reality to it.**

Corollary — **no half-truths.** Either the DB is the truth (persist everything) or
the YAML is (persist nothing extra). Persisting *just the algorithms* to enable a
"keep signing under the old alg" fallback was **rejected** as a half-truth: it
would have the server sign Ed25519 forever while the config says FALCON512.

## 3. Design decisions — the four "thoughts"

| # | Idea | Verdict |
|---|------|---------|
| 1 | `tdns-checkconf` — validate new config *and correlate against the running server* to warn about painful changes before applying | **[DECIDED] build it** |
| 2 | Persist per-policy algorithms so an alg change can fall back to the old alg (soft-warn, keep signing) | **[DECIDED] reject** — half-truth (see §2) |
| 3 | Treat a same-name alg change as a `policy-reset`: converge (drop old keys, regenerate under the new alg), keep signing rather than SERVFAIL | **[LEANING] yes** — see §3.1 |
| 4 | Make `config reload` itself the guardrail: server evaluates the new config, and refuses a dangerous converge unless `confirm=true` | **[DECIDED] yes** — see §3.2 |

### 3.1 Converge-instead-of-refuse (Thought 3) **[LEANING]**

Change `reconcileActiveKeyAlgorithms` from **refuse** → **drop-and-regenerate**
(what `policy-reset` does): the zone keeps signing, now under the new algorithm.
This is where "restart = policy-reset" lives, but note it generalizes:

- The reconcile runs at **every sign** — restart's first-bind, reload's deferred
  re-sign, **and the background resigner on a live server**. So convergence fires
  without a restart too. "Restart = reset" is too narrow; it's "the signer
  converges keys to the policy."
- Converge **breaks the chain of trust**: the parent DS still matches the old KSK.
  Validators go BOGUS until the new DS propagates. **[DECIDED] mitigate** by
  auto-driving the new DS via CDS/CSYNC (delegationsync already exists). This
  shrinks the dominant, unbounded term (wait for a human to update the registry)
  to a bounded one. It does **not** reach zero: an abrupt swap still has an
  irreducible bogus window of ~max(DS TTL, DNSKEY TTL) for resolvers holding the
  old cached DS. Keep those TTLs low on PQ-migrating zones.
- The window-free production answer is a **make-before-break** algorithm rollover
  (RFC 6781: whole-zone double-signature during transition). It is **[OPEN /
  future]** and genuinely expensive — PQ signatures balloon the transitional
  zone. The abrupt converge is the deliberate shortcut that trades the bogus
  window for not double-signing; that trade is only acceptable behind the §3.2
  gate.

### 3.2 The reload guardrail (Thought 4) **[DECIDED, with open sub-points]**

- **Server-side gate.** The refusal lives in the reload *handler*
  (`ReloadConfig`/`ReloadZoneConfig`, both under `confMu`, `config.go:564/607`),
  **not** in `tdns-cli`. A client-only check is bypassed by SIGHUP and direct API
  calls. `tdns-cli` only (a) renders a richer negative response and (b) carries a
  `confirm=true` field. **[DECIDED]**
- **Free SIGHUP coverage.** Because the gate is in `Reload*`, SIGHUP hits it too
  and cannot set `confirm=true`, so a dangerous converge is held/refused
  automatically — exactly the "un-confirmable trigger" behavior we want, no extra
  code. **[DECIDED]**
- **Without `confirm`: refuse the whole reload atomically.** Cleaner than a
  partial reload, and it usefully surfaces a latent dangerous edit to an operator
  who was reloading for something unrelated. **[LEANING]**
- **Un-confirmable triggers (restart / crash / SIGHUP) → hold-and-scream**, not
  detonate and not permanent keep-old: come up serving the existing keys, log
  ERROR + zone status + alert, and wait for an explicit `reload --confirm`. Framed
  as a *transient guardrail on the one path that structurally cannot consent* —
  distinct from the §2 steady-state half-truth. **[OPEN]** — Johan has not
  ratified that this reads differently enough from steady-state keep-old. True
  server startup (`ParseConfig(false)`, `main_initfuncs.go:125`) is the residual
  path that bypasses `Reload*`; closing it uses the same primitive at startup.

## 4. The template-fallback bug **[DECIDED: it's a bug]** — independent

> **[UPD 2026-07-24] ALREADY FIXED on main — no work needed (PR-A dropped).**
> Verified against current `parseconfig.go`: `ExpandTemplate` (parseconfig.go:1253)
> runs BEFORE the policy resolution and gap-fills `DnssecPolicy` only when the
> zone left it empty (zone-wins, line 1277). The zone loop then calls
> `resolveZonePolicyRef` (parseconfig.go:1718) at line 885, which **fails closed**:
> an explicit-but-unresolvable policy sets `zconf.DnssecPolicy = ""` **and**
> `zd.SetError(DnssecError, …)` (parseconfig.go:886-889) → the zone is quarantined,
> never silently signed under the template's `default`. The §8 live evidence
> (2026-07-19) already relied on this fail-closed behavior. So PR-A is a no-op and
> is not part of the implemented PR-B.

A zone with an **explicit** `dnssecpolicy` whose name does **not** resolve
currently falls back to the template's policy (observed: `test.foo` bound to
`no-such-policy-xyz` silently signed under the template's `default`). This is
wrong: an explicit-but-unresolvable policy must **fail closed** (SERVFAIL / the
zone's own `DnssecError`), never silently sign under a *different* policy. Either
publish under the correct policy or don't publish. Lives in the zone/template
policy resolution (`resolveZonePolicyRef`, `parseconfig.go:1570`, called from
`parseconfig.go:790`), independent of §3/§3.2.

## 5. Feasibility of the server-side dry-run (investigated 2026-07-17)

> **[UPD 2026-07-24] Confirmed and built (this is the core of PR-B).** Two notes on
> drift: (a) the anchors moved — `ParseConfig` decode is now parseconfig.go:283-330,
> `parseDnssecConfig` is parseconfig.go:1624, `reloadDnssecFromFile` is
> parseconfig.go:1431; (b) the §5.3 "refactor `processConfigFile`+decode into a
> shared `decodeConfigFile`" was **NOT** done — the implemented `dryParseDnssecPolicies`
> re-reads the file the SAME way `reloadDnssecFromFile` does (a scratch `&Config{}`
> receiver + `parseDnssecConfig`), which is the §5 "decode into a scratch `*Config`"
> path and needs no refactor. `decodeConfigFile` extraction stays a future de-dup.
> Also: the "build once, three consumers" payoff did NOT materialize as a single
> shared primitive — `config check` (PR-D, PR #303) had already shipped its OWN
> CLIENT-side predictor (`checkPolicyAlgVsActiveKeys` / `missingRoleAlgs`,
> config_check_cmds.go). PR-B adds a parallel SERVER-side predictor
> (`policyAlgStrandsActiveKeys`, config_reload_guardrail.go); both are small, pure,
> and unit-tested. Consolidating them is deferred (see §9).

**Verdict: low-complexity for the part that matters; most enabling code exists.**

- The config decode targets a **receiver**, not globals: `ParseConfig` reads files
  via `processConfigFile` and decodes into `Result: conf` (`parseconfig.go:281-330`).
  No global viper in this path → decoding into a **scratch `*Config`** is trivial.
- `parseDnssecConfig` (`parseconfig.go:1481`) is almost-pure — only writes
  `conf.Internal.{DnssecPolicies,…}` on the receiver. Run it on the scratch.
- Two precedents already exist: `ValidateDnssecPoliciesFromFile`
  (`ksk_rollover_policy.go:653`, pure file→policies) and `reloadDnssecFromFile`
  (`config.go:623`, re-read just the dnssec block). `buildRuntimeConfig`
  (`runtime_config.go:53`) already copies the policies map.
- Only the **early** part of `ParseConfig` (decode) + `parseDnssecConfig` runs in
  the dry-run — none of the heavy side effects (TSIG, KeyDB, refreshers).

**What the pitstop needs:**
1. `dryParseConfig(cfgfile) → (map[string]DnssecPolicy, error)` — ~30–50 lines,
   mostly reuse.
2. **Correlation** — read-only loop over `Zones`: for each signed `zd`, compare
   `newPolicies[zd.DnssecPolicyName]` KSK/ZSK alg vs the running active-key alg
   (keystore). This is `reconcileActiveKeyAlgorithms` as a dry-run. ~40–60 lines
   + a result struct.
3. **Refactor for honesty:** extract `processConfigFile` + the decode
   (`parseconfig.go:281-330`) into a shared `decodeConfigFile(cfgfile, target)` so
   the dry-run and the real parse cannot diverge.

**Payoff:** this dry-run+correlate primitive *is* `tdns-checkconf`'s
server-correlation (Thought 1) and the startup-hold check. Build once, three
consumers. Return structured data, not just logs.

## 6. Open questions / forks **[OPEN]**

- **Coverage scope of the correlation.** v1 = same-name alg change (cheap; policies
  + keystore only). Catching a *zone rebound to a different-alg policy* in the same
  dry-run needs the new zone→effective-policy-name mapping factored out of
  `ParseZones` (`parseconfig.go:582`, entangled). The existing classifier already
  detects name changes → recommend v1 skips it and flips the classifier's terminal
  action from refuse→confirm-gated-converge.
- **TOCTOU / two-phase reload.** Re-parse-after-confirm (simple; tiny window if the
  file changes between dry-run and apply) vs parse-to-scratch-then-commit (clean;
  no window; refactors `Reload*`; synergizes with the transactional-reload theme).
- **Hold-vs-refuse** on un-confirmable triggers (§3.2) — ratify or reject.
- **Template fix placement** — fast-track ahead of PR-2 (if it touches no PR-2
  line) or land after.
- **make-before-break** algorithm rollover — future project, out of scope here.

## 7. Work breakdown & sequencing **[PROPOSED — not ratified]**

Ordering is driven by *dependency*, not file proximity. The one hard constraint:

> **PR-B (guardrail) MUST precede PR-C (converge).** Converge-instead-of-refuse is
> a naked DS-break footgun without the confirm gate. Keep `refuse` until the gate
> exists. PR-B alone (gate + keep `refuse`) is a shippable safety win on its own.

| PR | Content | Depends on | Files (hot?) |
|----|---------|-----------|--------------|
| **PR-2** | transactional policy reload (in flight, #292) | — | `zone_policy_apply.go`, `refreshengine.go` (hot) |
| **PR-A** | template fail-closed fix (§4) | — (independent) | `parseconfig.go` (`resolveZonePolicyRef`) |
| **PR-B** | guardrail: `decodeConfigFile` + `dryParseConfig` + keystore correlation + server-side confirm gate + hold-on-un-confirmable (§3.2, §5) | PR-2 landed | `parseconfig.go`, `config.go` |
| **PR-C** | converge: `refuse → drop+regen` + auto-CDS (§3.1) | **PR-B** | `sign.go`, keystore, delegationsync |
| **PR-D** | `tdns-checkconf` (reuses PR-B primitive) | PR-B | new CLI; parallel-safe with PR-C |

**Avoiding the file-conflict pain:** cut every new-work branch off **post-PR-2
main**, never off current main. Then there is nothing to rebase (respects the
no-rebase preference); the new work edits the settled files. Cost is short
serialization; PR-2 is close.

**Optional de-risk:** the `decodeConfigFile` extraction + `dryParseConfig`
scaffolding is behavior-neutral and touches a parseconfig.go region PR-2 does not
(the decode block). It *could* land as a tiny precursor PR before/alongside PR-2
without conflict. Otherwise fold it into PR-B.

**Decisions reserved for Johan:** the PR-2 merge itself; fast-tracking PR-A;
spinning out the `decodeConfigFile` precursor; ratifying §3.1/§3.2 LEANING/OPEN
items; the coverage-scope and TOCTOU forks in §6.

---

## 8. Live evidence + ratified decisions (2026-07-19)

PR-2 live testing on the foffe PQ testbed produced a concrete motivator for §3.2
and three ratified follow-ups. Full context:
`docs/2026-07-19-transactional-policy-reload-pr2-live-results.md`.

**Live evidence for §3.2 (the reload guardrail).** Deleting a `dnssec.policies`
entry a running signed zone depends on, then a plain `config reload-zones`,
**silently quarantined the serving zone** (parseconfig fail-closed at
`parseconfig.go:792` → `DnssecError` → online-signing ignored → zone stopped
signing). `config check` **would have predicted it** (FAIL on the undefined
`dnssecpolicy` ref) — proving the dry-run+correlate primitive (§5) is exactly what
the reload gate should run before applying. This is the live demonstration that
fail-closed-at-parse is strictly worse than refuse-at-reload-with-preview (§3.2):
the former disrupts a running zone and needs a **restart** to undo; the latter
never touches it. **Strengthens §3.2 → build it.**

**Ratified decisions:**

- **[DECIDED] Do NOT clear `DnssecError` on policy re-resolve — yet.** The obvious
  fix for "a zone quarantined by a removed policy doesn't recover on re-add
  reload" (`ClearError(DnssecError)` in `resolveZonePolicyRef`'s usable branch) is
  **unsafe**: `DnssecError` is one `ErrorType` slot covering distinct causes
  (parse-unresolvable ref `parseconfig.go:794`; sync-time quarantine
  `zone_policy_apply.go:355`; future signing failures), and `ClearError` is keyed
  by type, not cause — a blanket clear could wipe an unrelated, still-valid
  `DnssecError`. **Blocked on a DNSSEC error-classification restructure** (new
  dependency; see `docs/2026-07-19-dnssec-error-classification-restructure.md`).
  Restart-only recovery stands as a known limitation until then.
- **[DECIDED] `reload-zones` must re-read the `zones:` block from file — but it is
  ORTHOGONAL to this guardrail and to PR-2.** Pre-existing bug in
  `ReloadZoneConfig`/`ParseZones` (`config.go:629`'s own "This is wrong" comment),
  affecting ALL config-driven zone changes (new zones, primaries, ACLs, options,
  zonefile, multisigner — not just `dnssecpolicy`). Fixed on its own branch.
- **[DECIDED] The reload guardrail (§3.2) is the destination** — not reached yet;
  the D episode is the case for it (PR-B in §7).
- **New dependency surfaced:** a **DNSSEC error-classification restructure** gates
  the `ClearError` fix and would sharpen §3.2's diagnostics.

---

## 9. Implementation — PR-B landed (2026-07-24) **[AUTHORITATIVE]**

Branch `feature/config-reload-policy-guardrail`, cut off current `main` (post-#292).
This section supersedes the §1–§7 sequencing where they disagree.

### 9.1 Verification of the plan against current main

| Plan item | Status on main (2026-07-24) | Action |
|-----------|-----------------------------|--------|
| PR-2 (transactional reload, #292) | **MERGED** — precondition met | — |
| §1 blind spot (same-name alg edit invisible to the classifier) | **Still real.** `classifyPolicyChange` (zone_policy_apply.go:85) resolves applied+intent from the same `ConfLive()` by name; a same-name edit → both resolve to the *new* policy → `PolicyChangeNone` → Branch 1 rebinds with no re-sign; `reconcileActiveKeyAlgorithms` (sign.go:302) then REFUSES at sign. | **Guardrail built (PR-B).** |
| §4 template fail-closed (PR-A) | **ALREADY FIXED** (see §4 note). | Dropped. |
| §5 server-side dry-run+correlate | Feasible as described; anchors moved. | **Built.** |
| PR-D `tdns-checkconf` | **ALREADY SHIPPED** as `config check` (#303), CLIENT-side. | Reused as prior art; not rebuilt. |
| PR-C converge (`refuse → drop+regen` + auto-CDS) | Not built; MUST follow PR-B. | **Deferred (out of scope).** |

### 9.2 What PR-B implements

The server-side reload guardrail (§3.2 / §5), all in `v2/`:

- **`config_reload_guardrail.go`** (new):
  - `policyAlgStrandsActiveKeys(want, active, relaxed)` — the **pure** dry-run of
    `reconcileActiveKeyAlgorithms`, lenient in the same sense as the CLI's
    `missingRoleAlgs` (zero-keys → not a miss; mid-rollover with the wanted alg
    present → not a miss). Compares **codepoints** (in-process, no name dance).
  - `dryParseDnssecPolicies()` — re-reads the `dnssec:` block into a throwaway
    `&Config{}` and runs `parseDnssecConfig` (no side effects); returns the
    would-be-new policies + the new `completeness` mode.
  - `detectStrandingPolicyChanges(newPolicies, relaxed)` — the §5.2 correlation: a
    read-only loop over live `Zones` comparing `newPolicies[zd.DnssecPolicyName]`
    (the zone's CURRENT bound name — same-name scope, §6) against the zone's active
    keys. Never mutates.
  - `ReloadGuardrailError` + `reloadGuardrailDecision(findings, confirm)` (the pure
    confirm gate) + `checkReloadPolicyGuardrail(confirm)` (the entry point).
- **`config.go`**: `ReloadConfig`/`ReloadZoneConfig` kept as thin wrappers that call
  new `reloadConfig(confirm)`/`reloadZoneConfig(ctx, confirm)`;
  `ReloadConfigConfirm`/`ReloadZoneConfigConfirm` added for the confirm-carrying
  API path. `checkReloadPolicyGuardrail` runs **first, under `confMu`, before any
  mutation** → a refusal is atomic.
- **`api_structs.go`**: `ConfigPost.Confirm`; `ConfigResponse.GuardrailBlocked` +
  `.GuardrailZones` (with `ReloadGuardrailZone`/`ReloadGuardrailRole`).
- **`apihandler_funcs.go`**: `reload`/`reload-zones` call the `*Confirm` variants
  and surface structured findings via `applyReloadGuardrail`.
- **`cli/config_cmds.go`**: `--confirm` flag on `reload` and `reload-zones`; a rich
  `renderReloadGuardrail` block on refusal.
- **Tests** (`config_reload_guardrail_test.go`): the pure predicate (10 cases incl.
  same-name catch, benign, zero-keys, mid-rollover, relaxed-vs-strict ZSK, CSK);
  the confirm gate; and an end-to-end `detectStrandingPolicyChanges` over a real
  KeyDB + live `Zones` (dangerous caught, benign clean, confirm proceeds, removed
  policy name skipped).

### 9.3 Forks resolved (owner AFK — minimal, safest, "YAML is truth / converge
behind a confirm gate")

- **§6 coverage scope → v1 = same-name only.** Uses the zone's current bound name
  vs new policies. A zone rebound FOO→BAR is left to the existing classifier
  (`PolicyChangeIncompatibleAlg` → refuse). A rare *simultaneous* name-change +
  same-name alg-edit can produce a fail-**safe** false-positive confirm prompt —
  accepted (the classifier still handles the rebind correctly).
- **§6 TOCTOU → simple re-parse.** Dry-parse to scratch → gate → then the real
  reload re-parses. Both parses are under `confMu` (µs apart, same file); the tiny
  window is accepted over refactoring `Reload*`. A refusal mutates nothing.
- **§3.2 hold-vs-refuse → SIGHUP hold is FREE and shipped.** SIGHUP calls
  `ReloadZoneConfig` (confirm=false) → the gate holds the change and logs ERROR.
  **True server startup hold is DEFERRED** (see §9.4).
- **§3.2 "refuse the whole reload atomically" [LEANING] → RATIFIED.** The gate runs
  before any mutation, so refusal is all-or-nothing and surfaces a latent dangerous
  edit even to an operator reloading for something unrelated.
- **Relaxed-mode ZSK → not flagged.** A ZSK alg change in `completeness: relaxed`
  is a supported gradual FIFO roll (reconcile no-ops); flagging it would refuse a
  safe op. KSK/CSK changes are flagged in either mode. (Server-side precision the
  CLI's mode-agnostic predictor lacks.)
- **Fail-open on error.** If the dry-parse or the keystore correlation errors, the
  reload proceeds (logged). The guardrail is an additive safety net; an internal
  hiccup must not brick a legitimate reload.
- **Predictor consolidation → NOT done.** Server predictor is parallel to the CLI's
  (§5 note). Deferred.

### 9.4 Deferred (documented, NOT in PR-B)

- **PR-C converge** (`refuse → drop+regenerate` + auto-CDS to bound the DS-break
  window). PR-B deliberately keeps the signer's REFUSE, so a *confirmed* reload
  applies the new binding but the signer still refuses to re-sign until the key is
  rolled (via the auto-rollover engine or, on a test zone, `policy-reset`). The
  hard sequencing constraint (§7: PR-B before PR-C) is honored.
- **True startup-hold** for the un-confirmable restart/crash path
  (`ParseConfig(false)` at first-bind). Needs the DNSSEC error-classification
  restructure (§8) to hold-and-scream without wiping unrelated `DnssecError`s;
  riskier and out of scope. Restart remains a way to force a dangerous alg change
  through — a known, documented limitation.
- **make-before-break** whole-zone double-signature rollover (§3.1) — future.
- **`decodeConfigFile` extraction** and **CLI/server predictor consolidation** —
  de-dup refactors, not behavior.
