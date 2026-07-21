# PR-2 transactional policy reload — live test results (foffe, 2026-07-19/20)

Results of executing the runbook
(`2026-07-19-transactional-policy-reload-pr2-selfdriven-runbook.md`) against the
foffe PQ testbed (NetBSD, ~137 pq.axfr.net combo zones). Server built from #292,
then rebuilt from each fix branch as defects were found and fixed.

**Per-row status for the whole matrix — including what is still unrun and why —
is the `Status` column in §4 of the test-plan doc.** This doc records outcomes,
findings and decisions.

## Results

| Scenario | Trigger | Outcome |
|----------|---------|---------|
| **A2** herd / no-re-sign (blocking ②) | reload-zones | ✅ 136/136 backfilled `applied=config`, **zero re-signs** — apex SOA+DNSKEY RRSIG inceptions byte-identical before/after (tdns-debug + independent `dig` cross-check) |
| First-bind apply at scale (① lock) | startup | ✅ 137 PQ zones loaded, 0 errors, no crash, `applied=config` recorded for all signed |
| **B1** compatible rename | two-step `config reload` + `reload-zones` | ✅ `preload-b`→`ed25519-ed25519` applied on the reload path; **inception advanced** (real synchronous re-sign). The two-step was a workaround for finding 2 — **single-step works now** |
| **B2** compatible rename | restart | ✅ applied → `preload-b`, still SECURE (applied≠intent detected across a fresh binding) |
| **C2** incompatible alg refuse | restart | ✅ applied **unchanged**, SOA RRSIG still alg 15 (ED25519, not MLDSA44); refuse-log fired; **zone came up signed, not SERVFAIL** (Finding-1 prevented) |
| **D1** deleted policy | reload-zones | ⚠️ fail-closed quarantine, not §5.6 soft-keep — see finding 4 |
| **Crash regression** (fix 1) | startup, 140 zones incl. 3 keyless | ✅ no crash, all signed — the SIGSEGV of finding 1 is closed |
| **`reload-zones` re-read** (fix 2) | single `reload-zones` | ✅ a zone's changed `dnssecpolicy` **and** a newly-added zone are now picked up without a restart — the finding-5 two-step is gone |
| **`config check` on PQ** (fix 3) | offline + online | ✅ online+role-aware check against the server's own algorithm set: **134 false FAILs → 0**; the one real FAIL (undefined policy ref) is no longer buried |
| **`config check` correlation** (fix 4) | online | ✅ declared-vs-active alg correlation now compares server-reported **names**; verified against live PQ zones |
| **Tip-build re-validation** (2026-07-20) | rebuild `13dfd47` + restart | ✅ 140 zones, **0 panics**, `applied_*` preserved (timestamps unchanged → no spurious re-apply), 0 real errors (15 warnings = expected large-alg advisories). Live-validates the CodeRabbit **CSK-as-ZSK guard**, until then unit-tested only |
| **A2 re-run on tip** | reload-zones | ✅ **140/140** — `applied.before-absent=140`, `applied.backfilled=140` (coverage guard silent), `a2.no-resign=140` at `--tolerance 0`, `reload.issued=1`, exit 0, same daemon pid |
| **C1** incompatible KSK refuse | **reload-zones** | ✅ `e.preload` ED25519 → `mldsa44-falcon512`: applied **unchanged**, S2 **byte-identical**, still alg 15 signed, S5 `zone_policy_apply.go:516` refuse log. Pre-flight `config check` predicted it (KSK+ZSK, 0 FAIL) |
| **C3** ZSK-only alg refuse | **reload-zones** | ✅ `b.preload` `preload-b` → `ed25519-falcon512` (KSK identical, only ZSK differs): refused, applied **unchanged**, S2 **byte-identical**, S5 refuse log `applied_zsk_alg=ED25519`. Confirms v1 refuses ZSK-only changes too |

## Findings

1. **🔴 CRASH (fixed): new online-signed zone first-load SIGSEGV.** A brand-new
   signed zone (no keys) crashed the daemon — nil `zd.DnssecPolicy` at
   `sign.go:505`, because PR-2 defers policy binding to the post-Ready sync while
   the load-time resign (`resignWorkingSetSOAIfSigned → EnsureActiveDnssecKeys`)
   runs first. Existing keyed zones return before the generate path (why unit
   tests + A2 missed it). Full write-up:
   `docs/2026-07-19-new-signed-zone-firstload-segv.md`. **FIXED and merged into
   #292** — two guards + regression tests, live-validated (140 zones incl. 3
   keyless, no crash, signed). A CodeRabbit review then found the first guard
   incomplete (a **CSK published as a ZSK**, flags 257, slipped past a
   `len(dak.ZSKs)==0` test); closed with an explicit `hasRealZSK` (flags 256)
   scan.

2. **Reload semantics — FIXED (fix 2), orthogonal to PR-2.** `reload-zones` alone
   re-read policy **definitions** (`reloadDnssecFromFile`) but **not** zone→policy
   mappings or new zones (used in-memory `conf.Zones`; flagged in-code at
   `config.go:629` as "This is wrong"). Confirmed live at the time: a changed
   `dnssecpolicy` needed the **two-step** `config reload` + `reload-zones` (B1) or
   a restart (B2), and a **new** zone needed a restart. This is a **pre-existing
   bug independent of the transactional-policy branch**, affecting *all*
   config-driven zone changes (primaries, ACLs, options, zonefile, multisigner —
   not just `dnssecpolicy`). Fixed with `reloadZonesFromFile()` (mirroring
   `reloadDnssecFromFile`) + a regression test; live-validated on foffe, and
   merged into #292 so it could be tested here. See ratified decision (2).

3. **`config check` PQ blindness — FIXED (fixes 3+4).** As a pure client
   `tdns-cli` has no PQ algorithm registration, so every PQ policy reported
   "unknown algorithm" — **134 false FAILs** on this config, burying the one real
   FAIL and blocking the alg predict-vs-actual cross-check. Fixed by making the
   check **online and role-aware**: it asks the *server* for its algorithm set
   (`<name, registered>` tuples via `list-algorithms`) rather than trying to know
   PQ codepoints client-side — which is the only correct design, since **PQ
   codepoints are assigned at runtime per deployment**. Offline mode degrades to
   WARN rather than FAIL for unrecognised algs. A follow-up fix corrected the
   declared-vs-active **correlation**, which compared a policy's alg *name*
   against a codepoint-derived string and so never matched for PQ. Both live-
   validated and merged into #292.

4. **Deleted-policy on reload → fail-closed quarantine; `config check` predicts
   it.** Deleting a policy *definition* a running signed zone depends on, then
   `config reload-zones` (a RELOAD, not a restart), quarantines the zone at
   parseconfig (`parseconfig.go:792`, "policy … does not exist" → `State: ERROR`,
   online-signing ignored) and it **stops signing** — fail-closed. Two notes:
   - **`config check` catches this as a pre-flight** (verified): it FAILs with
     *"d.preload references dnssecpolicy \"preload-drop\" which is not defined"*
     before the reload. The pre-flight works as designed — BUT at the time that
     real FAIL was the 135th, buried under 134 **false PQ FAILs** (finding 3), so
     on the PQ set you had to `grep` for it. **Finding 3 is now fixed**, so the
     pre-flight is usable as intended: this exact D1 breakage is predicted, alone,
     before you reload.
   - Fail-closed **pre-empts PR-2's §5.6 soft-keep** (keep serving under existing
     keys + warning), and the quarantine is **not reload-recoverable** — a
     config-ERROR zone is skipped by `reload-zones` (`HasServiceImpactingError`),
     so restoring the policy + `reload-zones` did NOT rescue it; recovery needed a
     **restart**. Design question: is fail-closed (guardrail §4) intended here, or
     should §5.6 soft-keep win for a running signed zone?

## Ratified decisions on the D thread (2026-07-19, with Johan)

Drilling into D produced three separable follow-ups (D itself is NOT a PR-2 bug —
PR-2 classifies/applies correctly; these are about the reload path around it):

- **(1) Clear `DnssecError` when a zone's policy re-resolves on reload — DEFERRED,
  wrong fix now.** The obvious one-liner (`ClearError(DnssecError)` in
  `resolveZonePolicyRef`'s usable branch, so a zone quarantined by a removed
  policy recovers on re-add without a restart) is UNSAFE: `DnssecError` is a
  single `ErrorType` slot covering distinct causes (parse-time unresolvable ref
  `parseconfig.go:794`; sync-time quarantine `zone_policy_apply.go:355`; future
  signing failures), and `ClearError` is keyed by type, not cause — a blanket
  clear could wipe an unrelated, still-valid `DnssecError`. **Blocked on a finer
  DNSSEC error classification** (split the type, or cause-keyed errors). Until
  then, "quarantined-by-removed-policy needs a restart to recover" is a known,
  documented limitation.
- **(2) `reload-zones` must re-read the `zones:` block from the config file(s) —
  CORRECT fix; ORTHOGONAL to PR-2.** Pre-existing bug in
  `ReloadZoneConfig`/`ParseZones` (`config.go:629`), independent of the
  transactional-policy branch, affecting ALL config-driven zone changes (new
  zones, primaries, ACLs, options, zonefile, multisigner — not just
  `dnssecpolicy`). Own branch off `main`, not #292.
- **(3) Reload guardrail (§3.2) — the destination, not yet reached.** The D
  episode is the live motivator: a plain reload silently quarantined a serving
  zone that `config check` would have flagged. The reload should run the
  dry-run+correlate server-side and refuse a service-breaking change unless
  `confirm=true` (policy-reset's preview-without-`--confirm` shape), which also
  gives SIGHUP/restart coverage for free.
- **New dependency surfaced:** a **DNSSEC error-classification restructure** now
  gates (1) and would sharpen (3)'s diagnostics.

## What remains (summary — authoritative per-row detail is §4 of the test plan)

Grouped by *what actually gates them*, not by group letter:

1. **Ready now — no missing tooling, just needs running:** **A4** (sig-validity
   edit + one resigner tick), **G2** (NOTIFY-vs-`zone reload` ConfigUpdate gate),
   **E1** (read-only dry-run smoke). *(C1 and C3 were in this bucket and are now
   done — see the results table.)*
2. **Needs a fixture, not new code:** **E2/E3/E4** (mutate keys / break DS — want
   a throwaway zone, and E3 wants it **delegated** with a DS in `pq.axfr.net` to
   be observable); **F1/F2** (an API/dynamic zone, and a catalog — no catalog is
   configured on foffe).
3. **Needs a harness we do not have:** **G1** (fault injection — the obvious lever
   is ruled out, see below), **G3/G4** (competing `policy-set` + reload under
   query load; likely an extension of `tdns-debug test churn`).
4. **Gated on a pending decision:** **D2** and **D4** — mechanically reachable,
   but the D group's *expected* behaviour is in flux pending ratified decisions
   (2)/(3); re-run once the reload guardrail lands. D4 additionally needs the
   error-classification restructure to induce a policy `Error` cleanly.
5. **H1's two uncovered legs:** CLI override + YAML drift, and the **Branch-1b
   in-flight ZSK roll** ("skipping config… ZSK roll in flight"). These are the
   only substantive H1 gaps — the rest of H1 is re-packaging of rows already run.

**Note on G1:** the D1 episode *removed* the obvious way to induce a first-load
sync failure. A "broken-then-fixed policy" trips `parseconfig`'s quarantine
upstream, so the retained-OnFirstLoad state is never reached and
`finishFirstLoadPolicy` never gets exercised. G1 needs a real test hook.

**H2 status (corrected 2026-07-20):** *not* blocked — the `pq.axfr.net`
delegation is published and the chain validates end-to-end (`ad` from 8.8.8.8,
`delv` "fully validated", DS `10549 15 2`). Residual: standard validators
implement only the ED25519 links, so **PQ leaves read INSECURE to them** and need
a PQ-aware validator (`dog +sigchase` / `tdns-imr`); and the `*.preload` fixtures
have no DS in `pq.axfr.net`, so they sit outside the chain until one is added.

## State left on foffe

140 zones, 0 errors, single instance, no crash, daemon idle. **All three binaries
(`tdns-auth`, `tdns-cli`, `tdns-debug`) are now built from the #292 tip
`13dfd47`** — the version skew noted previously is gone.

Fixtures `b/c/d/e.preload.axfr.net` + policies `preload-b`/`preload-drop` loaded,
all restored to their pre-test policies after C1/C3. Config is byte-identical to
the pre-rebuild backup except one intentional change: `c.preload` was normalised
from `mldsa44-falcon512` back to `ed25519-ed25519` to clear a stale
post-C2 drift, so the restart baseline would be clean.

Backups for rollback: binary `/usr/local/libexec/tdns-auth.bak-20260719-2312`,
config `/etc/tdns/tdns-auth.yaml.pre-rebuild-20260719`, keystore
`/var/lib/tdns/tdns-auth.db.pre-a2-20260719`, plus the older `.prematrix` /
`.pre-pr2` set. All four fixes are merged into #292; the three fix branches have
been cleaned up.

**Note on the A2 re-run:** arming (`UPDATE ZonePolicyOverride SET
applied_policy=NULL, …`) is a prerequisite — without it every zone takes the
same-name no-op branch and the run is clean-but-vacuous. The DB was left
re-populated at `140|140` by the run itself, so re-arming is required before any
future A2.
