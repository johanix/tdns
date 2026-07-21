# Unmerged-branch review — 2026-07-19

Extended review of the tdns branches that still carry commits not reachable from
`origin/main` (`474f492`). For each branch: size relative to `main`, objective,
merge readiness, CodeRabbit (CR) review state — **both findings that were
addressed and, especially, any that were not** — and the corresponding design
doc under `docs/`. Ends with a cross-branch conflict matrix and a recommended
landing order.

## Scope

Most remote branches are already merge-committed into `main`; the genuinely
unmerged set is small. By explicit decision this review **excludes**:

- Dead / experimental local branches: `johani-test-1`, `rrcache-module`
  (commit msg: *"most likely a failed attempt"*), `mpauditor-1`.
- Remote-only, no-PR branches: `origin/86-store-private-keys-as-pem-blocks`,
  `origin/keybootstrap`, `origin/mldsa44-sig0-fork`.
- External / bot PRs: #278 (dependabot), #107 (`leon/ixfr-support`, contributor
  fork, 2025).

**In scope (10 branches / 5 open PRs):**

| # | Branch | PR | Δ vs main | Behind | CR state | Readiness |
|---|--------|----|-----------|--------|----------|-----------|
| B | `feature/transactional-policy-reload-pr2` | [#292](https://github.com/johanix/tdns/pull/292) | +859/−274, 5f | 24 | ✅ 5/5 resolved | **Review-done; needs your -race+live gate** |
| A0 | `feature/ddns-keystate-phase0` | [#294](https://github.com/johanix/tdns/pull/294) | +418/−102, 10f | 23 | ⚠️ **rate-limited → unreviewed** | Retrigger CR, then ready |
| A1 | `feature/ddns-keystate-phase1` | [#295](https://github.com/johanix/tdns/pull/295) | +295/−41 vs phase0 | 23 | ⚠️ **skipped (non-default base) → unreviewed** | Retarget→main after A0, then review |
| A2/A3 | `feature/ddns-keystate-phase2`, `…-phase3a` | — | 0 (== phase1 tip) | — | — | Empty placeholders |
| C1 | `fix/imr-nits` | [#300](https://github.com/johanix/tdns/pull/300) | +254/−51, 4f | 3 | ⚠️ **2 open Major findings** | Address CR (or waive), then ready |
| C2 | `imr-transport-selection-phase2` | — (supersedes #257) | +1210/−46, 12f | 9 | n/a (no PR) | Needs PR + review + validation |
| C3 | `imr-transport-selection-wip` | [#257](https://github.com/johanix/tdns/pull/257) | +903/−49, 11f | 380 | old | **Superseded by C2 — close** |
| D | `fix/bmake-portable-alg-env` | [#298](https://github.com/johanix/tdns/pull/298) | +53/−10, 3f | 3 | ✅ 0 actionable | **Ready** |
| E | `docs/agent-dsync-proxy-plan` | — | +426 (1 doc) | 311 | n/a | **Stale — delete candidate** |

All five open PRs report `mergeable=MERGEABLE`, `mergeStateStatus=CLEAN`, and a
green status check as of this review.

---

## A. DDNS / KeyState draft-alignment stack — #294, #295 (+ placeholders)

**Design doc:** [`docs/2026-07-16-ddns-delegation-keystate-draft-alignment-plan.md`](2026-07-16-ddns-delegation-keystate-draft-alignment-plan.md)
(in `main`; both PR bodies cite it phase-by-phase). Supporting background:
`2026-03-07-delegation-sync-refresh-plan.md`, `2026-03-09-agent-driven-parent-delegation-sync.md`,
`2026-02-26-rfi-keystate-inventory-plan.md`, `2026-05-15-delegation-backend-invariant.md`.

Re-aligns tdns (the reference implementation) to **draft-berra-dnsop-keystate-03**
and **draft-ietf-dnsop-delegation-mgmt-via-ddns-02**. All work is in `v2/` only.
`phase1` is **stacked on** `phase0` (base branch = `feature/ddns-keystate-phase0`,
not `main`); phase1 = phase0 + one commit `b66ffe5`.

### A0 — `feature/ddns-keystate-phase0` (PR #294) — Phase 0, correctness fixes

Commits: `dc1a451` align KeyState EDNS(0) option to -03 · `443ffdf` correct
UPDATE-receiver RCODE/EDE mapping (BADKEY vs REFUSED) · `25de9e4` carry SIG(0)
UPDATEs over TCP regardless of size. Touches `keystate.go`, `edns0/edns0_keystate.go`,
`sig0_validate.go`, `childsync_utils.go`, `updateresponder.go`,
`defaultqueryhandlers.go` + phase0 tests. The "contradicts the draft" fixes
(K-1/2/3, D-8 rcode inversion, D-2a force-TCP).

- **Readiness:** mergeable/CLEAN, green CI, targets `main`. **But CodeRabbit was
  rate-limited** — its comments are a *"Review limit reached… we couldn't start
  this review"* warning (2026-07-16 19:06) plus a manual re-trigger (22:30) that
  produced **no review and no inline threads**. Treat #294 as **not yet reviewed
  by CR**, not as "clean." Retrigger now that the limit has reset before merging.
- **Validation:** live-validation on the testbed still pending (per project notes).

### A1 — `feature/ddns-keystate-phase1` (PR #295) — Phase 1, KeyState-03 completion

Adds `b66ffe5`: full receiver key-state map (`GetKeyStatus` / `childKeyState`,
K-4, with validated≠trusted independence) and QTYPE=KEY inquiry (K-5); codes 7/8
land as dormant P2 stubs. New `keystate_map_test.go`, larger `keystate.go`
(+265), plus `keybootstrapper.go`, `parentsync_bootstrap.go`.

- **Readiness:** mergeable vs its base (phase0). **CodeRabbit skipped it** —
  *"Auto reviews are disabled on base/target branches other than the default
  branch"* — because the PR targets `phase0`, not `main`. It will not get a CR
  review until **retargeted to `main`** (do this once #294 merges). So #295 is
  also **currently unreviewed**.

### A2/A3 — `feature/ddns-keystate-phase2`, `…-phase3a`

Reserved worktrees; both tips == phase1 (`b66ffe5`), **zero unique commits**, no
PRs. Nothing to review yet — they hold space for the design-note-first Phase 2/3
work that branches off phase1. Leave as-is.

---

## B. Transactional DNSSEC policy reload — PR-2 — #292

**Design docs:** [`2026-07-15-transactional-policy-reload-plan.md`](2026-07-15-transactional-policy-reload-plan.md)
+ [`-decisions.md`](2026-07-15-transactional-policy-reload-decisions.md); follow-on
[`2026-07-17-config-reload-policy-guardrail-plan.md`](2026-07-17-config-reload-policy-guardrail-plan.md)
(the guardrail lane sequenced **after** this PR); related
`2026-07-15-finding4-async-reload-signing-plan.md`, `2026-06-16-dnssec-policy-change-handling.md`.

Commits: `7eaa6a1` wire refresh-engine policy sync through the transactional core
· `1c64fbe` address CR findings · `44f4d2d` keep signed zones serving when the
intent policy is deleted; gate reload sync. Wires the three refresh-engine sites
through `resolvePolicyPair → backfill → classify → apply/refuse`
(`syncZoneDnssecPolicyFromConfig`), removes `applyReloadedPolicyLocked`, and
closes the backfill GATE (served apex SOA RRSIG matching intent alg; Branch-0
backfill only post-`InstallInitialSnapshot`). Concentrated in `refreshengine.go`
(±307) and `zone_policy_apply.go` (+259), with a new `zone_policy_reload_test.go`
(+321).

- **CodeRabbit:** reviewed 2026-07-16; **5 findings, all resolved** — Ready-check
  before reading the working set (`zone_policy_apply.go:288`), return resolver
  errors instead of swallowing (`:396`), never bind policies whose Error is set
  (`:466`), plus two now-outdated Major items (make sync fail-closed on rollover;
  the refreshengine site). This is the **best-reviewed** branch in the set.
- **Readiness:** deepest/riskiest change here (policy + refresh core, 24 commits
  behind main). GitHub reports a clean merge, but the standing merge gate is a
  **full `-race` run + the live testbed matrix** — that is the only thing left.
- **Leverage:** landing it **unblocks the config-reload guardrail lane** (PR-A..D
  in `2026-07-17-…-guardrail-plan.md`), so its validation has the highest
  downstream payoff.

---

## C. IMR cluster — #300, phase2, #257

### C1 — `fix/imr-nits` (PR #300) — imr nits collector

**Design doc (partial):** [`2026-07-18-imr-transport-stats-design.md`](2026-07-18-imr-transport-stats-design.md)
+ [`-review.md`](2026-07-18-imr-transport-stats-review.md) (in `main`) cover the
transport-stats surface; the apex-NS fix is a standalone bug (project note N1).

Commits: `5aae020` fix cold QTYPE=NS looping to "max iterations" (referral NS is
in AUTHORITY `r.Ns`, not `r.Answer`) · `84edd47` render transport-stats from the
local cache in the REPL · `c66f757` add `suffix` filter to transport-stats.
Touches `apihandler_imr.go`, `cli/imr_transport_stats_cmd.go` (+214),
`dnslookup.go`, new `transport_stats_filter_test.go`. All fixes verified live on
real auth servers (axfr.net / dsync.se) per PR body.

- **⚠️ CodeRabbit — 2 OPEN Major findings (unaddressed).** Reviewed 2026-07-19
  00:12 UTC, *after* the last commit (00:08 UTC), so they stand against the tip:
  1. `cli/imr_transport_stats_cmd.go:38` — **Unify DNS-aware zone/suffix matching
     across local + API paths.** Raw string matching permits partial-label
     matches, is case-sensitive, and disagrees on precedence when both filters
     are set. Wants label-boundary/case-normalized equality in both
     `imr_transport_stats_cmd.go` and `apihandler_imr.go`, with regression cases.
     *(Major, "quick win".)*
  2. `cli/imr_transport_stats_cmd.go:84` — **Propagate cancellation through CLI /
     API-client / server iteration** (`cmd.Context()` → dispatcher/renderers,
     select on cancel + closed `IterBuffered()`, stop server iteration on
     `r.Context()` cancel). *(Major, "heavy lift".)*
- **Readiness:** mechanically mergeable/CLEAN/green, but **not review-clean** —
  decide to fix or consciously waive #1/#2 first. #1 is genuinely a correctness
  nit worth doing; #2 is larger and arguably deferrable.

### C2 — `imr-transport-selection-phase2` (no PR) — DNSKEY transport-selection policy

**Design doc:** [`docs/2026-06-12-transport-selection-policy.md`](2026-06-12-transport-selection-policy.md)
— **carried in-branch, not yet in `main`** — plus in-branch
`docs/2026-07-06-pr257-merge-conflict-analysis.md`; builds on
`2026-05-21-large-ksk-distinct-algs-and-imr-tcp-signal.md` (in main).

The live continuation of the #257 work: DNSKEY transport-policy enum +
transport-selection, wired into the large-KSK metrics path (`large_ksk.go`,
`imr_large_ksk_metrics.go` +117, `dnslookup.go` +39, `config.go`, `imrengine.go`,
`parseconfig.go`, sample YAMLs). Contains #257's two real commits (`313b3ea`,
`8c91063`) plus two merges of `main` and a docs commit — i.e. **a strict superset
of #257**, brought up to date with main (behind only 9).

- **Readiness:** largest change in the set (+1210) with **no PR**. Needs a PR
  opened, a CR review, and validation before it can land.

### C3 — `imr-transport-selection-wip` (PR #257) — WIP/scratch

The historical PR (title marks it "WIP/scratch"), 380 behind main, last touched
2026-06-12. Its entire content is subsumed by C2. **Recommendation: close #257**
(and either open a fresh PR from `phase2` or repurpose #257's head to phase2 — a
force-update/rebase, which is your call given the no-rebase preference; opening a
new PR avoids that).

---

## D. `fix/bmake-portable-alg-env` (PR #298) — build-tooling fix

**Design doc:** none (build-portability fix; area overlaps genalgs / the
algorithm-metadata tooling). Note a separate, older `origin/fix/bmake-portability`
exists — confirm this one supersedes it.

Single commit `7645d56`: `algs-libs.mk` used GNU-make-only `export VAR := value`
to push `PKG_CONFIG_PATH`/`CGO_LDFLAGS` into `go build`'s environment; NetBSD's
base `make` (bmake, e.g. on foffe) silently drops it, so pkg-config comes up empty
for every C-backed algorithm. `genLibsMk` now emits plain vars + one combined
`ALGS_ENV`. Touches `cmdv2/genalgs/env.go`, `genalgs/main_test.go`,
`utils/Makefile.common` (+53/−10).

- **CodeRabbit:** real review, **0 actionable findings.**
- **Readiness:** **Ready.** Small, isolated, low blast radius; only caveat is
  confirming it was exercised under bmake on foffe (the PR describes that host).

---

## E. `docs/agent-dsync-proxy-plan` — stale docs branch

Two commits (`88274f1` add plan, `72ee144` correct hook-reuse claim + risk/LOC/
time estimates) adding a single file
`docs/2026-06-22-agent-dsync-proxy-for-clueless-primary-plan.md`.

- **The doc already exists in `main`** (the `feat/agent-dsync-proxy` impl branch
  merged, carrying it), and **main's copy is 553 lines richer** than this
  branch's version (`git diff main:doc branch:doc` = +62/−553). `main` also has
  `guide/agent-dsync-proxy.md`. This branch is a stale earlier draft — 311 behind.
- **Recommendation: delete the branch.** First eyeball the 62 lines unique to the
  branch (the "risk/LOC/time estimates" edit) in case any nuance isn't in main's
  version; salvage by hand if so, otherwise discard.

---

## Cross-branch conflict matrix

**No hard conflicts among in-scope branches.** File-overlap analysis:

| Pair | Shared files | Result |
|------|--------------|--------|
| `fix/imr-nits` × `imr-transport-selection-phase2` | `v2/dnslookup.go` | **Merges clean** — disjoint functions (`handleAnswer` ~L2364 vs `IterativeDNSQueryWithLoopDetection`/`buildQuery` ~L1129–1884). `git merge-tree` exit 0. |
| policy-reload-pr2 × everything | none | Isolated (`refreshengine.go`, `zone_policy_*`). |
| ddns-keystate × everything | none | Isolated (`keystate.go`, `sig0_validate.go`, `childsync_*`). |
| bmake × everything | none | Isolated (genalgs / Makefile). |

Only real coupling is **logical**, not textual: C1 and C2 are both IMR work and
both edit `dnslookup.go` in different spots — whichever lands second should
re-run the imr smoke tests. The ddns stack has the usual **stacked-PR ordering**
constraint (A0 before A1).

---

## Recommended prioritization

Branches are near-independent, so ordering is driven by *effort-to-finish*,
*review/validation gaps*, and *downstream leverage* rather than conflicts.

1. **#298 `fix/bmake-portable-alg-env` — merge now.** Smallest, isolated, CR-clean,
   green. Only confirm it was run under bmake on foffe. Clears the queue by one.

2. **#300 `fix/imr-nits` — address the 2 open CR Major findings (at least #1), then
   merge.** It's otherwise done and live-verified. Finding #1 (unify DNS-aware
   matching) is a real correctness nit worth fixing; #2 (context cancellation) is
   a heavier lift you may consciously defer — but decide explicitly rather than
   merging over an open Major.

3. **#294 → #295 ddns-keystate stack.** Retrigger CodeRabbit on #294 (the earlier
   run was rate-limited), merge #294 to `main`, **retarget #295 to `main`** so CR
   will finally review it, then merge #295. Isolated and incremental; live-verify
   on the testbed per plan.

4. **#292 transactional-policy-reload-pr2.** Review is *complete* (5/5 resolved) —
   the only gate left is your **full `-race` + live-matrix** run. It's the deepest
   change, but it **unblocks the config-reload guardrail lane**, so its payoff is
   highest. If that validation is already green, promote it above #3.

5. **`imr-transport-selection-phase2` — open a PR, get a CR review, validate**, then
   **close #257** as superseded. Largest change; no reason to rush it ahead of the
   finished work above.

6. **Housekeeping:** delete `docs/agent-dsync-proxy-plan` (superseded by main's
   richer doc — salvage the 62 unique lines first if any); leave the empty
   `phase2`/`phase3a` worktrees; reconcile `fix/bmake-portable-alg-env` vs the
   older `fix/bmake-portability`.

### The one real judgment call

**#292 vs #294/#295 for "next real feature merge."** #292 is the most-reviewed and
highest-leverage but the riskiest and gated on your validation run; the ddns stack
is lower-risk and incremental but currently *unreviewed* by CR. If your `-race` +
live matrix for #292 is ready to run, do it and land #292 first; if not, the ddns
stack is the safer thing to advance while #292's validation is pending.

---

## Decisions for you

- **#300:** fix or waive the 2 open CR Major findings before merge?
- **#294/#295:** retrigger CR on #294 and retarget #295→main to get them reviewed
  before merge, or merge on the strength of tests + your own review?
- **#292:** is the `-race` + live-matrix gate ready to run?
- **#257 / phase2:** open a fresh PR from `phase2` (avoids rebase) and close #257,
  or force-update #257's branch?
- **`docs/agent-dsync-proxy-plan`:** OK to delete after salvaging any unique lines?

*(Method: `git` ahead/behind + `merge-tree` vs `origin/main` @ `474f492`; PR
metadata and CodeRabbit review threads via `gh`/GraphQL, 2026-07-19. No branches
were modified and nothing was committed.)*
