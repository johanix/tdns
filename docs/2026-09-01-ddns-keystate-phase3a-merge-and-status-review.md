# PR #312 merge-forward + status review

**Date:** 2026-09-01
**Branch:** `feature/ddns-keystate-phase3a` (PR [#312](https://github.com/johanix/tdns/pull/312), base `main`)
**Worktree:** `/Users/johani/src/git/tdns-project/tdns-ddns-keystate-phase3a`
**Plan document:** `docs/2026-07-16-ddns-delegation-keystate-draft-alignment-plan.md`

Reviews the state of PR #312 after catching it up with `main` (335 commits behind at the time), and checks whether the 2026-07-16 plan is still a sufficient guide for the remaining Phase 2 work.

---

## 1. Merge result

`origin/main` merged into `feature/ddns-keystate-phase3a` as merge commit **`df6ffc34`** (GPG-signed, forward-merge, not a rebase). **Not pushed to origin.**

Verified independently (fresh, not cached), `GOROOT=/opt/local/lib/go CGO_ENABLED=1`:

- `go build ./...`, `go vet ./...`, `go test -race -count=1 ./...` clean with zero failures/warnings in all six `v2` submodules: `v2`, `v2/cli`, `v2/cache`, `v2/edns0`, `v2/core`, `v2/debug`.
- Full primary build (`cd cmdv2 && make`) succeeds: `tdns-auth`, `tdns-cli`, `tdns-agent`, `tdns-imr`, `dog`.
- No leftover conflict markers anywhere; working tree clean.

No conflicts were resolved blindly ours/theirs — see the merge commit message for the reasoning behind each non-trivial hunk (option-code table in `edns0_defs.go`, the `applyValidationFailure` consolidation in `updateresponder.go`, the RCODE-propagation contract in `childsync_utils.go`, etc.). This branch's own history already contains two examples of a *textually clean* merge that silently produced broken/wrong code (commits `0b586b1`, `7f4ccc80`) — the merge was re-checked against that failure mode specifically, not just for absence of conflict markers.

---

## 2. Status vs. the 2026-07-16 plan

| Item | Doc claims | Verified actual | Key evidence |
|---|---|---|---|
| K-1 codepoints → -03 | DONE | **DONE** | `v2/edns0/edns0_keystate.go:25-42,89-107` |
| K-2 malformed → code 0 | DONE | **DONE** | `v2/keystate.go:76-84` |
| K-3 response MUST be signed | DONE | **DONE**, fails closed twice | `v2/keystate.go:20-48` |
| K-4 full receiver code set | PARTIAL (7,8 dormant) | **PARTIAL, exactly as claimed** | `v2/keystate.go:185-231` (TODOs at :201-206, :220-226) |
| K-5 inquiry QTYPE=KEY | DONE | **DONE** | `v2/keystate.go:279-287` |
| K-6 KEY-DATA sub-reason | DECLINED | **DECLINED**, documented at emit site | `v2/keystate.go:156-164` |
| D-8 rcode/EDE semantics | DONE | **MOSTLY DONE** — rcode inversion fixed; the two new private EDE codes (KEY-VALIDATION-FAILED, MANUAL-BOOTSTRAP-REQUIRED) were never added | `v2/sig0_validate.go:356-357,431-432`; absent from `v2/edns0/edns0_ede.go` |
| D-2a UPDATE over TCP | DONE | **DONE** | `v2/childsync_utils.go:129-131` |
| D-2b retry + RCODE handling | DONE (PR #312) | **DONE** | `v2/delsync_retry.go`, wired at `delegation_sync.go:546`, `delsync_proxy_update.go:442` |
| D-4 `DEL…ANY KEY` guard | DONE (PR #312) | **DONE**, both halves | `v2/ops_key.go:230-232`; `v2/bootstrap_ceremony.go:30-139` |
| D-6 child consumes SVCB bootstrap | NOT STARTED | **NOT STARTED** — and the parent emit path is weaker than the doc implies (sample config ships no `bootstrap:` subtree at all) | `v2/svcb_defs.go:11`; `v2/ops_dsync.go:294-318`; `cmdv2/auth/tdns-auth.sample.yaml:180-228` |
| D-7 mutual authentication | NOT STARTED; receiver-KEY publication "unconfirmed" | **PARTIAL** — receiver-KEY publication is done (sub-item ii); child-side signature verification (i) and signed plain-UPDATE responses (iii) are still missing | KEY publication: `v2/zone_utils.go:1677-1691` → `ops_key.go:16`; missing verification: `v2/parentsync_bootstrap.go:150-250`, `v2/keybootstrapper.go:276-345` |
| D-3b CDS/CSYNC on UPDATE path | NOT STARTED, deferred | **PARTIAL** — the DS/RFC-7344/8078 half landed independently via `#386`; RFC 7477 NS/glue half still scanner-only | `v2/delegation_coherence.go:209-297`, wired at `v2/updateresponder.go:638-645` |

**Bottom line on status:** Phase 0 and Phase 1 are trustworthy as documented (two small corrections above). D-2b and D-4 (this PR) fully verify. Of the three remaining Phase 2 items, D-3b is furthest along (needs re-scoping, not redesign); D-6 and D-7 are least started.

---

## 3. Is the plan doc still sufficient?

**Recommendation: needs a real design pass before D-6/D-7 are picked up. D-3b needs a re-scoping pass, not a redesign.**

The plan's method (locate by symbol, re-check line anchors) held up fine — every named symbol still exists, drift is cosmetic. The problem isn't stale line numbers; it's that three pieces of independent work landed on `main` since 2026-07-16 and changed *what the remaining work actually is*, not just where it lives.

### Blocking findings

1. **A second, independent child-side implementation now exists** (`v2/delsync_proxy_update.go`, from `dsync-api-proxy` #343 — the tdns-agent proxy path). It shares D-2a/D-2b (same `SendUpdateWithRetry`, same DSYNC lookup) but has **no** `BootstrapSig0KeyWithParent` call and no KeyState inquiry — its bootstrap is unconditionally manual (`proxyBootstrapInstruction`, `v2/delsync_proxy_update.go:193`). D-6 ("child selects the strongest method the parent advertises") and D-7 ("child verifies signed responses") both need an explicit scope decision: auth-child only, or does the proxy path need its own version of each? The plan doesn't know this second implementation exists.

2. **The plan's one concrete D-6 config instruction targets the wrong side of the tree.** It says to add `delegationsync.parent.bootstrap.methods` — that field already exists (`v2/config_delegationsync.go:54-56`, `DelegationSyncParentConf.Bootstrap.Methods`, added by `delegationsync-config-struct` #360). D-6 is a *child*-side behavior; `DelegationSyncChildConf` (`:59-64`) has nowhere to put a bootstrap-method preference. #360 also imposes a "single reader, no viper" contract on this struct that the plan predates.

3. **D-3b's extraction rationale needs to be rewritten.** `parent-checks-delegation-coherence` (#386) already implemented the RFC 7344/8078 DS-side acceptance check as a *fresh* free function (`v2/delegation_coherence.go`), not by lifting the scanner's logic — so there are now two independent implementations of the same rule (the new one, and the scanner's `ProcessCDSNotify`/`ProcessCSYNCNotify` in `v2/scanner.go:714-1288`). The plan's sizing estimate (~457 lines, one file) is also roughly half the real scope — the actual acceptance-decision logic lives in `scanner.go`, not `scanner_csync.go`, with a scan-pipeline calling convention that's harder to reuse from an UPDATE handler.

### Non-blocking, but worth folding into any design pass

- D-7 is smaller than the doc thinks: receiver-KEY publication (sub-item ii) is already done and confirmed — struck from the remaining work. One real bug found in passing: `v2/zone_utils.go:1678` expands the DSYNC target template without the `"." → "root"` substitution that `ops_dsync.go` applies elsewhere, so a root-zone parent would compute a different target name for key publication than for DSYNC publication/response-signing. Worth its own issue.
- The DSYNC `{target}` lookup shape is stable for D-6/D-7 purposes (`DsyncTarget.Name` + `imr.ImrQuery`, same two-line pattern already used for A/AAAA) — no rework needed there, just a stated relationship to the newer scheme-selection layer (`walkSyncPlan`, `pickRolloverSchemes`).
- `case-insensitive-names` is already fully applied to every load-bearing comparison in this area (`core.EqualNames` in `bootstrap_ceremony.go:67`, `updateresponder.go`) — no action needed, aside from the pre-existing (unrelated) truststore key-string caveat.
- The Cross-cutting "unify the vocabulary" section undercounts the problem: it's four settings across two independently-configured verification engines (`v2/truststore_verify.go` typed config vs. `v2/keybootstrapper.go` still reading raw viper keys), plus a stale config-doc block in the sample YAML (`tdns-auth.sample.yaml:275-281`) pointing at two keys nothing reads.

---

## Out of scope for this review

Implementing D-6, D-7, or D-3b (or the Cross-cutting vocabulary unification) was explicitly not part of this task. This document records where things stand and what a design pass would need to resolve; it does not resolve them.
