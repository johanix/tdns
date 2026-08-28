# tdns open PR review (correctness and safety)

**Status:** review of the eight live open PRs on 24 Aug 2026. Stale
[#107](https://github.com/johanix/tdns/pull/107) was excluded as requested.
Source: GitHub diffs plus the matching local worktrees. No GitHub review
comments were posted. CI check-rollup from GitHub was empty for every open PR,
so these verdicts are from code and tests, not from a green suite on the host.

| | |
|---|---|
| PRs reviewed | 8 of 9 open |
| Approve as-is | 1 (#377, into #343, not onto `main`) |
| Request changes | 6 |
| Close (superseded) | 1 (#382) |
| Skipped | #107 (IXFR/stupidns, last updated Feb 2025) |

**Do not merge the stack onto `main` yet.** Two independent holes can still
make a signed child bogus, and two API paths will post a bearer credential to
an unvalidated DSYNC target. Land the parent-side net (#386) and the DS-intent
gate (#385) after those fixes, then #343. #377 is the only PR that is ready
now, and it must land into #343, not onto `main`.

## Verdicts

| PR | Verdict | Base | Why |
|---|---|---|---|
| [#386](https://github.com/johanix/tdns/pull/386) coherence | Request changes | `main` | Rule is right; UPDATE can skip the check, and refusals are SERVFAIL. |
| [#385](https://github.com/johanix/tdns/pull/385) DS intent | Request changes | `main` | Known/empty split is sound; pre-publish is still ungated. |
| [#382](https://github.com/johanix/tdns/pull/382) replace-DS | **Close** | `main` · draft · conflict | Panic half is #383. DS half is the footgun #385 closes. |
| [#378](https://github.com/johanix/tdns/pull/378) per-scheme DSYNC | Request changes | `feature/dsync-api-proxy` | Helper is correct; restart still never calls it. |
| [#377](https://github.com/johanix/tdns/pull/377) IMR wait | **Approve** | `feature/dsync-api-proxy` | Bounded retry, no deadlock, does not run against a nil IMR. |
| [#351](https://github.com/johanix/tdns/pull/351) rollover API | Request changes | `main` | Last-resort API is right; DSYNC DNSSEC gate is missing. |
| [#343](https://github.com/johanix/tdns/pull/343) sync plan | Request changes | `main` | Architecture is right; API plan dropped DNSSEC and hashes SEP keys. |
| [#312](https://github.com/johanix/tdns/pull/312) D-2b/D-4 | Rebase first | `main` · conflict | Ceremony is sound on the branch; a naive merge with #359 is unsafe. |

## Recommended merge order

After the blocking fixes, this is the order that keeps the parent from
publishing a bogus DS and keeps the API credential off an attacker endpoint.

| Step | PR | Action |
|---|---|---|
| 0 | #382, #107 | Close #382. Leave #107 alone. |
| 1 | #386 | Fix UPDATE child name + REFUSED rcode + validated DNSKEY lookup, then merge to `main`. |
| 2 | #385 | Gate DS on non-idle rollover phases, not only `RolloverInProgress`, then merge to `main`. |
| 3 | #343 | Restore DSYNC `Validated` on API; empty DS only when there is no DNSKEY RRset. Then merge. |
| 4 | #377 | Merge into the #343 branch as-is (already based there). |
| 5 | #378 | Drop the `SetupZoneSync` all-or-nothing guard; clone the published slice. Merge into #343. |
| 6 | #351 | Same DSYNC `Validated` gate; switch to `CredentialForChild` after #343. Merge after #386. |
| 7 | #312 | Rebase onto current `main`. Keep #359 fail-closed except for a recognized ceremony DEL. |

## Cross-cutting defects

### DS empty vs unknown

`len(newDS)==0` is overloaded: no opinion (NS-only update), genuinely unsigned,
signed-elsewhere, and “no SEP bit”. Treating emptiness as “delete the parent
DS” makes a signed child bogus.

#382 does that unconditionally. #343’s API path does it when there is no
SEP-flagged DNSKEY. #385 is the correct encoding (`Known` + empty vs unknown)
and should land instead of #382.

### Unvalidated DSYNC + API credential

Deleted `BestSyncScheme` refused API unless the DSYNC lookup DNSSEC-validated.
The new plan (#343) stores `Validated` and never reads it. Rollover (#351)
never consults it either.

URI/TXT validation at the discovered target does not help: a spoofed DSYNC
names an attacker zone whose URI/TXT then validate. The bearer credential is
posted there. Same hole on two PRs.

## Blocking findings

| Sev | PR | Location | Finding |
|---|---|---|---|
| High | #386 | `updateresponder.go:635` | `childNameFromUpdate` trims to one label; multi-label children skip the coherence check. |
| High | #386 | `updateresponder.go:621` | Coherence failure returns an error → SERVFAIL. Policy refusals are REFUSED. Rollover will retry a permanent no. |
| High | #386 | `delegation_coherence.go:228` | DNSKEY lookup ignores `ImrResponse.Validated`. Unauthenticated keys can bless a bogus DS. |
| High | #385 | `delegation_utils.go:618` | `RolloverInProgress` is set at `AtomicRollover`. DS pre-publish runs from idle with the flag still false. |
| High | #343 | `delegation_sync_plan.go:286` | `planConsiderApi` dropped the DSYNC DNSSEC gate. Bearer credential can follow a spoofed DSYNC. |
| High | #343 | `delsync_proxy_api.go:175` | Empty DS is declared when no SEP DNSKEY exists. A flags-256 KSK makes the parent delete DS. |
| High | #351 | `ksk_rollover_schemes.go:72` | `pickRolloverSchemes` never reads `dsync.Validated`. Same credential-theft hole as #343. |
| Crit | #312 | `zone_updater.go` vs #359 | Naive merge: either every bootstrap is rejected, or fail-closed on class ANY is lost. |
| High | #378 | `zone_utils.go:1192` | `SetupZoneSync` still skips `PublishDsyncRRs` if any DSYNC exists. Add-api-and-restart still no-ops. |
| High | #378 | `ops_dsync.go:55` | Appends onto the published DSYNC snapshot slice. URI/TXT can leak into the live DSYNC RRset. |

Line numbers are against the PR head worktrees as of 24 Aug 2026, not against
`main`.

---

## Per PR

### #386 Refuse a delegation change that would make the child bogus

**Verdict:** request changes. **Base:** `main`.
**PR:** https://github.com/johanix/tdns/pull/386
**Branch:** `fix/parent-checks-delegation-coherence`

Parent-side continuity check for UPDATE and DSYNC API: at least one resulting
DS must hash a child-published DNSKEY; empty DS is allowed; lookup failure is
fail-closed. The simulator and the eight rule tests are sound for one-label
children. Unauthorized principals are still stopped by policy.

The UPDATE integration is not. Child identity is re-derived with weaker
arithmetic than `IsChildDelegation` 400 lines above, so an authorized principal
can still publish a bogus DS for `foo.bar.example.` of `example.`. Returning
`cerr` trips `applyValidationFailure`, which substitutes SERVFAIL when
`ValidationRcode` is still NOERROR. The DNSKEY fetcher never looks at
`resp.Validated`.

Also: `touched` means “the update mentioned DS”, not “the DS set would
change”, so a no-op DS delete next to an NS change now depends on child
reachability. SEP-only matching false-rejects a usable ZONE-bit CSK. Land this
(fixed) before any API DS push.

### #385 Fix where the reconcile gets its DS set

**Verdict:** request changes. **Base:** `main`.
**PR:** https://github.com/johanix/tdns/pull/385
**Branch:** `fix/reconcile-defers-ds-during-rollover`

Commit 3 (`NewDSKnown` / replace-mode) and the Known-vs-empty split are the
right encoding. No keystore rows means signed elsewhere, not unsigned.
Unrecognised key states cannot silently become a delete. CodeRabbit’s earlier
comments were addressed in `934d6681`.

A1+A2 do not close the original outage. The engine places a DS while the key
is still `created` and `RolloverInProgress` is still false (idle →
`pending-parent-push`). Reconcile’s current view omits `created`, so an
explicit sync during observe can still delete the DS the rollover just sent.

The zone-updater producer still hashes SEP DNSKEYs and never sets
`NewDSKnown`, so it is accidentally DS-inert rather than gated. Treat
engine-owns-DS as non-idle DS work (`pending-parent-push` / observe /
softfail), not only the swap flag. Do not add `created` to the current-view
predicate.

### #382 Let replace-mode UPDATE remove a DS (draft)

**Verdict:** close. **Base:** `main` (draft, conflicting).
**PR:** https://github.com/johanix/tdns/pull/382
**Branch:** `fix/replace-mode-ds-removal`

Two commits. The apex-SOA panic fix is already on `main` as
[#383](https://github.com/johanix/tdns/pull/383) (merged 23 Aug). That is the
GitHub conflict. Do not re-land it.

The remaining change makes `CreateChildReplaceUpdate` always emit DS CLASS
ANY, even when `newDS` is empty. On the update-driven path, `computeNewDS`
returns early unless DNSKEY was touched, so an NS-only replace would delete a
signed child’s DS. #385 exists to close that footgun. Close this draft; do not
rebase the DS commit.

### #378 Guard the DSYNC RRset per scheme

**Verdict:** request changes. **Base:** `feature/dsync-api-proxy` (not `main`).
**PR:** https://github.com/johanix/tdns/pull/378
**Branch:** `fix/dsync-per-scheme-guard`

`publishedDsyncSchemes` is correct. It does not fix #371: `SetupZoneSync`
still refuses to call `PublishDsyncRRs` if any DSYNC exists, so
add-api-and-restart still publishes nothing.

The CLI path that does reach the new code aliases the published snapshot
slice and appends onto it. Spare capacity from zone-file load means URI/TXT
can be written into the live TypeDSYNC RRset with no serial bump. Tests only
cover the helper, never `PublishDsyncRRs`.

### #377 Wait for the IMR before starting proxy work

**Verdict:** approve. **Base:** `feature/dsync-api-proxy` (not `main`).
**PR:** https://github.com/johanix/tdns/pull/377
**Branch:** `fix/proxy-imr-startup-race`

The real #372 bug: proxy discovery needs the IMR, the first transfer wins the
startup race, `BuildParentSyncPlan` skipped every scheme, and nothing retried.
This re-queues `PROXY-SYNC` and `PROXY-UPDATE-SETUP` from a helper goroutine
(so the syncher cannot deadlock on a full channel), waits 30×2s, honours
cancellation, and still refuses to run against a nil IMR.

Residual: after ~60s a one-shot SETUP is dropped if priming is merely slow;
readiness is “pointer assigned”, which is after `PrimeWithHints` and before
trust-anchor init. Tests cover `deferForImr`, not the syncher gate. Merge into
#343, do not retarget at `main`.

### #351 Rollover DSYNC target reuse + API last resort

**Verdict:** request changes. **Base:** `main`.
**PR:** https://github.com/johanix/tdns/pull/351
**Branch:** `feature/rollover-dsync-schemes`

Two real bugs, both correctly diagnosed. UPDATE no longer throws away the
planner’s target and re-looks up with a narrower filter. API is last-resort
only when neither UPDATE nor NOTIFY is advertised; `force-*` does not fall
back; the POST is DS-only. CodeRabbit’s scheme-table comment was fixed.

`pickRolloverSchemes` never consults `dsync.Validated`. `BestSyncScheme` on
this same tree already treats that as mandatory for API because the DSYNC RR
names where the bearer credential is sent. Discovering URI/TXT at the
(possibly attacker-chosen) target does not close it.

Author already noted `CredentialFor(parent)` will disagree with #343’s
`CredentialForChild`. Land #386 before this ships API DS push: the parent on
this base still only authorizes RRtype/name.

### #343 One sync plan, DSYNC API, BestSyncScheme gone

**Verdict:** request changes. **Base:** `main`.
**PR:** https://github.com/johanix/tdns/pull/343
**Branch:** `feature/dsync-api-proxy`

Central PR. The ladder is the right shape: one DSYNC discovery,
UPDATE/API/NOTIFY in configured order, unsigned NOTIFY removed from the plan,
`BestSyncScheme` and its `net.LookupHost` deleted. CodeRabbit items on
`walkSyncPlan` context, stale `UpdateResult`, and keystore/`SignMsg` errors
are fixed. Child-specific credentials match most-specific-wins; that is not a
confused-deputy bug.

Two merge blockers. `planConsiderApi` stores `Validated` and never reads it —
a regression versus the deleted chooser. The new API payload hashes SEP
DNSKEYs and, after `f92b2f0f`, sends an explicit empty DS when that set is
empty. SEP is advisory; a signed zone whose KSKs are flags 256 tells the
parent to delete DS.

Also: NOTIFY matching is CSYNC|ANY while this PR emits NOTIFY(CDS); vacuous
NOTIFY success can still stop the walk when the zone has no CDS/CSYNC;
unsigned DS repair is implemented only on API while unsigned zones are steered
to UPDATE. Prefer omitting DS from the API request until B1 (CDS) lands,
except the true no-DNSKEY-RRset delete.

### #312 UPDATE retry + bootstrap DEL-ANY-KEY guard

**Verdict:** rebase, do not merge. **Base:** `main` (conflicting).
**PR:** https://github.com/johanix/tdns/pull/312
**Branch:** `feature/ddns-keystate-phase3a`

Keep this PR. `main` has not subsumed D-2b or D-4. On this branch a bogus
self-signed DEL+ADD cannot evict a trusted KEY: class ANY is skipped at apply,
the ADD is stored untrusted, and cleanup runs only after DNS(+DNSSEC)
promotion.

It is CONFLICTING with `main` in the two security-sensitive files
(`zone_updater.go`, `truststore_verify.go`). #359 fail-closed treats class ANY
as a hard error. Take `main` wholesale → every legitimate bootstrap is
rejected. Take this branch wholesale → lose fail-closed, and this branch
already dropped `ur.respond` on `TRUSTSTORE-UPDATE` / `CHILD-UPDATE` (10s hang
then SERVFAIL, while the write may have landed).

Also: two overlapping bootstraps for the same child can delete each other’s
newly trusted key; EDNS 65002 collision fix is still needed on `main` and is a
lab wire break; EDE 513 sits in IETF-review space. Rebase; special-case only a
recognized ceremony DEL; restore `ur.respond`; serialize per-child cleanup.

---

## What was not reviewed

[#107](https://github.com/johanix/tdns/pull/107) (`leon/ixfr-support`, last
updated 3 Feb 2025) was skipped as requested.
