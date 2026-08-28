# tdns open PR re-review (24 Aug 2026, evening)

**Status:** second pass. The previous review is
[`2026-08-24-open-pr-review.md`](2026-08-24-open-pr-review.md). All live PRs
except [#312](https://github.com/johanix/tdns/pull/312) were updated.
[#382](https://github.com/johanix/tdns/pull/382) has been closed.
[#107](https://github.com/johanix/tdns/pull/107) is still skipped.

Source: GitHub diffs plus the matching local worktrees at the PR heads listed
below. No GitHub review comments were posted.

| | |
|---|---|
| Ready to merge onto `main` | #385, #343, #351 |
| Ready to merge into #343 | #377, #378 |
| Not ready | #386 (one new HIGH), #312 (rebase) |
| Closed since last review | #382 |

**Headline:** the two cross-cutting defects from this morning are closed on
every PR that had them. The stack can start landing. Hold #386 for a bootstrap
carve-out, and do not merge #312 until it is rebased.

## Verdicts

| PR | Head | Merge readiness | Why |
|---|---|---|---|
| [#386](https://github.com/johanix/tdns/pull/386) coherence | `ff1f1b4e` | **Not ready** | Yesterday’s five findings are fixed. Requiring `ImrResponse.Validated` on every non-empty resulting DS makes first-DS bootstrap via UPDATE/API impossible. |
| [#385](https://github.com/johanix/tdns/pull/385) DS intent | `a7027a3f` | **Ready for `main`** | Phase gate covers DS pre-publish. Update path now takes DS from the keystore. |
| [#378](https://github.com/johanix/tdns/pull/378) per-scheme DSYNC | `9bbbb30e` | **Ready into #343** | Restart now calls `PublishDsyncRRs`. Published slice is copied, not aliased. Do not retarget at `main`. |
| [#377](https://github.com/johanix/tdns/pull/377) IMR wait | `5407d050` | **Ready into #343** | Still approved. Polling replaced by a close-once readiness latch. |
| [#351](https://github.com/johanix/tdns/pull/351) rollover API | `3c7ed437` | **Ready for `main`** | Unvalidated DSYNC no longer selects API. Can land before #343 and before a fixed #386. |
| [#343](https://github.com/johanix/tdns/pull/343) sync plan | `0636f105` | **Ready for `main`** | API DNSSEC gate restored. Proxy omits DS except an empty set when there is no DNSKEY RRset. Fold #377 and #378 in first. |
| [#312](https://github.com/johanix/tdns/pull/312) D-2b/D-4 | `9debb445` | **Not ready** | Unchanged. Rebase first. Deep review below. |

## Recommended merge order

| Step | PR | Action |
|---|---|---|
| 1 | #385 | Merge to `main`. |
| 2 | #351 | Merge to `main` (independent of #343). After both #343 and #351 are on `main`, switch rollover to `CredentialForChild`. |
| 3 | #377, #378 | Merge into `feature/dsync-api-proxy` (#343). |
| 4 | #343 | Merge to `main` with #377/#378 folded in. |
| 5 | #386 | Carve-out: require `Validated` only when the child already has a DS. Then merge. |
| 6 | #312 | Rebase onto the resulting `main`. Do not GitHub-merge as-is. |

#351 does not need to wait for #386. Main already accepts API DS from
delegation-sync (#349) with the same parent check (RRtype/name only). This PR
closes a credential-theft hole on the child; blocking it on unfixed #386 delays
that for no child-side gain. A *fixed* #386 is still the parent-side net and
should follow promptly.

## Previous findings — disposition

### Closed (the morning’s two themes)

**Unvalidated DSYNC + API credential** — fixed on both #343
(`planConsiderApi`) and #351 (`selectRolloverDsyncRRs`). Same gate, same
`AllowInsecure` switch: skip API unless the DSYNC lookup DNSSEC-validated.

**DS empty vs unknown** — #382 closed. #343’s API path now omits DS when a
DNSKEY RRset exists, and declares empty DS only when it does not (SEP bit is
not consulted). #385’s `Known` vs empty encoding is intact.

### Per-PR leftovers from the morning

| Finding | PR | Now |
|---|---|---|
| Multi-label child skipped the coherence check | #386 | **Fixed.** `childNameFromUpdate` deleted; DS owner is the delegation. |
| Coherence error → SERVFAIL | #386 | **Fixed.** Sets `ValidationRcode = REFUSED` before returning the error. |
| DNSKEY lookup ignored `Validated` | #386 | **Fixed as an attack, overreached onto bootstrap** (new HIGH below). |
| `touched` meant “mentioned DS” | #386 | **Fixed.** `sameDSSet` bail-out. |
| SEP-only match false-rejected CSK | #386 | **Fixed.** Match requires ZONE bit, not SEP. |
| `RolloverInProgress` missed pre-publish | #385 | **Fixed.** Gate is non-idle phase *or* the swap flag. |
| `computeNewDS` hashed SEP keys | #385 | **Fixed.** Keystore + `NewDSKnown`. |
| Stale `compareParentDS` comment | #385 | Still open, docs only. |
| `SetupZoneSync` skipped `PublishDsyncRRs` | #378 | **Fixed.** Always calls it. |
| Append onto published DSYNC slice | #378 | **Fixed.** Copied into a new slice with no spare capacity. |
| IMR wait was a pointer poll | #377 | **Improved.** Close-once latch after `PrimeWithHints`. |
| `pickRolloverSchemes` ignored `Validated` | #351 | **Fixed.** |
| `planConsiderApi` dropped DNSSEC gate | #343 | **Fixed.** |
| Empty DS keyed off “no SEP DNSKEY” | #343 | **Fixed.** Predicate is absence of the DNSKEY RRset. |
| UPDATE still hashes DNSKEY | #343 | Still open, deferred B1. Not a hold. |
| NOTIFY filter is CSYNC\|ANY, PR emits CDS | #343 | Still open, medium. Not a hold. |
| Vacuous NOTIFY can stop the walk | #343 | Partial. Unsigned gated; signed-without-CDS still can. |

---

## #386 — the remaining blocker

Yesterday’s five findings are actually fixed. The Validated patch (`b1e244fe`)
is the right fix for “unauthenticated keys can bless a bogus DS” **when the
child already has a DS**. It is the wrong bound for RFC 8078 bootstrap.

`imrDnskeyFetcher` now fails closed on `!resp.Validated`
(`delegation_coherence.go:322-324`). `CheckDelegationCoherence` still fetches
whenever the resulting set is non-empty (`:219-228`), including
`currentDS == nil` plus an add. An insecure child’s DNSKEY can never be
`ValidationStateSecure` (there is no DS to chain through). The update is
refused.

The tests still claim bootstrap works (`TestCoherenceAllowsBootstrappingWithAMatchingDS`)
because `fetcherFor` never consults `Validated`. The production fetcher and
the tests disagree.

The commit comment conflates **currently insecure** with **would be bogus**.
Continuity is “don’t break a working chain”. Bootstrap is “add a DS that
matches a published key, with the UPDATE already SIG(0)/API-authenticated”.
An authorised child can go insecure (empty resulting set skips the fetch) and
then cannot come back via UPDATE/API.

**Fix:** require `Validated` only when `len(currentDS) > 0`. For
`currentDS == nil`, still fetch and require a match against published ZONE-bit
keys, but do not demand IMR Secure. Add a test that drives that contract on
the real fetcher.

Until that lands, do not merge #386.

---

## #312 — in-depth (design doc + unimplemented work)

HEAD is still `9debb445` (22 Aug). GitHub: `CONFLICTING` / `DIRTY`. The
branch’s plan is
[`docs/2026-07-16-ddns-delegation-keystate-draft-alignment-plan.md`](2026-07-16-ddns-delegation-keystate-draft-alignment-plan.md)
(read the **branch** copy; `main` still has the original “ready for
implementation” text).

### What the plan says this PR is

Phase 2 items **D-2b** (UPDATE send retry + RCODE handling) and **D-4**
(bootstrap `DEL … ANY KEY` + no-delete-until-validated). Everything else is
explicitly out of this PR.

### D-2b vs draft vs code

Draft (`delegation-mgmt-via-ddns-02`): wait ≥5s before treating absence as
timeout, exponential backoff, give up after ≤5 retries. NOERROR = accepted.
REFUSED = do not stop on a single one. BADKEY(17) = fall back to bootstrap.

| Draft rule | This PR | Notes |
|---|---|---|
| ≥5s per-attempt wait | **Miss** | `dns.Client` has no `Timeout`; miekg default is 2s. The 5s is the *backoff between attempts*, not the wait for a response. |
| Exp backoff, ≤5 attempts | Yes | 5s, 10s, 20s, 40s. `delsync_retry.go`. |
| NOERROR → done | Yes | |
| REFUSED → bounded retry | Yes | Exhausts the budget. |
| BADKEY → re-bootstrap | Yes, exactly one | Then hard error. |
| Cancellation | Yes | `retryWithBackoff` waits on `ctx`. |

Callers: `SyncZoneDelegationViaUpdate`, `ProxyUpdateParent`. Shared
`SendUpdate` stays single-shot (CLI, KSK DS push). Correct split.

#305 (report parent rejection RCODEs from `SendUpdate`) is **not on `main`**.
Without it, D-2b’s BADKEY/REFUSED arms never fire on the wire. Keep it in this
PR.

`BootstrapSig0KeyWithParent` still returns `nil` on a non-NOERROR rcode.
`sendUpdateWithRetry` then treats re-bootstrap as success and retries the
original UPDATE once. Eventual stop is correct; the log is a lie. Return an
error unless the bootstrap is NOERROR.

SERVFAIL → bounded retry is a justified extension (indistinguishable from
no-response). Keep.

### D-4 vs draft vs code

Draft: bootstrap UPDATE is `DEL child ANY KEY` + `ADD KEY`. Receiver MUST NOT
act on the DEL to remove an already-trusted key until the new key is
validated.

On **this branch**, that holds:

1. Child sends DEL+ADD (`ops_key.go:224-234`). `main` is still ADD-only.
2. `bootstrapCeremony` accepts exactly one class-INET KEY plus optional
   class-ANY KEY with `Rdlength==0`. Bare DEL is not a ceremony.
3. Apply **skips** class ANY. ADD is stored untrusted.
4. After successful commit, `registerPendingKeyReplacement`.
5. After DNS(+DNSSEC) promotion, `applyPendingKeyReplacement`.

A bogus self-signed DEL+ADD cannot evict the trusted key, because cleanup is
gated on independent promotion. The pending map is in-memory by design:
restart may leave the old key, never evicts early.

**#359 (merged 19 Aug) is the clash.** `main` treats class ANY as `applyErr`
and fail-closed. Take `main` wholesale → every legitimate bootstrap is
rejected. Take this branch wholesale → lose fail-closed for a non-ceremony
class-ANY, and this branch already dropped `ur.respond` on
`TRUSTSTORE-UPDATE` / `CHILD-UPDATE` (10s hang then SERVFAIL, while the write
may have landed).

Required resolution: fail-closed for every class ANY **except** a recognized
`bootstrapCeremony` DEL (skip that one RR, do not `applyErr`). Restore
`ur.respond` from `main`. After a failed commit, do not trigger verification.

`git merge-tree` vs current `main`: conflict markers only in
`zone_updater.go` and `truststore_verify.go`. **`updateresponder.go` auto-merges
without markers and drops `bootstrapCeremony` from `ApproveTrustUpdate`.**
That restoration is mandatory or D-4 is dead after rebase even if
`zone_updater.go` is perfect.

Two overlapping promotions for the same child can still delete each other’s
newly trusted key (`applyPendingKeyReplacement` has no per-child lock). That
is a dual-success race, not the bogus-eviction the PR guards. Serialize
per-child before merge.

### Unimplemented remaining items (consulted, not in scope)

Do **not** implement these in #312. Shipping D-2b/D-4 without them is safe
for those two items.

| Item | State | Coupling with #312 | Ship #312 without it? |
|---|---|---|---|
| **D-6** SVCB `bootstrap` SvcParamKey | NOT STARTED. Parent emits it; child never parses it. | None. | Yes. |
| **D-7** Mutual auth | NOT STARTED. Highest remaining Phase 2 item: child still accepts an unsigned KeyState response. | D-2b’s KeyState poller reuses the backoff but still trusts unsigned answers. | Yes for D-2b/D-4 correctness. The forgery hole stays until its own PR. |
| **D-3b** CDS/CSYNC acceptance on UPDATE | NOT STARTED, own PR (scanner extraction first). #386 overlaps the *intent* for DS only; it is not scanner reuse. | None. KEY ceremony, not DS/NS. | Yes. Do not wait on #386. |
| **K-4(7)** KEY_REFUSED | Dormant. Needs a SIG(0) accepted-algorithm policy that also **refuses** those UPDATEs. | None. | Yes. |
| **K-4(8)** KEY_VALIDATION_FAILED | Dormant. Plan claims “8 becomes implementable once #312 lands.” | **Plan is wrong.** See below. | Yes; 8 stays dormant. |
| Phase 3 IANA | Deferred. | EDNS 65002 collision is a real bug on `main` today. | Split 65002→65006 as its own PR. Do not restore EDE 513 here (two wire breaks if Phase 3 later moves to 49152). |
| Vocabulary | NOT STARTED. | None. | Yes. |

**K-4(8) and the plan table.** The branch docs say D-2b/D-4 build the durable
retry/exhaustion state code 8 needs. The TODO at `v2/keystate.go:220-226` on
**this branch and on `main`** is the truth: `TriggerChildKeyVerification`
exhaustion still only logs, persists nothing, and runs in an in-memory
goroutine lost on restart. What #312 actually adds:

- D-2b retry is in-process for one send. Gone on return.
- D-4 `pendingKeyReplacements` records “cleanup after trust”, not “validation
  exhausted”, and is in-memory by design.

Shipping #312 does **not** unblock code 8. Implementing 8 from this PR’s
artifacts would still confuse “in progress” with “failed” across restart.
Need a persisted verification-exhaustion bit in the truststore. Follow-up,
not a merge gate. Strike the plan sentence.

### Is #312 still the right vehicle?

**Rebase and keep.** `main` has not subsumed D-2b or D-4. Closing would throw
away the ceremony, the retry engine, #305, and the review fixes already on
the branch.

**Split #306 (EDNS).** The 65002 KEYSTATE/PROVIDERSYNC collision is a bug on
`main` today and should not wait on the ceremony rebase. Land 65002→65006 +
`TestLocalOptionCodesAreUnique` as its own PR. Leave EDE 513 until Phase 3
or a single 49152 decision.

**Do not expand** to D-6, D-7, or D-3b.

### Punch list before merge

1. Rebase onto current `main`. Resolve `zone_updater.go` / `truststore_verify.go`
   as above. **Manually restore** `ApproveTrustUpdate` ceremony — auto-merge
   will not.
2. Keep #359 fail-closed for every class ANY that is not a `bootstrapCeremony`
   DEL.
3. Restore `ur.respond` on TRUSTSTORE-UPDATE and CHILD-UPDATE. Do not trigger
   verification after a failed commit.
4. Per-child serialization of `applyPendingKeyReplacement`.
5. `BootstrapSig0KeyWithParent`: non-NOERROR → error.
6. Per-attempt UPDATE timeout ≥5s (draft miss).
7. Tests: ceremony+#359 apply path; `ur.respond`; overlapping promotion;
   BADKEY re-bootstrap when bootstrap itself is refused.
8. Split or defer #306 (65002 yes, own PR; EDE 513 no).
9. Update the plan: strike “code 8 becomes implementable once #312 lands.”

Do not merge on GitHub’s auto-merge. The silent `updateresponder.go` drop plus
the class-ANY `applyErr` clash are each enough on their own.

---

## Residual (not merge-blocking)

- **#385:** `computeNewDS` still does not consult `rolloverOwnsDS`. Replace
  mode + an external DNSKEY-touching UPDATE during a DS-work phase could send
  an authoritative set that omits `created`. Follow-up, one line.
- **#385:** idxOK-abort can return the engine to idle with a `created` key
  whose DS is already at the parent. Engine bug, not this PR.
- **#378:** guard is per scheme, not `(scheme, type, port)`. Additive publish
  may hitchhike an UPDATE SVCB. Tests still do not exercise `PublishDsyncRRs`.
- **#377:** announce is after `PrimeWithHints`, before trust-anchor init.
  Unbounded wait if the IMR never comes (intentional vs dropping SETUP).
- **#351:** last-resort is advertisement-only (UPDATE advertised but
  unresolvable does not fall back to API). Safer than putting a credential on
  the wire because DNS failed.
- **#343:** UPDATE path still hashes DNSKEY (existing `main` defect; B1 after
  this). NOTIFY matching is CSYNC\|ANY while the PR emits NOTIFY(CDS). A
  signed zone with no CDS/CSYNC can still stop the walk on a vacuous NOTIFY.

## What was not reviewed

[#107](https://github.com/johanix/tdns/pull/107) remains skipped.
CI check-rollup from GitHub was empty for every open PR.
