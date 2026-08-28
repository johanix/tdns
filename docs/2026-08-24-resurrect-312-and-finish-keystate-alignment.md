# Resurrect #312 and finish the ddns + keystate alignment

**Status:** plan, not authorised. Written 24 Aug 2026 after the #312
in-depth review and the evening re-review of the open stack.
**Supersedes, does not replace:**
[`2026-07-16-ddns-delegation-keystate-draft-alignment-plan.md`](2026-07-16-ddns-delegation-keystate-draft-alignment-plan.md)
is still the item catalogue. This document is the *execution* plan: how to
get #312 onto `main` without losing #359, and how to finish the remaining
items as separately reviewable PRs.
**Worktree:** `v2/` only. Never patch the legacy `tdns/` tree.

Drafts (unchanged):

- `draft-ietf-dnsop-delegation-mgmt-via-ddns-02`
- `draft-berra-dnsop-keystate-03`

Line numbers below are as of 24 Aug 2026 and will drift. Relocate by symbol.

---

## 1. Why this exists

[#312](https://github.com/johanix/tdns/pull/312) (`feature/ddns-keystate-phase3a`,
HEAD `9debb445`, last push 22 Aug) owns real work that `main` has not subsumed:
UPDATE send retry (D-2b), the bootstrap `DEL ANY KEY` + deferred-delete
ceremony (D-4), and parent-rejection RCODE propagation (#305). It is
`CONFLICTING` with `main`.

The prescribed fix is a GPG-signed merge of `origin/main` into the feature
branch, with a human pass of every overlapping file — including files git
reports as clean. **Do not rebase.** A GitHub “Update branch” / unattended
merge is unsafe: #359 fail-closed treats class ANY as a hard error, and git’s
auto-merge of `updateresponder.go` silently drops `bootstrapCeremony` from
`ApproveTrustUpdate`.

The 16 Jul plan’s status table on the #312 branch claims D-2b/D-4 **DONE**
and that K-4 code 8 “becomes implementable once #312 lands”. The first is
true **on the branch**. The second is false — see §5.4. This document
corrects that and sequences the rest.

Do not expand #312 to D-6, D-7, or D-3b. They are not required for D-2b/D-4
correctness and would make the merge unreviewable.

---

## 2. Inventory

### 2.1 Already on `main` (do not redo)

| Item | Notes |
|---|---|
| K-1 KeyState codepoints | -03 registry. `0`/`1` are receiver codes. `11` gone. |
| K-2 malformed request | Unrecognised KEY-STATE → `KEY_REQUEST_MALFORMED(0)`. |
| K-3 signed KeyState response | Fail-closed: omit the option rather than send unsigned. |
| D-8 rcode/EDE | Unknown key → `BADKEY(17)`; known-untrusted → `REFUSED`+EDE. |
| D-2a TCP | Delegation UPDATEs forced to TCP. |
| K-5 QTYPE=KEY | Inquiry is `QTYPE=KEY`. Remaining `TypeANY` are DSYNC-target lookups. |
| K-6 KEY-DATA | **DECLINED.** KEY-DATA stays 0; human text in EXTRA-TEXT. |
| #359 fail-closed | Class ANY in a TRUSTSTORE-UPDATE is `applyErr` and rolls back. `ur.respond` on every TRUSTSTORE/CHILD exit. |
| #360 config struct | `truststore_verify.go` uses `DelegationSyncConfig()`, not viper. |
| #386 (when landed) | Parent-side DS continuity on UPDATE and DSYNC API. Overlaps D-3b’s *intent* for DS only. Not scanner reuse. Not a #312 dependency. |

### 2.2 On #312, not on `main`

| Item | What the branch actually has |
|---|---|
| D-2b | `SendUpdateWithRetry` / `retryWithBackoff`. Exp backoff 5/10/20/40s, ≤5 attempts, BADKEY → exactly one re-bootstrap, REFUSED exhausts the budget, cancellation via `ctx`. Shared `SendUpdate` stays single-shot. |
| D-4 | Child sends `DEL ANY KEY` + `ADD KEY`. Receiver `bootstrapCeremony` recognises it. Apply skips class ANY. ADD stored untrusted. Cleanup after DNS(+DNSSEC) promotion. Pending map is in-memory by design. |
| #305 | `SendUpdate` returns the parent’s rcode. Without this, D-2b’s BADKEY/REFUSED arms never fire. Keep it in the resurrected PR. |
| #306 (partial) | PROVIDERSYNC moved 65002 → 65006. EDE 513 “restored” by splitting the iota block. See §3: split the collision, leave EDE. |
| #307 | ValidateUpdate rcode/EDE relay. **Already on main** via `applyValidationFailure`. Drop when merging main. |

### 2.3 Not started (the rest of the 16 Jul plan)

| Item | Why it is not #312 |
|---|---|
| D-7 mutual auth | Highest remaining *exposure*. Child still accepts an unsigned KeyState response. K-3 signs replies; the child never checks. |
| D-6 SVCB `bootstrap` | Parent already emits it (`ops_dsync.go`, private `SvcbBootstrapKey=65282`). Child never parses it. |
| D-3b CDS/CSYNC on UPDATE | Completeness. Own two-step PR after scanner extraction. #386 is not a substitute. |
| K-4(7) KEY_REFUSED | Needs a SIG(0) accepted-algorithm policy that also **refuses** those UPDATEs. |
| K-4(8) KEY_VALIDATION_FAILED | Needs a **persisted** verification-exhaustion bit. #312 does not build that. |
| Vocabulary | Three naming schemes for bootstrap methods. Fold into D-6, or a tiny follow-up. |
| Phase 3 IANA | Flip once when IANA assigns. No churn until then. |

### 2.4 Known defects on the #312 branch that the resurrection must fix

These were found in the 24 Aug review. The branch was not updated.

1. Per-attempt UPDATE timeout is miekg’s **2s** default, not the draft’s ≥5s.
   The 5s is only the backoff *between* attempts (`delsync_retry.go`,
   `childsync_utils.go` `dns.Client{Net: "tcp"}` with no `Timeout`).
2. `BootstrapSig0KeyWithParent` returns `nil` on a non-NOERROR rcode
   (`ops_key.go`). Retry then treats re-bootstrap as success.
3. Two overlapping promotions for the same child can delete each other’s
   newly trusted key (`applyPendingKeyReplacement`, no per-child lock).
4. This branch dropped `ur.respond` on TRUSTSTORE-UPDATE / CHILD-UPDATE
   (10s hang then SERVFAIL, write may have landed). `kdb.Begin` failure
   continues; verification can run after a failed commit.
5. `truststore_verify.go` still reads viper; `main` uses
   `DelegationSyncConfig()`.
6. Auto-merge of `updateresponder.go` **drops** `bootstrapCeremony`.

---

## 3. Recommended PR sequence

Land these in order. Each is independently reviewable and revertable.
Do not combine 0 with 1, or 1 with anything after it.

```
PR-0   EDNS 65002 collision          (tiny, can land now, independent of #312)
PR-1   resurrected #312              (D-2b + D-4 + #305 + merge-safety)
PR-2   D-7 mutual auth               (highest remaining exposure)
PR-3   D-6 SVCB bootstrap            (+ vocabulary if cheap)
PR-4   K-4(8) durable exhaustion     (unblocked in *intent* only after PR-1;
                                     still needs new persistence)
PR-5   K-4(7) SIG(0) algorithm policy
PR-6a  D-3b extract scanner checks   (scanner behaviour identical)
PR-6b  D-3b wire UPDATE path
PR-7   Phase 3 IANA                  (when assigned, one pass)
```

**Relative to the current open stack** (#385, #386, #343, #351, #377, #378):
PR-0 can land immediately. PR-1 merges `origin/main` into
`feature/ddns-keystate-phase3a` **now**, then merges `main` again whenever
those PRs land — they touch the same files (`childsync_utils.go`,
`delegation_sync.go`, `delsync_proxy_update.go`, `updateresponder.go`,
`zone_updater.go`). Repeated merge-from-main is the expected workflow, not a
failure. Do not wait for the stack. Do not rebase.

#386 is **not** a prerequisite for PR-1. D-4 is a KEY ceremony, not DS.

---

## 4. PR-0 — EDNS 65002 collision (do first, independently)

**The bug is on `main` today.** `EDNS0_KEYSTATE_OPTION_CODE` and
`EDNS0_PROVIDERSYNC_OPTION_CODE` are both 65002
(`edns0_defs.go:9`, `edns0_providersync.go:14`). They are not used together
on the wire yet, but the collision is a latent parser bug.

**Do:**

- Move PROVIDERSYNC to **65006** in `edns0_defs.go` (next free after
  CHUNK query endpoint 65005), matching #312.
- Add `TestLocalOptionCodesAreUnique` from the #312 branch
  (`edns0_codepoints_test.go`).
- Cherry-pick only those files. Do not take the EDE 513 “restore”.

**Do not:**

- Renumber EDE 513. On `main`, `EDEDNSSECBogus` sits in the `513+iota`
  private block, so `EDESig0KeyNotKnown` compiles as **514**. #312 splits
  the blocks so 513 is 513 again. That is a lab wire break *now*, and
  Phase 3 will move the private codes to 49152–65535 later — two breaks.
  Leave EDE until PR-7, or decide 49152 once in a dedicated PR. #312’s last
  commit already refused the IANA-range move.

**Acceptance:** `go test ./edns0` asserts every local option code is unique.
KEYSTATE stays 65002 (as in draft-berra-dnsop-keystate). No EDE value changes.

**Vehicle:** new PR off `main`. Do not wait for #312. Close the #306 portion
of #312 onto this.

---

## 5. PR-1 — resurrect #312

Keep the existing GitHub PR. Merge `origin/main` into
`feature/ddns-keystate-phase3a` (GPG-signed merge commit, `--no-ff`, no
rebase, no history rewrite). A previous merge-from-main already produced one
silent semantic conflict (`retryWithBackoff` vs `KEY_TEMPORARY_FAILURE`);
that is why §5.3 requires a human pass of auto-merged files, not an argument
against merging.

### 5.1 What stays in the PR

- D-2b: `v2/delsync_retry.go`, `delsync_retry_test.go`, callers in
  `delegation_sync.go` / `delsync_proxy_update.go`.
- D-4: `v2/bootstrap_ceremony.go`, `bootstrap_ceremony_test.go`, ceremony
  recognition in `sig0_validate.go` and `ApproveTrustUpdate`, skip-not-apply
  of the ceremony DEL, `registerPendingKeyReplacement` /
  `applyPendingKeyReplacement`.
- #305: `SendUpdate` rcode contract (`gotResponse`).
- The review-fix commits already on the branch (`529cb73`, `28c26df`,
  `9debb445`) — retry cleanup, context on backoff. Keep them; they should
  survive the merge.

### 5.2 What leaves the PR

- #306 EDNS → PR-0 (already landed, or land first and drop the files).
- #307 ValidateUpdate relay → already on `main`; drop.
- EDE 513 restoration → PR-7 or never (see §4).
- The plan-doc claim that K-4(8) is unblocked by this PR → rewrite in the
  same commit that updates the doc (see §5.6).

### 5.3 Merge `origin/main` into the feature branch

Do this locally. Do not use GitHub “Update branch” or “Resolve conflicts”:
those will auto-merge `updateresponder.go` and drop D-4.

```
git fetch origin
git checkout feature/ddns-keystate-phase3a
git merge --no-ff origin/main    # GPG-sign the merge commit
```

Resolve conflicted files using the table below. Then **diff every
auto-merged overlapping file against both parents** (`git show :2:path` /
`:3:path`, or `git log -1 -p` after the merge) and apply the same table to
files with no markers. Then `go build`, `go vet`, `go test -race` of `v2`
and `v2/edns0`. Repeat this merge whenever `main` moves (in particular when
#385/#386/#343 land). That is cheaper than waiting and is the intended
workflow.

Trial `git merge-tree` vs `origin/main` (as of 24 Aug) showed:

| File | Markers | Resolution |
|---|---|---|
| `v2/zone_updater.go` | yes | **Dangerous.** Take **main’s** TRUSTSTORE-UPDATE skeleton: `kdb.Begin` fail → `ur.respond` + `continue`; `applyErr` + rollback; empty-actions fail; commit fail → respond; success → `ur.respond(true)`. Take **main’s** CHILD-UPDATE `ur.respond` on every exit. Special-case **only**: if `bootstrapCeremony(ur.Actions)` and the class-ANY RR is the ceremony DEL (`Rdlength==0`, same owner as the ADD, `!ur.Trusted`), `continue` that RR — do **not** set `applyErr`. After **successful** commit, `registerPendingKeyReplacement`, then `TriggerChildKeyVerification` only if commit succeeded. |
| `v2/truststore_verify.go` | yes | Take **main’s** `DelegationSyncConfig()` / `keyVerificationRetrySettings` / `waitOrDone`. **Keep** `kdb.applyPendingKeyReplacement(...)` after successful trust promotion. |
| `v2/updateresponder.go` | **none (silent)** | Git auto-merge **drops** `bootstrapCeremony` from `ApproveTrustUpdate`. **Must restore** the ceremony exception (branch `updateresponder.go` ~738–754). `main` still has `len(r.Ns) != 1` reject. Without this, D-4 is dead after the merge even if `zone_updater.go` is perfect. |
| `v2/childsync_utils.go` | none | Keep `SendUpdateContext` + rcode propagation. Take `main`’s `DelegationSyncConfig()` where this file still has viper. |
| `v2/ops_key.go` | none | Keep DEL+ADD + `SendUpdateContext`. Take `main`’s `DelegationSyncConfig()` for keygen. Fix non-NOERROR → non-nil error here. |
| `v2/delegation_sync.go`, `v2/delsync_proxy_update.go` | none | Keep `SendUpdateWithRetry`; take `main`’s config/plan-ladder if #343 has landed. |
| `v2/sig0_utils.go` | none | Keep explicit rcode check after `SendUpdate`; take `DelegationSyncConfig()` for keygen. |
| `v2/sig0_validate.go` | not in conflict set | Confirm `bootstrapCeremony` is still used after the merge. |
| `v2/bootstrap_ceremony.go` | new file | Should apply cleanly. Then add the per-child lock (next section). |

Invariant after the merge: a **non-ceremony** class-ANY in a TRUSTSTORE-UPDATE
is still `applyErr` (#359). A **ceremony** DEL is skipped, not applied, and
not an error.

Landing #312 onto `main` afterwards is the ordinary PR merge. That is fine
once the branch is current and the human pass has been done. The forbidden
step is an unattended merge *of* `main` *into* the branch.

### 5.4 Correctness fixes to land in the same PR (not later)

Do these on the branch after merging `main` (or in commits on top of the
merge) before asking for review.

1. **Per-attempt timeout ≥5s.** Set `dns.Client.Timeout` (or equivalent read
   deadline) to at least 5s on the D-2b path. Draft: wait ≥5s before treating
   absence as timeout. The backoff interval is not that wait.
2. **Bootstrap non-NOERROR is an error.** `BootstrapSig0KeyWithParent` must
   not return `nil` unless `rcode == NOERROR`. Otherwise D-2b logs
   “re-bootstrapped, retrying” for a bootstrap that never landed.
3. **Per-child lock on `applyPendingKeyReplacement`.** Two `TriggerChildKeyVerification`
   goroutines that both reach `trusted` can each delete the other’s newly
   trusted key, leaving none. `pendingKeyReplacements` is a `sync.Map` keyed
   by `child::keyid`, which does not serialise per child. A per-child mutex
   (or equivalent “only delete keys older than the winner”) is enough. Do not
   persist the pending map; in-memory-by-design is still correct (fail-safe:
   old key remains, never evicted early).
4. **Do not trigger verification after a failed commit.** Main’s fail-closed
   path closes this; keep it.

SERVFAIL → bounded retry is a justified extension (indistinguishable from
no-response). Keep. NOTIMP and the rest stay terminal.

### 5.5 Tests that must exist after merging main (none of these exist today)

| Test | What it pins |
|---|---|
| Ceremony + #359 | Class ANY that *is* a ceremony DEL is not `applyErr`. Any other class ANY in a TRUSTSTORE-UPDATE *is*. |
| `ur.respond` | TRUSTSTORE-UPDATE success and failure answer on `ur.Resp`. No 10s hang. |
| Overlapping promotion | Two concurrent `applyPendingKeyReplacement` for the same child cannot delete both keys. |
| BADKEY recovery | Re-bootstrap that itself gets a non-NOERROR rcode is an error, not “re-bootstrapped, retrying”. |
| Per-attempt timeout | A parent that answers at 3s is accepted (would fail today on the 2s default). Optional if the Client.Timeout change is trivial and reviewed. |

Existing tests to keep: ceremony shape, RDLENGTH≠0 rejection, deferred cleanup
happy path, “no pending ⇒ no eviction”, cleanup retry/cancel, BADKEY bound,
transport retry, backoff cancel, SendUpdate rcode vs unreachable.

### 5.6 Plan-doc edit in the same PR

On the branch copy of `docs/2026-07-16-ddns-delegation-keystate-draft-alignment-plan.md`:

- D-2b/D-4 stay **DONE (PR #312)** once this lands, with a note that
  per-attempt timeout and bootstrap rcode were completed in the resurrection.
- **Strike** “8 becomes implementable once #312 lands.” Replace with: code 8
  needs a persisted verification-exhaustion record in the truststore (PR-4).
  D-2b retry is in-process for one send; D-4 pending map records “cleanup
  after trust”, not “validation exhausted”; `TriggerChildKeyVerification`
  exhaustion still only logs (`truststore_verify.go`).
- Point at this document for sequencing.

Also update `main`’s copy of the 16 Jul plan in a follow-up commit on `main`
(or in this PR) so the two copies do not diverge again. Prefer: this PR
updates the doc; `main` receives it on merge.

### 5.7 Acceptance for PR-1

- `go build`, `go vet`, `go test -race` green on `v2` and `v2/edns0`.
- A self-signed `DEL ANY KEY`+`ADD KEY` does not evict a trusted KEY until
  the new key validates.
- A non-ceremony class ANY TRUSTSTORE-UPDATE still fail-closes (#359).
- A dropped first UPDATE is retried with ≥5s per-attempt wait and exp backoff.
- BADKEY triggers exactly one re-bootstrap; a failed re-bootstrap is an error.
- Two overlapping bootstraps for the same child cannot wipe both keys.

---

## 6. After #312 is on `main`

### 6.1 PR-2 — D-7 mutual authentication (do next)

Highest remaining exposure. K-3 already signs KeyState replies. The child
does not verify them (`parentsync_bootstrap.go` inquiry path; same in
`keybootstrapper.go`). An unsigned or wrong-key KeyState response is
accepted. That is the forged-response attack the draft’s mutual-auth
section exists to close.

**Do, in this order, in one PR if it stays small, else split (i) vs (iii):**

1. **Confirm/implement receiver KEY publication** as a KEY RR at the DSYNC
   `{target}`. Parent already has SIG(0) keys for the update target
   (`SetupZoneSync` / `ParentSig0KeyPrep`). Make the KEY queryable and
   DNSSEC-validatable.
2. **Child acquires that KEY** (IMR, DNSSEC-validated; manual fallback if
   the parent is insecure / `allow-insecure`).
3. **Child verifies SIG(0) on KeyState inquiry responses.** Unsigned,
   wrong-key, or failed verify → ignore the option, same as “KeyState
   unsupported”. Do not act on a forged `KEY_TRUSTED` / `KEY_UNKNOWN`.
4. **Signing plain UPDATE responses** is a draft SHOULD. Do it if it is
   cheap (same signer as K-3). Do not block (1)–(3) on it.

**Acceptance:** a forged (unsigned / wrong-key) KeyState response is
rejected by the child. The receiver’s KEY is published at the DSYNC target
and validates when the parent is signed.

**Not in this PR:** D-6 method selection, D-3b, signing every UPDATE if it
turns into a project.

### 6.2 PR-3 — D-6 child consumes SVCB `bootstrap`

Parent already emits `bootstrap="..."` (`ops_dsync.go`,
`SvcbBootstrapKey=65282`). Child method choice is config-only.

**Do:**

- Look up SVCB at the DSYNC `{target}`.
- Parse `bootstrap`; prefer signed `at-apex` / `at-ns` over `unsigned` over
  `manual`.
- Fall back to config when the SVCB is absent.
- Sample config: `delegationsync.parent.bootstrap.methods` (already discussed
  in the 16 Jul plan).

**Vocabulary (fold in if it stays mechanical):** map
`updatepolicy.child.keybootstrap:[manual,dnssec-validated,consistent-lookup]`
and `delegationsync.parent.update.key-verification.mechanisms:[at-apex,at-ns]`
onto the draft names `at-apex / at-ns / unsigned / manual`. If that touches
too many call sites, split as PR-3b.

**Acceptance:** parent SVCB `bootstrap="unsigned,manual"` → child does not
attempt `at-apex`.

### 6.3 PR-4 — K-4(8) KEY_VALIDATION_FAILED

**Do not implement 8 from PR-1’s artifacts.** They do not persist.

Need:

- A durable column (or equivalent) on the child SIG(0) truststore row:
  verification-exhausted, or attempt count + last error.
- `TriggerChildKeyVerification` writes it when the retry budget is spent.
- `childKeyState` / `GetKeyStatus` emits **8** when that bit is set;
  otherwise 9 (in progress) as today.
- Clearing the bit on a new bootstrap / new KEY upload.

**Acceptance:** a truststore key whose automatic verification has exhausted
returns 8 across process restart. A key still being retried returns 9.

### 6.4 PR-5 — K-4(7) KEY_REFUSED

Needs a SIG(0) accepted-algorithm policy that **also refuses** UPDATEs
signed with a rejected algorithm. A report-only policy is incoherent
(`keystate.go` TODO at the emit site).

This belongs with authorization policy, not with retry. Do not sneak it
into PR-1 or PR-2.

**Acceptance:** an UPDATE signed with a policy-rejected algorithm is
REFUSED (with an EDE if one exists); a KeyState inquiry for that key
returns 7.

### 6.5 PR-6a / PR-6b — D-3b CDS/CSYNC acceptance on UPDATE

Decided 22 Aug: two PRs, in this order.

**6a — extract.** Lift the acceptance logic out of `scanner_csync.go`
(~457 lines, seven methods on `*Scanner`, ~53 references to scanner
state) into free functions. Scanner remains the only caller. Review
purely against “the scanner behaves identically.”

**6b — wire.** Run those functions on an authenticated CHILD-UPDATE
before apply. A delegation UPDATE that would fail CSYNC/CDS acceptance
is refused with the same policy as a scanner would.

**Relation to #386.** #386 is parent-side DS continuity (“at least one
resulting DS hashes a child DNSKEY”), with a bootstrap carve-out. That
is RFC 7344 continuity for DS, on UPDATE and API. It is **not**:

- RFC 8078 CDS-delete sentinel handling beyond “empty DS is allowed”,
- RFC 7477 NS/glue / CSYNC,
- DNSSEC-validated CDS (the scanner still has
  `DNSSEC validation of direct CDS query not yet implemented`).

Land #386. Do not treat it as D-3b. Do not block PR-1 on it.
PR-6b should *reuse* #386 for the DS-continuity piece rather than
reimplementing it; the new work is CSYNC/NS and the CDS-shaped checks
the scanner already runs.

**Last of remaining Phase 2.** D-7 is exposure; this is completeness.

### 6.6 PR-7 — Phase 3 IANA (when assigned)

One pass, no earlier:

| Code | Today | Then |
|---|---|---|
| DSYNC UPDATE scheme | `2` (`core/rr_dsync.go`) | IANA |
| SVCB `bootstrap` | private `65282` (`svcb_defs.go`) | IANA |
| KeyState option | local `65002` | IANA |
| EDE KEY-KNOWN-NOT-TRUSTED, KEY-VALIDATION-FAILED, MANUAL-BOOTSTRAP-REQUIRED | private 513+ (actually 514+ on `main` until the iota split) | IANA; private-use is 49152–65535 if still experimental |

No churn until then. If a lab-only EDE fix is needed before IANA, move the
whole private block to 49152 **once**, not 513 now and 49152 later.

---

## 7. What not to do

- Do not rebase `feature/ddns-keystate-phase3a`. Merge `origin/main` into it.
- Do not use GitHub “Update branch” / “Resolve conflicts” for #312. Merge
  locally, restore `bootstrapCeremony`, then push. The ordinary PR merge onto
  `main` is fine once the branch is current.
- Do not accept git’s auto-merge of overlapping files without a human pass.
  `updateresponder.go` is the known silent drop.
- Do not implement D-6, D-7, or D-3b inside the resurrected #312.
- Do not emit KeyState 8 from the in-memory pending map or the in-process
  retry loop.
- Do not emit KeyState 7 from a report-only algorithm list.
- Do not restore EDE 513 as part of PR-0 or PR-1.
- Do not patch `tdns/edns0/edns0_keystate.go` (legacy tree).
- Do not wait for D-3b or #386 to resurrect #312.
- Do not put an IMR DNSKEY lookup on `ZoneUpdaterEngine` as a “fix” for
  #386’s check-then-queue residual. That is a different PR, if ever, and
  the wrong goroutine.

---

## 8. Working rules (unchanged)

- Branch off current `main`; GPG-sign every commit (`-S`), including merge
  commits.
- **No rebase.** Bring a feature branch current by merging `origin/main`
  into it (`--no-ff`, GPG-signed). Repeat as `main` moves.
- No Cursor / AI byline.
- `build` + `vet` + full `v2 -race` green before each commit
  (`GOROOT=/opt/local/lib/go`). Default build needs no liboqs.
- Implement → commit → push → open (or update) PR → **stop** (do not merge).
- Update the status table in
  `docs/2026-07-16-ddns-delegation-keystate-draft-alignment-plan.md`
  in the same PR that lands each item.

### Suggested live test (after PR-1 + PR-2)

On the parentsync testbed: child publishes KEY → parent bootstraps
(each of at-apex / at-ns / unsigned) → child inquires KeyState
(QTYPE=KEY) → receives a **signed** response with the right code, and
**rejects** a forged unsigned one (PR-2) → sends a delegation UPDATE
over TCP with retry (PR-1) → parent applies; BADKEY → re-bootstrap
once; overlapping bootstrap does not wipe the trusted key.

---

## 9. Mapping back to the 16 Jul plan

| 16 Jul item | This plan | State after execution |
|---|---|---|
| Phase 0 (K-1, K-2, K-3, D-8, D-2a) | — | Already on `main` |
| K-5, K-6 | — | DONE / DECLINED on `main` |
| D-2b, D-4 | **PR-1** | DONE, with the resurrection fixes |
| #305 rcode | **PR-1** | DONE (prerequisite of D-2b) |
| #306 65002 | **PR-0** | DONE; EDE left for PR-7 |
| D-7 | **PR-2** | DONE |
| D-6 + vocabulary | **PR-3** | DONE |
| K-4(8) | **PR-4** | DONE (durable bit, not #312 leftovers) |
| K-4(7) | **PR-5** | DONE |
| D-3b | **PR-6a then 6b** | DONE |
| Phase 3 IANA | **PR-7** | When assigned |
| K-4 codes 1,4,5,6,9,10 | — | Already emitted on `main` |
