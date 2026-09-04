# Implementation plan — align tdns to delegation-mgmt-via-ddns-02 + keystate-03

**Status:** in progress. Item status is recorded on each item below and
summarised here; update both as work lands.

**2026-09-01 — PR #312 merged forward to `main` (`df6ffc34`), not yet pushed/landed.
Reordered D-7 ahead of D-6 within Phase 2** (D-7 was already flagged
"highest-value of the three remaining Phase 2 items" in its own entry, but the
doc never reflected that in the ordering — the KeyState inquiry channel is
plain UDP with no response-signature check on the child side today, which is
a live spoofing exposure, not just an incompleteness). LOC estimates added for
every remaining item, calibrated against this branch's own comparably-scoped,
already-shipped work (see each item and the sizing note after the table).

**2026-09-02 — delegation-sync unification (PR #471) closed the cross-cutting
vocabulary item and shrank D-6 / D-7.** Dead KeyBootstrapper engine gone; one
`delegationsync.policies.*` vocabulary; parent SVCB advertisement now
reconciles independently of DSYNC synthesize; receiver-KEY publication uses
`DsyncUpdateTargetName` (root-zone `{ZONENAME}` expansion). Child
`update.bootstrap.methods` is parsed and consumed at bootstrap (SVCB
intersection; absent SVCB falls back to the configured list).

**2026-09-02 — D-7's required part (i) landed** on
`feature/ddns-keystate-d7-mutual-auth`: the child verifies the UPDATE
Receiver's SIG(0) on KeyState responses against a receiver KEY that is either
manually trusted or DNSSEC-validated together with the DSYNC that named it;
unauthenticated responses (and the SVCB bootstrap advertisement) are rejected
unless `delegationsync.child.update.allow-insecure` is set; the inquiry moved
to TCP. Decisions in `docs/2026-09-02-ddns-keystate-d7-mutual-auth.md`.
Only (iii), signing plain UPDATE responses, remains of D-7.

**2026-09-02 — D-6 closed** on `feature/ddns-keystate-d6-at-ns-signal`
(stacked on D-7): `at-ns` publishes the child's keystore KEY at
`_sig0key.<child>._signal.<ns>` through the existing RFC 9615 signal
publisher (`signal_republish.go`), is offered only where this server is
primary for a signal name, and is back in the omit-default. A failed SVCB
lookup is now retried rather than read as "no advertisement". Notes in
`docs/2026-09-02-ddns-keystate-d6-at-ns-signal.md`.

**2026-09-02 — K-4 code 8 and D-8's two EDEs closed** on
`feature/ddns-keystate-k4-code8-d8-ede` (stacked on D-6): verification
exhaustion is recorded on the truststore row (`validation_failed`,
`validation_error`, migrated in), the KeyState inquiry reports
KEY_VALIDATION_FAILED(8) with the reason, and a signed UPDATE from such a key
is REFUSED with EDE KEY-VALIDATION-FAILED; a manual-policy parent answers
MANUAL-BOOTSTRAP-REQUIRED. The child treats "manual" as waiting for the
operator (Info), not as an error. Notes in
`docs/2026-09-02-ddns-keystate-k4-code8-d8-ede.md`. Of K-4 only code 7 remains.

| Phase | Item | State | Est. remaining LOC (impl+tests) |
|---|---|---|---|
| 0 | K-1 codepoints, K-2 malformed, K-3 signed response, D-8 rcode/EDE (partial), D-2a TCP | **DONE** (on main) | — |
| 1 | K-5 QTYPE=KEY | **DONE** (on main) | — |
| 1 | K-6 KEY-DATA sub-reason | **DECLINED** — optional; KEY-DATA stays 0, documented at the emit site | — |
| 0 | D-8 two missing private EDE codes | **DONE** (2026-09-02) — 541 KEY-VALIDATION-FAILED, 542 MANUAL-BOOTSTRAP-REQUIRED, emitted from `TrustUpdate` | — |
| 1 | K-4 code 8 (KEY_VALIDATION_FAILED) | **DONE** (2026-09-02) — exhaustion persisted on the truststore row, emitted by `childKeyState` | — |
| 1 | K-4 code 7 (KEY_REFUSED) | **DORMANT** — waits on a SIG(0) accepted-algorithm policy (report+enforce, not just report) | ~150-300 |
| 2 | D-2b UPDATE retry, D-4 bootstrap ceremony | **DONE** (PR #312) | — |
| 2 | **D-7** mutual auth (moved ahead of D-6 — see note above) | **(i)+(ii) DONE** (2026-09-02) — child verifies signed KeyState responses; only (iii) signing plain UPDATE responses (draft SHOULD) remains | ~80-150 (iii only) |
| 2 | **D-6** SVCB bootstrap consumption | **DONE** (2026-09-02) — intersection+selection, `at-ns` publishes at `_signal` via the shared signal publisher, satisfiability filter, default restored, failed lookup retried | — |
| 2 | D-3b CDS/CSYNC acceptance (NS/glue half) | **DONE** (2026-09-02) — DS half via #386; NS/glue rules extracted (`delegation_csync.go`) and wired into `ApproveChildUpdate` and the DSYNC API (`delegation_csync_update.go`) | — |
| 3 | IANA alignment | **DEFERRED** by design | — |
| — | Cross-cutting vocabulary (4 settings, 2 config-reading engines) | **DONE** (PR #471) | — |

**Core Phase 2 remainder (D-7(iii) + D-3b): ~480-850 LOC.
Everything not yet done (adds K-4 code 7 ~150-300): ~630-1150 LOC.**
See "Remaining-work sizing" after the Phase 2 section for the calibration basis and per-item reasoning.

**Ordering note:** K-4's code 8 was blocked on Phase 2. It reports
"validation failed", which could not be distinguished from "in progress" while
the only failure source ran in an in-memory goroutine lost on restart. D-2b/D-4
(#312) build the durable retry/exhaustion state it needs, so **8 becomes
implementable once #312 lands** — see the TODO at the emit site in
`v2/keystate.go`.

Self-contained.
**Base:** branch off `main` (`33ed2e7` or later). Work in the **`v2/` tree only** — never patch the legacy `tdns/` tree (slated for deletion).
**tdns is the reference implementation of both drafts**, so this is *re-alignment to the current draft text*, not green-field. Line anchors below are as of this survey and **drift — re-locate by symbol**.

## Drafts this plan targets (exact versions)

- **draft-ietf-dnsop-delegation-mgmt-via-ddns-02** — DNS UPDATE across the zone cut for delegation sync; DSYNC "UPDATE" scheme; SIG(0) bootstrap + mutual auth.
  Local copy: `/Users/johani/src/git/drafts/draft-ietf-dnsop-delegation-mgmt-via-ddns/draft-ietf-dnsop-delegation-mgmt-via-ddns-02.md`
- **draft-berra-dnsop-keystate-03** — the KeyState EDNS(0) option (child inquires SIG(0) key state; parent reports).
  Local copy: `/Users/johani/src/git/drafts/draft-berra-dnsop-keystate/draft-berra-dnsop-keystate-03.md`
- Background gap survey (verbatim current-state anchors): `/Users/johani/src/git/drafts/draft-ietf-dnsop-delegation-mgmt-via-ddns/IMPL-GAP-ddns+keystate-vs-tdns.md`

The two drafts are **coupled**: KeyState is delegation-mgmt's key-state inquiry channel, and the KeyState codes overlap semantically with the delegation-mgmt EDE codes. Implement them together. **Correctness fixes (things that contradict the current drafts) come before feature completion.**

---

## Phase 0 — Correctness fixes (currently WRONG vs the drafts). Small, high-value, do first.

### K-1. KeyState codepoints → keystate-03 registry — **DONE**
- **Draft (keystate-03 §"Defined and Reserved Values", registry table):** `0=KEY_REQUEST_MALFORMED`, `1=KEY_TEMPORARY_FAILURE` (both **receiver**-set), `2=INTENT_INQUIRE_KEY` (sender), `3` unassigned, `4=KEY_TRUSTED`, `5=KEY_UNKNOWN`, `6=KEY_INVALID`, `7=KEY_REFUSED`, `8=KEY_VALIDATION_FAILED`, `9=KEY_BOOTSTRAP_AUTO`, `10=KEY_BOOTSTRAP_MANUAL`, `11-127` unassigned, `128-255` Private.
- **Current (WRONG):** `v2/edns0/edns0_keystate.go:15-30` has `KeyStateRequestAutoBootstrap=0`, `KeyStateRequestManualBootstrap=1`, `KeyStateBootstrapAutoPending=11`. Code `0` is semantically inverted (tdns "please auto-bootstrap" vs draft "malformed request").
- **Change:** Reassign `0=KeyStateRequestMalformed`, `1=KeyStateTemporaryFailure`. **Delete** the `0/1` sender-request meaning (keystate-03 removed sender bootstrap-request codes — bootstrap initiation is via the self-signed DNS UPDATE + the SVCB `bootstrap` SvcParamKey, not KeyState). **Delete** `KeyStateBootstrapAutoPending=11` (unassigned in -03). Keep `2,4-10`. Update the `KeyStateToString` map (`edns0_keystate.go:77-96`). Update **every consumer** of the removed constants (search `KeyStateRequestAutoBootstrap`, `KeyStateRequestManualBootstrap`, `KeyStateBootstrapAutoPending`): `v2/keystate.go` (ProcessKeyState uses 0 for auto-bootstrap `:64`, emits 11 `:84`), `v2/parentsync_bootstrap.go`, `v2/keybootstrapper.go`.
- **Also** bump all `draft-berra-dnsop-keystate-02` source comments → `-03` (`edns0_keystate.go:14,20,33`, `keystate.go:26`, `defaultqueryhandlers.go:53`).
- **Acceptance:** no path emits/accepts `0` or `1` as sender codes; `11` gone; a wire round-trip unit test asserts the -03 values.

### K-2. Malformed-request handling — **DONE**
- **Draft (keystate-03 §Protocol-Level Responses):** a receiver that gets an unrecognized/unassigned KEY-STATE (incl. 3, 11-127) in a request MUST respond `KEY_REQUEST_MALFORMED(0)`. A well-formed receiver recognizes only sender code `2` as a valid inquiry.
- **Current (WRONG):** `v2/keystate.go:102-108` default branch returns `KeyStateInvalid(6)`; the `switch` treats `0` (auto-bootstrap) and `2` as valid.
- **Change:** after K-1, make the request switch accept only `2 (INTENT_INQUIRE_KEY)`; every other value → respond `KEY_REQUEST_MALFORMED(0)` with `KEY-DATA=0` and `KEY-ID` echoed (or 0 if unparseable).
- **Acceptance:** an inquiry with KEY-STATE=99 gets a response with KEY-STATE=0.

### K-3. KeyState response MUST be SIG(0)-signed — **DONE**
- **Draft (keystate-03 §"KeyStates Set By The UPDATE Receiver"; ddns-02 §Mutual Authentication):** the inquiry response MUST be signed by the UPDATE Receiver's SIG(0) key. An unsigned response to an inquiry is the forged-response attack vector.
- **Current (WRONG):** `v2/keystate.go:28-34` sends the response **unsigned** when no active SIG(0) key is found or when `SignMsg` errors ("better than failing entirely").
- **Change:** fail closed — if the receiver cannot SIG(0)-sign a KeyState response, do **not** attach the KeyState option (respond as if unsupported) rather than sending an unsigned key-state signal. Log loudly. (Coordinate with D-7.)
- **Acceptance:** no code path emits a KeyState option on an unsigned message.

### D-8. UPDATE-receiver rcode/EDE semantics — **DONE**

**Closed 2026-09-02** (`docs/2026-09-02-ddns-keystate-k4-code8-d8-ede.md`):
`EDESig0KeyValidationFailed` (541) and `EDESig0ManualBootstrapRequired` (542)
appended to the private block; `TrustUpdate` picks among the three
bootstrap-state EDEs for a known-but-untrusted signer with the same precedence
`childKeyState` gives KeyState 10/8/9 (`knownUntrustedKeyEDE`). On the child,
`errBootstrapManual` makes "manual" an Info-level wait rather than an ERROR on
every load.
- **Draft (ddns-02 §§"RCODE BADKEY", "Communication in Case of Errors", §IANA EDE):** **unknown key → `BADKEY(17)`** (child falls back to bootstrap). **Key known-but-not-trusted → `REFUSED`** carrying an EDE (`KEY-KNOWN-NOT-TRUSTED`). Three new EDE codes: KEY-KNOWN-NOT-TRUSTED, KEY-VALIDATION-FAILED, MANUAL-BOOTSTRAP-REQUIRED.
- **Current (WRONG — confirm against the code before changing):** survey found the mapping inverted — unknown key → `BADSIG(16)`+EDE"known-not-trusted"; known-not-trusted → `BADKEY(17)`. See `v2/sig0_validate.go:31,274,288-311` and `v2/updateresponder.go:281-300`.
- **Change:** unknown/unlocatable signer key → `BADKEY(17)`. Known-but-`!Trusted` key → `REFUSED` + EDE `KEY-KNOWN-NOT-TRUSTED` (existing private `EDESig0KeyKnownButNotTrusted=514`, `v2/edns0/edns0_ede.go:17-68`). Add private EDE codes for `KEY-VALIDATION-FAILED` and `MANUAL-BOOTSTRAP-REQUIRED` (values remain private/experimental until IANA — Phase 3). Keep `SERVFAIL` only for hard validation errors.
- **Reassessed 2026-09-01, post-merge:** the rcode inversion fix (the actual correctness bug) is confirmed done — `v2/sig0_validate.go:356-357,431-432`. The two remaining EDE codes were added 2026-09-02 (see above).
- **Acceptance:** update signed by an unknown key → `BADKEY`; by a known-untrusted key → `REFUSED`+EDE514.
- **Est. size (the two missing EDE codes only):** ~15-30 LOC — two consts + registry-uniqueness test entries + wiring at the (small number of) emit sites once K-4 codes 7/8 give them somewhere to be emitted from. Trivial in isolation; sequence it after K-4 codes 7/8 rather than before, since there's currently nothing that would emit them.

### D-2a. Child UPDATE over TCP — **DONE**
- **Draft (ddns-02 §"Choice of SIG(0) Signature Algorithm"):** these UPDATEs are infrequent and SHOULD be carried over TCP (or DoT) — avoids UDP spoofing/fragmentation for a message that mutates parent state and accommodates larger (PQ) SIG(0) signatures.
- **Current (WRONG):** `v2/childsync_utils.go:65-73` `SendUpdate` uses UDP unless `msg.Len() > 1232`.
- **Change:** force TCP for delegation-sync UPDATEs regardless of size (do not gate on message length on this path).
- **Acceptance:** delegation UPDATE always goes over TCP.

---

## Phase 1 — KeyState-03 completion (PARTIAL/MISSING)

### K-4. Emit the full receiver code set (4-10) with a 1:1 state map — **PARTIAL**
- **Done:** 1, 4, 5, 6, 9, 10 emitted; `childKeyState` maps validated-not-trusted to 10 rather than collapsing it into an error.
- **Dormant — 7 (KEY_REFUSED):** waits on a SIG(0) accepted-algorithm policy. A report-only algorithm policy is incoherent (it must also refuse the UPDATEs it reports on), so it belongs with the Phase 2 authorization work. **Est. size:** ~150-300 LOC — this is a small policy feature (allow/deny-list config, enforcement at validation time, plus the reporting wire-up), not just a code emit.
- **Done — 8 (KEY_VALIDATION_FAILED), 2026-09-02:** `runChildKeyVerification` (the engine behind `TriggerChildKeyVerification`, now with an injectable verifier) records exhaustion on the truststore row via the `validation-failed` subcommand; `childKeyState` reports 8 after the manual cases and before 9; the EXTRA-TEXT carries the recorded reason. A verification abandoned by a restart records nothing and stays 9 until the child re-uploads — the honest answer, since nothing was concluded.
- **Draft (keystate-03 §"KeyStates Set By The UPDATE Receiver"):** codes 4 KEY_TRUSTED, 5 KEY_UNKNOWN, 6 KEY_INVALID, 7 KEY_REFUSED, 8 KEY_VALIDATION_FAILED, 9 KEY_BOOTSTRAP_AUTO, 10 KEY_BOOTSTRAP_MANUAL; plus 1 KEY_TEMPORARY_FAILURE for transient inability.
- **Current (2026-09-03):** `childKeyState` maps trusted→4, structurally broken→6, validated-not-trusted→10, manual policy→10, recorded validation failure→**8**, otherwise→9; missing→5; transient store error→1. Only 7 (KEY_REFUSED) is still never emitted (dormant, above). On the UPDATE channel `sendUpdateWithRetry` treats REFUSED+541/542 as terminal and REFUSED+514 as a bounded retry.
- **Change:** give tdns's SIG(0) key states a full 1:1 map: distinguish *validation failed* (→8) from *generic invalid/algorithm-mismatch* (→6); emit `7 (KEY_REFUSED)` when the key/algorithm is rejected by policy; emit `10 (KEY_BOOTSTRAP_MANUAL)` from the manual-bootstrap policy state (not from a sender request); emit `1 (KEY_TEMPORARY_FAILURE)` on transient store errors.
- **Acceptance:** each internal key state produces its correct -03 code; a truststore key whose validation failed returns 8, not 6.

### K-5. Child inquiry QTYPE=KEY — **DONE** (the remaining `TypeANY` are DSYNC-target lookups, which this item excludes)
- **Draft (keystate-03 §"KeyStates Set By The UPDATE Receiver"):** the inquiry is `QNAME=child.parent, QTYPE=KEY`.
- **Current (PARTIAL):** inquiry uses `dns.TypeANY` (`v2/parentsync_bootstrap.go:148,205`, `v2/keybootstrapper.go:288`).
- **Change:** use `dns.TypeKEY` for the KeyState inquiry query. (The DSYNC-target lookups at `:142,199,281` are a separate lookup — leave those unless they are the same query.)
- **Acceptance:** inquiry packets carry QTYPE=KEY.

### K-6. KEY-DATA sub-reason (optional) — **DECLINED**, deliberately: KEY-DATA stays 0 everywhere and human detail stays in EXTRA-TEXT
- **Draft (keystate-03 §KEY-DATA / codes 6,7):** KEY-DATA MUST be 0 except codes 6/7 MAY carry a receiver-defined sub-reason.
- **Current:** KEY-DATA never populated (reasons in EXTRA-TEXT).
- **Change (optional/low-priority):** for codes 6/7 optionally set a sub-reason byte; keep human text in EXTRA-TEXT. Ensure KEY-DATA=0 for all other codes.

---

## Phase 2 — delegation-mgmt-via-ddns-02 completion (PARTIAL/MISSING)

### D-2b. UPDATE send retry policy + RCODE handling — **DONE** (PR #312)
- **Draft (ddns-02 §"No response to a DNS UPDATE"; §RCODE sections):** SHOULD wait ≥5s before timeout, exponential backoff (double each time), give up after ≤5 retries. RCODE: NOERROR=accepted; REFUSED (don't stop on a single one, may stop after repeated); BADKEY(17)→fall back to bootstrap.
- **Current (MISSING):** `v2/childsync_utils.go:75-124` tries each address once, no backoff/retry/timeout. (The `5s,10s,20s,40s ≤5` pattern already exists for the KeyState poller `v2/parentsync_bootstrap.go:52-131` — lift/reuse it.)
- **Change:** add a retry loop on the UPDATE send (≥5s timeout, exp backoff, ≤5 tries); interpret RCODE explicitly: NOERROR done; `BADKEY(17)` → trigger re-bootstrap (`BootstrapSig0KeyWithParent`); REFUSED → log, bounded retry; no-response → timeout+retry per policy.
- **Acceptance:** a dropped first UPDATE is retried with backoff; a BADKEY response triggers re-bootstrap.

### D-4. Bootstrap ceremony `DEL … ANY KEY` + explicit no-delete-until-validated — **DONE** (PR #312)
- **Draft (ddns-02 §§"Bootstrapping...", "Re-bootstrapping In Case of Errors"):** the self-signed bootstrap UPDATE is `DEL child.parent ANY KEY` + `ADD child.parent KEY`. The receiver MUST NOT act on the `DEL ANY KEY` to remove an already-**trusted** key until the newly added key has been validated.
- **Current (PARTIAL):** `v2/ops_key.go:155-227` `BootstrapSig0KeyWithParent` builds an **ADD-only** update (no DEL). Re-bootstrap safety holds only by construction (untrusted KEY-deletes refused, `v2/updateresponder.go:440-464,657-683`).
- **Change:** include the `DEL child ANY KEY` half in the bootstrap/re-bootstrap UPDATE (child side). On the receiver, make the "do not delete a trusted key until the replacement is validated" rule an **explicit** guard in the KEY-RRset delete path, not just an emergent property. Preserve the existing refusal of untrusted deletes.
- **Acceptance:** a self-signed re-bootstrap UPDATE carrying `DEL ANY KEY`+`ADD KEY` does not evict the currently-trusted key until the new key validates.

### D-7. Mutual authentication — child verifies the receiver's signature/KEY; sign plain UPDATE responses — **(i)+(ii) DONE, (iii) open**

**Implemented 2026-09-02** (`v2/keystate_verify.go`; design and decisions in
`docs/2026-09-02-ddns-keystate-d7-mutual-auth.md`). `QueryParentKeyState`
(the dead `…Detailed` twin is gone) sends the inquiry over TCP, keeps the
reply's wire bytes, and runs `sig0Verify` over them. A reply is authenticated
when its SIG(0) verifies with a receiver KEY that is (a) in the child's
truststore and marked trusted (`tdns-cli truststore sig0 add … ; … trust`), or
(b) published at the DSYNC UPDATE target with **both** the KEY lookup and the
DSYNC lookup DNSSEC-validated — `DsyncTarget.Validated` now exists for that;
an unvalidated DSYNC would let a forged target choose the identity. A present
but failing signature is always rejected. A reply that merely cannot be
authenticated is rejected unless `delegationsync.child.update.allow-insecure`
is set (then acted on with a Warn). The same switch gates the SVCB bootstrap
advertisement, which is otherwise treated as absent when unvalidated (the
#471 review's carry-over 6). A bogus DNSSEC verdict, on the receiver KEY,
the DSYNC or the SVCB, is never waived. **Behaviour change, scoped
precisely:** the KeyState poller (`ParentSyncAfterKeyPublication`) refuses an
unauthenticated reply by default, so under an unsigned parent with no manually
trusted receiver key it does not reach the bootstrap it would otherwise
trigger. That poller has no caller in this repo today — only tdns-mp calls
it, against its June pin — and the tdns-auth child path
(`DelegationSyncSetup`) never inquires at all, so it still sends its KEY
UPDATE regardless. tdns-mp should adopt the exported function when it bumps.

**Moved ahead of D-6 (2026-09-01)** as the highest-value of the three
remaining Phase 2 items: before it, the KeyState inquiry went over plain UDP
and the child took the reply at face value. (Closed 2026-09-02, above.)

- **Draft (ddns-02 §§"Mutual Authentication", "Bootstrapping the UPDATE Receiver's Key Into the Child", "Publishing the UPDATE Receiver's Key"):** the UPDATE Receiver maintains its own SIG(0) key, publishes it as a KEY record at the DSYNC {target}, and signs its responses; the child acquires+validates that KEY (DNSSEC or manual) and MUST verify signed responses (esp. KeyState inquiry responses).
- **Current (PARTIAL — reassessed 2026-09-02 after PR #471):**
	  - **(ii) DONE:** the receiver's KEY is published at the DSYNC {target} — `SetupZoneSync` now calls `DsyncUpdateTargetName` (the same helper DSYNC publication and the responder use), so a root-zone parent no longer computes a different target for key publication than for DSYNC publication/signing. The DSYNC RRset owner is `dsyncOwnerName` (`_dsync.root.` for the root), used by both publish and unpublish.
  - **(i) DONE (2026-09-02):** see the implementation note above. The two call sites are one (`QueryParentKeyState`), and it verifies.
  - **(iii) MISSING:** plain UPDATE responses are unsigned; only `keyStateResponseWriter` (`v2/keystate.go`) signs.
- **Change:** (i) child acquires+validates the UPDATE Receiver's KEY (from the DSYNC {target}, DNSSEC-validated, else manual) and **verifies the SIG(0) signature** on KeyState inquiry responses — reject/ignore unsigned or invalidly-signed responses. Reuse the existing `sig0Verify` primitive (`v2/sig0_validate.go`) rather than writing a new verifier. (iii) Consider signing plain UPDATE responses (draft SHOULD; the MUST is on inquiry responses).
- **Acceptance:** a forged (unsigned/wrong-key) KeyState response is rejected by the child; the receiver's KEY is published and DNSSEC-validatable.
- **Est. size (i, the required part):** ~250-430 LOC impl+tests — acquire/cache/validate the receiver KEY + wire `sig0Verify` into the two remaining call sites + reject-on-failure branches + tests. The third consumer and the root-zone target bug are gone.
- **Est. size (iii, optional/SHOULD):** ~80-150 LOC — mostly reuses `keyStateResponseWriter`'s existing signing pattern applied to the generic UPDATE responder.

### D-6. Child consumes the SVCB `bootstrap` SvcParamKey — **DONE**

**Closed 2026-09-02** (`docs/2026-09-02-ddns-keystate-d6-at-ns-signal.md`).
The `_signal` producer already existed for the transfer-driven HSYNCPARAM
`pubkey` case (`signal_republish.go`); the bootstrap path now uses the same
publisher when `at-ns` is selected, sourcing the keystore KEY so it does not
wait on the asynchronous apex publication. `at-ns` is offered only when at
least one apex NS has its signal name in a zone this server is primary for
(never for a proxy), and is back in the omit-default. Rollover refreshes the
signal names a bootstrap populated. A failed SVCB lookup is
`errBootstrapAdvertisementLookup`, retried by both the KeyState poller and the
BADKEY re-bootstrap arm rather than treated as an absent advertisement.
- **Draft (ddns-02 §"SvcParamKey bootstrap", §"Publishing Supported Bootstrap Methods"):** parent publishes an SVCB at the DSYNC {target} with `bootstrap="at-apex,at-ns,unsigned,manual"` (subset); the child SHOULD prefer the strongest method the parent advertises that it can satisfy.
- **Current (reassessed 2026-09-02 after T4 defects):** parent **emits and reconciles** the SVCB from the bound `delegationpolicy`. Child looks up that SVCB at the DSYNC UPDATE target, intersects with `CompiledChildMethods`, and selects the strongest overlap (`at-apex` > `at-ns` > `unsigned` > `manual`). Empty intersection refuses. Absent SVCB falls back to the child's configured list. Omit-default is `[at-apex, at-ns]` since `_signal` publication landed (2026-09-02); `at-ns` is offered only where this server is primary for a signal name. Proxy still drops `at-ns` even when opted in. `manual` does not send the KEY UPDATE. BADKEY recovery uses the same willing list as the first ceremony (`zd.Options[OptDelSyncProxy]`).
- **Change (done 2026-09-02):** when the selected method is `at-ns`, the auth child publishes the KEY at `_sig0key.<child>._signal.<ns>` before sending the ceremony; a proxy cannot and never offers `at-ns`.
- **Acceptance (met):** with a parent SVCB `bootstrap="unsigned,manual"` and the child default, bootstrap refuses rather than attempting `at-apex`; `at-ns` selected → `_signal` name published (`TestPublishSig0KeyAtSignalNames`).

### D-3b. CDS/CSYNC acceptance semantics on the UPDATE path — **DONE** (2026-09-02, in two PRs; DS half had landed independently)

**Step 1 done 2026-09-02** on `feature/ddns-keystate-d3b-csync-extract`
(off `main`, not stacked): `ProcessCSYNCNotify`'s RFC 7477 rules are
`computeCsyncDelta` and friends in `v2/delegation_csync.go`, network and
stored-delegation access injected, scanner still the only caller, behaviour
byte-identical. The dead pre-NOTIFY path (`CheckCSYNC`, `CsyncAnalyze*`) is
deleted. Notes in `docs/2026-09-02-ddns-keystate-d3b-csync-extraction.md`.

**Step 2 done 2026-09-02** on `feature/ddns-keystate-d3b-csync-wire`
(stacked on step 1): `CheckDelegationNSCoherence` /
`CheckDelegationNSCoherenceForUpdate` (`v2/delegation_csync_update.go`)
apply the rules to an asserted change, scoped to what the update touches,
asking the parent's current nameservers for the child through the scanner's
fetcher; wired into `ApproveChildUpdate` and the DSYNC API handler after the
DS check, same refusal shape. `dsAfterActions` generalised to
`rrsetAfterActions`. Notes and the decisions (scoping, whom to ask, the
deferred EDE) in `docs/2026-09-02-ddns-keystate-d3b-update-wiring.md`. The
DS-duplication question stays open and separate. **D-3b is closed.** (The
LOC totals in this document are maintained on the D-7/D-6/K-4 stack, not
here, to avoid a merge conflict; they read ~80-150 for D-7(iii) once
everything is in.)

- **Reassessed 2026-09-01, post-merge:** `parent-checks-delegation-coherence` (#386, merged to `main` independently of this plan) already implemented the **DS/RFC7344/8078 half** — `v2/delegation_coherence.go:209-297` `CheckDelegationCoherence`, a free function with an injected `dnskeyFetcher`, wired into the UPDATE path at `v2/updateresponder.go:638-645` (`ApproveChildUpdate`, refuses with `REFUSED`+EDE) and the DSYNC-API path at `v2/dsync_api_delegation.go:262`. This is good news (D-3b's DS half is done) and a complication: it was written as a **fresh implementation**, not by extracting the scanner's logic as this plan prescribes, so there are now two independent implementations of the DS acceptance rule — this one, and the scanner's `ProcessCDSNotify` (`v2/scanner.go:1114-1288`). **Remaining scope is the RFC 7477 NS/glue half only** (plus, optionally, reconciling the DS duplication — see below).
- **Why its own PR:** "reuse the scanner's check functions" understates this,
  and undercounts it. `scanner_csync.go` (464 lines, 6 `*Scanner` methods, 53
  references to scanner state) is *not* where the acceptance-decision logic
  lives — it's in `v2/scanner.go`: `ProcessCSYNCNotify:714-1090` (~376 lines)
  and `ProcessCDSNotify:1114-1288` (~174 lines), both with a scan-pipeline
  signature (`ctx, tuple, parentZD, scanType, options, responseCh`) that's
  harder to call from an UPDATE handler than the `CsyncAnalyze*` helpers are.
  Real extraction scope is roughly double the original ~457-line estimate.
- **Do it in two steps, in this order:** (1) extract the NS/glue acceptance logic into
  free functions (same shape as `CheckDelegationCoherence`) with the scanner still its only caller, reviewable purely
  against "the scanner behaves identically"; (2) wire the UPDATE path to the
  extracted functions, alongside the already-wired `CheckDelegationCoherence`. Bundling the refactor with the behaviour change makes
  both unreviewable and puts a live path at risk for a completeness item.
- **Last of the remaining Phase 2 items.** D-7 is exposure; this is
  completeness.
- **Draft (ddns-02 §"Processing the UPDATE"):** once authenticated, the change is subjected to the **same** acceptance checks a CDS/CSYNC scanner runs — RFC7344/8078 for DS, RFC7477 for NS/glue.
- **Current (DONE), after both steps:** DS/RFC7344/8078 via `CheckDelegationCoherence` (see above); the RFC7477 NS/glue rules extracted into `v2/delegation_csync.go` in step 1, and applied to an UPDATE's asserted result by `CheckDelegationNSCoherence` (`v2/delegation_csync_update.go`) in step 2, wired into `ApproveChildUpdate` and the DSYNC API handler after the DS check with the same REFUSED+EDE / 409 shape.

  The scanner and the UPDATE path have SEPARATE drivers, deliberately: the scanner derives a change from what the child publishes (`computeCsyncDelta`), while the UPDATE path validates a change somebody asserted. They share everything below the rule -- `childRRsetFetcher` and its agreement requirement, `csyncTypes`, `inBailiwickNSNames`, `canonicalNameSet` -- and the residue is that the rule itself is stated twice, so a change to it has to reach both or the UPDATE path silently becomes a bypass.

  The `CsyncAnalyzeNS` / `CsyncAnalyzeA` / `CsyncAnalyzeAAAA` helpers this bullet used to name were the **dead pre-NOTIFY path**, not the live rules, and step 1 deleted them along with `CheckCSYNC`, `UpdateCsyncStatus` and `TypeBitMapToString`. The live logic was always inline in `ProcessCSYNCNotify`, which is what got extracted.
- **Change:** extract the NS/glue acceptance logic into a free function in `CheckDelegationCoherence`'s style and wire it into `ApproveChildUpdate` the same way. Separately decide whether to reconcile the now-duplicated DS logic (`CheckDelegationCoherence` vs. `ProcessCDSNotify`) or accept the duplication — the plan's original two-implementations-is-bad rationale for extraction now argues for reconciling, but that's a larger, riskier refactor than just adding the NS/glue half, so it should be a separate, explicit decision rather than something this item quietly grows to include.
- **Acceptance:** a delegation UPDATE that would fail CSYNC/CDS acceptance is refused with the same policy as a scanner would.
- **Est. size:** ~400-700 LOC impl+tests for the NS/glue extraction + wiring, calibrated against `v2/delegation_coherence.go`'s actual size for the DS half (357 impl + 328 test = 685 LOC total, already shipped via #386) as the closest real analogue in this codebase for "extract acceptance logic into an injectable free function, wire into `ApproveChildUpdate`, test both". **+150-250 LOC more** if the DS-duplication reconciliation is taken on as part of the same effort rather than deferred.

---

## Phase 3 — IANA alignment (DEFER — not "wrong" today; these are experimental placeholders the drafts mark TBD)

Flip in one pass once IANA assigns: DSYNC **UPDATE scheme** (currently `2`, `v2/core/rr_dsync.go:41`), SVCB **`bootstrap`** key (currently private `65282`, `v2/svcb_defs.go:11`), KeyState **option code** (currently local `65002`, `v2/edns0/edns0_defs.go:9`), and the three **EDE** codes (currently private `513/514`, `v2/edns0/edns0_ede.go`). No churn until then.

---

## Cross-cutting cleanup
- **Normalize the bootstrap-method vocabulary — DONE (PR #471).** One named-policy vocabulary (`delegationsync.policies.*`, bound per-zone with `delegationpolicy:`). The dead KeyBootstrapper engine is gone. Sample YAML and templates no longer mention `keybootstrap` / `keyupload` / `key-verification`. `scanner.options` / `scanner.at-apex.*` stay put (scanner-specific meaning, out of scope). Remaining D-6 work is consumption of the advertisement, not a second vocabulary.

---

## Remaining-work sizing — calibration basis

Every LOC estimate above is anchored to this branch's own already-shipped,
comparably-shaped work rather than guessed from scratch — this codebase's
convention is thorough test coverage roughly matching or exceeding
implementation size, confirmed by every calibration point below:

| Reference (already shipped) | Shape | Actual size |
|---|---|---|
| D-2b retry engine (`v2/delsync_retry.go` + test) | new retry/backoff subsystem, several call sites wired | 154 impl + 224 test = 378 LOC |
| D-4 bootstrap ceremony (PR #312 commit `60137cd1`, 7 files) | add a verification/trust gate to an existing exchange | 318 net insertions (126 new file + 129 new test file + edits to 5 existing files) |
| D-3b's DS half, `v2/delegation_coherence.go` + test (#386, independent) | extract acceptance logic into an injectable free function, wire into `ApproveChildUpdate`, test | 357 impl + 328 test = 685 LOC |

D-7(i) and D-6 are sized against the D-4 row (same "gate an existing exchange"
shape); D-3b's remaining NS/glue half is sized against the delegation_coherence.go
row directly, since it is the closest real analogue for exactly that job in
this codebase. `v2/sig0_validate.go:232`'s existing `sig0Verify` primitive is
assumed reused rather than reimplemented for D-7, which is reflected in its
estimate being smaller than D-4's full 318 despite being a similarly-scoped
"add verification to an exchange" job — D-4 also had to invent the ceremony's
wire format and deferred-delete bookkeeping from nothing, D-7(i) does not.

**Totals (re-based 2026-09-02 after D-7(i), D-6, K-4 code 8 and D-8 landed):**
- **Core Phase 2 remainder (D-7(iii) + D-3b): ~480-850 LOC**
- **Everything not yet done (adds K-4 code 7 ~150-300): ~630-1150 LOC**

These are order-of-magnitude ranges for planning, not commitments — treat them
the same way the plan treats line-anchors: useful for sizing the work now,
expected to need re-checking against the code at the time each item is
actually picked up.

---

## Working rules
- Branch off `main`; GPG-sign every commit (`-S`, never `--no-gpg-sign`); no `Co-Authored-By`/AI byline.
- `build` + `vet` + full `v2 -race` green before each commit (`GOROOT=/opt/local/lib/go CGO_ENABLED=1`).
- Suggested PR slicing: **PR-1 = Phase 0** (correctness, small, mergeable on its own); **PR-2 = Phase 1** (KeyState completion); **PR-3 = Phase 2** (delegation completion). Phase 3 folded in whenever IANA assigns.
- Implement → commit → push → open PR → **stop** (do not merge).

## Test plan
- Unit: KeyState wire round-trips with -03 values; malformed-request → code 0; each internal key state → correct -03 code; DSYNC UPDATE-scheme parse/print.
- Integration/live (on the parentsync testbed): child publishes KEY → parent bootstraps (each of at-apex/at-ns/unsigned) → child inquires KeyState (QTYPE=KEY) → receives a **signed** response with the right code → sends a delegation UPDATE over TCP → parent applies via provisioning; BADKEY→re-bootstrap loop; forged (unsigned) KeyState response rejected by the child.
