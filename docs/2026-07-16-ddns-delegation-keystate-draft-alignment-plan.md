# Implementation plan — align tdns to delegation-mgmt-via-ddns-02 + keystate-03

**Status:** ready for implementation. Self-contained.
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

### K-1. KeyState codepoints → keystate-03 registry
- **Draft (keystate-03 §"Defined and Reserved Values", registry table):** `0=KEY_REQUEST_MALFORMED`, `1=KEY_TEMPORARY_FAILURE` (both **receiver**-set), `2=INTENT_INQUIRE_KEY` (sender), `3` unassigned, `4=KEY_TRUSTED`, `5=KEY_UNKNOWN`, `6=KEY_INVALID`, `7=KEY_REFUSED`, `8=KEY_VALIDATION_FAILED`, `9=KEY_BOOTSTRAP_AUTO`, `10=KEY_BOOTSTRAP_MANUAL`, `11-127` unassigned, `128-255` Private.
- **Current (WRONG):** `v2/edns0/edns0_keystate.go:15-30` has `KeyStateRequestAutoBootstrap=0`, `KeyStateRequestManualBootstrap=1`, `KeyStateBootstrapAutoPending=11`. Code `0` is semantically inverted (tdns "please auto-bootstrap" vs draft "malformed request").
- **Change:** Reassign `0=KeyStateRequestMalformed`, `1=KeyStateTemporaryFailure`. **Delete** the `0/1` sender-request meaning (keystate-03 removed sender bootstrap-request codes — bootstrap initiation is via the self-signed DNS UPDATE + the SVCB `bootstrap` SvcParamKey, not KeyState). **Delete** `KeyStateBootstrapAutoPending=11` (unassigned in -03). Keep `2,4-10`. Update the `KeyStateToString` map (`edns0_keystate.go:77-96`). Update **every consumer** of the removed constants (search `KeyStateRequestAutoBootstrap`, `KeyStateRequestManualBootstrap`, `KeyStateBootstrapAutoPending`): `v2/keystate.go` (ProcessKeyState uses 0 for auto-bootstrap `:64`, emits 11 `:84`), `v2/parentsync_bootstrap.go`, `v2/keybootstrapper.go`.
- **Also** bump all `draft-berra-dnsop-keystate-02` source comments → `-03` (`edns0_keystate.go:14,20,33`, `keystate.go:26`, `defaultqueryhandlers.go:53`).
- **Acceptance:** no path emits/accepts `0` or `1` as sender codes; `11` gone; a wire round-trip unit test asserts the -03 values.

### K-2. Malformed-request handling
- **Draft (keystate-03 §Protocol-Level Responses):** a receiver that gets an unrecognized/unassigned KEY-STATE (incl. 3, 11-127) in a request MUST respond `KEY_REQUEST_MALFORMED(0)`. A well-formed receiver recognizes only sender code `2` as a valid inquiry.
- **Current (WRONG):** `v2/keystate.go:102-108` default branch returns `KeyStateInvalid(6)`; the `switch` treats `0` (auto-bootstrap) and `2` as valid.
- **Change:** after K-1, make the request switch accept only `2 (INTENT_INQUIRE_KEY)`; every other value → respond `KEY_REQUEST_MALFORMED(0)` with `KEY-DATA=0` and `KEY-ID` echoed (or 0 if unparseable).
- **Acceptance:** an inquiry with KEY-STATE=99 gets a response with KEY-STATE=0.

### K-3. KeyState response MUST be SIG(0)-signed
- **Draft (keystate-03 §"KeyStates Set By The UPDATE Receiver"; ddns-02 §Mutual Authentication):** the inquiry response MUST be signed by the UPDATE Receiver's SIG(0) key. An unsigned response to an inquiry is the forged-response attack vector.
- **Current (WRONG):** `v2/keystate.go:28-34` sends the response **unsigned** when no active SIG(0) key is found or when `SignMsg` errors ("better than failing entirely").
- **Change:** fail closed — if the receiver cannot SIG(0)-sign a KeyState response, do **not** attach the KeyState option (respond as if unsupported) rather than sending an unsigned key-state signal. Log loudly. (Coordinate with D-7.)
- **Acceptance:** no code path emits a KeyState option on an unsigned message.

### D-8. UPDATE-receiver rcode/EDE semantics (VERIFY the inversion first, then fix)
- **Draft (ddns-02 §§"RCODE BADKEY", "Communication in Case of Errors", §IANA EDE):** **unknown key → `BADKEY(17)`** (child falls back to bootstrap). **Key known-but-not-trusted → `REFUSED`** carrying an EDE (`KEY-KNOWN-NOT-TRUSTED`). Three new EDE codes: KEY-KNOWN-NOT-TRUSTED, KEY-VALIDATION-FAILED, MANUAL-BOOTSTRAP-REQUIRED.
- **Current (WRONG — confirm against the code before changing):** survey found the mapping inverted — unknown key → `BADSIG(16)`+EDE"known-not-trusted"; known-not-trusted → `BADKEY(17)`. See `v2/sig0_validate.go:31,274,288-311` and `v2/updateresponder.go:281-300`.
- **Change:** unknown/unlocatable signer key → `BADKEY(17)`. Known-but-`!Trusted` key → `REFUSED` + EDE `KEY-KNOWN-NOT-TRUSTED` (existing private `EDESig0KeyKnownButNotTrusted=514`, `v2/edns0/edns0_ede.go:17-68`). Add private EDE codes for `KEY-VALIDATION-FAILED` and `MANUAL-BOOTSTRAP-REQUIRED` (values remain private/experimental until IANA — Phase 3). Keep `SERVFAIL` only for hard validation errors.
- **Acceptance:** update signed by an unknown key → `BADKEY`; by a known-untrusted key → `REFUSED`+EDE514.

### D-2a. Child UPDATE over TCP
- **Draft (ddns-02 §"Choice of SIG(0) Signature Algorithm"):** these UPDATEs are infrequent and SHOULD be carried over TCP (or DoT) — avoids UDP spoofing/fragmentation for a message that mutates parent state and accommodates larger (PQ) SIG(0) signatures.
- **Current (WRONG):** `v2/childsync_utils.go:65-73` `SendUpdate` uses UDP unless `msg.Len() > 1232`.
- **Change:** force TCP for delegation-sync UPDATEs regardless of size (do not gate on message length on this path).
- **Acceptance:** delegation UPDATE always goes over TCP.

---

## Phase 1 — KeyState-03 completion (PARTIAL/MISSING)

### K-4. Emit the full receiver code set (4-10) with a 1:1 state map
- **Draft (keystate-03 §"KeyStates Set By The UPDATE Receiver"):** codes 4 KEY_TRUSTED, 5 KEY_UNKNOWN, 6 KEY_INVALID, 7 KEY_REFUSED, 8 KEY_VALIDATION_FAILED, 9 KEY_BOOTSTRAP_AUTO, 10 KEY_BOOTSTRAP_MANUAL; plus 1 KEY_TEMPORARY_FAILURE for transient inability.
- **Current (PARTIAL):** `v2/keystate.go:150-173` `GetKeyStatus` maps trusted→4, validated-not-trusted→9, present-not-validated→**6**, missing→5. **Codes 7 (KEY_REFUSED) and 8 (KEY_VALIDATION_FAILED) are never emitted**; validation-failure collapses into 6.
- **Change:** give tdns's SIG(0) key states a full 1:1 map: distinguish *validation failed* (→8) from *generic invalid/algorithm-mismatch* (→6); emit `7 (KEY_REFUSED)` when the key/algorithm is rejected by policy; emit `10 (KEY_BOOTSTRAP_MANUAL)` from the manual-bootstrap policy state (not from a sender request); emit `1 (KEY_TEMPORARY_FAILURE)` on transient store errors.
- **Acceptance:** each internal key state produces its correct -03 code; a truststore key whose validation failed returns 8, not 6.

### K-5. Child inquiry QTYPE=KEY
- **Draft (keystate-03 §"KeyStates Set By The UPDATE Receiver"):** the inquiry is `QNAME=child.parent, QTYPE=KEY`.
- **Current (PARTIAL):** inquiry uses `dns.TypeANY` (`v2/parentsync_bootstrap.go:148,205`, `v2/keybootstrapper.go:288`).
- **Change:** use `dns.TypeKEY` for the KeyState inquiry query. (The DSYNC-target lookups at `:142,199,281` are a separate lookup — leave those unless they are the same query.)
- **Acceptance:** inquiry packets carry QTYPE=KEY.

### K-6. KEY-DATA sub-reason (optional)
- **Draft (keystate-03 §KEY-DATA / codes 6,7):** KEY-DATA MUST be 0 except codes 6/7 MAY carry a receiver-defined sub-reason.
- **Current:** KEY-DATA never populated (reasons in EXTRA-TEXT).
- **Change (optional/low-priority):** for codes 6/7 optionally set a sub-reason byte; keep human text in EXTRA-TEXT. Ensure KEY-DATA=0 for all other codes.

---

## Phase 2 — delegation-mgmt-via-ddns-02 completion (PARTIAL/MISSING)

### D-2b. UPDATE send retry policy + RCODE handling
- **Draft (ddns-02 §"No response to a DNS UPDATE"; §RCODE sections):** SHOULD wait ≥5s before timeout, exponential backoff (double each time), give up after ≤5 retries. RCODE: NOERROR=accepted; REFUSED (don't stop on a single one, may stop after repeated); BADKEY(17)→fall back to bootstrap.
- **Current (MISSING):** `v2/childsync_utils.go:75-124` tries each address once, no backoff/retry/timeout. (The `5s,10s,20s,40s ≤5` pattern already exists for the KeyState poller `v2/parentsync_bootstrap.go:52-131` — lift/reuse it.)
- **Change:** add a retry loop on the UPDATE send (≥5s timeout, exp backoff, ≤5 tries); interpret RCODE explicitly: NOERROR done; `BADKEY(17)` → trigger re-bootstrap (`BootstrapSig0KeyWithParent`); REFUSED → log, bounded retry; no-response → timeout+retry per policy.
- **Acceptance:** a dropped first UPDATE is retried with backoff; a BADKEY response triggers re-bootstrap.

### D-4. Bootstrap ceremony `DEL … ANY KEY` + explicit no-delete-until-validated
- **Draft (ddns-02 §§"Bootstrapping...", "Re-bootstrapping In Case of Errors"):** the self-signed bootstrap UPDATE is `DEL child.parent ANY KEY` + `ADD child.parent KEY`. The receiver MUST NOT act on the `DEL ANY KEY` to remove an already-**trusted** key until the newly added key has been validated.
- **Current (PARTIAL):** `v2/ops_key.go:155-227` `BootstrapSig0KeyWithParent` builds an **ADD-only** update (no DEL). Re-bootstrap safety holds only by construction (untrusted KEY-deletes refused, `v2/updateresponder.go:440-464,657-683`).
- **Change:** include the `DEL child ANY KEY` half in the bootstrap/re-bootstrap UPDATE (child side). On the receiver, make the "do not delete a trusted key until the replacement is validated" rule an **explicit** guard in the KEY-RRset delete path, not just an emergent property. Preserve the existing refusal of untrusted deletes.
- **Acceptance:** a self-signed re-bootstrap UPDATE carrying `DEL ANY KEY`+`ADD KEY` does not evict the currently-trusted key until the new key validates.

### D-6. Child consumes the SVCB `bootstrap` SvcParamKey
- **Draft (ddns-02 §"SvcParamKey bootstrap", §"Publishing Supported Bootstrap Methods"):** parent publishes an SVCB at the DSYNC {target} with `bootstrap="at-apex,at-ns,unsigned,manual"` (subset); the child SHOULD prefer the strongest method the parent advertises that it can satisfy.
- **Current (PARTIAL):** parent **emits** it (`v2/ops_dsync.go:159-185`, private `SvcbBootstrapKey=65282`); child never parses it — method choice is config-only.
- **Change:** child looks up the SVCB at the DSYNC {target}, parses the `bootstrap` value, and selects the strongest supported method (prefer signed `at-apex`/`at-ns` over `unsigned` over `manual`). Fall back to config when the SVCB is absent. Add `delegationsync.parent.bootstrap.methods` to the sample config (`cmdv2/auth/tdns-auth.sample.yaml`).
- **Acceptance:** with a parent SVCB `bootstrap="unsigned,manual"`, the child selects accordingly rather than attempting `at-apex`.

### D-7. Mutual authentication — child verifies the receiver's signature/KEY; sign plain UPDATE responses
- **Draft (ddns-02 §§"Mutual Authentication", "Bootstrapping the UPDATE Receiver's Key Into the Child", "Publishing the UPDATE Receiver's Key"):** the UPDATE Receiver maintains its own SIG(0) key, publishes it as a KEY record at the DSYNC {target}, and signs its responses; the child acquires+validates that KEY (DNSSEC or manual) and MUST verify signed responses (esp. KeyState inquiry responses).
- **Current (PARTIAL):** receiver signs only KeyState replies (`v2/keystate.go:21-38`), not plain UPDATE responses; child does **not** verify the receiver's signature/KEY (`v2/parentsync_bootstrap.go:181-191`, `v2/keybootstrapper.go:328-335`). Receiver-KEY publication at {target} unconfirmed.
- **Change:** (i) child acquires+validates the UPDATE Receiver's KEY (from the DSYNC {target}, DNSSEC-validated, else manual) and **verifies the SIG(0) signature** on KeyState inquiry responses — reject/ignore unsigned or invalidly-signed responses. (ii) Confirm/implement receiver-KEY publication as a KEY RR at the DSYNC {target}. (iii) Consider signing plain UPDATE responses (draft SHOULD; the MUST is on inquiry responses).
- **Acceptance:** a forged (unsigned/wrong-key) KeyState response is rejected by the child; the receiver's KEY is published and DNSSEC-validatable.

### D-3b. CDS/CSYNC acceptance semantics on the UPDATE path
- **Draft (ddns-02 §"Processing the UPDATE"):** once authenticated, the change is subjected to the **same** acceptance checks a CDS/CSYNC scanner runs — RFC7344/8078 for DS, RFC7477 for NS/glue.
- **Current (PARTIAL):** the UPDATE path applies SIG(0)-trust + name-scope + an RR-type policy gate only (`v2/updateresponder.go:484-512`); the RFC7344/8078/7477 semantic checks live in the scanner path and are not reused for UPDATEs.
- **Change:** run the scanner's CDS/CSYNC acceptance checks on the UPDATE-carried delegation change before applying it (reuse the scanner's check functions).
- **Acceptance:** a delegation UPDATE that would fail CSYNC/CDS acceptance is refused with the same policy as a scanner would.

---

## Phase 3 — IANA alignment (DEFER — not "wrong" today; these are experimental placeholders the drafts mark TBD)

Flip in one pass once IANA assigns: DSYNC **UPDATE scheme** (currently `2`, `v2/core/rr_dsync.go:41`), SVCB **`bootstrap`** key (currently private `65282`, `v2/svcb_defs.go:11`), KeyState **option code** (currently local `65002`, `v2/edns0/edns0_defs.go:9`), and the three **EDE** codes (currently private `513/514`, `v2/edns0/edns0_ede.go`). No churn until then.

---

## Cross-cutting cleanup
- **Normalize the bootstrap-method vocabulary** to the drafts' canonical `at-apex / at-ns / unsigned / manual`. Today three inconsistent naming schemes coexist: `updatepolicy.child.keybootstrap:[manual,dnssec-validated,consistent-lookup]`, `delegationsync.parent.update.key-verification.mechanisms:[at-apex,at-ns]`, and the free-form SVCB `bootstrap.methods` string. Pick the canonical names, map the others internally, update sample config + templates.
- **Do NOT patch** `tdns/edns0/edns0_keystate.go` (legacy tree; still carries removed -02 policy codes 3/11/12) — it's slated for deletion.

---

## Working rules
- Branch off `main`; GPG-sign every commit (`-S`, never `--no-gpg-sign`); no `Co-Authored-By`/AI byline.
- `build` + `vet` + full `v2 -race` green before each commit (`GOROOT=/opt/local/lib/go CGO_ENABLED=1`).
- Suggested PR slicing: **PR-1 = Phase 0** (correctness, small, mergeable on its own); **PR-2 = Phase 1** (KeyState completion); **PR-3 = Phase 2** (delegation completion). Phase 3 folded in whenever IANA assigns.
- Implement → commit → push → open PR → **stop** (do not merge).

## Test plan
- Unit: KeyState wire round-trips with -03 values; malformed-request → code 0; each internal key state → correct -03 code; DSYNC UPDATE-scheme parse/print.
- Integration/live (on the parentsync testbed): child publishes KEY → parent bootstraps (each of at-apex/at-ns/unsigned) → child inquires KeyState (QTYPE=KEY) → receives a **signed** response with the right code → sends a delegation UPDATE over TCP → parent applies via provisioning; BADKEY→re-bootstrap loop; forged (unsigned) KeyState response rejected by the child.
