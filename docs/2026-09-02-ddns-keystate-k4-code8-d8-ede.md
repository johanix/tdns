# K-4 code 8 (KEY_VALIDATION_FAILED) and D-8's two EDE codes

**Written 2026-09-02.** Closes K-4 code 8 and the D-8 remainder of
`docs/2026-07-16-ddns-delegation-keystate-draft-alignment-plan.md`, in the
order the handover asked for (the EDEs need an emitter, and code 8 is it).
Branch `feature/ddns-keystate-k4-code8-d8-ede`, stacked on D-6 (#473) which
is stacked on D-7 (#472).

## What "validation failed" is, and where it now lives

The parent verifies an uploaded child KEY asynchronously
(`TriggerChildKeyVerification`): look it up via the policy's mechanisms,
retry with backoff, promote to trusted on success. Before this change the
exhausted case logged a Warn and persisted nothing, so the truststore row
looked exactly like "verification in progress" and `childKeyState` had to
report KEY_BOOTSTRAP_AUTO(9) for both. keystate-03's code 8 and ddns-02's
"known, but validation failed" state exist precisely to tell the child that
**waiting will not help**.

The handover said #312 had built "durable retry/exhaustion state" for this.
It had not, on the parent side: #312 gave the policy its retry parameters and
made the verification goroutine cancellable. The durable state is added here:

- `Sig0TrustStore` gains `validation_failed`, `validation_error`,
  `validation_failed_at`, in the CREATE TABLE and in `dbMigrateSchema` (the
  existing `ALTER TABLE ADD COLUMN` pattern; a pre-existing row migrates to
  not-failed).
- New truststore subcommand `validation-failed` sets them. The `WHERE
  trusted=0` clause means an operator's trust decision outranks an automatic
  failure. `verify` (success) clears them; a re-upload replaces the row and
  so clears them.
- `list`, `FindSig0TrustedKey` and the startup cache load (`LoadSig0ChildKeys`)
  read them into `Sig0Key.ValidationFailed` / `ValidationError`. The startup
  load matters: `FindSig0TrustedKey` answers from that cache first, so a
  restart would otherwise forget the failure until the first cache miss.
- The verification goroutine's body is now `runChildKeyVerification`, taking
  a `childKeyVerifier` (one attempt: accepted, dnssecValidated, reason).
  The production verifier wraps `VerifyChildKey` and the IMR; tests inject
  one. On exhaustion the engine records `"<n> attempts via <mechanisms>:
  <last reason>"`.

### Emission

- **KeyState** (`childKeyState`): 4 trusted; 6 structurally invalid; 10
  validated-not-trusted; 10 manual policy; **8 validation failed**; 9
  otherwise. The manual cases come first on purpose: under a manual policy
  "manual bootstrap required" is the actionable state whatever the automatic
  attempt did. For 8 the EXTRA-TEXT carries the recorded reason; KEY-DATA
  stays 0 (K-6 is declined).
- **EDE** (`TrustUpdate`, for an UPDATE signed by a known-but-untrusted key,
  always on REFUSED): `knownUntrustedKeyEDE` with the same precedence —
  manual policy → 542 MANUAL-BOOTSTRAP-REQUIRED; recorded failure → 541
  KEY-VALIDATION-FAILED; otherwise 514 KEY-KNOWN-NOT-TRUSTED. The EDE is
  chosen for the signer whose signature actually verified, not
  `Signers[0]`. Codes appended at the end of the private block (values
  pinned in `TestEDECodeValues`); private until IANA assigns (Phase 3).

### The child's side of "manual"

`bootstrapSig0KeyWithParent` returned a plain error when the selected method
was `manual`, so a zone whose parent legitimately requires manual bootstrap
logged an ERROR on every load. It now returns `errBootstrapManual`, and:

- `DelegationSyncSetup` logs Info ("waiting for the operator") and returns
  nil;
- the KeyState poller (`ParentSyncAfterKeyPublication`) does the same for
  the sentinel and for an explicit KeyState 10, and treats KeyState **8** as
  terminal with an Error naming the parent's recorded reason and what to
  fix, rather than the generic "unexpected key state";
- the BADKEY re-bootstrap arm stays terminal but says what the operator has
  to do.

The management API's `bootstrap-sig0-key` still returns the error: an
operator explicitly asked for an automatic bootstrap that cannot happen, and
the message says why.

## Decisions worth recording

- **A restart mid-verification records nothing.** The row stays "in
  progress" (9) until the child re-uploads. Persisting "started at" and
  resuming verification at startup would be the fuller answer, but it needs
  the zone registry and IMR up before `LoadSig0ChildKeys` runs, which they
  are not. Nothing was concluded, so 9 is the honest report; recorded as a
  possible follow-up, not hidden.
- **A trusted key is never marked failed** (`WHERE trusted=0`). The only
  way a trusted key reaches the engine is a manual `trust` racing an
  in-flight verification; the operator wins.
- **Manual outranks failed** on both channels, so the child is told the
  thing it can act on.

## Tests

`truststore_validation_failed_test.go`: persist / read back through `list`,
`FindSig0TrustedKey` and the startup cache; cleared by `verify` and by
re-upload; never set on a trusted key; the schema migration on an old-shaped
table with a pre-existing row; the engine records exhaustion with the reason
and the inquiry reports 8 with it, then a later success clears it and the
inquiry reports 4; a cancelled run records nothing and reports 9.
`keystate_map_test.go`: 8, and manual-over-failed. `sig0_validate_d8_test.go`:
`knownUntrustedKeyEDE` and `TrustUpdate` for all three states plus the
verified-signer selection. `edns0_codepoints_test.go`: the two values and
their strings. `delsync_retry_test.go`: the manual sentinel is terminal.
