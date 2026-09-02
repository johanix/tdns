# D-7: child-side mutual authentication for the KeyState inquiry channel

**Written 2026-09-02.** Implements the required part of item D-7 of
`docs/2026-07-16-ddns-delegation-keystate-draft-alignment-plan.md` (Phase 2),
picked up from `handovers/2026-09-02-ddns-keystate-alignment-remainder.md`.
Branch `feature/ddns-keystate-d7-mutual-auth`, off `main` @ `5bd73cca`
(post-#471). Records the trust-model decisions, which are not derivable from
the code, and what was deliberately left out.

## The exposure this closes

The child's KeyState inquiry (`QueryParentKeyState`, `parentsync_bootstrap.go`)
went over UDP and took the KEY-STATE code in the reply at face value. The
parent side already signed its replies (`keyStateResponseWriter`,
`keystate.go`, K-3) and published the signing KEY at the DSYNC UPDATE target
(`SetupZoneSync` → `Sig0KeyPreparation`, D-7(ii)), but nothing on the child
checked the signature. A network attacker able to inject a response could
report the child's key as unknown (needless re-bootstrap) or as trusted
(suppress a needed one). ddns-02 §"Mutual Authentication" makes signing the
inquiry response a MUST and verifying it the point of the exercise.

## What landed

All in `v2/`. New file `keystate_verify.go`; edits in
`parentsync_bootstrap.go`, `dsync_lookup.go`, `config_delegationsync.go`,
`child_bootstrap.go`, `ops_key.go`, `truststore.go`; both daemon sample YAMLs.

### Verification (`verifyKeyStateResponse`)

The SIG(0) must be the last additional RR (RFC 2931; also where miekg's
`SIG.Verify` looks) and its SignerName must be the DSYNC UPDATE target the
inquiry was sent to. Verification runs over the **bytes as received**, not a
re-pack: `exchangeRawCancellable` keeps the wire form. A re-pack of the parsed
message is only usually identical (compression, case, truncation), and the
existing UPDATE-side re-pack already needed a workaround for RFC 2136 §2.5.2
records; authentication should not depend on "usually".

The verifier is the existing `sig0Verify` package var (`sig0_validate.go`), so
tests can provoke `ErrSig`/`ErrTime` without a second seam and the validity
window is checked exactly as for inbound UPDATEs.

### Trust model — what makes a response *authenticated*

A response is authenticated when its signature verifies with a receiver KEY
the child has reason to trust. Two sources, tried in this order:

1. **Manually trusted** (draft: "manual bootstrap ... in reverse"). A KEY in
   the child's truststore for the receiver name, keyid, **marked trusted**.
   This is `tdns-cli truststore sig0 add --child <target> --src <keyfile>`
   followed by `... trust --keyid <id>`, i.e. the same table and CLI the
   parent uses for child keys; nothing new to learn. An entry that is merely
   *added* (untrusted) counts for nothing. Manual trust authenticates on its
   own, regardless of how the target name was discovered: the operator bound
   that exact (name, keyid) to the parent out of band, and a forged DSYNC
   target cannot produce a signature that verifies under it.

2. **DNSSEC-validated** (draft: "the common case"). The KEY RRset published at
   the receiver name, fetched through the IMR, **and** the DSYNC lookup that
   named the receiver, **both** DNSSEC-validated. The second condition is the
   decision worth recording: the DSYNC target *is* the receiver's identity.
   If only the KEY lookup were required to validate, an attacker who can
   forge the (unvalidated) DSYNC answer could name a target in a zone they
   control and legitimately sign; the child would then "authenticate" the
   attacker's replies. `DsyncTarget` therefore now carries `Validated`
   (from `DsyncResult.Validated`, which only the API scheme consulted
   before), and `DsyncResult`'s comment no longer says UPDATE does not need
   it.

DNS-validated keys are **not** persisted to the truststore. The IMR caches the
RRset with its validation state for its TTL, so repeated inquiries do not
re-query, and a receiver key rollover becomes visible when the cache entry
expires. Persisting would add TOFU-like state with no benefit.

### Policy — `delegationsync.child.update.allow-insecure`

Default **false**: a response that cannot be authenticated is rejected. The
draft (§"Authenticating Responses") leaves acting on unauthenticated responses
to local policy for the unsigned-parent-zone case; that is what this knob is.
With it set, a response that is unsigned, or signed with a key the child has
no authenticated copy of, is acted on with a **Warn** naming the knob.

Two things it does **not** do, deliberately:

- It never makes a *wrong* signature acceptable. A SIG(0) that is present
  but fails (tampered bytes, wrong signer name, outside its validity window,
  unknown keyid where a key *was* found) is rejected regardless. Only the
  *inability* to authenticate is waivable, never a failed check.
- It is one switch for both parent-derived inputs the child acts on: KeyState
  responses and the SVCB bootstrap advertisement (below). Same reasoning as
  the API scheme's `child.api.allow-insecure`, and the same word.

**Behaviour change, scoped precisely (corrected after the external review's
T1):** the verification runs wherever a KeyState *inquiry* is made, and in
this repo that is one place, the poller `ParentSyncAfterKeyPublication`.
Under an **unsigned** parent zone with no manually trusted receiver key that
poller now refuses the reply by default, with an error naming the knob, and
since its bootstrap UPDATE is triggered by a KEY_UNKNOWN reply, it sends
none. Two things that statement does *not* cover:

- The poller has **no caller in this repo**. Only tdns-mp calls it, against
  its June `tdns/v2` pin and with the old signature, so until tdns-mp bumps
  nothing running from this repo makes the inquiry.
- The tdns-auth child path (`DelegationSyncSetup` → `bootstrapSig0Key`)
  **never inquires**. It looks up DSYNC, selects a method and sends the KEY
  UPDATE. D-7 verification does not run there, so an unsigned parent still
  gets an automatic KEY UPDATE from tdns-auth, knob or no knob. The UPDATE
  *response* is unsigned until D-7(iii).

**The `allow-insecure` composition (the review's T2).** An unauthenticated
SVCB advertisement is treated as absent, so the child falls back to its
configured method list rather than letting a forged advertisement talk it
out of bootstrapping. The cost is that a legitimate *unsigned* parent cannot
steer either: with the default child list, an unsigned parent advertising
`unsigned,manual` gets an `at-apex` KEY UPDATE in strict mode (the parent's
unsigned policy accepts exactly that), while `allow-insecure: true` honours
the advertisement, finds an empty intersection and **refuses**. So an
unsigned-parent lab that turns the knob on must also opt into `unsigned` in
`child.update.bootstrap.methods`, or turning the knob on makes the auth
child stricter. The sample YAML says so next to the knob. The alternative,
treating an unauthenticated advertisement as present-but-unusable and
refusing, would make a forged advertisement a denial of bootstrap; kept the
fallback.

**Bogus is not insecure (the review's T3).** The IMR now exposes its DNSSEC
verdict (`ImrResponse.ValidationState`) rather than only a Secure boolean,
and `DsyncTarget` carries `Bogus`. A **bogus** verdict on the receiver KEY,
on the DSYNC that named the receiver, or on the SVCB advertisement is a chain
of trust that exists and failed: refused regardless of `allow-insecure`. Only
*insecure* (an unsigned zone) is waivable. A manually trusted key is pinned
and still authenticates whatever DNSSEC said about the DSYNC.

**Next address on a failed verification (the review's T4).** `queryKeyState`
no longer stops at the first address that answers: a response that fails
verification is logged and the next address of the target is tried, so a
single poisoned address is a non-event rather than a per-attempt denial.
Only when every address fails does the verification error surface, and a
wrong signature is never made acceptable by the retry.

### Transport

The inquiry now goes over **TCP**, like the delegation UPDATEs themselves
(D-2a). Two reasons beyond spoofing resistance: the reply carries a SIG(0)
that may be post-quantum sized, and the Do53 mux's `udpTruncate` wrapper sits
*outside* `keyStateResponseWriter`, so an oversized UDP reply would be
truncated after signing and lose the very SIG being checked. The parent's
DSYNC UPDATE port already had to accept TCP for D-2a.

### SVCB bootstrap advertisement (carry-over 6 from the #471 reviews)

`advertisedBootstrapMethods` consumed the parent's SVCB `bootstrap` set
without consulting `resp.Validated`. It now counts only when both the DSYNC
and the SVCB validated, or under `allow-insecure`; otherwise it is treated as
**absent** and the child falls back to its configured list, with a Warn. Absent
rather than refusing is the right fail-closed shape here: a forged
advertisement could otherwise talk the child out of bootstrapping (`manual`
only) — with fallback it can do nothing. A legitimate unsigned parent that
advertises `manual` will receive a KEY UPDATE it holds for approval, which is
harmless.

### API surface

`QueryParentKeyState` and the never-called `QueryParentKeyStateDetailed` are
merged into one exported function returning
`(*edns0.KeyStateOption, authenticated bool, error)`. The "detailed" variant
had zero callers in this repo.

`FindSig0TrustedKey` moved from `ZoneData` to `KeyDB` (the child verifying a
response has no zone in hand); the `ZoneData` method is a one-line wrapper.

## Not done, and why

- **D-7(iii), signing plain UPDATE responses** (draft SHOULD; the MUST is on
  inquiry responses). Untouched. The 15-odd `w.WriteMsg(m)` sites in
  `updateresponder.go` want the same writer-wrapping treatment
  `keyStateResponseWriter` gives the query path; sized ~80–150 LOC in the
  plan. Separate change.
- **tdns-mp** (`tdns-mp/v2/parentsync_utils.go`) carries its own copy of the
  old unverified inquiry ("local copies because the originals are unexported")
  and drives the `parentsync-inquire` CLI verb from `apihandler_agent.go`. It
  pins a published `tdns/v2` from June and is outside this repo. When it
  bumps, it should delete the copy and call `tdns.QueryParentKeyState`, which
  now also returns whether the answer was authenticated — worth showing in
  `displayKeyStateInquiry`.
- **Carry-over 9** (a failed SVCB lookup collapses into "absent") is
  unchanged; it is D-6's, and the gate added here sits after that collapse.
- **`LookupDSYNCTarget`'s `Validated` propagation** is one assignment and is
  not unit-tested (the function is network-bound end to end). Covered by the
  plan §8 integration items, which remain unrun.

## Tests

`keystate_verify_test.go` (real ED25519 keys, real verifier):
table over authenticated / unvalidated-key / unvalidated-DSYNC / unsigned /
wrong-signer / unknown-keyid / tampered-in-flight / lookup-failure, each
under both policies; manual-trust lifecycle (absent → added-untrusted →
trusted, plus tampering against a trusted key); verifier `ErrSig`/`ErrTime`
via the `sig0Verify` seam; the IMR fetcher on a secure cache hit; and a
**TCP round trip** against an in-process `dns.Server` whose handler signs with
the real `keyStateResponseWriter` — the test that proves the received bytes
verify against a real server pack, and that the inquiry is TCP (the responder
listens on nothing else). `child_bootstrap_test.go`: the advertisement gate,
pure and through a seeded IMR cache. `config_delegationsync_model_test.go`:
the knob decodes and does not alias the API one.
