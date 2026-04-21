# ML-DSA-44 SIG(0) Support: Implementation Plan

Date: 2026-04-19 (plan) / 2026-04-20 (implementation complete)
Status: **Implemented (prototype)**

## Implementation Summary

The plan below has been fully implemented.  End-to-end
verification on the NetBSD test lab (2026-04-20):

1. `keystore sig0 generate --algorithm MLDSA44` created a key in
   the agent's keystore as a PKCS#8 PEM block.
2. `keystore sig0 export` wrote the BIND-convention `.private` +
   `.key` pair to disk.
3. `agent zone update create --signer foo.bar. --key …` composed
   an UPDATE interactively, signed it with the ML-DSA-44 SIG(0)
   key, and sent it to the receiver.
4. Receiver (tdns agent at `ns1.dnslab`) validated the SIG(0)
   against the pre-loaded TrustStore (`mldsa44.Verify` in the
   fork), policy approved, direct backend mutated the live zone,
   AXFR reflected the change.

### What landed

- **Fork** `johanix/dns` branch `mldsa44-sig0`
  (commit `6dbf3c7c`): algorithm 199 `MLDSA44`, `AlgorithmToString`
  + `AlgorithmToHash` entries, keygen, `sign()` pass-through,
  `SIG.Verify` case, BIND-format private-key IO,
  `publicKeyMLDSA44()`, `setPublicKeyMLDSA44()`,
  compile-time `crypto.Signer` assertion, `TestSIG0` loop plus
  `TestMLDSA44PrivateKeyRoundTrip`, `TestMLDSA44PublicKeyLength`,
  `TestMLDSA44UpdateRoundTrip`.
- **tdns** `johanix/tdns` branch `mldsa44-sig0-fork`
  (through commit `ca79c80`): `replace` directive pinning
  miekg/dns at the fork pseudo-version in all 11 v2/cmdv2 go.mod
  files; hand-rolled PKCS#8 encoder/decoder for ML-DSA-44 using
  the FIPS 204 OID `2.16.840.1.101.3.4.3.17`
  (stdlib `x509.MarshalPKCS8PrivateKey` does not know the
  algorithm as of Go 1.25); type-switch case for
  `*mldsa44.PrivateKey` in `GenerateKeyMaterial`; algorithm-switch
  case in `PrepareKeyCache`; new `keystore sig0 export` CLI
  command writing BIND-convention files consumable by
  `tdns.ReadPrivateKey`; `config status -v` surfacing `db.file`;
  centralised `AttachUpdateCreateFlags` helper adding
  `--signer`/`--key`/`--server` to every `update create` entry
  point; fix for inverted-logic nil-pointer panic in
  `CreateUpdate`'s keyfile branch; CLI help now lists supported
  algorithms per-context (SIG(0) vs DNSSEC).
- **tdns-mp** `johanix/tdns-mp` branch `mldsa44-sig0-fork`:
  `replace` directive pinning miekg/dns at the fork across all
  five v2 + cmd go.mod files.

### TCP enforcement in the sender

Implemented generically in `SendUpdate()`
(`tdns/v2/childsync_utils.go`): if the packed UPDATE message
exceeds 1232 bytes (the advertised EDNS UDP buffer), the
client switches to TCP.  This is size-based rather than
algorithm-specific, so any UPDATE sender in either tdns or
tdns-mp that uses the library `SendUpdate` gets the right
transport automatically — including the CLI (`update create`),
delegation sync, SIG(0) bootstrap, and SIG(0) rollover paths.

### Deviation from the plan

The plan asserted that tdns was fully algorithm-agnostic and
needed no code changes.  That was wrong.  The PKCS#8 PEM path
(`readkey.go`) uses `x509.MarshalPKCS8PrivateKey`, which has no
built-in ML-DSA support in Go 1.25; hand-rolled PKCS#8
marshal/unmarshal using the FIPS 204 OID had to be added.
Additionally, the type switch in `GenerateKeyMaterial` and the
algorithm switch in `PrepareKeyCache` each needed a new case for
`*mldsa44.PrivateKey`.  Net tdns-side change: ~170 lines of
added code.

### Remaining operational followups

These do not block the prototype but should be tracked:

- **Pre-published DS pool mechanism.**  The sliding-window DS
  pool described in
  `draft-johani-dnsop-dnssec-rapid-rollover` is not yet
  implemented in tdns.  Adding it is the next substantive piece
  of work.  Requires pool-depth config, child-side rotation
  scheduler, parent-side UPDATE composition (remove
  `DS_n` + append `DS_{n+k}`).
- **Self-signed bootstrap test.**  Test 11 below was deferred
  during the prototype; the live test used a pre-loaded
  TrustStore.  Worth closing the loop on that path with a
  separate test.
- **Linear issue.**  No Linear tracking issue created yet; worth
  doing once the IETF draft solidifies enough to give the
  overall project a shape.
- **IETF draft prose on TCP-mandatory.**  Already captured in
  `draft-johani-dnsop-dnssec-rapid-rollover`; no change needed
  in `draft-ietf-dnsop-delegation-mgmt-via-ddns` if the
  TCP-mandatory wording lives in the new draft.

---

The remainder of this document preserves the plan as written on
2026-04-19 for historical reference.

## Motivation

DNSSEC is not a high-value target for quantum attack — signatures
are public and short-lived, and forgery requires online real-time
attack against a live zone. The economic argument (cheap automated
rollover vs. very expensive quantum hardware with better targets)
means rapid rollover of cheap EC keys is a viable defense without
migrating DNSSEC zone-signing to PQC algorithms.

The weak point is the *authorization* of those rapid rollovers:
updating the parent's DS RRset must itself be authenticated by a
key that cannot be broken in the rollover window. This plan uses
SIG(0) with a PQC-safe algorithm (ML-DSA-44) as the outer trust
anchor for DDNS UPDATEs of the parent DS RRset, per
draft-ietf-dnsop-delegation-mgmt-via-ddns.

Why ML-DSA-44 specifically:
- NIST-standardized (FIPS 204).
- Available in CIRCL (already a tdns dependency via HPKE):
  `github.com/cloudflare/circl/sign/mldsa/mldsa44`.
- Reasonable sizes: 1312-byte public key, 2420-byte signature,
  2560-byte private key. Irrelevant for SIG(0) since these are
  infrequent transactions and will be carried over TCP.
- `crypto.Signer`-compatible API.

SIG(0) is the right integration point because it is purely an
on-the-wire transaction signature — never stored in zones, never
cached, never queried for. Only the child-side sender and the
DSYNC-discovered parent-side receiver need to understand the
algorithm.

## Scope

In scope:
- Add ML-DSA-44 as a DNSSEC algorithm number in our fork of
  miekg/dns.
- Sign and verify SIG(0) transaction signatures using ML-DSA-44.
- Key generation, private-key file format, public key in a KEY
  record (both wire and text presentation).

Out of scope:
- RRSIG (zone) signing with ML-DSA-44. Zone signing stays on
  cheap EC; the DNSSEC code path will continue to support EC
  algorithms and does not need to understand ML-DSA-44.
- Upstreaming to miekg/dns. This is a private-use algorithm and
  Miek will not merge non-standardized PQC.
- Post-quantum hybrid signatures (e.g. ED25519+ML-DSA). Possible
  future work; not needed for the prototype.

## Key decisions

### Algorithm number: 199

RFC 4034's 253 (PRIVATEDNS) and 254 (PRIVATEOID) are *meta-*
algorithm slots: they require the KEY RDATA and SIG RDATA to
begin with a domain-name or OID prefix naming the actual
algorithm. Using them would mean building prefix handling into
the wire format and sign/verify paths. For a prototype, we
instead take algorithm number **199** from the currently
unassigned range and treat it as a flat, self-contained
algorithm. This is a deliberate hijack — we are not an
allocation authority, and the number is scoped to our fork and
our deployments. If the algorithm is ever standardized, IANA
will assign a different number and we re-map.

### Fork miekg/dns

The top-level maps (`AlgorithmToString`, `AlgorithmToHash`,
`StringToAlgorithm`) are exported, but sign/verify dispatch is
done via hardcoded `switch` statements inside unexported code
paths (`dnssec.go:307, 331, 343, 443`; the verify switch in
`sig0.go`). Adding to the public maps alone is not enough —
execution will fall through to the default case and error out.
There is no registration API.

Therefore: fork miekg/dns as `tdns-project/dns` (or equivalent),
pin our modules to the fork, and add ML-DSA-44 as a normal
internal case in the switch statements.

### Hash dispatch: identityHash (crypto.Hash = 0)

ML-DSA-44 ingests the raw message — it does not pre-hash like
RSA or ECDSA. miekg already handles this for Ed25519 via
`identityHash` and `crypto.Hash(0)`. We reuse the same path:
`AlgorithmToHash[MLDSA44] = 0`. The existing sign/verify flow
then passes the raw concatenated wire bytes to the signer, which
is correct for ML-DSA.

### Signature format: raw pass-through

CIRCL's `mldsa44.Sign` returns the FIPS-204 flat 2420-byte
signature, not DER-wrapped. We pass it through unchanged, like
Ed25519. No marshal/unmarshal shim. (If the first end-to-end
sign/verify test disagrees with this assumption, we add a shim
then.)

### TCP only

A single SIG(0)-signed UPDATE carries at least 2420 bytes of
signature plus the message body, which blows past 512-byte UDP
and may push past typical 4096-byte EDNS0 buffers once a KEY
record is also carried. We mandate TCP for these transactions
both in the child sender and the parent receiver. This aligns
with the broader draft-ietf-dnsop-delegation-mgmt-via-ddns plan.

### crypto.Signer wrapper: only if needed

CIRCL's `mldsa44.PrivateKey` is documented as `crypto.Signer`-
compatible. We will confirm with a compile-time assertion
(`var _ crypto.Signer = (*mldsa44.PrivateKey)(nil)`). If it
satisfies the interface with `opts.HashFunc() == 0` and
`digest` treated as the raw message, no wrapper is needed. If
not, a thin adapter lives next to the keygen code.

## File-by-file change map (in our fork of miekg/dns)

All paths relative to the fork root.

### dnssec.go

- **L23-L45 (algorithm constants)**: add
  `MLDSA44 uint8 = 199`.
- **L48-L65 (`AlgorithmToString`)**: add
  `MLDSA44: "MLDSA44"`.
- **L71-L81 (`AlgorithmToHash`)**: add `MLDSA44: 0`.
- **L307 (`RRSIG.signAsIs` switch)**: leave alone. We do not
  sign RRSIGs with ML-DSA-44. If the switch falls through to
  `ErrAlg`, that is correct behavior for zone signing.
- **L331 (`sign()` post-processing switch)**: extend the raw
  pass-through case that already covers Ed25519 to also cover
  `MLDSA44`. This is what makes SIG(0) signing work, because
  `SIG.Sign` in `sig0.go` calls through `sign()`.
- **L443 (`RRSIG.Verify` switch)**: leave alone (out of scope).
- **new `publicKeyMLDSA44()` method** on `*DNSKEY`: base64-
  decode `k.PublicKey`, validate length == 1312, return as
  `mldsa44.PublicKey`.

### dnssec_keygen.go

- **`(k *DNSKEY) Generate`**: add `MLDSA44` case. Ignore the
  `bits` argument (ML-DSA-44 has fixed parameters) or require
  `bits == 0`. Call `mldsa44.GenerateKey(rand.Reader)`, set the
  public-key field via a new `setPublicKeyMLDSA44` helper,
  return the private key.
- **new `setPublicKeyMLDSA44(pk mldsa44.PublicKey)`**: marshal
  the 1312-byte key to base64, store in `k.PublicKey`.

### dnssec_privkey.go

- **`(r *DNSKEY) PrivateKeyString`**: add case for
  `mldsa44.PrivateKey`. Serialize as BIND-style private-key
  file:

        Private-key-format: v1.3
        Algorithm: 199 (MLDSA44)
        PrivateKey: <base64 of 2560 bytes>

### dnssec_keyscan.go

- **`(k *DNSKEY) ReadPrivateKey`**: add `MLDSA44` case calling
  a new `readPrivateKeyMLDSA44`.
- **new `readPrivateKeyMLDSA44`**: parse `PrivateKey` field,
  base64-decode, validate length == 2560, return as
  `mldsa44.PrivateKey`.

### sig0.go

- **`SIG.Sign`** (~L13-L72): no direct code change. The flow
  already delegates to `sign()`, which we extended in
  `dnssec.go:L331`. The `hashFromAlgorithm` lookup returns
  `identityHash` because we set
  `AlgorithmToHash[MLDSA44] = 0`.
- **`SIG.Verify`** (~L76-L193) switch: add `MLDSA44` case.
  Extract the public key via `k.publicKeyMLDSA44()`, call
  `mldsa44.Verify(pk, hashed, sig)`, return `nil` on success /
  `ErrSig` on failure.

### sig0_test.go

- **L15**: add `MLDSA44` to the algorithm list.
- **L22-L30**: add `MLDSA44` case for key-size parameter (fixed
  value; content is don't-care since `Generate` ignores bits).

### Imports

All five files above add
`github.com/cloudflare/circl/sign/mldsa/mldsa44`. This is
additive; CIRCL is already pulled in transitively by tdns.

### Compile-time interface check

Add to the same file where `setPublicKeyMLDSA44` lives:

    var _ crypto.Signer = (*mldsa44.PrivateKey)(nil)

If this fails to compile, add a thin wrapper type that takes
`(rand, digest, opts)` and calls the CIRCL API, then store the
wrapper in `ReadPrivateKey`.

## Not required

- **Key tag computation**. RFC 4034 App. B is algorithm-agnostic
  — it checksums the packed RDATA. The 1312-byte public key fits
  the default path in `DNSKEY.KeyTag()` unchanged.
- **KEY presentation format**. The public key is rendered as
  base64 of the raw public-key bytes via the existing
  `DNSKEY.String()` code path. No per-algorithm branch needed.
- **Wire-format size limits**. A 1312-byte KEY RDATA and 2420-
  byte SIG RDATA are both well under the 65535-byte RDLEN cap.
  Existing `len(buf) > int(^uint16(0))` check in `sig0.go:59`
  covers the total-message case.

## tdns integration: what already works

An audit of tdns v2 shows the full SIG(0) pipeline is already
algorithm-agnostic. The integration points we care about are:

- **Key generation + publication**: `v2/sig0_utils.go`
  `GenerateKeyMaterial` (L99-L259) dispatches on algorithm number
  only to pick a key size; the actual keygen call at L168 is
  `nkey.(*dns.KEY).Generate(bits)` — delegated to miekg.
  Publication (`v2/ops_key.go` `PublishKeyRRs`, L17-L47) and
  parent bootstrap/rollover (`BootstrapSig0KeyWithParent` L155-
  L280, `RolloverSig0KeyWithParent` L283-L498) don't branch on
  algorithm.
- **Signing UPDATEs**: `v2/sign.go` `SignMsg` (L46-L89) calls
  `sigrr.Sign(key.CS, &m)` via `crypto.Signer`. No tdns-side
  algorithm dispatch.
- **Receiving + verifying UPDATEs**: `v2/updateresponder.go`
  `UpdateResponder` (L75-L349) → `v2/sig0_validate.go`
  `ValidateUpdate` (L20-L182). KEY lookup has three paths:
  TrustStore (`FindSig0TrustedKey`), DNS (`FindSig0KeyViaDNS`),
  and self-signed upload (L121-L143). Verification at L152 is
  `sig.Verify(&keyrr, msgbuf)` — no algorithm whitelist.
- **CLI for hand-crafted UPDATEs**: `v2/cli/update.go`
  `CreateUpdate` (L112-L380), registered as `child update
  create` and `zone update create` (L85-L99). Takes `--key`
  keyfile, reads via `ReadPrivateKey`, signs via `tdns.SignMsg`.
  Fully functional and algorithm-agnostic.

**Consequence**: once the miekg fork supports algorithm 199,
every tdns code path picks it up automatically. No tdns edits
required for the prototype. This collapses the test plan onto
the fork changes plus live exercise with existing tdns code.

## Test plan

### Unit (in the fork)

1. Extend `sig0_test.go` loop to include `MLDSA44`; confirm
   sign-then-verify round-trip.
2. Negative: flip one byte of the signature, confirm `ErrSig`.
3. Negative: truncate the public key to 1311 bytes, confirm
   `publicKeyMLDSA44` rejects.
4. Private-key file round-trip: `PrivateKeyString` →
   `ReadPrivateKey` → sign/verify.
5. TCP wire: pack a real UPDATE with SIG(0) over TCP; parse on
   the receiver and verify.

### Integration (exercise tdns end-to-end)

The goal here is to drive the same code paths the real system
will use for DS-rollover UPDATEs, not a synthetic harness.

6. **Keygen via tdns.** Run `GenerateKeyMaterial` with algorithm
   199. Confirm we get a valid `mldsa44.PrivateKey`, that
   `PrivateKeyString` produces a BIND-style file, and that
   `ReadPrivateKey` round-trips it.

7. **Manual bootstrap via TrustStore.** Pre-load the ML-DSA-44
   KEY into the receiver's TrustStore (skipping child-key-upload
   and DNS-lookup bootstrap for this first pass). This is the
   simplest path and isolates the algorithm change from the
   bootstrap machinery.

8. **Hand-crafted UPDATE via CLI.** Use `child update create
   --key <mldsa44.key>` to build and send a SIG(0)-signed UPDATE
   adding a DS RR. Assert:
   - Client-side: the UPDATE packs with a 2420-byte SIG(0), goes
     out over TCP (enforce TCP in the sender for alg 199).
   - Receiver-side (`ValidateUpdate`): TrustStore hit, `sig.
     Verify` succeeds, `TrustUpdate` returns the expected
     trust status.

9. **Negative receiver.** Send the same UPDATE with one
   signature byte flipped. Confirm `ValidateUpdate` returns a
   verification failure and the UPDATE is rejected.

10. **`ops_key.go` publish path.** Drive `PublishKeyRRs` for an
    ML-DSA-44 KEY. Confirm the KEY RR carries `Algorithm=199`
    and the 1312-byte base64-encoded public key, and that it
    round-trips through zone-file text.

11. **Self-signed bootstrap (optional second pass).** Once (7-
    10) work, retry with the KEY delivered via self-signed
    upload (`ValidateUpdate` L121-L143) instead of pre-loaded
    TrustStore, to confirm that bootstrap path still works with
    a private-use algorithm.

12. **Parent DS-rollover scenario (end-to-end).** The real
    target: child signs a DDNS UPDATE of the parent's DS RRset
    with its ML-DSA-44 SIG(0) key, parent receives via DSYNC-
    discovered endpoint over TCP, verifies, applies. This
    exercises the full draft-ietf-dnsop-delegation-mgmt-via-ddns
    flow with PQC-safe outer authentication.

## Deployment path

1. Fork miekg/dns into tdns-project.
2. Land the changes above on a branch in the fork.
3. Point tdns and tdns-mp `go.mod` replace directives at the
   fork.
4. Generate a test ML-DSA-44 key pair, wire it into tdns's
   SIG(0) signing path, send a signed UPDATE, verify on the
   receiver.
5. Update draft-ietf-dnsop-delegation-mgmt-via-ddns prose to
   note TCP-mandatory for ML-DSA-44 SIG(0).

## Open items

All items from the original plan are resolved (see the
Implementation Summary above).  For completeness:

- CIRCL `mldsa44.PrivateKey` satisfies `crypto.Signer` with
  `HashFunc() == 0` semantics. **Confirmed** via compile-time
  assertion.
- CIRCL returns a raw 2420-byte signature, not DER. **Confirmed**
  by the first sign/verify test — no marshal/unmarshal shim
  required.
- Linear project for tracking. **Still pending** — deferred until
  the `draft-johani-dnsop-dnssec-rapid-rollover` Internet-Draft
  solidifies and the broader body of work has a shape worth
  tracking as one project.
