# Proposal: pluggable signature algorithms in miekg/dns

**Audience:** miekg/dns maintainers (issue / discussion draft)
**Author:** Johan Stenstam (johani@johani.org)
**Date:** 2026-05-13

## Motivation

Three drivers are converging that make today's "all algorithms are
hardcoded switches" model painful:

1. **Post-quantum.** NIST FIPS 204 (ML-DSA) is the first PQ signature
   standard with a credible deployment path for DNSSEC SIG(0) / RRSIG.
   No IANA codepoint yet, but operators want to experiment now.
2. **Pre-IANA experimentation in general.** The DNSSEC Algorithm
   Numbers registry has no general-purpose private-use range —
   `PRIVATEDNS` (253) and `PRIVATEOID` (254) are single algorithms
   whose real identifier lives in the key rdata, not a range one can
   freely allocate within. Experimenting with a new algorithm today
   means squatting on an Unassigned codepoint (with the collision
   risk fully on the experimenter), or waiting on IANA. Either way
   it currently requires forking the library to wire the chosen
   number through the switches.
3. **Third-party crypto stacks.** Modern PQ algorithms ship in
   research-grade Go libraries (e.g. cloudflare/circl); pulling those
   into miekg/dns directly is unattractive (dependency bloat, churn,
   FIPS / supply-chain questions). The natural fit is to keep them
   out-of-tree and let downstreams wire them in.

Today every new algorithm requires touching 6+ files inside
miekg/dns. Downstreams either fork (sacrificing upstream updates) or
do nothing. A small, additive registration API would let downstreams
implement private-use algorithms without forking, and keep miekg/dns
itself lean (IANA-assigned algorithms only).

## Current per-algorithm hook surface

To make this concrete, here is everything one currently has to touch
to add a new algorithm. This was measured against a working ML-DSA-44
SIG(0) implementation in our fork (~199 lines across 6 production
files).

| File | What | Purpose |
|---|---|---|
| `dnssec.go` | algorithm constant (`uint8`) | the number itself |
| `dnssec.go` | `AlgorithmToString` map entry | display name |
| `dnssec.go` | `AlgorithmToHash` map entry | which `crypto.Hash` (or 0 for identity-hash) |
| `dnssec.go` | `sign()` switch arm | post-`crypto.Signer.Sign` shaping (pass-through? ASN.1 DER like ECDSA?) |
| `dnssec.go` | `(*RRSIG).Verify` switch arm | the actual `Verify` call for RRSIG |
| `dnssec.go` | `(*DNSKEY).publicKeyXxx()` | DNSKEY rdata wire bytes → `crypto.PublicKey` |
| `dnssec_keygen.go` | `(*DNSKEY).Generate` switch | generate a fresh keypair |
| `dnssec_keygen.go` | `(*DNSKEY).setPublicKeyXxx()` | `crypto.PublicKey` → DNSKEY rdata wire bytes |
| `dnssec_keyscan.go` | `(*DNSKEY).ReadPrivateKey` switch + `readPrivateKeyXxx` helper | parse BIND-style private key file |
| `dnssec_privkey.go` | `(*DNSKEY).PrivateKeyString` switch | serialize private key back to BIND-style file |
| `sig0.go` | `(*SIG).Verify` switch arm | SIG(0) verify dispatch |

The signing side is already pluggable for free via the `crypto.Signer`
interface — any third-party private key type that satisfies it (CIRCL's
`*mldsa44.PrivateKey` does, for example) drops into `sign()` unchanged.
The verify side and the key-management side are the parts that need
attention.

## Proposed API

A single registration entry point in a new file (`algorithm.go`),
plus a thin interface backed by the existing per-algorithm switches.
Built-in algorithms (RSA, ECDSA, Ed25519) stay where they are; the
new registry is only consulted when the switches don't match.

```go
// Algorithm is the user-supplied implementation of a DNSSEC signature
// algorithm. Registered via RegisterAlgorithm. Built-in IANA-assigned
// algorithms (RSA, ECDSA, Ed25519) are not registered through this
// API — they live in the existing switches.
type Algorithm interface {
    // Name is the string used in BIND-style private key files
    // ("Algorithm: <num> (<name>)") and in AlgorithmToString output.
    Name() string

    // Hash returns the crypto.Hash applied to the signed bytes
    // before passing them to Sign/Verify. Return 0 for identity-hash
    // algorithms (Ed25519, ML-DSA) where the full wire bytes reach
    // the signer unchanged.
    Hash() crypto.Hash

    // Generate returns a fresh keypair. bits is the caller's
    // size hint; algorithms with fixed parameters should require
    // bits == 0 and return ErrKeySize otherwise.
    Generate(bits int) (crypto.PrivateKey, error)

    // PublicKeyFromWire decodes a DNSKEY rdata public key field
    // into a crypto.PublicKey. The input is the raw key bytes
    // (already base64-decoded from DNSKEY.PublicKey).
    PublicKeyFromWire(keybuf []byte) (crypto.PublicKey, error)

    // PublicKeyToWire is the inverse: encode a crypto.PublicKey
    // into the DNSKEY rdata public-key bytes (pre-base64).
    PublicKeyToWire(pub crypto.PublicKey) ([]byte, error)

    // ReadPrivateKey parses a BIND-style private key file's key
    // material lines (already parsed into a map[name]value) into
    // a crypto.PrivateKey.
    ReadPrivateKey(fields map[string]string) (crypto.PrivateKey, error)

    // PrivateKeyToString serializes the private key into the
    // BIND-style "Key: <base64>" lines (no header — the caller
    // adds "Private-key-format" and "Algorithm:").
    PrivateKeyToString(priv crypto.PrivateKey) (string, error)

    // Verify checks a signature. hashed is Hash()-processed bytes
    // (or raw bytes for identity-hash algorithms).
    Verify(pub crypto.PublicKey, hashed, sig []byte) error

    // SignaturePostProcess shapes the output of crypto.Signer.Sign
    // before it lands in the wire RR. For most algorithms this is
    // a pass-through; ECDSA strips ASN.1 DER, etc. Default: return
    // sig unchanged.
    SignaturePostProcess(sig []byte) ([]byte, error)
}

// RegisterAlgorithm wires an Algorithm into the dispatch tables.
// num must not be one that already has a built-in implementation
// (RSA*, ECDSA*, ED25519, ED448) — those are rejected so the
// registry can't shadow built-ins. All other numbers are accepted,
// including PRIVATEDNS (253), PRIVATEOID (254), and any IANA-
// Unassigned codepoint; the caller bears the collision risk for
// Unassigned numbers. Re-registering a number is an error (panic
// at init time, consistent with how Go's encoding registries work).
func RegisterAlgorithm(num uint8, impl Algorithm) error
```

## Dispatch path

Each existing switch grows a default arm that consults the registry:

```go
switch alg {
case RSASHA1, ...:
    // unchanged
case ECDSAP256SHA256, ...:
    // unchanged
case ED25519:
    // unchanged
default:
    if impl, ok := lookupAlgorithm(alg); ok {
        return impl.Verify(pub, hashed, sig)
    }
    return ErrAlg
}
```

Net code increase in miekg/dns: ~10–20 lines per switch (8 switches),
plus the new `algorithm.go` file (~120 lines including the interface
+ registry + tests for the registry itself). Maybe 300 lines total.

## Example: ML-DSA-44 as an out-of-tree implementation

A downstream package using CIRCL would look like:

```go
package mldsa44dns

import (
    "github.com/miekg/dns"
    "github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

const Algorithm uint8 = 199

func init() {
    if err := dns.RegisterAlgorithm(Algorithm, &impl{}); err != nil {
        panic(err)
    }
}

type impl struct{}

func (impl) Name() string                { return "MLDSA44" }
func (impl) Hash() crypto.Hash           { return 0 } // identity
func (impl) Generate(bits int) (crypto.PrivateKey, error) { /* ... */ }
func (impl) PublicKeyFromWire(buf []byte) (crypto.PublicKey, error) { /* ... */ }
// ... etc
```

The user imports the package once for its side-effects:

```go
import _ "github.com/example/mldsa44dns"
```

and miekg/dns now handles algorithm 199 in every codepath.

## What stays out

- **Built-in algorithms** are not migrated to the registry. The
  proposal is purely additive — RSA / ECDSA / Ed25519 keep their
  existing switch arms. Migrating them would be a large diff with
  no operational benefit and would risk subtle behavioral drift.
- **DS digest algorithms** (SHA-1, SHA-256, SHA-384 for DS RR
  generation) are a separate enum and out of scope. They could
  follow the same pattern later if needed.
- **NSEC3 hash algorithms** likewise out of scope.

## Backward compatibility

Fully additive. No existing API changes. Programs that don't
register anything see no behavioral difference.

## Open questions for upstream

1. **Number-range policing**: there is no general-purpose private-use
   range in the DNSSEC Algorithm registry, so "strict by range" is
   not really an option. The natural rule is "reject numbers with
   built-in implementations; accept everything else, including
   Unassigned codepoints and `PRIVATEDNS`/`PRIVATEOID`". Worth
   confirming that matches maintainer preference, and whether the
   registry should warn (vs silently accept) for clearly-Unassigned
   numbers to nudge experimenters toward 253/254 where appropriate.
2. **Error vs panic**: panic at init is the Go convention for
   registry conflicts (cf. `image.RegisterFormat`), but some shops
   prefer `error`. Either works.
3. **Thread safety**: should `lookupAlgorithm` use `sync.RWMutex`,
   or is "register at init, read forever" enough? `image` does the
   latter.
4. **Hash() return for identity**: `crypto.Hash(0)` is the obvious
   sentinel and what built-ins already use internally. Worth
   documenting.
5. **`SignaturePostProcess` default**: my draft makes it required.
   Could be optional with a sensible default if `Algorithm` becomes
   a struct of optional functions instead of an interface.

## What I'd be willing to implement

I have a working ML-DSA-44 implementation against the current
hardcoded scheme. If there's appetite for this proposal, I'd:

1. Implement the registry + interface in a PR with no algorithm
   conversions (pure infrastructure).
2. Migrate my ML-DSA-44 work into an out-of-tree package against
   that PR, as a worked example.
3. Provide a test suite that exercises a synthetic test-only
   algorithm through every code path (parse, generate, sign,
   verify, RRSIG, SIG(0)).

The PR itself would be small (~300 lines, mostly comments and
tests).
