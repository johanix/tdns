# TDNS Guide: Post-Quantum DNSSEC

TDNS supports post-quantum (PQ) signature algorithms for both DNSSEC
(RRSIG over RRsets) and SIG(0) (transaction signatures on DNS UPDATE).
The same algorithm and key can be used in either role: a SIG(0) ML-DSA-44
key signing a delegation UPDATE goes through exactly the same code path
as an ML-DSA-44 ZSK signing an RRset.

This guide is for two audiences: **builders**, who compile tdns binaries
with the algorithms they need, and **operators**, who deploy PQ policies
and drive PQ key/algorithm rollovers. It is standalone; it supersedes the
"Post-Quantum Algorithm Support" section that previously lived in
[special-features.md](special-features.md).

> **Experimental codepoints.** The DNSKEY algorithm numbers used here
> (199–214) are in the IANA-Unassigned range and are coordinated only
> inside this project. They **will** change when the IETF assigns real
> codepoints. Treat them, and PQ DNSSEC generally, as experimental.

## Contents

1. [Architecture: the three layers](#1-architecture-the-three-layers)
2. [The `dnssec-algorithms` module and why it is separate](#2-the-dnssec-algorithms-module-and-why-it-is-separate)
3. [Supported algorithms](#3-supported-algorithms)
4. [KSK vs ZSK suitability](#4-ksk-vs-zsk-suitability)
5. [Building tdns with PQ algorithms](#5-building-tdns-with-pq-algorithms)
6. [Registering algorithms: the generated model](#6-registering-algorithms-the-generated-model)
7. [The `dns.Algorithm` interface](#7-the-dnsalgorithm-interface)
8. [Worked example: PQ policies and a ZSK-algorithm rollover](#8-worked-example-pq-policies-and-a-zsk-algorithm-rollover)
9. [Validating PQ-signed zone data](#9-validating-pq-signed-zone-data)
10. [Inspecting a chain with `dog +sigchase +algchase`](#10-inspecting-a-chain-with-dog-sigchase-algchase)

---

## 1. Architecture: the three layers

PQ support in tdns rests on three layers, each with a distinct job and a
distinct place in the source tree:

1. **A forked `miekg/dns`** (`github.com/johanix/dns`) that turns the
   library's otherwise-hardcoded algorithm dispatch into a **pluggable
   registry**. Upstream miekg/dns has roughly six hardcoded
   `switch alg {}` sites — in `dnssec.go` (sign, verify), `sig0.go`, the
   key-file parser, and `Generate`. The fork gives each an extra arm that
   consults a process-wide registry, so an algorithm that is *not* built
   into the library can still be signed, verified, generated, parsed, and
   serialized by anyone holding a `dns.Algorithm` implementation
   ([§7](#7-the-dnsalgorithm-interface)). The classical built-ins
   (RSASHA\*, ECDSAP\*, ED25519, ED448) keep their existing switches and
   cannot be re-registered. Every module that wants PQ support carries a
   `replace github.com/miekg/dns => github.com/johanix/dns <version>`
   directive. Design and rationale:
   [`docs/2026-05-13-miekg-dns-pluggable-algorithms-proposal.md`](../docs/2026-05-13-miekg-dns-pluggable-algorithms-proposal.md).

2. **The `dnssec-algorithms` module** — a separate repository of unified
   Go wrappers, one subpackage per algorithm, each presenting the single
   `dns.Algorithm` interface over a heterogeneous third-party
   implementation (pure-Go CIRCL; the liboqs C library; the SQIsign and
   QR-UOV reference C libraries). It also holds the authoritative
   algorithm **registry** (codepoint ↔ name ↔ role ↔ package). Why it
   lives outside tdns is [§2](#2-the-dnssec-algorithms-module-and-why-it-is-separate).

3. **Generated compile-time registration** in each tdns app. An app
   declares the algorithms it wants in an `algs.list` file; the `genalgs`
   generator turns that, plus the registry, into the Go files that
   register those algorithms at process start. An app gets exactly the
   algorithms it selected — no runtime configuration, no dynamic loading,
   no "enable everything" fallback ([§6](#6-registering-algorithms-the-generated-model)).

The layering matters: layer 1 is a generic DNS-library capability
(reusable by any miekg/dns consumer), layer 2 is a reusable algorithm
collection (not tdns-specific), and only layer 3 is tdns application
logic. A signature produced anywhere in the stack validates everywhere,
because sign and verify dispatch through the same registry.

---

## 2. The `dnssec-algorithms` module and why it is separate

`dnssec-algorithms` is a standalone Go module
([github.com/johanix/dnssec-algorithms](https://github.com/johanix/dnssec-algorithms)),
**not** a package inside the tdns tree. It is a repository of **unified Go
wrappers**: each subpackage (`mldsa44`, `slhdsa128s`, `falcon512`, …)
implements the single `dns.Algorithm` interface ([§7](#7-the-dnsalgorithm-interface))
over one underlying implementation, hiding whether that implementation is
pure-Go CIRCL, a call into liboqs, or a call into the SQIsign or QR-UOV
reference C library. A caller that holds a `dns.Algorithm` never has to
know which backend is underneath.

It lives outside tdns for four reasons:

- **(a) Reusable beyond tdns.** The wrappers present a standard
  `dns.Algorithm` interface and are useful to any consumer of the forked
  miekg/dns, not just tdns. Keeping them in a separate module lets other
  projects depend on them without pulling in the tdns application tree.
- **(b) Isolation of the C-library / cgo surface.** The liboqs, SQIsign,
  and QR-UOV backends require native C libraries and cgo. Confining that
  messy per-algorithm build surface to a dedicated module keeps the
  default tdns build graph free of cgo except where an app deliberately
  links a C-backed algorithm.
- **(c) Home of the algorithm registry.** Codepoints and the
  codepoint↔name↔role table are *algorithm-collection* facts, not tdns
  application logic. They belong with the algorithms they describe, in
  `dnssec-algorithms/registry/registry.go` — the single source of truth
  the generator reads ([§6](#6-registering-algorithms-the-generated-model)).
- **(d) Pinned, but must be a local checkout.** The Go module is version-
  pinned in each app's `go.mod` like any dependency. But the **C-library
  discovery scripts** (`liboqs/liboqs-env.sh`, `sqisignc/sqisign-env.sh`,
  `qruovc/qruov-env.sh`) are run from a local working copy at build time
  to locate the installed native libraries. So even though the *module*
  is pinned, a developer building C-backed algorithms needs a local
  `dnssec-algorithms` checkout on disk — the "pinned but must be local"
  point. See [§5](#5-building-tdns-with-pq-algorithms).

A tdns build that selects no PQ algorithms (an app with no `algs.list`,
[§6](#6-registering-algorithms-the-generated-model)) needs neither the
module beyond the normal pin nor a local checkout — it builds standalone
with the classical built-in algorithms only.

---

## 3. Supported algorithms

The algorithms implemented under
[dnssec-algorithms](https://github.com/johanix/dnssec-algorithms), as
recorded in the authoritative registry
(`dnssec-algorithms/registry/registry.go`):

| DNSKEY # | Name | Backend | Roles | Family / status |
|---------:|------|---------|-------|-----------------|
| 199 | ML-DSA-44 (FIPS 204) | CIRCL (pure Go) | KSK | Lattice; FIPS 204 final |
| 200 | ML-DSA-65 (FIPS 204) | CIRCL (pure Go) | KSK | Lattice; FIPS 204 final |
| 201 | ML-DSA-87 (FIPS 204) | CIRCL (pure Go) | KSK | Lattice; FIPS 204 final |
| 202 | SLH-DSA-128s (FIPS 205) | CIRCL (pure Go) | KSK | Hash-based; FIPS 205 final |
| 203 | Falcon-512 | liboqs (cgo) | KSK + ZSK | Lattice; NIST-selected (FN-DSA draft) |
| 204 | Falcon-1024 | liboqs (cgo) | KSK | Lattice; NIST-selected (FN-DSA draft) |
| 205 | MAYO-1 | liboqs (cgo) | KSK + ZSK | Multivariate (UOV); NIST onramp |
| 206 | MAYO-2 | liboqs (cgo) | KSK + ZSK | Multivariate (UOV); NIST onramp |
| 207 | MAYO-3 | liboqs (cgo) | KSK + ZSK | Multivariate (UOV); NIST onramp |
| 208 | MAYO-5 | liboqs (cgo) | KSK | Multivariate (UOV); NIST onramp |
| 209 | SNOVA-24_5_4 | liboqs (cgo) | KSK + ZSK | Multivariate (UOV); NIST onramp |
| 210 | SNOVA-37_17_2 | liboqs (cgo) | KSK + ZSK | Multivariate (UOV); NIST onramp |
| 211 | SNOVA-25_8_3 | liboqs (cgo) | KSK + ZSK | Multivariate (UOV); NIST onramp |
| 212 | SQIsign-I | SQIsign C lib (cgo) | KSK + ZSK | Isogeny; NIST onramp (watched — SIDH-class risk) |
| 213 | QR-UOV (q=31, L=3) | QR-UOV C lib (cgo) | KSK + ZSK | Multivariate (UOV); NIST onramp |
| 214 | CROSS RSDP-G-128-small | liboqs (cgo) | KSK | Code-based (RSDP-G); NIST onramp |

**Codepoints (199–214) are experimental and project-internal** — they are
in the IANA-Unassigned range and will change when the IETF assigns real
numbers. The registry
(`dnssec-algorithms/registry/registry.go`) is the source of truth for this
table; if it and this document disagree, the registry wins (and this table
should be updated). Family and size details are from
[`pqc-algorithm-families.md`](https://github.com/johanix/dnssec-algorithms/blob/main/docs/pqc-algorithm-families.md).

**Backend build requirements.** CIRCL-backed algorithms (the ML-DSA
family, SLH-DSA) build with the standard Go toolchain, no cgo. The
liboqs-, SQIsign-, and QR-UOV-backed algorithms require the respective
native C library and cgo at build time ([§5](#5-building-tdns-with-pq-algorithms)).

**Roles** (KSK vs KSK + ZSK) come from the registry's per-algorithm
capabilities and reflect signature-size suitability, not cryptographic
strength — see [§4](#4-ksk-vs-zsk-suitability).

**Sizes, level, and maturity** are recorded per algorithm in the registry
(`AlgorithmFacts` in `dnssec-algorithms/registry/registry.go`) alongside
the codepoint/role decisions, and flow through the generated metadata to
the server, which reports them to `tdns-cli`. So
`tdns-cli ... keystore <sig0|dnssec> algorithms` shows each algorithm's
key/signature sizes, NIST level, maturity, and description with no local
configuration. **Signing/validation cost** is the one exception: it is
machine-dependent, measured per CPU architecture by
`dnssec-algorithms/cmd/algbench` into `algorithm-costs.yaml`, and shown
only when the CLI is pointed at that file (`algorithms.costsfile`).

---

## 4. KSK vs ZSK suitability

<!-- PLACEHOLDER — to be written. -->

The role column in [§3](#3-supported-algorithms) is a signature-**size**
judgment, not a strength judgment. A KSK signs only the apex DNSKEY RRset
(fetched rarely, cached), so a large signature is tolerable; a ZSK signs
every RRset in the zone, so its signature appears in every response and
must fit the per-response RRSIG budget against the ~64 KB DNSKEY-RRset
ceiling and common UDP limits. Algorithms marked KSK-only have signatures
too large to place on every RRset.

This is the "algorithm-split" model (a large-signature KSK algorithm plus
a small-signature ZSK algorithm). The full cryptographic-family analysis —
lattice vs. code-based vs. multivariate, and the size/strength tradeoffs —
lives in
[`dnssec-algorithms/docs/pqc-algorithm-families.md`](https://github.com/johanix/dnssec-algorithms/blob/main/docs/pqc-algorithm-families.md);
this section will summarize the operator-facing sizing constraints and
link there for the rest.

> _TODO: sizing table (per-response RRSIG budget, DNSKEY-RRset ceiling),
> summary of the family analysis, cross-links to the alg-split rationale
> in [draft-johani-dnsop-dnssec-alg-split] and key-rollover.md §15._

---

## 5. Building tdns with PQ algorithms

<!-- PLACEHOLDER — to be written (item 5). -->

This section will cover per-platform native-library install and the tdns
build flow:

- **NetBSD** (pkgsrc), **Debian/Linux** (apt + build-from-source; liboqs
  static), **macOS** (MacPorts — currently unverified).
- Sourcing the `-env.sh` discovery scripts **from bash**, pkg-config, and
  the NetBSD `LD_LIBRARY_PATH=/usr/pkg/lib` quirk.
- The current build flow (`algs.list` + `make`, which auto-runs the
  generator — see [§6](#6-registering-algorithms-the-generated-model)),
  which **replaces** the older `make WITH_LIBOQS=1 …` flag model.

`dnssec-algorithms/BUILDING.md` is authoritative for native-library
install; this section references it rather than duplicating it.

> _TODO: write against the current (post-generator) build flow. Do NOT
> describe `make WITH_*` — that mechanism was removed in the generator
> cutover. Confirm/flag macOS._

---

## 6. Registering algorithms: the generated model

An app links exactly the algorithms it selects — there is no runtime
configuration, no dynamic loading, and no "enable everything" fallback.
Selection is a per-app plain-text file, **`algs.list`**, one algorithm
**name** per line (matching the registry's `Name` column,
[§3](#3-supported-algorithms)); comments (`#`) and blank lines are ignored:

```
# cmdv2/auth/algs.list
MLDSA44
SLHDSA128S
FALCON512
CROSSRSDPG128SMALL
```

The `genalgs` generator (`cmdv2/genalgs`) reads two inputs — the
authoritative registry in a local `dnssec-algorithms` checkout, and this
`algs.list` — and emits three files into the app directory:

- **`metadata_algs.go`** — `RegisterMetadata(...)` for **every** registry
  algorithm (name, codepoint, role). Pure data, compiled into every app,
  so a binary can name any algorithm it encounters even if it cannot
  verify with it (this is what lets `dog +algchase` name PQ codepoints,
  [§10](#10-inspecting-a-chain-with-dog-sigchase-algchase)).
- **`registered_algs.go`** — `Register(...)` for each **selected**
  algorithm, wiring its real implementation into the dispatch tables. No
  build tags: the generator verified each C library was installed before
  emitting these calls.
- **`algs-env.mk`** — a Makefile fragment recording the C-library build
  environment (`PKG_CONFIG_PATH`) and the `dnssec-algorithms` checkout
  location (`ALGREPO`).

These three are **build artifacts** — gitignored, regenerated per build
host so the linked algorithm set always matches that host's installed
libraries. The committed input is `algs.list`.

**Adding a new algorithm** to an app is therefore one line in that app's
`algs.list` (plus, if the algorithm is new to the project, one row in the
registry). No codepoints are edited by hand, no cross-app synchronization
is needed, and there is no separate CLI name list to keep in step.

**Running the generator.** `make` runs `genalgs` automatically when
`registered_algs.go` is missing or older than `algs.list`, using the
`ALGREPO` recorded in `algs-env.mk` from a previous run. The **first**
time (no `algs-env.mk` yet), run it once by hand to record the path:

```
cd cmdv2/auth
../genalgs/tdns-genalgs --algrepo <path-to-dnssec-algorithms> --list algs.list --out .
make
```

Thereafter a plain `make` regenerates as needed. Three cases determine
whether the generator runs at all:

| `algs.list` | genalgs runs? | Needs dnssec-algorithms? |
|-------------|---------------|--------------------------|
| **absent** | no | **no** — builds standalone, classical algorithms only |
| present but empty (comments/blanks) | yes, metadata-only | yes (registry) |
| present with entries | yes, full | yes |

So a tdns binary that does not care about PQ simply has no `algs.list` and
builds with no dependency on `dnssec-algorithms` at all. Metadata-only
apps (e.g. query/validation tools that must *name* algorithms but not sign
with them) use an empty `algs.list`. Use `-v` on `genalgs` to trace every
step it takes (path resolution, registry parse, each `-env.sh` run, files
written).

> This replaces the previous **blank-import** model (`import _
> ".../mldsa44"` in each app's `main`, plus a hand-maintained per-app
> `RegisterMetadata` block and build-tag-gated `pq_algorithms_*.go`
> files). If you find that pattern in older docs or branches, it is
> obsolete.

---

## 7. The `dns.Algorithm` interface

Each algorithm subpackage in `dnssec-algorithms` implements the
`dns.Algorithm` interface from the forked miekg/dns
(`github.com/johanix/dns`, `algorithm.go`). The application binds an
implementation to a codepoint via `RegisterAlgorithm` (tdns wraps this in
its own `algorithms.Register`; see [§6](#6-registering-algorithms-the-generated-model)).

```go
// github.com/johanix/dns  (forked miekg/dns), algorithm.go
type Algorithm interface {
    // Name is the short upper-case name used in private-key files
    // ("Algorithm: <num> (<name>)") and in AlgorithmToString output.
    Name() string

    // Hash returns the crypto.Hash applied to the signed bytes before
    // signing/verifying. Return 0 for identity-hash algorithms
    // (ED25519, ML-DSA, ...) where the full wire bytes reach the signer.
    Hash() crypto.Hash

    // Generate returns a fresh keypair. bits is a size hint; algorithms
    // with fixed parameters require bits == 0 and return ErrKeySize
    // otherwise. The private key must satisfy crypto.Signer.
    Generate(bits int) (crypto.PrivateKey, error)

    // PublicKeyFromWire decodes DNSKEY/KEY rdata public-key bytes.
    PublicKeyFromWire(keybuf []byte) (crypto.PublicKey, error)

    // PublicKeyToWire is the inverse (pre-base64 rdata bytes).
    PublicKeyToWire(pub crypto.PublicKey) ([]byte, error)

    // ReadPrivateKey parses a BIND-style private-key file's key-material
    // lines (lexed into map[name]value, names lower-cased).
    ReadPrivateKey(fields map[string]string) (crypto.PrivateKey, error)

    // PrivateKeyToString serializes the private key into the BIND-style
    // "Field: <base64>" body lines. Returns an error on failure.
    PrivateKeyToString(priv crypto.PrivateKey) (string, error)

    // Verify checks a signature. hashed is the Hash-processed bytes (or
    // raw bytes for identity-hash algorithms); sig is the on-wire
    // signature. Returns nil, ErrSig on mismatch, or another error.
    Verify(pub crypto.PublicKey, hashed, sig []byte) error

    // SignaturePostProcess shapes crypto.Signer.Sign output before it is
    // written to the wire. Built-in ECDSA strips ASN.1 DER; RSA and
    // ED25519 are pass-through. Most implementations return sig unchanged.
    SignaturePostProcess(sig []byte) ([]byte, error)
}
```

Two points that older documentation got wrong:

- `PrivateKeyToString` returns **`(string, error)`**, not `string`.
- The interface includes **`SignaturePostProcess`**; it is not optional.
  It lets an algorithm reshape the raw `crypto.Signer` output into the
  exact on-wire form (the built-in ECDSA case strips ASN.1 DER; most PQ
  algorithms return the signature unchanged).

Signing goes through Go's standard `crypto.Signer` — each PQ private-key
type implements it, so tdns's `SignMsg`/`SignRRset` need no per-algorithm
special-casing. Registration also populates the library's
`AlgorithmToString`, `AlgorithmToHash`, and `StringToAlgorithm` maps, so
callers that read those directly observe the new algorithm by name and
number.

---

## 8. Worked example: PQ policies and a ZSK-algorithm rollover

DNSSEC signing in tdns-auth is driven by a **dnssec policy**, which names
(among other things) the KSK algorithm and the ZSK algorithm. Policies can
inherit from reusable **templates** (`dnssec.templates:`), so two related
policies stay compact by sharing everything except the algorithm choice.
This section walks a classical baseline and a PQ / algorithm-split target,
then the CLI rollover between them.

The **algorithm-split** target pairs a large-signature KSK algorithm with
a small-signature ZSK algorithm, confining the large signatures to the
apex DNSKEY RRset while ordinary responses stay small (see
[§4](#4-ksk-vs-zsk-suitability) and the alg-split I-D). This is exactly
the deployment the "relaxed" completeness mode exists for.

> _TODO (worked, runnable — not just links):_
> - _Two complete policies via templates: (P1) a classical baseline (e.g.
>   ECDSAP256 KSK+ZSK) and (P2) a PQ alg-split target (large-KSK, e.g.
>   SLHDSA128S, + small-signature ZSK, e.g. FALCON512). Show the
>   `dnssec.templates:` + `dnssecpolicy:` YAML._
> - _The CLI ZSK-algorithm rollover P1→P2, mirroring the autumn-2026 lab._

For now, the rollover mechanics are documented in the key-rollover guide;
this section will reproduce them as a self-contained worked example. The
essentials:

**ZSK-algorithm rollover is implemented** (relaxed mode). It reuses the
normal ZSK pipeline: you bind the zone to a policy carrying the new ZSK
algorithm, and newly-generated ZSKs use it while the old-algorithm keys
drain out in FIFO order — nothing is swapped synchronously. It requires
`dnssec: completeness: relaxed` (the alg-split model, which drops
maintained whole-zone double-signing); under the default `strict` it is
refused. The two-command workflow:

```
# 1. bind the new ZSK algorithm (changes only FUTURE keys)
auto-rollover policy-change --zone Z --policy newalg-policy

# 2. drive the drain (each 'asap' promotes the next standby)
auto-rollover asap --zone Z --zsk
```

See [key-rollover.md §14 (ZSK rollover)](key-rollover.md) and
[§15 (Algorithm rollover)](key-rollover.md) for the full mechanics, the
`completeness` knob, and worked timing.

**KSK-algorithm rollover is an upcoming feature.** It needs the parent-DS
engine and is currently **refused with a clear error** rather than run
unsafely — as are a CSK-algorithm change, a both-roles-at-once change, and
a ZSK-algorithm change under `strict` completeness.

---

## 9. Validating PQ-signed zone data

<!-- PLACEHOLDER — to be written (item 9). -->

In principle validation "just works": a validator (tdns-imr) dispatches
through the same algorithm registry as the signer, so any algorithm it has
linked, it can validate. This is not asserted here — it must be **tested**,
per algorithm, and this section will record the measured status.

> _TODO: an evidence-backed sign-with-X → validate-with-imr test matrix,
> one row per algorithm, recording actual pass/fail (validation status)
> rather than an assertion. Build the matrix, then fill the table._

| Algorithm | Sign (tdns-auth) | Validate (tdns-imr) | Status |
|-----------|------------------|---------------------|--------|
| _…_ | _…_ | _…_ | _pending_ |

---

## 10. Inspecting a chain with `dog +sigchase +algchase`

<!-- PLACEHOLDER — to be written (item 10). -->

`dog +sigchase` walks and verifies the DNSSEC chain for a name/type,
emitting a per-link verdict. Adding `+algchase` annotates each algorithm
number in the chain with its name (e.g. `alg=203 (FALCON512)`), which is
possible because every dog binary carries the full metadata table
([§6](#6-registering-algorithms-the-generated-model)) even though dog is a
validator/diagnostic tool. `+algchase` implies `+sigchase`.

> _TODO: a worked `dog +sigchase +algchase` invocation against a PQ-signed
> zone, annotated output, and how codepoint + name + role are reported per
> link. See [app-dog.md](app-dog.md)._
