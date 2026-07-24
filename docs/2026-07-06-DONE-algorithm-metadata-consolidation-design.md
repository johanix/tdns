# Algorithm Metadata Consolidation: retire algorithms.yaml's static data

**Date:** 2026-07-06
**Status:** DESIGN — not yet implemented.
**Scope:** dnssec-algorithms (`registry/`, `cmd/algbench`) + tdns
(`v2/algorithms`, `v2/cli`, `v2/apihandler_funcs.go`, `cmdv2/genalgs`)

## Problem

After the algorithm-registry generator cutover
([2026-07-05-algorithm-registry-generator-design.md](2026-07-05-algorithm-registry-generator-design.md)),
every tdns binary (including tdns-cli) carries generated metadata for
**all** registry algorithms: codepoint, name, and role
(ForSIG0/ForDNSSEC/ForKSK/ForZSK). The `keystore ... algorithms` listing,
however, still enriches the server-reported set from a separate
hand-maintained `algorithms.yaml`
(`v2/cli/algorithm_profiles.go`), keyed by algorithm name, carrying:

- `publickeybytes`, `signaturebytes`, `secretkeybytes`
- `securitylevel` (NIST PQ level)
- `maturity` (final/draft/candidate/builtin)
- `description`
- `signingcost`, `validationcost` (relative to ED25519 = 1)

This means algorithm facts are now maintained in **two** places — the
registry (`dnssec-algorithms/registry/registry.go`) and the yaml — and
adding an algorithm means editing both. The yaml never fed
name↔codepoint↔role (that is server-authoritative and now also in
compiled-in metadata); it is purely descriptive enrichment for the
listing.

## Key insight 1: the yaml holds two kinds of data

The fields split by nature, and the split decides where each belongs:

| Field | Nature | Home |
|---|---|---|
| publickeybytes, signaturebytes, secretkeybytes | **static** — fixed by the algorithm spec, identical on every machine | **dnssec-algorithms repo** |
| securitylevel | static (NIST level) | **dnssec-algorithms repo** |
| maturity | static, changes rarely (standardization status) | **dnssec-algorithms repo** |
| description | static | **dnssec-algorithms repo** |
| signingcost, validationcost | **machine-dependent** — the yaml itself warns these shift across architectures (AVX2 x86 vs NEON arm64, RSA bignum, ...) | **measured, per-arch** (stays in a yaml) |

Baking a signature size (e.g. ML-DSA-44 = 2420 bytes) into
dnssec-algorithms is correct: it is universal. Baking a *cost* multiplier
in would be a lie: it is only true for the machine it was measured on. So
the static data moves into dnssec-algorithms (single source of truth), and
the cost data stays as measured enrichment — but reshaped to hold
**multiple architectures** in one file.

## Key insight 2: decisions vs. facts — a SEPARATE structure, not a wider row

The existing registry row is a set of **project decisions**: which
codepoint *we* assigned, whether *we* permit an algorithm as a KSK/ZSK,
how *we* wire it (package, group). The incoming static data is **external
facts**: signature/key sizes fixed by the spec, the NIST security level,
the standardization maturity. These have different owners, different
change-drivers, and different lifetimes — a codepoint changes when we
decide; a signature size changes only if the algorithm spec changes.

So the static facts do **not** widen the `Alg` row. The `Alg` struct and
the `Algorithms` table stay exactly as they are today — one scannable line
per algorithm, pure decisions. The facts go in a **separate sibling
structure** in the same file, keyed by **Name**.

Name, not codepoint, is the join key: names are stable (ML-DSA-44 is
ML-DSA-44 regardless of which codepoint we assign it), whereas the
codepoint is precisely the local decision that will churn when the IETF
assigns real numbers. Keying facts by codepoint would couple the facts to
a value we intend to change; keying by name does not. (The current yaml
already keys enrichment by name — this preserves that property.)

## Design

### Part 1 — Static facts as a sibling structure (dnssec-algorithms)

The `Alg` struct and the `Algorithms` table are **left unchanged** (see
Key insight 2). Add a separate sibling structure in the same
`registry.go`, keyed by **Name**:

```go
// Alg (unchanged) — our DECISIONS. One scannable line per algorithm.
// var Algorithms = []Alg{ {199, "MLDSA44", kskOnly, base+"mldsa44", PureGo}, ... }

// Facts is external, machine-independent information about an algorithm,
// fixed by its specification — NOT a project decision. Kept separate from
// Alg so the decisions table stays a clean one-line-per-alg list.
type Facts struct {
    PubKeyBytes   int    // DNSKEY/KEY public key size
    SigBytes      int    // RRSIG/SIG signature size (typical; note variable-length)
    SecKeyBytes   int    // stored private key size
    SecurityLevel int    // NIST PQ level 1/3/5; 0 = classical/unspecified
    Maturity      string // final | draft | candidate | builtin
    Description   string // free-form note
}

// AlgorithmFacts is keyed by algorithm Name — stable across codepoint
// changes (a codepoint is a project decision that will change on IANA
// assignment; the name does not). An algorithm may appear in Algorithms
// (a decision made) with no Facts entry yet (facts not filled in); the
// consumer renders that as "-", exactly as the old yaml did.
var AlgorithmFacts = map[string]Facts{
    "MLDSA44": {PubKeyBytes: 1312, SigBytes: 2420, SecKeyBytes: 2560,
        SecurityLevel: 2, Maturity: "final", Description: "ML-DSA-44 (FIPS 204), lattice"},
    // ... one entry per algorithm ...
}
```

Populate every entry from the existing measured yaml
(`cmdv2/cli/algorithms.measured-arm64.example.yaml`), which already has
all the sizes/levels/maturity/descriptions. This is a data migration, not
new measurement — the sizes are already known.

This is a **schema addition in a separate, pinned module**, so it requires
a publish + re-pin cycle (same as the CROSS work). The registry stays pure
data (no new imports).

### Part 2 — Generator carries the static fields (tdns/cmdv2/genalgs)

`genalgs` already parses the `Algorithms` slice via `go/parser` and emits
`RegisterMetadata(codepoint, name, caps)`. Extend:

- `parseRegistry` to also parse the `AlgorithmFacts` map, and **join it to
  each algorithm by Name** (an algorithm with no Facts entry gets zero
  values → rendered "-" downstream).
- The generated `metadata_algs.go` `RegisterMetadata` calls (and the
  underlying `algorithms.Register/RegisterMetadata` + `entry`) to carry the
  static facts alongside the existing name/codepoint/caps.

The facts are static data — safe and correct to compile into every binary,
including tdns-cli.

### Part 3 — Server reports the static fields (tdns/v2)

`AlgorithmInfo` (`v2/algorithms/algorithms.go`) gains the static fields;
`All()` populates them from the registered entries. The server handler
(`v2/apihandler_funcs.go:132`, `Algorithms: algorithms.All()`) then
carries them to the CLI automatically — no handler change, just the wider
struct. The listing gets sizes/level/maturity/description **from the
server**, so those columns no longer need the yaml.

### Part 4 — Cost data: multi-arch yaml in dnssec-algorithms

The remaining machine-dependent data (`signingcost`, `validationcost`)
stays in a yaml, but reshaped to hold multiple architectures and moved
next to the tool that produces it (`dnssec-algorithms/cmd/algbench`):

```yaml
# dnssec-algorithms/algorithm-costs.yaml
# Signing/validation cost relative to ED25519 (= 1), per architecture.
# Produced by cmd/algbench; the *shape* is stable, the exact factors are
# hardware-specific.
costs:
   arm64:
      MLDSA44:    { signing: 3.1,  validation: 1.9 }
      SLHDSA128S: { signing: 7946, validation: 4.1 }
      # ...
   amd64:
      MLDSA44:    { signing: 2.8,  validation: 1.7 }
      # ...
```

- **cli reads it from the local ALGREPO checkout** (already required for
  the `-env.sh` scripts; `algs-env.mk` records `ALGREPO`). No dependency
  on `/etc/tdns` for cost display.
- **Arch selection: operator picks / show all.** A config key
  (`algorithms.costarch: amd64`) selects which arch's costs to show. With
  no key set, the listing shows all available arches (a cost column pair
  per arch, or a clearly-labelled note). No server-arch protocol change;
  the cli↔server arch mismatch is made explicit rather than guessed.
- **algbench writes/updates an arch block.** `algbench --arch arm64`
  emits/merges the `costs.arm64` block, so refreshing costs for a machine
  is one command. (Today algbench prints a paste-ready block; extend it to
  write the multi-arch file.)

### Part 5 — Retire the tdns-side algorithms.yaml enrichment

Once Parts 1–4 land:

- `v2/cli/algorithm_profiles.go`'s `algorithmProfile` loses the static
  fields; the listing reads them from `AlgorithmInfo`. What remains of the
  profile path is only the cost lookup against the new multi-arch file.
- The `/etc/tdns/algorithms.yaml` sample files
  (`cmdv2/cli/algorithms.sample.yaml`,
  `algorithms.measured-arm64.example.yaml`) are removed or reduced to a
  pointer at the new cost file.
- `special-features.md` / `pq-dnssec.md` updated to describe the new model
  (static data from the registry via the server; costs from the
  algbench-produced multi-arch file).

## Also fix: algbench is out of sync with the registry

`cmd/algbench` has its own **hardcoded** algorithm list with the OLD
codepoints (200=SLHDSA128S, 204=SQISIGN1, ...) and is missing CROSS (214).
It should be refactored to iterate the registry (like genalgs does),
so it can never drift from the codepoint assignments again. This is a
natural companion to Part 4 (algbench is being touched anyway).

## Migration / sequencing

Because the registry is a separate pinned module, order matters:

1. **dnssec-algorithms:** add the `AlgorithmFacts` sibling map to
   `registry.go` (leaving `Alg`/`Algorithms` unchanged), populated from the
   measured yaml; refactor `algbench` to read the registry and write the
   multi-arch cost file; add `algorithm-costs.yaml`. Publish; note the
   version.
2. **tdns:** extend `genalgs` + `algorithms.AlgorithmInfo`/`All()` +
   metadata registration for the static fields; re-pin dnssec-algorithms.
3. **tdns:** rework the cli listing to read static data from
   `AlgorithmInfo` and cost data from the multi-arch file via ALGREPO;
   drop the static half of `algorithm_profiles.go`.
4. Remove/retire the tdns-side `algorithms.yaml` samples; update docs.

Each step builds and is testable on its own; the listing keeps working
throughout (it falls back to "-" for any column whose source isn't wired
yet).

## Out of scope

- Changing what the server reports as *supported* (still `algorithms.All()`,
  real algorithms only — unchanged).
- name↔codepoint resolution (server-authoritative for for-server commands;
  local metadata for offline paths — unchanged, see the generator design
  doc's "CLI codepoint sourcing" invariant).
