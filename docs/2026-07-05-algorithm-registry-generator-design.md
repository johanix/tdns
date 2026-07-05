# Algorithm Registry & Code-Generator Design

**Date:** 2026-07-05
**Status:** Design AGREED, ready to implement (no code written yet). This doc is
the implementation reference — build from it top to bottom via the sequencing at
the end.
**Scope:** tdns (`v2/algorithms`, `cmdv2/*`) + dnssec-algorithms

## Concrete schema sketch (Input 1 — registry.go in dnssec-algorithms)

```go
package registry // pure data — imports NOTHING from adapter packages

type LibGroup string
const (
    PureGo  LibGroup = "purego"   // no build tag
    Liboqs  LibGroup = "liboqs"
    SQIsign LibGroup = "sqisign"
    QRUOV   LibGroup = "qruov"
)

type Caps struct{ ForSIG0, ForDNSSEC, ForKSK, ForZSK bool }

type Alg struct {
    Codepoint uint8
    Name      string   // registry/BIND name, e.g. "CROSSRSDPG128SMALL"
    CLIName   string   // --algorithm flag value, e.g. "cross-rsdpg-128-small"
    Caps      Caps
    Package   string   // import path string, e.g. ".../cross_rsdpg_128_small"
    Group     LibGroup
}

var Algorithms = []Alg{
    // ... one row per algorithm; codepoint assigned here, ONCE ...
    {214, "CROSSRSDPG128SMALL", "cross-rsdpg-128-small",
        Caps{ForSIG0:true, ForDNSSEC:true, ForKSK:true, ForZSK:false},
        "github.com/johanix/dnssec-algorithms/cross_rsdpg_128_small", Liboqs},
}
```

Input 2 (per-app) is a plain-text `algs.list`, one `Name` per line. The
generator matches those names against `Algorithms` to recover codepoint, caps,
package, and group.

## Problem

The `codepoint ↔ algorithm` mapping is hand-maintained, redundantly, across
several files and repos, and it has already drifted:

- `cmdv2/cli/main.go` — `RegisterMetadata` for codepoints 199–211 (15 algs).
- `cmdv2/dog/main.go` — `RegisterMetadata` for **only** 201, 202, 203 (3 algs).
- `cmdv2/auth/pq_algorithms_liboqs.go` — `Register` for 201–211 (+ CROSS 214).
- `cmdv2/imr/pq_algorithms_liboqs.go` — its own copy.
- Plus `_sqisign.go` / `_qruov.go` build-tag files per app.
- `v2/cli/algorithms.go` — a separate hand-maintained CLI name list.

Consequences already visible: dog knows the *names* of only 3 algorithms, so a
future `dog +sigchase +algchase` would print bare numbers for SQIsign (204),
QR-UOV (205), CROSS (214), etc. Adding one algorithm currently means editing
~5–9 files by hand and keeping the codepoint identical across all of them (done
manually for CROSS this session — exactly the error-prone situation to remove).

### Why per-app codepoints are wrong

A codepoint is a **wire-protocol identity**. Two tdns apps built from the same
tree must never disagree that 214 = CROSS, or they cannot interoperate. Per-app
*selection* (which algs an app links an implementation for) is legitimate;
per-app *numbering* is a latent interop bug. The current model conflates the two.

## Design

Two inputs, one generator, generated registration files.

### Input 1 — the metadata table (global, one source of truth)

Lives in **dnssec-algorithms** (`registry.go`), a compile-checked Go slice.
It sits next to the adapter packages it indexes; users already keep a local
dnssec-algorithms checkout (for the C-lib env scripts), so codepoint edits touch
nothing new, and adapters stop hard-coding their own codepoint.

**Pure data — no imports of adapter packages.** Columns:

| Column | Purpose | Emitted at runtime? |
|---|---|---|
| `codepoint` (uint8) | wire identity | yes → `RegisterMetadata` |
| `name` (string) | BIND label / registry name | yes → `RegisterMetadata` |
| `cli_name` (string) | `--algorithm` flag value | drives CLI name list |
| `caps` (ForSIG0/ForDNSSEC/**ForKSK/ForZSK**) | usage constraints | yes → `RegisterMetadata` |
| `package` (string path) | implementing Go package | generator-only (→ import) |
| `lib_group` (purego/liboqs/sqisign/qruov) | build-tag group | generator-only (→ tag + file) |

`package` and `lib_group` are **strings**, never live imports — importing the
table must pull in zero cgo, so `dog` (and any name-aware UI) can link the whole
table with no liboqs/sqisign/qruov dependency. The generator turns the string
package paths into real imports in the generated impl files.

### Input 2 — the per-app implementation list (dead simple)

A plain-text file per app in tdns, **one algorithm name per line**, matching the
`name` column exactly. Nothing else — no codepoints, no caps, no packages. The
generator resolves each name against Input 1 to recover everything.

```
# cmdv2/auth/algs.list
MLDSA44
SLHDSA128S
FALCON512
MAYO1
SNOVA24_5_4
CROSSRSDPG128SMALL
```

```
# cmdv2/agent/algs.list   (deliberately smaller subset)
MLDSA44
FALCON512
```

Adding a new algorithm = **one row in Input 1** + **its name in the Input 2
lists of the apps that should implement it.** No codepoints touched by hand, no
cross-app sync, no separate CLI list.

### The generator

A `cmd/` tool in **tdns**, invoked via `go generate ./...`. The **metadata table
path is an explicit argument** to the generator — which also hands it the exact
dnssec-algorithms repo location for free (see "Third-party lib auto-detection").
For each app it emits:

1. **`metadata_gen.go`** — `RegisterMetadata(codepoint, name, caps)` for **all**
   algs in Input 1. Pure Go, no build tags, compiled into every app. This is the
   global codepoint↔name↔role mapping. Fixes dog's stale list; enables `+algchase`.

2. **`impl_<group>_gen.go`** — one file per lib_group, each `//go:build <group>`
   tagged (except purego, untagged), containing `Register(codepoint, pkg.New(),
   caps)` for **only** the algs in that app's Input 2 list that belong to that
   group. This replaces the hand-maintained `pq_algorithms_*.go` files.

Result: `metadata` is uniform everywhere; `impl` is per-app-selected and
build-tag-gated, both generated, both consistent by construction.

### Third-party lib auto-detection (generate-time)

Because the generator is given the dnssec-algorithms path, it can run that repo's
existing `-env.sh` scripts to discover which C libs are actually installed —
**with no changes to the scripts** (verified 2026-07-05). Each script is already
machine-consumable: bare invocation prints `export PKG_CONFIG_PATH=...`
(and `CGO_LDFLAGS`, etc.) to **stdout**, sends human diagnostics to **stderr**,
and exits non-zero when the lib is not found.

```
run  bash <dnssec-algs>/liboqs/liboqs-env.sh   (capture stdout, exit code)
  exit 0 + non-empty stdout → PRESENT; stdout IS the exact env to bake in
  exit != 0 / empty stdout  → ABSENT; skip that group's impl file, warn
```

Same for `sqisignc/sqisign-env.sh`, `qruovc/qruov-env.sh`. From one pass the
generator learns the full present/absent picture **and** the exact per-lib env.

With that, the generator can:
- **Emit impl files only for libs that are present** — no more failing deep in
  the linker with an undefined-reference; the operator is told up front which
  groups were skipped and why.
- **Emit one consolidated build-env artifact** (`algs-env.sh` or a Makefile
  fragment) that sets `PKG_CONFIG_PATH` / `CGO_LDFLAGS` / (NetBSD)
  `LD_LIBRARY_PATH` for *all detected libs at once* — replacing the current
  "source three scripts + remember the NetBSD LD_LIBRARY_PATH quirk + pass the
  right WITH_* flags by hand" dance with "source one generated file."

**Honest boundary — this does NOT eliminate build-time env.** cgo reads
pkg-config *during `go build`*, a separate process from `go generate`, possibly
on a different machine. The generator can *detect and emit* the env; it cannot
*inject* it into a later build. So the win is "generate the correct env once, in
one file, from real detection" — not "no env vars ever." Generated
`_gen.go` files must not hard-code "lib X is installed" as if universal; the
build-env file is advisory for the build host, and `WITH_*`/build tags remain the
authoritative gate at compile time.

## Prerequisite change — `record()` must promote, not panic

`v2/algorithms/algorithms.go` `record()` currently panics on any duplicate
codepoint. The new model registers metadata for **all** algs (Input 1) and then,
in a lib build, also registers a real impl for **some** — so codepoint 214 gets
`RegisterMetadata` *and* `Register`. Today the second call panics.

Fix: `record()` must **promote** a metadata-only entry to real when a genuine
impl is later registered for the same codepoint — verify `name` and `caps`
match, wire the impl into miekg/dns, set `real=true`. Panic only on genuine
conflict (same codepoint, *different* name; or two real impls).

The `entry` struct already carries `real bool` for exactly this metadata-vs-impl
distinction; only `record()`'s duplicate handling needs to change.

## Role field (`ForKSK` / `ForZSK`)

`Capabilities` gains two bools alongside `ForSIG0`/`ForDNSSEC`:

```go
type Capabilities struct {
    ForSIG0   bool
    ForDNSSEC bool
    ForKSK    bool // may be used as a KSK
    ForZSK    bool // may be used as a ZSK
}
```

`ForDNSSEC` stays the umbrella (a DNSSEC-usable alg); `ForKSK`/`ForZSK` refine
it. Example: CROSS-RSDP-G-128-small = `{ForSIG0:true, ForDNSSEC:true,
ForKSK:true, ForZSK:false}` — its ~9 KB signature is fine in the (occasional,
TCP/DoT) DNSKEY response but would bloat every RRSIG as a ZSK. Blast radius is
small: only `SupportedSIG0`/`SupportedDNSSEC` predicates + the JSON export read
`Capabilities` today; the additions are purely additive.

**Enforcement point: the dnssec policy parser.** A policy names algorithms for
the KSK and ZSK roles; the parser rejects a policy that assigns a `ForZSK:false`
algorithm to the ZSK role (or `ForKSK:false` to the KSK role), failing early at
config-load rather than at signing time. This is the right seam — role usage is
declared in policy, so role legality is checked where policy is validated.

**No family field.** Cryptographic family (lattice/code-based/multivariate/…)
is analysis-doc material — it lives in
`dnssec-algorithms/docs/pqc-algorithm-families.md`, not the runtime registry.
`+algchase` reports codepoint + name + role; "what family is 214" is answered by
the analysis doc.

## Out of scope

- **PKCS#8 OID tail** (`3,99,N` per adapter) — a dnssec-algorithms concern,
  stays hand-assigned in the adapter. Not driven by this generator.
- Any change to how *implementations* are built (liboqs/sqisign/qruov C libs) —
  see `dnssec-algorithms/BUILDING.md` and the pending PQ build guide.

## Why this unblocks the PQ documentation

The forthcoming `guide/pq-dnssec.md` "registering algorithms" section should
describe the *clean* model ("add a row to the registry + a name to the app
list, run `go generate`"), not the current hand-maintained one. Hence: land this
refactor (or at least freeze its shape) before writing that section, so the doc
does not describe something with a known expiry date.

### PQ documentation requirements (accumulated — for the doc phase, step 7)

`guide/pq-dnssec.md` (split out of `special-features.md` §4; standalone;
builder + operator audience) must cover, at minimum:

- **The three-layer architecture** — forked miekg/dns (pluggable registry) +
  dnssec-algorithms module + the generated compile-time registration.
- **What `dnssec-algorithms` is and WHY it lives outside tdns.** Its role: a
  repository of **unified Go wrappers** presenting a single `dns.Algorithm`
  interface over heterogeneous third-party algorithm implementations (pure-Go
  CIRCL; the liboqs C library; the SQIsign and QR-UOV reference C libraries).
  Why separate: (a) it is reusable by consumers other than tdns — the wrappers
  are not tdns-specific; (b) it isolates the messy per-algorithm C-lib build
  and cgo surface from the tdns app tree; (c) it is where codepoints and the
  algorithm registry live (see this design), which are algorithm-collection
  facts, not tdns app logic; (d) it must be a **local checkout** for the C-lib
  `-env.sh` discovery scripts even though the Go module is pinned — the
  "pinned but must be local" point.
- **Supported algorithms** — complete table: family, key/sig sizes, backend
  (pure-Go / liboqs / own C lib), standardization status. Codepoints included
  but clearly marked experimental/project-internal.
- **KSK vs ZSK suitability summary** — the sizing constraints (per-response
  RRSIG budget vs. the 64 KB DNSKEY-RRset ceiling; alg-split), with the full
  family analysis LINKED to `dnssec-algorithms/docs/pqc-algorithm-families.md`.
- **Per-platform build** — NetBSD (pkgsrc), Debian/Linux (apt + build-from-
  source; liboqs static), macOS (MacPorts — flag as unverified). Native lib
  install, env scripts (source from **bash**), pkg-config, the NetBSD
  `LD_LIBRARY_PATH=/usr/pkg/lib` quirk, `make version && make WITH_*`. Reference
  `dnssec-algorithms/BUILDING.md` as authoritative; don't duplicate it.
- **Registering algorithms** — the clean generated model (registry row + app
  `algs.list` + `go generate`), NOT the old hand-maintained blank-import story.
- **Corrected `dns.Algorithm` interface** — current §4.2 is wrong: missing
  `SignaturePostProcess`; `PrivateKeyToString` returns `(string, error)`.
- **Bridge to policy + rollover (worked, runnable — not just links):**
  - Two complete PQ policies using **policy templates** (to keep them compact),
    e.g. a classical baseline and a PQ / alg-split (large-KSK + small-ZSK) target.
  - A **CLI worked example of a ZSK algorithm rollover** P1→P2 between them
    (mirrors the autumn-2026 lab's core operation).
  - Note that **KSK algorithm rollover is an upcoming feature** (not yet built).
- **Validation of PQ-signed zone data** — "in theory it just works" (validator
  dispatches through the same registry). Needs an evidence-backed
  sign-with-X → validate-with-imr test matrix per algorithm, and the doc records
  the **validation status** per alg (not asserted — tested).
- **`dog +sigchase +algchase`** — once it exists (step 6), document how it
  reports codepoint + name + role along a chain.

## Suggested sequencing

1. `record()` promotion fix (small; unblocks metadata+impl coexistence).
2. `ForKSK`/`ForZSK` added to `Capabilities`.
3. `registry.go` metadata table in dnssec-algorithms (pure data).
4. Generator `cmd/` tool in tdns + per-app `algs.list` files; wire `go:generate`.
5. Replace hand-maintained `pq_algorithms_*.go` and the CLI name list with
   generated output; delete the manual `RegisterMetadata` blocks in cli/dog.
6. `dog +sigchase +algchase` (now trivial — global metadata is always present).
7. Write `guide/pq-dnssec.md` against the finished model.
