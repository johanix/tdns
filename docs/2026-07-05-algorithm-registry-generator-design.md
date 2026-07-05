# Algorithm Registry & Code-Generator Design

**Date:** 2026-07-05
**Status:** Design AGREED and implementation-ready (no code written yet). All
three earlier gaps resolved with verified seams (role-enforcement point,
CLI codepoint-sourcing invariant, +algchase). This doc is the implementation
reference — build from the sequencing (PR-A/B/C) at the end; the "Verified
implementation seams" index lists every file:symbol to touch.
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
| `caps` (ForSIG0/ForDNSSEC/**ForKSK/ForZSK**) | usage constraints | yes → `RegisterMetadata` |
| `package` (string path) | implementing Go package | generator-only (→ import in `registered_algs.go`) |
| `group` (purego/liboqs/sqisign/qruov) | lib the impl needs | generator-only (→ availability check via `-env.sh`) |

**IMPLEMENTED (PR-B):** the table is `registry/registry.go` in dnssec-algorithms
(package `registry`), pure data, verified to import zero cgo. `package` and
`group` are **strings**. No `cli_name` column: the CLI upper-cases input before
matching, so `name` doubles as the typed name. `group` no longer maps to a build
tag (see the revised generator section) — it names the library whose presence the
generator checks at generate time.

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

### The generator — NO BUILD TAGS (revised 2026-07-05)

`cmdv2/genalgs`, invoked via `go generate`. Interface:

```
genalgs --algrepo <dir> --list <algs.list> --out <dir> [--pkg main]
```

The **`--algrepo` argument is the root of a dnssec-algorithms checkout** — one
path from which the generator derives everything it needs from that repo:
- the registry table at `<algrepo>/registry/registry.go`, which it **parses via
  `go/parser`** (no import / go.mod replace) and extracts the `Algorithms` slice
  from — keeping the table type-checked Go in its own repo while decoupling the
  generator from go.mod entanglement or a fixed layout;
- the availability scripts at `<algrepo>/{liboqs,sqisignc,qruovc}/*-env.sh` (below).

This is faithful to the agreed "explicit argument" design and matches the
"pinned-but-local checkout" principle: the caller (the Makefile) points
`--algrepo` at the local dnssec-algorithms working copy.

**Availability is resolved at GENERATE time, so there are NO build tags.** This
is the key shift from the original design. Previously each impl file carried
`//go:build liboqs` and `go build -tags liboqs` decided at compile time whether
it was included. Instead:

1. The generator reads the app's `algs.list` (what the operator WANTS) + the
   registry (all algs + their lib group).
2. For each wanted alg it checks the lib group is **actually installed** by
   running the group's `-env.sh` (see below).
3. **A wanted alg whose lib is ABSENT is a hard error** — generation fails with,
   e.g., "algs.list selects SQISIGN1 but the sqisign library was not found;
   install it or remove SQISIGN1 from algs.list." No silent skip.
4. If all wanted algs are available, it emits **two plain-Go files, no tags:**
   - **`metadata_gen.go`** — `RegisterMetadata(...)` for **all** registry algs.
     Needs no libs (pure data). The global codepoint↔name↔role table; fixes
     dog's stale list, enables `+algchase`.
   - **`registered_algs.go`** — a single flat file of `Register(...)` calls for
     **every** selected alg (all lib groups together — no per-group split,
     because availability is already guaranteed). Replaces all the
     hand-maintained `pq_algorithms_*.go` files.

Why one impl file is now possible: the per-file split existed ONLY because Go
allows one `//go:build` constraint per file, so liboqs vs. sqisign impls had to
live in separate files to be tagged independently. With availability decided at
generate time, the emitted code is known-good against the installed libs and
needs no tag — so all `Register` calls collapse into one file.

**Consequences (accepted, see build integration):**
- `make WITH_LIBOQS=1 …` flags and `//go:build` tags are **removed**. What gets
  compiled in = `algs.list` ∩ installed libs, resolved by the generator.
- The generated `metadata_gen.go` and `registered_algs.go` are **build
  artifacts — NOT committed** (gitignored), regenerated per build host so the
  binary's algorithm set always matches that host's actual libraries.
- Therefore a clean checkout does **not** compile until `go generate` runs:
  generation is a mandatory build step (the Makefile runs it before `go build`).
  A stray `go build` on a fresh tree yields a binary with zero algorithms — the
  Makefile is what prevents that footgun.

### Third-party lib availability detection (generate-time)

The generator runs dnssec-algorithms' existing `-env.sh` scripts to learn which
C libs are installed — **no changes to the scripts** (verified 2026-07-05). Each
prints `export PKG_CONFIG_PATH=...` (and `CGO_LDFLAGS`) to **stdout**, human
diagnostics to **stderr**, and exits non-zero when the lib is absent.

```
run  bash <registry-repo>/liboqs/liboqs-env.sh   (capture stdout, exit code)
  exit 0 + non-empty stdout → PRESENT; stdout is the exact env for the build
  exit != 0 / empty stdout  → ABSENT
```

Same for `sqisignc/sqisign-env.sh`, `qruovc/qruov-env.sh`. The generator uses
this to (a) **fail** if a wanted alg's lib is absent, and (b) emit **one
consolidated build-env artifact** (`algs-env.sh` / Makefile fragment) setting
`PKG_CONFIG_PATH` / `CGO_LDFLAGS` / (NetBSD) `LD_LIBRARY_PATH` for all needed
libs at once — replacing the "source three scripts + remember the NetBSD
LD_LIBRARY_PATH quirk + pass WITH_* flags by hand" dance.

**Boundary that still holds:** cgo reads pkg-config during `go build`, so the
build still needs that env in its process — the generator emits it (the build-env
artifact) but cannot inject it into a separate `go build`. The Makefile sources
the artifact. Because the generated impl file is regenerated per host and not
committed, there is no cross-machine "lib X assumed present" hazard: the file
always reflects the host it was generated on.

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

**Enforcement point (verified seam): `parseDnssecPolicyConfImpl`.** A dnssec
policy names a `KSKAlgorithm` and a `ZSKAlgorithm` (both `uint8` codepoints —
`DnssecPolicy` struct, `v2/structs.go:449`). Enforcement is a new sibling check
next to the existing `validateSplitAlgorithm` call in
`parseDnssecPolicyConfImpl` (`v2/ksk_rollover_policy.go:604`):

```go
alg, kskAlg, zskAlg, err := resolvePolicyRoleAlgorithms(name, dp)
...
if err := validateSplitAlgorithm(name, kskAlg, zskAlg, splitAllowed); err != nil {
    return nil, err
}
if err := validateRoleCapabilities(name, kskAlg, zskAlg); err != nil { // NEW
    return nil, err
}
```

`validateRoleCapabilities` checks `algorithms.Caps(kskAlg).ForKSK` and
`Caps(zskAlg).ForZSK`; on failure it returns
`policy %q: algorithm %s (%d) is not permitted as a KSK/ZSK`. **No new plumbing
downstream:** the returned error flows into the existing broken-policy path
(`DnssecPolicy{Name: name, Error: reason}`, `v2/parseconfig.go:1460`). The
`DnssecPolicy.Error` docstring already enumerates "disallowed KSK/ZSK split" as a
rejection reason and states a broken policy is kept-but-unusable and its zones
quarantined — so ForKSK/ForZSK is simply one more reason feeding that same
mechanism.

**IMPLEMENTED (PR-A):** `validateSplitAlgorithm` has **three** production call
sites, not two — the role check was added beside every one:
`v2/ksk_rollover_policy.go:610` (`parseDnssecPolicyConfImpl`), `:680` (the
non-`Impl` loop), and `v2/parseconfig.go:1476` (the live `parseDnssecConfig`
path, which uses `markBroken(err)` to set `Error`). The third site is the one the
running daemon actually takes; it was missed in the original two-site estimate and
found only because the enforcement test initially passed for the wrong reason (a
split-check rejection masking the absent role check). Lesson recorded: any future
per-policy validation must cover all three sites (or they should be refactored to
one shared helper).

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

## CLI codepoint sourcing — invariant to preserve (GAP 2, verified)

The CLI (`v2/cli/algorithms.go`) already follows the right rule and it must be
kept: **for any command that will hit a server (generate/use/list-for-a-role),
the CLI resolves name↔codepoint from the SERVER, never from its own table** —
`resolveServerAlgorithm(role, name, use)` calls the `list-algorithms` API and
hard-fails if the server is unreachable (no local fallback). Only genuinely
offline paths (`debug sig0 generate`, parsing an exported-key blob) use the local
`algregistry.AlgorithmNumber`.

The generator does NOT change this. It only regenerates the local
`RegisterMetadata` block that backs the *offline* paths — which is currently
hand-maintained and incomplete, so those offline paths break on any alg not in
the manual list; complete generated metadata fixes exactly that. **The
server-sourced path in `algorithms.go` is untouched.**

Why keep server-sourcing even though local metadata is now complete:
1. The local table (`RegisterMetadata`) knows an alg *exists* but not whether
   *this server* was built with its implementation (`WITH_LIBOQS` etc.) — only
   the server's `list-algorithms` reflects its `real` (usable) set. Resolving a
   for-server command locally would defer the failure to the server by one step.
2. CLI and server may be different builds/versions; identical-at-build-time
   metadata does not guarantee identical-at-runtime across two deployed binaries.

**Invariant (comment it in code, do not erode post-generator):** for-server
commands use `resolveServerAlgorithm`; the local generated table is for offline
paths only.

## +algchase — design (GAP 3, verified)

`+algchase` **requires `+sigchase`** (it annotates what sigchase already walks;
alone it is meaningless). dog flags are string-keyed in an `options` map
(`options["sigchase"]="true"`, parsed at `cmdv2/dog/dog.go:549`). Add
`options["algchase"]` similarly; if `algchase && !sigchase`, error
`+algchase requires +sigchase`.

`+sigchase` already builds per-link `link.Notes` lines (`v2/chase.go`, e.g. :183)
that reference the signing key / keytag and whether the RRSIG validates. From the
key, dog has the RRSIG's algorithm codepoint. `+algchase` enriches those existing
notes with the algorithm *name* via `algorithms.AlgorithmName(codepoint)`. This
works only once dog carries the full codepoint→name table — i.e. it depends on
step 5 (the generator populating dog's `RegisterMetadata`), NOT on new chase
logic. Until then dog can only print bare numbers (the current bug). So
`+algchase` is a display enhancement gated on step 5, not new traversal code.

## Verified implementation seams (quick index)

| Concern | File : symbol |
|---|---|
| `record()` promote-not-panic | `v2/algorithms/algorithms.go:88` `record()` |
| `Capabilities` + entry | `v2/algorithms/algorithms.go:39` / `:49` |
| classical builtin table | `v2/algorithms/algorithms.go:210` `init()` |
| caps consumers (blast radius) | `SupportedSIG0` `:140`, `SupportedDNSSEC` `:147`, `All()`/JSON `:185`, `v2/cli/algorithms.go` |
| policy struct | `v2/structs.go:449` `DnssecPolicy` (`Error`, `KSKAlgorithm`, `ZSKAlgorithm`) |
| role enforcement seam | `v2/ksk_rollover_policy.go:604` `parseDnssecPolicyConfImpl` (+ ~677 wrapper) |
| broken-policy path | `v2/parseconfig.go:1460` |
| CLI server-sourced resolve | `v2/cli/algorithms.go` `resolveServerAlgorithm` / `fetchServerAlgorithms` |
| hand-maintained metadata to replace | `cmdv2/cli/main.go`, `cmdv2/dog/main.go` |
| impl files to replace | `cmdv2/{auth,imr,agent}/pq_algorithms_{liboqs,sqisign,qruov}.go` |
| sigchase flag / notes | `cmdv2/dog/dog.go:549`, `v2/chase.go` |
| C-lib detect scripts | `dnssec-algorithms/{liboqs,sqisignc,qruovc}/*-env.sh` |

## Suggested sequencing

Branch/PR boundaries follow the repo split (dnssec-algorithms is a separate
repo needing publish+re-pin).

**PR-A (tdns) — foundation, fully specified, locally testable:**
1. `record()` promote-not-panic (verify name/caps match; wire impl into
   miekg/dns; set `real=true`; panic only on genuine conflict). + unit tests.
2. `ForKSK`/`ForZSK` on `Capabilities`; set them on the 5 classical builtin-table
   entries (all `ForKSK:true, ForZSK:true`); thread through `All()`/JSON export
   and the cli reader.
3. Role enforcement: `validateRoleCapabilities` in `parseDnssecPolicyConfImpl`
   (+ the wrapper). + parse tests (a ForZSK:false alg as ZSK ⇒ policy `Error` set,
   zone quarantined).

**PR-B (dnssec-algorithms):**
4. `registry.go` pure-data metadata table (schema above); one row per alg incl.
   CROSS. Commit, publish, note the version for re-pin.

**PR-C (tdns) — generator + cutover. NO BUILD TAGS (revised model above):**
5. Generator `cmdv2/genalgs`: `-registry <path>` arg (AST-parse the registry
   `.go`, no import); `-env.sh` availability detection with **fail-on-missing**;
   emit `metadata_gen.go` (all algs) + a single flat `registered_algs.go` (all
   selected impls, no tags) + a consolidated build-env artifact. Generated files
   are build artifacts — gitignored, not committed.
   *(A first cut of genalgs — import-based, per-group tagged files — was committed
   as `1735f15`; it is superseded by this revised model and must be reworked.)*
6. Per-app `algs.list` (committed) + `go:generate` wiring. Delete the
   hand-maintained `pq_algorithms_*.go` and the manual `RegisterMetadata` blocks
   (cli/dog). **Prove equivalence:** generated registration ≡ current per-app
   behavior (same codepoints, same per-app subsets). Preserve the CLI
   server-sourcing invariant.
7. **Build integration (Makefiles):** `go generate` before `go build` per app;
   drop `WITH_LIBOQS/SQISIGN/QRUOV` flags and all `//go:build` tags; source the
   generated build-env artifact. A clean checkout builds via `make`, which
   generates first. *(Approach discussed separately before implementing.)*

**Follow-ups (separate branches):**
8. `dog +algchase` (display enhancement; depends on step 6 metadata).
9. Write `guide/pq-dnssec.md` against the finished model.
