# ML-DSA-44 built into tdns

**Written 2026-09-24.** No issue filed yet. Line references are to tdns main
at `5aeffdd2`, dnssec-algorithms main at `4d74f08`, tdns-apps main at
`3db502d` and tdns-mp main at `da4992f`.

**Status:** T1 (§2) is implemented on branch `feature/mldsa44-built-in`; §9
records what it settled. D1, A1 and M1 have not started. Decided: the
implementation leaves dnssec-algorithms (§3); it is not kept there as a
second copy.

## Summary

- **Goal.** Every tdns binary signs and validates ML-DSA-44 (algorithm 18),
  whether or not the build has an `algs.list`.
- **How.** The implementation moves from `dnssec-algorithms/mldsa44` into tdns
  as `v2/algorithms/mldsa44`, and `v2/algorithms` registers it at init, as it
  already does ED448.
- **Keys.** Nothing to migrate. The codepoint is already 18, and the moved
  code keeps the OID and the stored key encoding byte for byte, so keys in
  existing keystores load and sign unchanged.
- **Four changes:** tdns (T1, §2), dnssec-algorithms (D1, §3), and two
  consumers of the dnssec-algorithms registry: tdns-apps zonegen (A1) and
  tdns-mp (M1) (§4).
- **The order is the risk (§5).** genalgs reads the dnssec-algorithms checkout
  on the build host. D1 must not reach a build host before every tdns branch
  built there contains T1.
- **Size (§7).** T1 is about 190 moved and 60 new production lines, plus
  tests. D1, A1 and M1 are small.

## 1. Where things stand

- dnssec-algorithms moved ML-DSA-44 to its IANA codepoint, 18 (#9), and made
  it usable in both DNSSEC roles (#10). Its row is `registry/registry.go:85`.
  The registry's header still calls its codepoints experimental; for ML-DSA-44
  that is no longer true.
- tdns links ML-DSA-44 only where an app's `algs.list` names it: agent, auth,
  dog, imr and signer (`cmdv2/*/algs.list`). genalgs turns the list into
  `registered_algs.go` (`algs.Register` for each listed algorithm) and
  `metadata_algs.go` (`algs.RegisterMetadata` for every registry row). An app
  without an `algs.list` has neither, and cannot sign or validate
  algorithm 18.
- ED448 is the precedent. `v2/algorithms/algorithms.go:345` registers it in
  every binary, and dnssec-algorithms keeps it out of its registry table so
  that genalgs never registers it a second time (`registry/registry.go:135`).
  Its code stays in dnssec-algorithms; ML-DSA-44's moves.
- genalgs reads `registry/registry.go` from the dnssec-algorithms working tree
  given by `--algrepo`, not from the version pinned in `go.mod`. A build host
  with an old or a new checkout generates accordingly.

## 2. tdns (T1)

### 2.1 The package

Move `mldsa44.go` and `pkcs8.go`, and their tests, from
`dnssec-algorithms/mldsa44` to `v2/algorithms/mldsa44`. The code is a thin
adapter over `github.com/cloudflare/circl/sign/mldsa/mldsa44`.

The PKCS#8 codec keeps registering with `dnssec-algorithms/pkcs8`. The keystore
needs a codec for every algorithm it signs with, on the read path, not only for
export (`v2/readkey.go:405`). The OID (2.16.840.1.101.3.4.3.17) and the
2560-byte expanded key encoding stay exactly as they are.

### 2.2 Registration

In `v2/algorithms` `init()`, next to ED448:

- `Register(MLDSA44, mldsa44.New(), dnssecCaps, Facts{...})`, with all four
  capabilities (SIG(0), DNSSEC, KSK, ZSK), as the registry row has them.
- A constant `algorithms.MLDSA44 = 18`, since miekg/dns has none.
- Facts as in the registry: 1312-byte public key, 2420-byte signature,
  2560-byte private key, NIST level 2, maturity `final`.

### 2.3 A built-in registered twice

`Register` panics when a codepoint gets a second real implementation. After
T1, generated code from an older genalgs, or from a checkout that still has
the row, can register ML-DSA-44 again. That happens in another repo that runs
its own copy of genalgs, or on a branch cut before T1. For the algorithms that
`v2/algorithms` registers itself (today ED448 and ML-DSA-44), a later
`Register` with the same name and codepoint is ignored instead. The check
comes before `dns.RegisterAlgorithm`, which would refuse the duplicate. A
second registration of any other algorithm still panics.

In that case the binary also links `dnssec-algorithms/mldsa44`, whose `init()`
registers a second PKCS#8 codec for the same OID. The two codecs are
identical, so it does not matter which one `dnssec-algorithms/pkcs8` tries
first.

### 2.4 genalgs

genalgs gets a fixed set of the algorithms tdns builds in: ED448 and MLDSA44.
It:

- leaves them out of both `metadata_algs.go` and `registered_algs.go`;
- accepts them in an `algs.list`, with a note on stderr that the entry is
  ignored, rather than failing as it does for an unknown name
  (`cmdv2/genalgs/main.go:206`).

This works whatever the checkout holds: a row at 18, a row at 199 (a checkout
from before #9), or no row (after D1). The set is a hardcoded list, since
genalgs has no dependencies and does not import `v2/algorithms`. A built-in
missing from it is harmless as long as the checkout's row matches tdns's own
registration (same codepoint and capabilities): its `RegisterMetadata` is
then a no-op on the real entry (`record()`, `algorithms.go:122`), and §2.3
absorbs its `Register`.

### 2.5 algs.list

Remove `MLDSA44` from `cmdv2/{agent,auth,dog,imr,signer}/algs.list`.

### 2.6 Comments and docs

- `v2/algorithms/algorithms.go`: the package comment's example registers
  ML-DSA-44 at 199 (line 23). Use another algorithm, and list ML-DSA-44 with
  ED448 as built in.
- `v2/go.mod:60`: the comment says ML-DSA-44 is wired in from dnssec-algorithms.
- `v2/readkey.go:405`: the PKCS#8 invariant now covers the built-ins too.
- `utils/Makefile.common:44`: "no algs.list" now means the classical
  algorithms plus ED448 and ML-DSA-44.
- `v2/large_ksk_test.go:283`: the synthetic catalog has ML-DSA-44 at 199.
  Cosmetic.
- `guide/pq-dnssec.md`: the algorithm table (line 131) still says 199 and
  KSK only, and the `algs.list` example (line 238) lists MLDSA44.
- `cmdv2/README.md`, `cmdv2/debug/README.md`: what an app without an
  `algs.list` gets.

Dated design docs are left as they are.

### 2.7 Modules

`cloudflare/circl` becomes a direct requirement of `v2`. Run `go mod tidy` in
`v2` and in every module that depends on it. Every module keeps
`dnssec-algorithms`, for ED448, the PKCS#8 registry and the other algorithms.

### 2.8 What changes for operators

- A build without an `algs.list` signs and validates algorithm 18. A tdns-imr
  built that way validates ML-DSA-44 zones that it could not validate before.
- Every binary, the CLIs included, links circl's ML-DSA-44 code.
- A keystore needs nothing: keys at 18 load through the same codec.

## 3. dnssec-algorithms (D1)

- Remove the `{18, "MLDSA44", ...}` row (`registry/registry.go:85`). Say in
  the table's comment that ML-DSA-44 is built into tdns.
- Keep `AlgorithmFacts["MLDSA44"]` (line 147), with a note like ED448's.
  zonegen reads sizes from it.
- Delete `mldsa44/` (four files, 439 lines).
- `cmd/algbench`: drop the ML-DSA-44 implementation (lines 57, 76). `-write`
  replaces this architecture's whole cost block (`cf.Costs[arch] = ...`,
  `cmd/algbench/main.go:378`), so the next run would drop ML-DSA-44's costs.
  Make `-write` keep rows for algorithms it did not measure, so the last
  measurement stays in `algorithm-costs.yaml`.
- `cmd/demo`: drop the ML-DSA-44 row (lines 31, 48).
- `pkcs8/pkcs8.go:22`: the doc comment's example names `mldsa44`.
- README, BUILDING and `docs/pqc-algorithm-families.md`: ML-DSA-44 now lives
  in tdns.

## 4. Consumers of the registry

- **tdns-apps zonegen (A1).** `lookupAlg` (`cmd/zonegen/algs.go:52`) finds
  ML-DSA-44 only as a row of `registry.Algorithms`. Add it to `builtinAlgs`
  (line 47), with both roles; its sizes still come from `AlgorithmFacts`.
  `builtinAlgs` takes codepoints from `dns.StringToAlgorithm`, which knows
  MLDSA44 only once the tdns that zonegen links registers it. zonegen pins a
  tdns from 2026-08-26, before T1. So either re-pin tdns past T1 in the same
  change, or give ML-DSA-44 an explicit codepoint, 18. The golden output must
  not change. This has to land before zonegen re-pins dnssec-algorithms past
  D1. (ED448 is missing from `builtinAlgs` too; A1 can add it.)
- **tdns-mp (M1).** `TestMLDSA44IsAtTheRegistryCodepoint`
  (`cmd/mpsigner/main_test.go:24`) fails when the row is gone. Rewrite it to
  check the tdns built-in. `cmd/mpsigner/algs.list.PQ-DNSSEC` may keep
  MLDSA44 or drop it (§2.4 accepts both). Due at the next re-pin of tdns or
  dnssec-algorithms.
- **tdns-transport:** no references.

## 5. Order

1. **T1.** Correct with any dnssec-algorithms checkout (§2.4).
2. **A1.** Any time.
3. **D1**, once every tdns branch that is built from a local dnssec-algorithms
   checkout contains T1. A branch without T1 still has MLDSA44 in its
   `algs.list`, and its genalgs fails on a D1 checkout with
   `unknown algorithm "MLDSA44"`.
4. **Re-pins** of dnssec-algorithms in tdns, tdns-apps and tdns-mp, whenever
   convenient; M1 goes with tdns-mp's.

## 6. Tests

### T1

- `TestMLDSA44IsBuiltIn` (`v2/algorithms`): in a test binary with no generated
  files, `AlgorithmNumber("MLDSA44")` is 18, `CapsReal(18)` has all four
  capabilities, `All()` includes it with its facts, and
  `dns.AlgorithmToString[18]` is `MLDSA44`.
- `TestMLDSA44KeyMintedBeforeTheMove` (`v2`): a fixture made with
  `dnssec-algorithms/mldsa44` at `4d74f08`: a PKCS#8 PEM private key, its
  DNSKEY and one RRSIG. The key loads through the keystore's read path
  (`PrepareKeyCache`), the fixture RRSIG verifies, and a new signature verifies
  against the fixture DNSKEY. `testdata/README` records how the fixture was
  made.
- `TestRegisterBuiltInAgain` (`v2/algorithms`): a second `Register` of
  ML-DSA-44 at 18 does not panic; a second real registration of a
  non-built-in still does.
- genalgs: `TestBuiltInsAreNotGenerated` (a registry fixture with an MLDSA44
  row emits neither `RegisterMetadata` nor `Register` for it) and
  `TestListNamingABuiltIn` (accepted with a row at 18, at 199, and with no
  row). Update the fixture row and the count in `main_test.go` (lines 39, 129).
- The moved tests (five in `mldsa44_test.go`, three in `pkcs8_test.go`) run
  in the new package.
- Mutation checks, each run once and reverted: without the `init()`
  registration the first two tests fail; without the genalgs filter
  `TestBuiltInsAreNotGenerated` fails; without §2.3 `TestRegisterBuiltInAgain`
  panics.
- `go vet` and `go test ./...` in every v2 module. Each `cmdv2` app builds
  with its `algs.list` and with none (`make version` first). `tdns-auth
  --version` from a build with no `algs.list` lists MLDSA44 at 18.

### D1

- `go test ./...`. `algbench -write` into a file that has a row for an
  algorithm it no longer measures keeps that row.

### A1

- The golden test passes unchanged after the re-pin past D1.

## 7. Size

| Change | Production | Tests | Other |
|---|---|---|---|
| T1 tdns | ~190 lines moved, ~60 new | ~250 moved, ~150 new, one fixture | 5 `algs.list` edits, `go mod tidy`, ~6 docs and comments |
| D1 dnssec-algorithms | ~25 lines; −439 deleted | ~20 | 3 docs |
| A1 zonegen | ~15 lines | golden unchanged | – |
| M1 tdns-mp | – | ~20-line rewrite | – |

## 8. Not in this plan

- **The stored key encoding.** `pkcs8.go` stores the expanded 2560-byte key,
  noted as a stopgap until the IETF's ML-DSA key-format specification lands.
  With the code in tdns, changing that is a tdns decision and a separate change
  (existing keystores must keep loading). This plan keeps the encoding as it is.
- **Keys minted at 199,** before dnssec-algorithms #9. The codepoint move
  orphaned them; this change neither helps nor hurts.
- **ED448** stays where it is: registered by tdns, implemented in
  dnssec-algorithms.

## 9. T1 as implemented (2026-09-24)

- **§2.3 goes one step further than written.** A repeat `RegisterMetadata`
  of a built-in is ignored too, whatever capabilities it carries: a
  dnssec-algorithms checkout from before #10 has ML-DSA-44 as KSK-only, and
  an older genalgs emits that. A repeat under the same name at another
  codepoint (a checkout from before #9, at 199) still panics; the genalgs
  filter keeps it out of generated code.
- **§2.4 as planned.** The duplicate check comes before the built-in check,
  so a list naming MLDSA44 twice is still an error.
- **The fixture** is `v2/testdata/mldsa44-before-move` (key tag 16984), with
  the program that made it (`mkfixture.go.txt`).
- **Modules.** Only `v2` changed: circl became a direct requirement, and
  `go mod tidy` dropped two checksums for an older dnssec-algorithms. The
  other modules build unchanged; what `go mod tidy` would change there
  predates this work and is left alone.
- **`v2/large_ksk_test.go`**: the synthetic catalog has ML-DSA-44 at 18.
- **Tests and mutation checks** as in §6. Without the `init()` registration,
  `TestMLDSA44IsBuiltIn`, `TestMLDSA44KeyMintedBeforeTheMove` and
  `TestRegisteringABuiltInAgainIsIgnored` fail. Without the genalgs list,
  `TestReadListIgnoresBuiltIns` and all three cases of
  `TestRunGeneratesNothingForBuiltIns` fail. Without §2.3,
  `TestRegisteringABuiltInAgainIsIgnored` panics. After the external
  review, two more: `TestReadListErrors` refuses a list naming MLDSA44
  twice (it fails if the built-in check comes first), and
  `TestBuiltInNameAtAnotherCodepointPanics` pins the 199 case (it fails if
  the repeat check matches the name alone).
- **Application builds.** Every app under `cmdv2` built, and its
  `--version` lists MLDSA44 at 18: auth, imr, dog and signer with their
  lists minus SQISIGN1 and QRUOV_Q31_L3 (those libraries were not
  installed); cli and ncli with their empty lists; debug with none (it has
  no `--version`); the agent with no generated files and with a pure-Go list.
  The version skew of §2.3 was built for real: files generated by the
  genalgs on main, from a list naming MLDSA44, register the
  dnssec-algorithms package at 18. The binary starts and lists MLDSA44 at 18.
- **Found in passing, not part of T1:** the agent cannot build with its own
  `algs.list` on main. Its `go.sum` lacks `liboqs-go`, which its three
  liboqs algorithms need; the other apps' modules have it.
