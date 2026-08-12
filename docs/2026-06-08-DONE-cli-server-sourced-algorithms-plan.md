# Plan: CLI queries the server for supported algorithms

Date: 2026-06-08
Status: implemented (branch cli-server-sourced-algorithms)

> **As-built note.** Two material changes from the original proposal,
> both validated live:
>
> 1. **Listing trigger:** a dedicated `algorithms` subcommand
>    (`keystore dnssec algorithms`, `keystore sig0 algorithms`) instead
>    of a bare `-a`. Bare `-a` collided with cobra's required-flag
>    handling (`--state`/`--keytype`) and forced `NoOptDefVal`
>    gymnastics. `-a` now means strictly "the algorithm I want",
>    server-resolved; an unknown or missing `-a` errors with the
>    server's supported list inline.
> 2. **Real-vs-metadata:** a live test revealed `All()` was reporting
>    metadata-only algorithms (registered by the server's
>    `pq_algorithms_no*.go` so the *old* CLI could recognize names),
>    so the server advertised algorithms it could not actually
>    generate with — the original `unknown algorithm: NNN` bug class.
>    Fixed by adding a `real` flag to the registry (`Register`→true,
>    `RegisterMetadata`→false, built-ins→true); `All()` returns only
>    real entries, so the server is honest by construction. The 7 now-
>    obsolete server-side `pq_algorithms_no*.go` files were deleted.

## Problem

The name↔codepoint mapping for DNSSEC algorithms is hardcoded
independently in two places:

- **server** (tdns-auth/agent/imr): via `algs.Register(...)` in each
  app's `init()` / `pq_algorithms_*.go`, which also populates
  miekg/dns's `dns.AlgorithmToString` / `dns.StringToAlgorithm`.
- **CLI** (tdns-cli): via `algs.RegisterMetadata(...)` in
  `cmdv2/cli/main.go`.

These can drift: different *sets* of algorithms, or — worse, silently
— the *same name mapped to a different codepoint*. The CLI builds its
`--algorithm` help text and validates the `-a` argument from its own
local registry, then sends a codepoint the server may interpret
differently.

The CLI never signs or verifies; it only needs to (a) show the user
what's available and (b) send the right codepoint. The server is the
only place that actually generates keys, so the server is the natural
source of truth.

## Goal

The CLI obtains the name↔codepoint↔caps map from **the same server it
will send the generate request to**, per invocation. No hardcoded
algorithm list in the CLI. `--help` stops claiming to enumerate algs.

## Design decisions (settled)

1. **Server is authority.** A new API endpoint returns the server's
   algorithm registry (number, name, ForSIG0, ForDNSSEC). Honest by
   construction: the server only `Register`s what it can actually use.
2. **CLI resolves per-invocation against the same role** it sends to
   (`GetApiClient(role)`). Wire format unchanged: CLI still sends a
   `uint8` codepoint, but resolves it from the server's map.
3. **Dedicated `algorithms` subcommand** → query the role's server and
   print its supported list. (Superseded bare `-a`; see As-built note.)
4. **`--help`** → static text pointing at the `algorithms` subcommand.
   No baked-in list.
5. **Hard fail** when the server is unreachable. No local fallback.
   (These commands send to the server anyway; offline resolution only
   defers the failure by one step.)
6. **`debug sig0 generate` stays local** — it runs `kdb.GenerateKeypair`
   in-process (it *is* server code), so it uses the in-process registry.
   Untouched.
7. Remove the hardcoded `RegisterMetadata` block from
   `cmdv2/cli/main.go`.

## Timing (verified)

`rootCmd.PersistentPreRun` (cmdv2/cli/root.go:26) calls `initApi()`
(root.go:33), populating `Globals.ApiClients`, BEFORE any command's
`Run` closure executes. So a server query inside `Run` (where
`PrepArgs` and `GetApiClient` already run) has a working client. No new
cobra hook needed. The static `--help` text is built at command-
construction (init) time, before any server contact — which is why
help can't enumerate per-server algs and instead points at the
`algorithms` subcommand.

## Implementation (as built)

### Step 1 — Server: registry exposes real-vs-metadata + All()

`v2/algorithms/algorithms.go`:

- Added a `real bool` to `entry`. `Register` records `real=true`,
  `RegisterMetadata` records `real=false`, built-ins `true` (they are
  usable via miekg/dns's switch arms). The internal helper
  `registerMetadata` was renamed `record(num, name, caps, real)`.
- Added `AlgorithmInfo{Number, Name, ForSIG0, ForDNSSEC}` (JSON-tagged)
  and `All() []AlgorithmInfo`, which returns **only `real` entries**,
  sorted by codepoint. This is the load-bearing correctness property:
  a server must not advertise algorithms it cannot actually use.

### Step 2 — Server: `/keystore` "list-algorithms" command

- `v2/api_structs.go`: `KeystoreResponse` gained
  `Algorithms []algorithms.AlgorithmInfo`. No import cycle: the `tdns`
  package did not previously import `v2/algorithms`, and `v2/algorithms`
  imports only miekg/dns + stdlib.
- `v2/apihandler_funcs.go`: `APIkeystore`'s `switch kp.Command` gained
  `case "list-algorithms"` → `resp.Algorithms = algorithms.All()`.
  Read-only; reuses the existing `/keystore` route + auth middleware.

### Step 3 — CLI: server-sourced helpers (v2/cli/algorithms.go)

The local helpers (`isKnownAlgorithm`, `AlgorithmNumber`,
`MustAlgorithmNumber`) were **kept** — they back the local-only paths
(`debug sig0 generate`, exported-key parsing) that have no server to
ask. Added alongside them:

- `fetchServerAlgorithms(role)` — `GetApiClient(role,false)` +
  `SendKeystoreCmd(KeystorePost{Command:"list-algorithms"})`, cached
  per role. **Hard-fails** if unreachable.
- `algUse` (useSIG0/useDNSSEC) + `resolveServerAlgorithm(role,name,use)`,
  `printServerAlgorithms(role,use)`, `serverAlgNames(...)`.
- `ResolveAlgorithm(role, use) uint8` — the entry point each remote
  generate command calls: resolves the name against the server's map,
  or on empty/unknown input prints an error with the server's list and
  exits 1.

### Step 4 — CLI: per-invocation resolution at the 6 remote sites

`-a` default changed from `"ED25519"` to `""`. Each remote command's
`Run` drops `"algorithm"` from its `PrepArgs(...)` and calls
`ResolveAlgorithm(role, use)` to get the codepoint:

- v2/cli/keystore_cmds.go — sig0 generate, dnssec generate
- v2/cli/zone_dsync_cmds.go — bootstrap, roll
- v2/cli/agent_zone_cmds.go — bootstrap, roll (role "agent")

### Step 5 — CLI: `algorithms` subcommand + help text

- Added a `algorithms` subcommand under both `keystore sig0` and
  `keystore dnssec` (calls `printServerAlgorithms(role, use)`).
- `sig0AlgorithmsHelp`/`dnssecAlgorithmsHelp` now append
  "(use the 'algorithms' subcommand to list what the server supports)".

### Step 6 — Delete obsolete server metadata files

The 7 server-side `pq_algorithms_no*.go` files (auth/imr/agent ×
liboqs/sqisign/qruov) only ever registered metadata to pad the old
CLI's registry. With the CLI now asking the server and `All()`
filtering on `real`, they are obsolete and were deleted. A server
built without a tag simply doesn't register/advertise that algorithm —
the honest behavior. The CLI's own `RegisterMetadata` block in
`cmdv2/cli/main.go` **stays** (it backs the local debug/export paths).

### Step 7 — build + live test

Default `make` and all-tags (`WITH_LIBOQS=1 WITH_SQISIGN=1
WITH_QRUOV=1`) builds pass. Verified against a running all-tags auth:
`algorithms` lists 12 (all real); `generate -a QRUOV1` and
`generate -a ed25519` (case-insensitive) succeed; `-a BOGUS` and
omitted `-a` error with the server's list inline; `debug sig0 generate`
(local path) still resolves the algorithm (fails only on missing
db.file, an unrelated env issue).

## Notes / follow-ups

- The `unknown algorithm: NNN` errors seen earlier (204, then 205) were
  the same root cause: a server built without the relevant tag has that
  algorithm only as metadata, so `GenerateKeyMaterial`'s
  `dns.AlgorithmToString` check rejects it. The `real` flag now keeps
  such an algorithm out of the advertised list entirely, so the CLI
  never offers it and the error can't arise via the server path.
- `debug sig0 generate` can only produce keys for algorithms the CLI
  binary has as a *real* implementation (built-ins). It registers only
  metadata for PQ algs, so a local PQ keygen there would fail — a
  pre-existing limitation, unchanged by this work.
- **Default `""` algorithm** may interact with `MarkFlagRequired` or
  other prepargs stages — check each command still errors sensibly when
  `-a` is omitted *entirely* (vs bare `-a`). Cobra treats `-a` with no
  value as a flag-needs-argument error unless the flag uses
  `NoOptDefVal`. **This is the crux of "bare -a":** set
  `flag.NoOptDefVal = "?"` (or similar sentinel) so `-a` alone is
  legal and yields the sentinel, which Run interprets as "list".
```
