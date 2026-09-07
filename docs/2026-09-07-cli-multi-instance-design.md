# Addressing several instances of one daemon from tdns-cli

**Date:** 2026-09-07
**Status:** phases 1 and 2 implemented on `feature/multi-instance-cli`
## The problem

A host can run **two independent `tdns-auth` instances**, responsible for
different sets of zones. They are peers, not a pipeline: neither is upstream of
the other.

`tdns-cli` assumes one instance per daemon type — it reaches the authoritative
server through the `apiservers` entry named `tdns-auth` — so the second
instance can only be addressed by putting its config in a separate tree and
passing `--config` on every single command. That is an error source: the flag
is easy to forget, and forgetting it silently operates on the *other*
nameserver.

What we want instead:

```
/etc/tdns/tdns-auth.yaml          # instance 1
/etc/tdns/sec-tdns-auth.yaml      # instance 2, same directory
/etc/tdns/tdns-cli.yaml           # one CLI config that knows about both

tdns-ncli auth    zone list       # instance 1
tdns-ncli sectdns zone list       # instance 2
```

The hard constraint: **the `sectdns` command tree must not be a copy of the
`auth` command tree.** One definition of every command, two targets.

## Why this is achievable

The auth command tree is *already* built by role-parameterised factories. From
`v2/cli/auth_cmds.go` and `cmdv2/cli/shared_cmds.go`:

```go
AuthCmd.AddCommand(NewZoneCmd("auth"))        // 23 subcommands
AuthCmd.AddCommand(NewKeystoreCmd("auth"))
AuthCmd.AddCommand(NewConfigCmd("auth"))
AuthCmd.AddCommand(NewTruststoreCmd("auth"))
AuthCmd.AddCommand(NewDaemonCmd("auth"))
AuthCmd.AddCommand(NewPingCmd("auth"))
AuthCmd.AddCommand(NewDebugCmd("auth"))
AuthCmd.AddCommand(NewDbCmd("auth"))
AuthCmd.AddCommand(NewStopCmd("auth"))
AuthCmd.AddCommand(NewDsyncApiCmd("auth"))
```

and the role -> target indirection already exists (`v2/cli/apiclient.go`):

```go
RegisterRole("auth", "tdns-auth")            // role  -> clientKey
client := tdns.Globals.ApiClients[clientKey] // clientKey -> ApiClient
```

So a second instance is **not a code clone**: it is a second *instantiation*
of the same factories with a different role string. That is the extension
point the package was built with — `tdns-mp` already uses it to override
`agent` -> `tdns-mpagent`.

**Verified empirically, not assumed.** A throwaway test called every factory in
the auth tree twice, with roles `"auth"` and `"sectdns"`:

```
NewZoneCmd: 23 subcommands on each tree
all auth-tree factories instantiated twice without panic
--- PASS
```

No panic, no shared-state damage. The package-level flag variables that these
commands bind to (`force`, `showError`, `errorTimeout`, `tdns.Globals.Zonename`)
are bound twice to two distinct commands, which is harmless: only one command
runs per invocation.

## What blocks it

### 1. Twenty-four call sites hardcode the role

This is the dangerous one, and it is bigger than first estimated.

| File | sites |
|---|---|
| `v2/cli/catalog_cmds.go` | 13 |
| `v2/cli/ksk_rollover_cli.go` | 7 |
| `v2/cli/ddns_cmds.go` | 3 |
| `v2/cli/auto_rollover_validate.go` | 1 |
| **total** | **24** |

They all look like this:

```go
func newKeystoreDnssecPolicyCmd(_ string) *cobra.Command {   // role discarded!
	...
	api, err := GetApiClient("auth", true)                    // ...and hardcoded
```

Note the `_ string`: the role is not merely unused, it is *explicitly
discarded*. Under a per-instance tree, `tdns-ncli sectdns keystore dnssec ds-push`
would silently drive **the wrong nameserver**. Not a crash, not an error
message: a rollover action against the wrong server. Every one of the 24 must
be converted to take and use the role.

These are latent defects today only because there has never been a second
instance. For the current single-instance `tdns-cli` the fix is a provable
no-op — the role at each of those sites *is* `"auth"`.

**Done (phase 2).** All 24 now call `GetApiClientForCmd(cmd, ...)`, which reads
the target off the command tree. Three of the seven in `ksk_rollover_cli.go`
were in helper functions rather than `Run` closures (`runWhenOnline`,
`fetchRolloverStatusOnline`); their only callers are `Run` closures, so the
command is threaded in. `TestNoHardcodedAuthRoleRemains` parses the package and
fails on reintroduction — it parses rather than greps, because a grep matches
prose about the problem, and a guard that cries wolf gets deleted.

The equivalent `"agent"`, `"imr"` and `"scanner"` literals are deliberately
untouched: those daemons have no per-instance tree factory, so their role is
still correct by construction. They become the same conversion the day one is
wanted, and the guard carries a comment saying so.

### 2. Five package-level command vars take no role

`CatalogCmd`, `DdnsCmd`, `DelCmd` and `authImrCmd` are plain `var`s, so they
cannot be instantiated per-instance, and a `*cobra.Command` has exactly one
parent — attaching the same var under two parents corrupts the tree. Each
becomes a `NewXxxCmd(role)` factory, with

```go
var CatalogCmd = NewCatalogCmd("auth")   // compatibility shim
```

kept so existing wiring in `cmdv2/cli/shared_cmds.go` compiles unchanged.

`authImrCmd` is half-done already: `addImrLeafCmds(authImrCmd, "auth")` is
role-parameterised; only the parent var is not.

**Done (phase 2).** `NewCatalogCmd(role)`, `NewDdnsCmd(role)`, `NewDelCmd(role)`
and `NewImrSubtree(role)`, with `var CatalogCmd = NewCatalogCmd("auth")`-style
shims so existing wiring compiles unchanged. The conversions are provably
shape-preserving: `show-cmds` output and the `--help` text of every converted
subtree are byte-identical before and after.

**`ReportCmd` and `NotifyCmd` are deliberately excluded.** They contain no
`GetApiClient` call at all: they are wire-protocol tools (send a NOTIFY, build
a report), not management-API clients. They are not instance-scoped and should
stay on the canonical tree only. Duplicating them would imply a targeting
relationship that does not exist.

### 3. The CLI config is read too late in the lifecycle

`initConfig()` / `initApi()` run from `rootCmd.PersistentPreRun`
(`cmdv2/cli/root.go:41`), which Cobra runs **after** `Find()` has already
resolved the command path. The instance list lives in `tdns-cli.yaml`, so it
must be read *before* `rootCmd.Execute()` for per-instance trees to exist at
routing time.

Fix: hoist a minimal read of just the `apiservers:` block into `Execute()`.
The rest of `initConfig` stays where it is.

## The config shape

One new optional field, `role:`. Backward compatible — an entry whose `name`
already matches a registered clientKey needs nothing.

```yaml
apiservers:
   - name:    tdns-auth              # canonical; name matches the registered clientKey
     baseurl: https://127.0.0.1:8989/api/v1
     apikey:  ...
     authmethod: X-API-Key

   - name:        sectdns            # becomes BOTH the command word and the clientKey
     role:        auth               # NEW: instantiate the "auth" tree against this target
     baseurl:     https://127.0.0.1:8990/api/v1
     apikey:      ...
     authmethod:  X-API-Key
     config-file: /etc/tdns/sec-tdns-auth.yaml
```

Wiring is then two lines per instance:

```go
RegisterRole(e.Name, e.Name)
rootCmd.AddCommand(NewAuthTree(e.Name))
```

`config-file:` **already exists** in `ApiDetails` (`v2/cli/apiclient.go:27`) and
is already used by `tdns-cli agent keys generate/show`. So
`/etc/tdns/sec-tdns-auth.yaml` — the single-directory goal — is already
expressible. `defaultCfgFileForRole` in `config_check_cmds.go` just needs to
prefer `ApiDetails.ConfigFile` over the compiled-in path. That is a fix worth
making on its own account.

**Guard required:** a config instance name must not shadow a built-in role
(`auth`, `agent`, `imr`) or one claimed downstream (`tdns-mp` registers
`signer` and `combiner`). Refuse at startup with a clear message rather than
silently overriding.

## Rejected alternative: Cobra aliases

Setting `AuthCmd.Aliases = []string{"sectdns"}` *does* route a deep subcommand
correctly — verified. But recovering *which* alias was typed does not work the
obvious way:

```
routed OK.  leaf CalledAs()="list"   parent(auth) CalledAs()=""
```

Cobra sets `commandCalledAs.called` only on the executed leaf
(`command.go:1137`). `findNext` does stash the typed name on every command in
the chain (`command.go:802`), but the field is unexported. So the alias would
have to be recovered by scanning `os.Args`.

It works and it is ~50 lines. It has one genuine merit: the override sits
inside `GetApiClient`, so all 24 hardcoded sites come out *right* instead of
silently wrong. But it is hidden global state, and `--help` would misdescribe
what `sectdns` is. Rejected — with the note that the alias trick remains the
emergency fallback if the 24-site conversion runs long.

## Delivery vehicle: a parallel binary, not a change to tdns-cli

Changing `tdns-cli` in place would put every existing invocation, every written
procedure and every expectation of behaviour on a refactor landing cleanly. So
the new behaviour ships as a **second binary alongside the existing one**,
`tdns-ncli` (`cmdv2/ncli/`).

This works because of how the change splits:

| Change | Lives in | Effect on `tdns-cli` |
|---|---|---|
| `Role` field on `ApiDetails` | `v2/cli` (shared) | additive, ignored |
| 24 hardcoded-role fixes | `v2/cli` (shared) | provable no-op (role *is* `"auth"` there) |
| 4 var -> factory conversions | `v2/cli` (shared) | none; `var XCmd = NewXCmd("auth")` shims kept |
| early `apiservers` read | `cmdv2/ncli/root.go` | none — new file |
| per-instance tree wiring | `cmdv2/ncli/root.go` | none — new file |
| help/discovery output | `cmdv2/ncli/root.go` | none — new file |

All the novel and risky logic is isolated in the new binary. What lands in the
shared `v2/cli` package is backward-compatible refactoring that `tdns-cli`
cannot observe.

This is honest about the residual risk rather than claiming there is none: the
`v2/cli` changes *are* shared, so a mistake there reaches `tdns-cli` too. The
mitigations are that the 24 role fixes are no-ops at the current call sites,
the factory conversions keep compatibility shims, and both binaries are built
and exercised side by side.

If `tdns-ncli` graduates it can take over the `tdns-cli` name and the old one
retires; that is a one-line change to `PROG` in the app Makefile. Nothing
forces the question — the two coexist indefinitely at a cost of ~300 bytes,
since both link the same library.

## What went wrong, and what caught it

Phase 2 introduced a real bug and a test caught it before it could ship.

The four canonical trees (`AuthCmd`, `AgentCmd`, `ImrCmd`, `ScannerCmd`) were
originally tagged with their target in **`cmdv2/ncli/shared_cmds.go`** — the new
binary's wiring. That made every `tdns-ncli` command work, and the package's
own tests passed. But `tdns-cli` imports the same library and does no such
tagging, so once the rollover commands under `zone` started resolving their
target from the tree, they were resolving it inside an *untagged* tree — and
`GetApiClientForCmd` correctly refuses an untagged tree rather than guessing.
Every `tdns-cli auth zone dnssec auto-rollover ...` command would have died
with a wiring error.

This is not a compile error, not a failure of any test of the command itself,
and invisible in the binary being worked on. `TestCanonicalAuthTreeStillTargetsAuth`
found it on the first run, because it asks the *library* what `AuthCmd` targets
rather than asking a binary.

The fix is the general lesson: **tag in the library where the tree is declared,
not in a binary's wiring** — one `init()` in `role_target.go`, next to the
mechanism it feeds, so it cannot be dropped when a command file is refactored.

## Work breakdown

Phases 1 and 2 are done. What they cost, against the estimate:

| Task | Est. | Status |
|---|---|---|
| `cmdv2/ncli/` skeleton sharing `v2/cli` | 2h | done |
| `Role` field + instance discovery + collision guard | 2h | done |
| Hoist `apiservers` read ahead of `Execute()` | 2h | done |
| `NewAuthTree(use, role)` | 2h | done |
| Convert `CatalogCmd`, `DdnsCmd`, `DelCmd`, `authImrCmd` | 4h | done |
| Fix 24 hardcoded-role call sites | 5h | done |
| Tests: routing, target resolution, reintroduction guard | 5h | done |
| `defaultCfgFileForRole` prefers `ApiDetails.ConfigFile` | 1h | done |
| Guide page | 4h | done |

Per-role decisions now ask what an instance is a flavour *of* rather than
comparing its name against the three built-in role names, via `effectiveRole`.
An instance with `role: auth` **is** a tdns-auth, so it gets `AppTypeAuth`'s
config sections and `/config/paths` daemon discovery, and `config check` reads
the file its own apiservers entry names:

```
tdns-ncli auth    config check   ->  Checking auth config: /etc/tdns/tdns-auth.yaml
tdns-ncli sectdns config check   ->  Checking sectdns config: /etc/tdns/sec-tdns-auth.yaml
```

which is the single-directory layout working end to end.

`guide/multi-instance-cli.md` covers the config shape, the single-directory
layout, the `listeners.udp-sockets` hazard, reserved instance names, and the
two daemon-side requirements (no pidfile, per-instance API key).

Writing it found a real hole: the guide's list of reserved names was wrong,
because `help`, `completion` and `show-cmds` are added to the command tree
*after* instance wiring runs and so were invisible to the collision check. The
first two are now forced in ahead of wiring; `show-cmds` is reserved by name,
since it must be attached afterwards in order to see the instance trees.
`TestReservedNamesAreAllRefused` keeps the guide's list honest.

## Relationship to tdns-signer

Independent, and this one should land first. The `tdns-signer` scoping
(same session, 2026-09-07) needs no CLI change to be useful, but if a signer
instance is ever added to a host that already runs `tdns-auth`, it inherits
this addressing scheme for free.
