# Signer-First tdns-mp Extraction

## Context

The original approach (copy entire tdns, delete non-MP
files, fix compilation) hit a wall: 69 files, 211 methods
on tdns types, massive cross-dependencies. The half-baked
tdns-mp repo doesn't compile and has no clear path forward.

New approach: start fresh, move one role at a time. The
signer has the smallest MP footprint — only 4 MP-specific
files. Move it first, learn from it, then combiner, then
agent.

## Step 0: Fresh start for tdns-mp

Scrap everything including the inherited tdns history.
Start with a clean empty repo.

```bash
cd tdns-mp
remote=$(git remote get-url origin)
rm -rf .git
git init
git remote add origin $remote
# Add .gitignore, LICENSE, README.md
git add -A && git commit -m "Initial: signer-first extraction"
git branch -M main
git push --force origin main
```

Then update clones on build server:
```bash
git fetch --all && git reset --hard origin/main
```

Create minimal structure:
```
tdns-mp/
  v2/
    go.mod   (module github.com/johanix/tdns-mp/v2)
  cmd/
    mpsigner/   (binary)
```

## Step 0.5: Hello-world verification

Before copying real files, verify the basic setup works:
create a trivial tdns-mp package that imports tdns and
tdns-transport, compiles, and runs.

```
v2/hello.go:
    package tdnsmp

    import tdns "github.com/johanix/tdns/v2"

    func Hello() string {
        return "tdns-mp using tdns " + tdns.Version
    }

cmd/hello/main.go:
    package main

    import (
        "fmt"
        tdnsmp "github.com/johanix/tdns-mp/v2"
    )

    func main() {
        fmt.Println(tdnsmp.Hello())
    }
```

Build and run. If this works, the module structure,
replace directives, and cross-repo imports are correct.
Delete hello.go and cmd/hello/ after verification.

## Step 0.6: Config struct with embedding

The `tdnsmp.Config` embeds `tdns.Config` and adds
MP-specific configuration and internal state:

```go
type Config struct {
    tdns.Config                      // DNS config (embedded)
    // MP config fields will migrate here from tdns
    // as each piece is extracted
}
```

MainInit is a receiver on `*tdnsmp.Config`:

```go
func (conf *Config) MainInit(ctx context.Context,
    defaultcfg string) error {
    // DNS infrastructure (call through to embedded tdns.Config)
    if err := conf.Config.MainInit(ctx, defaultcfg); err != nil {
        return err
    }
    // MP additions on top
    conf.initSignerCrypto()
    conf.createTransportManager()
    conf.registerChunkHandler()
    conf.registerPeers()
    return nil
}
```

When calling into tdns, the embedded `conf.Config` is
passed automatically (or explicitly as `&conf.Config`).
MP-specific state (InternalMpConf fields like MsgQs,
TransportManager, AgentRegistry) will eventually move
from `tdns.InternalMpConf` to the tdnsmp.Config. For now
they stay in tdns.Config via the embedded InternalMpConf
and are accessed through the embedding.

The binary creates `tdnsmp.Config`:

```go
func main() {
    var conf tdnsmp.Config
    conf.MainInit(ctx, defaultcfg)
    conf.StartMPSigner(ctx)
    conf.Config.MainLoop(ctx, cancel)
}
```

## Step 1: Copy signer-specific files

Only 4 MP-specific files (into `v2/`):
- `signer_msg_handler.go` — MsgQs consumer, KEYSTATE
- `signer_transport.go` — JOSE crypto initialization
- `key_state_worker.go` — automatic key state transitions
- `signer_chunk_handler.go` — extracted from
  combiner_chunk.go (just RegisterSignerChunkHandler)

Plus startup orchestration (new files in `v2/`):
- `main_init.go` — MainInit()
- `start_signer.go` — StartMPSigner()

Plus the binary:
- `cmd/mpsigner/main.go` (adapted from tdns authv2)

## Key Design Decision: Startup Model

tdns-mp's `MainInit()` calls `tdns.MainInit()` for all
DNS infrastructure, then adds MP components on top:

```go
func MainInit(conf *tdns.Config, ...) error {
    // DNS infrastructure (delegates to tdns)
    tdns.MainInit(conf, ...)

    // MP additions
    initSignerCrypto(conf)
    createTransportManager(conf)
    registerChunkHandler(conf)
    registerPeers(conf)
    return nil
}

func StartMPSigner(conf *tdns.Config, ...) error {
    // DNS engines (delegates to tdns)
    tdns.StartAuth(conf, ...)

    // MP engines
    startSignerMsgHandler(conf)
    startKeyStateWorker(conf)
    startSignerSyncRouter(conf)
    return nil
}
```

This avoids replicating tdns startup ordering and stays
in sync as tdns evolves. The MP code in tdns.MainInit()
runs harmlessly (guarded by conf.MultiProvider.Active).
When we eventually strip MP from tdns, those guards
become dead code that gets removed.

## Key Design Decision: API Router

tdns already has `RegisterAPIRoute(func(router *mux.Router)
error)` in registration.go. tdns-mp registers MP-specific
API endpoints before APIdispatcher starts:

```go
tdns.RegisterAPIRoute(func(router *mux.Router) error {
    router.HandleFunc("/api/v1/signer/keystate",
        signerKeystateHandler).Methods("POST")
    return nil
})
```

No local router needed. tdns serves all endpoints,
tdns-mp just registers additional ones.

## Step 2: Create go.mod and try to compile

```
module github.com/johanix/tdns-mp/v2

replace (
    github.com/johanix/tdns/v2 => ../../tdns/v2
    github.com/johanix/tdns-transport/v2 => ../../tdns-transport/v2
    github.com/johanix/tdns/v2/core => ../../tdns/v2/core
    github.com/johanix/tdns/v2/edns0 => ../../tdns/v2/edns0
    github.com/johanix/tdns/v2/cache => ../../tdns/v2/cache
)
```

Package is `package tdnsmp`. Files import:
- `tdns "github.com/johanix/tdns/v2"` for types
- `"github.com/johanix/tdns-transport/v2/transport"` for TM

## Step 3: Fix compilation iteratively

The 4 MP files will have unresolved references. Expected:

**signer_msg_handler.go**:
- Already standalone functions (not methods on tdns types)
- Needs `tdns.` prefix on types: Config, KeyDB, MsgQs
- Calls `sendKeystateInventoryToAgent` — also standalone

**signer_transport.go**:
- `initSignerCrypto(conf *Config)` — standalone
- Needs `tdns.Config` prefix
- Uses `transport.PayloadCrypto`, `jose.Backend`

**key_state_worker.go**:
- `KeyStateWorker(ctx, conf)` — standalone
- Uses `tdns.Config`, `tdns.KeyDB`, `tdns.Zones`
- Calls `triggerResign` — unexported in tdns, needs wrapper

**signer_chunk_handler.go**:
- `RegisterSignerChunkHandler()` — standalone
- Creates `CombinerState` (type stays in tdns)
- Calls `tdns.RegisterNotifyHandler` — already exported

For each unresolved reference:
- Type: use `tdns.TypeName`
- Exported function in tdns: call `tdns.FuncName()`
- Unexported function in tdns: create wrapper in
  tdns/v2/wrappers.go

## Step 4: Create wrappers in tdns as needed

Add to `tdns/v2/wrappers.go`. Expected:
- `TriggerResign(conf *Config, zone string)` — wraps
  unexported `triggerResign`
- Possibly a few more; compiler will tell us

KeyDB methods are already exported (methods on *KeyDB),
so they're callable cross-package without wrappers.

## Step 5: Binary (cmd/mpsigner)

```go
package main

import (
    tdns "github.com/johanix/tdns/v2"
    tdnsmp "github.com/johanix/tdns-mp/v2"
)

func main() {
    // ... flag parsing, config loading ...
    tdnsmp.MainInit(conf, ctx)
    tdnsmp.StartMPSigner(conf, ctx)
    tdns.MainLoop(conf)
}
```

## Step 6: CLI tool (cmd/mpcli)

tdns-cli is structured as a thin shell that loads cobra
commands via shared_cmds.go. We follow the same pattern
for mpcli: pick and choose which command sets to include.

```
cmd/mpcli/
    main.go        — app setup, cobra root command
    shared_cmds.go — imports selected command sets
```

shared_cmds.go imports:
- From tdns/v2/cli: base commands that apply to all apps
  (ping, version, daemon, zone list, etc.)
- From tdns-mp/v2/cli: MP-specific signer commands
  (auth peer, keystate, etc.)

tdns-mp/v2/cli/ contains signer-specific CLI commands
adapted from tdns/v2/cli/auth_cmds.go and
auth_peer_cmds.go. These register cobra commands that
talk to the mpsigner API.

API endpoint access: mpcli sends commands to whatever
endpoints the mpsigner exposes. Endpoints that don't
apply (pure-DNS agent commands etc.) simply aren't
exposed as CLI commands — no de-registration needed.

## Step 7: Verify

- tdns-mp builds: `cd v2 && go build ./...`
- mpsigner binary builds: `cd cmd/mpsigner && go build`
- mpcli binary builds: `cd cmd/mpcli && go build`
- tdns unchanged: all 6 binaries still build from tdns
- Lab test: mpsigner handles KEYSTATE, beats, pings
- Lab test: mpcli can ping, show status, peer operations

## Files in tdns-mp (signer)

**MP-specific logic** (copied from tdns, adapted):
1. `v2/signer_msg_handler.go`
2. `v2/signer_transport.go`
3. `v2/key_state_worker.go`
4. `v2/signer_chunk_handler.go`

**Startup orchestration** (new):
5. `v2/main_init.go` — MainInit()
6. `v2/start_signer.go` — StartMPSigner()

**CLI commands** (copied from tdns/v2/cli/, adapted):
7. `v2/cli/auth_cmds.go` — signer commands
8. `v2/cli/auth_peer_cmds.go` — peer operations
9. `v2/cli/hsync_cmds.go` — HSYNC commands
10. `v2/cli/hsync_debug_cmds.go` — HSYNC debug
11. `v2/cli/distrib_cmds.go` — distribution tracking
12. `v2/cli/jose_keys_cmds.go` — JOSE key management
13. `v2/cli/jwt_cmds.go` — JWT operations
14. `v2/cli/keys_generate_cmds.go` — key generation
15. `v2/cli/keystore_cmds.go` — keystore operations
16. `v2/cli/transaction_cmds.go` — transaction tracking

The mpcli binary registers commands from BOTH:
- `tdns/v2/cli` — base commands (ping, version, daemon,
  zone list, config, debug, etc.)
- `tdns-mp/v2/cli` — MP commands listed above

When combiner/agent are added later, their CLI files
(agent_*.go, combiner_*.go, parentsync_cmds.go) also
move to tdns-mp/v2/cli/.

**Binaries**:
17. `cmd/mpsigner/main.go`
18. `cmd/mpcli/main.go`
19. `cmd/mpcli/shared_cmds.go`

## What tdns needs to export

Wrappers in `tdns/v2/wrappers.go`:
- `TriggerResign` — wraps unexported triggerResign
- Others TBD (compiler-driven)

Already exported and usable:
- `MainInit`, `StartAuth`, `MainLoop`
- `APIdispatcher`, `RefreshEngine`, `DnsEngine`
- `RegisterNotifyHandler`, `RegisterAPIRoute`
- All KeyDB methods
- All Config methods

## Estimated Scope

- 16 files in tdns-mp v2/ (~2500-3500 lines, mostly adapted)
- 3 binary/CLI files (~100 lines)
- ~5-10 wrappers in tdns/v2/wrappers.go
- 0 changes to existing tdns logic (only additions)

## Risk

Low. MainInit/StartAuth handle DNS setup, tdns-mp layers
MP on top. No startup ordering to replicate. API routes
use existing registration mechanism.

## Future: Combiner and Agent

After signer works:
- Combiner: add CombinerMsgHandler, combiner_utils,
  agent policy, API handlers. Same startup pattern.
- Agent: add HsyncEngine, SDE, gossip, provider groups,
  leader election, agent discovery. Biggest scope.

Each role adds its own `Start*()` function and registers
its engines/handlers. The `MainInit()` pattern is shared.
