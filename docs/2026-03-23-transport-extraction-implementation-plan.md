# Transport Extraction: Detailed Implementation Plan

Date: 2026-03-23
Status: AGREED — ready for execution
Prerequisite: 2026-03-21-transport-extraction-analysis.md

## Context

The tdns v2 monolith (~190 .go files) needs splitting into
three repos: `tdns` (DNS library), `tdns-transport`
(communication), `tdns-mp` (multi-provider apps). The analysis
doc (`2026-03-21-transport-extraction-analysis.md`) is agreed.
This plan addresses three concerns:

1. **Testable checkpoints** — verify "it works" before
   completion
2. **Testing tdns-transport** — it has no applications of
   its own
3. **Copy-then-delete** — safer than "move"

## Key Architectural Facts

- Sub-packages `core/`, `crypto/`, `edns0/`, `cache/`,
  `hpke/` are **already separate Go modules** with own
  `go.mod` files, linked via `replace` directives. This is
  a huge advantage.
- `agent/transport/` and `distrib/` are part of the main
  `github.com/johanix/tdns/v2` module (no own go.mod).
- All ~55 MP files are `package tdns` — they freely access
  unexported fields of ZoneData, Config, etc. This is the
  **central challenge** for tdns-mp extraction.
- `agent/transport/` is already clean: imports only `core`,
  `distrib`, `edns0`, `crypto` — no globals, no main
  package.

## Application Distribution (Forked Binaries)

Each app exists in both repos: a simplified "DNS-only"
version in tdns, and a full MP version in tdns-mp.

| Binary | Repo | Role |
|---|---|---|
| tdns-auth | tdns | Auth nameserver + DNSSEC signing |
| tdns-agent | tdns | Delegation sync (child/parent DSYNC) |
| tdns-combiner | tdns | Delegation management (simplified) |
| tdns-cli | tdns | CLI for the above |
| dogv2 | tdns | DNS query tool |
| imrv2 | tdns | Recursive resolver |
| tdns-mpsigner | tdns-mp | Inline signer with full MP transport |
| tdns-mpagent | tdns-mp | Full MP agent (gossip, sync, combiner) |
| tdns-mpcombiner | tdns-mp | Full combiner (contributions, coordination) |
| tdns-mpcli | tdns-mp | CLI with agent/combiner/signer MP cmds |

The tdns versions are the "original" pre-MP applications.
The tdns-mp versions are the current full-featured binaries.
This means tdns cleanup (Phase 3) is "strip MP features from
the simplified versions" rather than "delete entire files."

## The Package Boundary Problem

Every MP file is `package tdns` and accesses unexported
fields like `zd.mu`, internal Config fields, etc. Moving
them to tdns-mp means a different Go module/package — they
lose access to all unexported identifiers.

**Chosen approach** (Full Phase 0): Before any extraction,
refactor the monolith to:
- Split InternalConf into DNS vs MP embedded structs
- Extract ZoneData MP fields into ZoneMPExtension
- Export fields MP code needs / add accessors
- Define interface abstractions for cross-boundary calls

This is the bulk of preparatory work and happens entirely
within the monolith where everything is safe and testable.

## Strategy: Copy-Then-Delete

Empty GitHub repos already created and cloned into
`tdns-project/tdns-transport/` and `tdns-project/tdns-mp/`.

For each new repo:
1. Copy tdns content (including `.git/`) into the cloned
   dir, replacing the empty clone's `.git/` with tdns's
   history
2. Re-set the remote to point at the correct GitHub repo
3. Delete files that don't belong (in small committed
   batches)
4. Restructure go.mod and import paths
5. Push to GitHub

The `.git/` copy preserves full history — deletions appear
as normal commits in the new repo. The new repos share
tdns's *past* history but immediately diverge. There is no
ongoing fork relationship — just shared ancestry so
`git log` and `git blame` work for copied code.

The original `tdns/` repo is **never modified** during
extraction. Only after new repos are proven working do we
modify tdns (Phase 3 = stripping MP features, not deleting).

**Phase 3 is low priority.** The MP versions of the apps
work fine. Phase 3 is about enabling other users to use the
simplified apps without pulling all three repos. It can
happen weeks/months after Phases 0-2.

## Commit and Branch Strategy

**Commit gradually.** Every logical step gets its own commit
— never bundle unrelated changes. When deleting files from
a new repo, each batch deletion is a separate commit. When
fixing compilation in Phase 2, each file that compiles gets
committed. The goal: any commit can be reverted without
affecting unrelated work.

**Branching**:
- **tdns repo**: Use a feature branch for Phase 0
  (`phase-0-prep`) since it's preparatory refactoring in
  the monolith. Merge to main after P0-done checkpoint.
  Use another branch for Phase 1.7/1.8 (`transport-switch`)
  when the monolith switches to importing tdns-transport.
- **tdns-transport and tdns-mp**: Work directly on main.
  These repos start as copies and diverge immediately —
  there is no "previous main" to protect. Tag each
  checkpoint (e.g., `phase-1-transport-done`).

**Checkpoint tags**: Tag every verified checkpoint in all
affected repos. Tags are the revert points if something
goes wrong later.

## Testable Checkpoints

| Checkpoint | What we verify |
|---|---|
| P0-done | Monolith builds, all tests pass, full lab test |
| P1-transport | tdns-transport builds+tests, exercise binary runs |
| P1-integrated | Monolith uses tdns-transport via replace, builds, lab test |
| P2-mp | tdns-mp builds, MP binaries work |
| P2-integrated | All 3 repos build, all binaries work, lab test |
| P3-clean | tdns builds standalone, simplified binaries work |

**The monolith remains fully buildable throughout.** We can
always fall back to it.

## Testing tdns-transport

tdns-transport has no applications of its own. Verification:

1. **Existing unit tests** move with it (2 transport + 3
   distrib + 3 crypto tests). Must pass.
2. **`go build ./...`** — compilation is the primary gate.
3. **Exercise binary** — `cmd/transport-exercise/main.go`:
   creates a router, registers test handlers, sends/receives
   a test message via the transport layer. Serves as both
   regression test and API usage documentation.
4. **Integration via monolith** — after P1, update the
   monolith to import tdns-transport. If all binaries build
   and lab test passes, tdns-transport is verified
   end-to-end.
5. **KDC/KRS modernization** (separate project, not just a
   test) — KDC/KRS currently use CHUNKs + distrib directly
   (pre-dating the DNS message router). When distrib/crypto
   move to tdns-transport, KDC/KRS must be re-targeted AND
   modernized to use the DNS message router with custom
   message types suited to KDC/KRS communication patterns.
   This is a real migration effort but validates the
   architecture with the first non-MP consumer. Tracked
   separately from this extraction plan.

---

## Phase 0: Prerequisite Refactoring (in monolith)

All changes in the current single repo. Goal: make the code
splittable without changing any behavior.

### 0.1: Split InternalConf

File: `v2/config.go`

Create two embedded structs:
```go
type InternalDnsConf struct {
    // ~35 DNS fields (KeyDB, RefreshZoneCh, QueryHandlers,
    // ValidatorCh, RecursorCh, ScannerQ, UpdateQ, etc.)
}

type InternalMpConf struct {
    // ~15 MP fields (MsgQs, TransportManager, AgentRegistry,
    // CombinerState, DistributionCache, MPZoneNames, etc.)
}

type InternalConf struct {
    InternalDnsConf
    InternalMpConf
}
```

Embedding preserves all existing field access via promotion.
No behavior change — purely structural preparation.

**Checkpoint**: `go build ./...` and `go test ./...` pass.

### 0.2: Extract MP fields from ZoneData

File: `v2/structs.go`

Move MP fields from ZoneData into a separate struct:
```go
type ZoneMPExtension struct {
    CombinerData         *core.ConcurrentMap[...]
    UpstreamData         *core.ConcurrentMap[...]
    MPdata               *MPdata
    AgentContributions   map[string]map[string]map[uint16]core.RRset
    PersistContributions func(...) error
    LastKeyInventory     *KeyInventorySnapshot
    LocalDNSKEYs         []dns.RR
    KeystateOK           bool
    KeystateError        string
    KeystateTime         time.Time
}
```

**OnFirstLoad stays on ZoneData** — it is used for non-MP
callbacks too (signing, delegation sync).

Add `MP *ZoneMPExtension` to ZoneData. Update ~106 access
sites across 10 files:
`zd.CombinerData` → `zd.MP.CombinerData`, etc.
Most accesses (79/106) are in combiner files that move to
tdns-mp anyway.

**Checkpoint**: build + test pass.

### 0.3: Export fields needed by MP code

Audit all MP files for unexported field access. Key items:
- `zd.mu` → add Lock()/Unlock() methods (or export as Mu)
- Any other unexported fields accessed cross-boundary

Add accessor methods where direct export is inappropriate.

**Checkpoint**: build + test pass.

### 0.4: Define interface abstractions

Create interfaces in tdns that tdns-mp will satisfy:
```go
type MessageEnqueuer interface {
    EnqueueForSpecificAgent(zone, agent string, msg interface{})
}
```

Replace concrete TransportManager references in code that
will stay in tdns (e.g., SDE's one hard reference) with
this interface.

**Checkpoint**: build + test pass.

### 0.5: Full verification

- Build all 6 binaries:
  `cd cmdv2 && GOROOT=/opt/local/lib/go make`
- Deploy to training lab, run multi-provider test suite
- **Tag this commit as "safe harbor"** — the fallback point

---

## Phase 1: Extract tdns-transport

### 1.1: Create repo via copy-then-delete

GitHub repo already cloned at `tdns-project/tdns-transport/`.

```bash
# Replace empty clone's .git with tdns history
rm -rf tdns-transport/.git
cp -r tdns/.git tdns-transport/.git
# Copy tdns content (excluding .git)
rsync -a --exclude='.git' tdns/ tdns-transport/
cd tdns-transport/
git remote set-url origin <tdns-transport-github-url>
git add -A && git commit -m "Import from tdns monolith"
```

Full git history preserved. Shared ancestry, independent
future.

### 1.2: Delete what doesn't belong

Each step is a separate commit:

1. Delete `tdns/` (v1 code)
2. Delete `cmdv2/` (all binaries)
3. Delete `v2/cli/` (CLI commands)
4. Delete all `v2/*.go` (main package files)
5. Delete sub-module dirs: `v2/core/`, `v2/edns0/`,
   `v2/cache/`, `v2/hpke/`, `v2/crypto/`
6. Delete `guide/`, `docs/`, `zonefiles/`, etc.

What remains:
```
tdns-transport/v2/
    agent/transport/   (17 .go files)
    distrib/           (11 .go files)
```

### 1.3: Restructure and create go.mod

Flatten `agent/transport/` → `v2/transport/` for cleaner
paths.

New `v2/go.mod`:
```
module github.com/johanix/tdns-transport/v2

require (
    github.com/johanix/tdns/v2/core v0.0.0
    github.com/johanix/tdns/v2/edns0 v0.0.0
    github.com/johanix/tdns/v2/crypto v0.0.0
)

replace (
    github.com/johanix/tdns/v2/core => ../../tdns/v2/core
    github.com/johanix/tdns/v2/edns0 => ../../tdns/v2/edns0
    github.com/johanix/tdns/v2/crypto => ../../tdns/v2/crypto
)
```

### 1.4: Update import paths

In transport/ and distrib/ files:
- Internal cross-references → within-module paths
- External (core, edns0, crypto) → keep tdns paths

### 1.5: Extract message types from core/messages.go

Copy transport message types (AgentMsg constants, all Post/
Response structs) to
`tdns-transport/v2/messages/messages.go`. Pure structs with
json tags — trivial extraction.

Types remain in tdns/core temporarily (monolith still needs
them). Removed from tdns in Phase 3.

### 1.6: Create exercise binary

`tdns-transport/v2/cmd/transport-exercise/main.go`:
- Creates a DNSMessageRouter
- Registers test handlers for hello/beat/sync
- Creates PeerRegistry with a test peer
- Exercises send/receive through the router
- Verifies crypto middleware pipeline
- Prints "PASS" on success

Serves as regression test + API documentation.

**Checkpoint P1-transport**:
`cd tdns-transport/v2 && go build ./... && go test ./...`
Exercise binary runs successfully.

### 1.7: Integrate into monolith

**This step modifies tdns** — the only Phase 1 step that
does.

In `tdns/v2/go.mod`, add:
```
require github.com/johanix/tdns-transport/v2 v0.0.0
replace github.com/johanix/tdns-transport/v2 => ../tdns-transport/v2
```

Update import paths in ~35 .go files across the monolith:
- `github.com/johanix/tdns/v2/agent/transport` →
  `github.com/johanix/tdns-transport/v2/transport`
- `github.com/johanix/tdns/v2/distrib` →
  `github.com/johanix/tdns-transport/v2/distrib`

Commit the go.mod change and all import path changes
together.

### 1.8: Delete extracted code from monolith

Delete `v2/agent/transport/` and `v2/distrib/` from tdns.
Separate commit after 1.7 is verified.

**Checkpoint P1-integrated**:
- `cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make` — all
  binaries
- All tests pass
- Deploy to lab, verify full system
- **Safe stopping point** — working two-repo setup

---

## Phase 2: Extract tdns-mp

Hardest phase due to package boundary + forked applications.

### 2.1: Create repo via copy-then-delete

GitHub repo already cloned at `tdns-project/tdns-mp/`.

```bash
# Same pattern as Phase 1
rm -rf tdns-mp/.git
cp -r tdns/.git tdns-mp/.git
rsync -a --exclude='.git' tdns/ tdns-mp/
cd tdns-mp/
git remote set-url origin <tdns-mp-github-url>
git add -A && git commit -m "Import from tdns monolith"
```

### 2.2: Delete what doesn't belong

Each step is a separate commit:

1. Delete `tdns/` (v1 code)
2. Delete pure-DNS-only apps: `cmdv2/imrv2/`,
   `cmdv2/dogv2/`
3. Delete sub-module dirs: `v2/core/`, `v2/edns0/`,
   `v2/cache/`, `v2/hpke/`, `v2/crypto/`
4. Delete `v2/agent/transport/`, `v2/distrib/`
   (in tdns-transport)
5. Delete pure-DNS files from `v2/*.go` — commit in batches
   Keep: `agent_*`, `combiner_*`, `signer_*`, `hsync_*`,
   `syncheddataengine.go`, `reliable_message_queue.go`,
   `gossip.go`, `provider_groups.go`,
   `key_state_worker.go`, `keystate.go`,
   `delegation_sync.go`, `parentsync_*`, MP API handlers,
   MP DB files
6. Delete pure-DNS CLI from `v2/cli/`
   Keep: `agent_*`, `combiner_*`, `signer_*`, `hsync_*`,
   `distrib_*`, `transaction_*`

### 2.3: Change package and create go.mod

Change `package tdns` → `package mp` in all remaining
v2/*.go.

New `v2/go.mod`:
```
module github.com/johanix/tdns-mp/v2

require (
    github.com/johanix/tdns/v2 v0.0.0
    github.com/johanix/tdns-transport/v2 v0.0.0
    github.com/johanix/tdns/v2/core v0.0.0
    github.com/johanix/tdns/v2/edns0 v0.0.0
    github.com/johanix/tdns/v2/crypto v0.0.0
    github.com/johanix/tdns/v2/cache v0.0.0
)

replace (
    github.com/johanix/tdns/v2 => ../../tdns/v2
    github.com/johanix/tdns-transport/v2 => ../../tdns-transport/v2
    github.com/johanix/tdns/v2/core => ../../tdns/v2/core
    github.com/johanix/tdns/v2/edns0 => ../../tdns/v2/edns0
    github.com/johanix/tdns/v2/crypto => ../../tdns/v2/crypto
    github.com/johanix/tdns/v2/cache => ../../tdns/v2/cache
)
```

### 2.4: Fix compilation — the hard part

All references to tdns types need qualifying:
- `*ZoneData` → `*tdns.ZoneData`
- `Conf.Internal` → qualified access via tdns package
- Unexported field access → use accessors added in Phase 0

~50 files, potentially hundreds of references. Approach:
fix one file at a time, commit after each compiles.

### 2.5: Rename application binaries

- `cmdv2/agentv2/` → builds `tdns-mpagent`
- `cmdv2/combinerv2/` → builds `tdns-mpcombiner`
- `cmdv2/authv2/` → builds `tdns-mpsigner`
- `cmdv2/cliv2/` → builds `tdns-mpcli`

Update Makefiles with new binary names.

**Checkpoint P2-mp**: `cd tdns-mp/v2 && go build ./...`

### 2.6: Verify integration

**Checkpoint P2-integrated**:
- tdns-mpagent, tdns-mpcombiner, tdns-mpsigner, tdns-mpcli
  build from tdns-mp
- All tdns binaries still build from tdns
- Deploy to lab, full system test with MP binaries

---

## Phase 3: Simplify tdns (LOW PRIORITY — separate effort)

This phase strips MP features from tdns to create simplified
"back to basics" versions of the applications. It is **not
on the critical path** — the full MP versions of all apps
work fine after Phases 0-2. This is about enabling other
users to use tdns applications without pulling in all three
repos.

Can happen weeks or months after Phase 2.

### 3.1: Remove MP-only code from tdns

Delete files with no simplified equivalent: `gossip.go`,
`provider_groups.go`, `combiner_msg_handler.go`,
`combiner_chunk.go`, `hsyncengine.go`,
`hsync_transport.go`, `syncheddataengine.go`,
`reliable_message_queue.go`, `key_state_worker.go`, MP API
handlers, MP DB files, etc.

### 3.2: Strip MP from shared files

Remove InternalMpConf, ZoneMPExtension, StartAgent MP
wiring, MP config parsing from `config.go`, `structs.go`,
`main_initfuncs.go`, `parseconfig.go`.

### 3.3: Simplify application binaries

- **tdns-agent**: delegation sync (DSYNC child/parent) only
- **tdns-auth**: auth nameserver + DNSSEC, no MP signer role
- **tdns-combiner**: delegation management only
- **tdns-cli**: DNS commands only (zone, rrset, debug, dsync)

### 3.4: Remove tdns-transport dependency

After stripping, tdns has zero tdns-transport imports.

**Checkpoint P3-clean**: tdns builds standalone, all
simplified binaries work, tdns usable as pure DNS library.

---

## Risk Summary

| Risk | Mitigation |
|---|---|
| Lost code during extraction | Copy-then-delete, never modify original |
| Package boundary breaks | Phase 0 exports/accessors done in monolith first |
| Build breaks | Monolith stays buildable throughout |
| Integration regression | Lab test at every checkpoint |
| Phase 2 too hard | Phase 1 is a safe stopping point |
| Forked binaries diverge | Clear naming (tdns-X vs tdns-mpX) |

## Estimated Effort

- Phase 0: 1 week (InternalConf split, ZoneData extraction,
  accessors, interface abstractions)
- Phase 1: 2-3 days (transport is already clean)
- Phase 2: 1-2 weeks (package boundary + ~50 files)
- **Critical path total: ~3-4 weeks (Phases 0-2)**
- Phase 3: 1 week (deferred — separate effort, low priority)

## Verification Strategy

At each checkpoint:
1. `go build ./...` in each repo
2. `go test ./...` in each repo
3. Build all relevant binaries
4. Deploy to NetBSD training lab
5. Run multi-provider quickstart scenario (MP binaries)
6. Run delegation sync scenario (simplified binaries)
7. Verify CLI commands against running services
