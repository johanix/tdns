# Transport Extraction Analysis: Three-Repo Architecture

Date: 2026-03-21
Status: AGREED — ready for detailed planning

## Goal

Split the tdns v2 monolith into three repos with a clear
dependency chain, keeping each focused on a single concern:

```
tdns-mp  →  tdns-transport  →  tdns
 (apps)     (communication)    (pure DNS)

any-app  →  tdns-transport  →  tdns
```

Two major drivers for this split:

**1. Navigability and change safety.** The v2 codebase is
approaching the point where it is difficult to navigate
and all changes become increasingly risky. The monolith
has ~190 .go files with deep cross-cutting concerns.
Splitting reduces the cognitive load per repo and makes
each change's blast radius smaller and more predictable.

**2. Reusability of the transport layer.** The CHUNK/JOSE framework and the DNS
message router are general-purpose infrastructure for
secure, reliable communication over DNS. They should be
usable by any application — not just multi-provider DNS.

The first concrete non-MP consumers are **KDC/KRS** (Key
Distribution Center / Key Receiver Service) for DNSSEC
private key distribution. They already use CHUNKs for
payload delivery but currently use HPKE inside CHUNK
rather than JOSE. They have nothing to do with
multi-provider — no SDE, no gossip, no combiner, no
agent coordination. They just need the transport
framework for secure message delivery over DNS.

After extraction, KDC/KRS would import tdns + tdns-transport
and get CHUNK transport + JOSE crypto without pulling in
any multi-provider machinery. This is the validation case
for the architecture.

Other future consumers:
- Management/control plane applications
- Any app needing authenticated, encrypted messaging
  between distributed components over DNS

By isolating tdns-transport as its own repo, any app can
import it alongside tdns without pulling in the entire
multi-provider stack (SDE, combiner logic, gossip, etc.).

## The Three Repos

### tdns — Pure DNS Library

DNS protocol implementation. Zones, queries, signing,
refresh, UPDATE/NOTIFY, caches. No knowledge of
multi-provider or agent-to-agent communication.

### tdns-transport — Communication Layer

General-purpose infrastructure for secure, reliable
communication over DNS. The CHUNK/JOSE framework, DNS
message router, transport abstractions, peer management,
and crypto middleware. Knows how to send/receive messages
between endpoints but has no opinion about what the
messages mean or what to do with the data.

This is a **reusable library** — any application can import
it to get authenticated, encrypted, reliable messaging
over DNS without taking a dependency on multi-provider
logic. Imports tdns for DNS primitives only.

### tdns-mp — Multi-Provider Applications

The application layer. SDE, HsyncEngine, combiner/signer
message handlers, agent discovery/authorization, role-specific
wiring, CLI commands for agent/combiner/signer. Imports both
tdns and tdns-transport.

## What Goes Where

### tdns (stays)

**Zone management:**
- Zone loading, parsing, serving
- ZoneDataRepo (pure zone data storage)
- Refresh engine
- Query handlers (DefaultQueryHandler, etc.)
- UPDATE/NOTIFY responders

**DNSSEC:**
- Signing, validation
- Key management (non-transport)
- DSYNC/delegation sync protocol basics

**DNS types:**
- All RR types including CHUNK, HSYNC3, HSYNCPARAM
  (DNS wire format — must be parseable by any DNS library)
- EDNS0 extensions
- DNS client

**Infrastructure:**
- Config basics (non-MP parts of config.go)
- CLI framework
- Cache modules
- Database layer (non-HSYNC tables)

### tdns-transport (new repo)

**Transport abstractions:**
- `agent/transport/` — 18 files, entire package
  - Transport interface (Hello, Beat, Sync, Confirm, etc.)
  - DNSTransport implementation (NOTIFY+CHUNK)
  - APITransport implementation (HTTPS REST)
  - DNSMessageRouter + middleware chain
  - Message handlers (HandleBeat, HandleSync, etc.)
  - ChunkNotifyHandler
  - PayloadCrypto (JWS/JWE)
  - Peer + PeerRegistry

**Distribution tracking:**
- `distrib/` — 12 files, distribution manifest/tracking

**Payload crypto:**
- `crypto/` — 6 files, JWS/JWE encryption (not DNSSEC)
- `hpke/` — 8 files, HPKE encryption (used by KDC/KRS)

**Message types:**
- AgentMsg constants (hello, beat, sync, update, etc.)
- AgentHelloPost, AgentBeatPost, AgentMsgPost, etc.
- PublishInstruction, RROperation
- All message serialization structs
- (Extracted from current core/messages.go)

**Transport manager core:**
- TransportManager struct + NewTransportManager
- Reliable message queue
- MsgQs channel struct definition

### tdns-mp (new repo)

**Sync engine:**
- SynchedDataEngine (wraps tdns ZoneDataRepo, adds sync
  state tracking, confirmation, remote agent tracking)
- HsyncEngine (agent-side message consumer)
- hsync_utils.go, hsync_beat.go, hsync_hello.go

**Role-specific message handlers:**
- CombinerMsgHandler (consumes MsgQs, calls
  CombinerProcessUpdate)
- SignerMsgHandler (consumes MsgQs, DNSKEY processing)

**Agent coordination:**
- agent_authorization.go (IsPeerAuthorized)
- agent_discovery.go (DNS-based peer discovery)
- gossip.go (GossipStateTable)
- provider_groups.go (ProviderGroupManager)

**Combiner/signer logic:**
- combiner_msg_handler.go, combiner_peer.go,
  combiner_chunk.go, combiner_utils.go
- signer_msg_handler.go, signer_peer.go,
  signer_transport.go
- CombinerProcessUpdate, agent policy evaluation

**Application wiring:**
- StartAgent, StartCombiner, StartAuth (role init)
- Multi-provider parts of main_initfuncs.go
- Multi-provider parts of config.go / parseconfig.go

**API handlers:**
- apihandler_agent.go, apihandler_agent_router.go
- apihandler_combiner.go

**Database:**
- db_hsync.go (HSYNC persistence)
- db_combiner_publish_instructions.go
- CombinerContributions tables

**CLI commands:**
- Agent/combiner/signer-specific CLI commands from v2/cli/
- Agent debug commands (RFI, resync, etc.)

**Application binaries:**
- agentv2, combinerv2, authv2 main packages
- (These currently live in tdns/cmdv2/ and would move)

## Current Separation Quality

The `agent/transport` package is already clean — zero
references to `Conf` or globals, everything injected via
interfaces and closures. This is the easiest part to extract.

The SDE is the most coupled component but moves entirely
to tdns-mp, avoiding the need to split it. It will import
tdns for ZoneDataRepo and tdns-transport for message types.

## Interface Boundaries

### tdns exports (consumed by tdns-transport)

- DNS RR types (dns.RR, CHUNK, HSYNC3, etc.)
- Zone data types (RRset, zone name types)
- DNS client for transport operations
- EDNS0 option types

### tdns-transport exports (consumed by tdns-mp and any app)

- Transport interface + implementations
- DNSMessageRouter + middleware pipeline
- PeerRegistry + Peer state machine
- MessageContext for handler functions
- ReliableMessageQueue
- MsgQs channel struct
- Message type constants and structs
- Distribution tracking
- PayloadCrypto (JWS/JWE)
- ChunkNotifyHandler

Any application can register its own message types and
handlers with the router. The middleware pipeline (auth,
crypto, stats, logging) works regardless of message
semantics. An app needs only to:
1. Import tdns-transport
2. Create a DNSMessageRouter
3. Register handlers for its own message types
4. Plug in crypto keys and peer authorization logic

### tdns-mp exports (consumed by application binaries)

- StartAgent(), StartCombiner(), StartAuth()
- CLI command registration
- Config types for multi-provider settings

## File-by-File Assignment

### Files staying in tdns

Core DNS:
- zone_*.go (zone loading, parsing)
- defaultqueryhandlers.go, updateresponder.go,
  notifyresponder.go
- sign.go, resigner.go, dnssec_validate.go
- refreshengine.go, structs.go
- dnslookup.go, zone_utils.go
- cache/*.go, edns0/*.go, hpke/*.go

Core types:
- core/rr_*.go (all RR types including CHUNK, HSYNC3)
- core/core_structs.go, core/rrset_utils.go
- core/chunk_utilities.go, core/notify_helpers.go
- core/dnsclient.go, core/transport.go
- core/concurrent_map.go, core/miek_utils.go

Config (DNS parts):
- Parts of config.go not related to MP
- Parts of parseconfig.go not related to MP

### Files moving to tdns-transport

Transport package (move as-is):
- agent/transport/transport.go
- agent/transport/api.go
- agent/transport/dns.go
- agent/transport/dns_message_router.go
- agent/transport/router_init.go
- agent/transport/handlers.go
- agent/transport/handler.go
- agent/transport/chunk_notify_handler.go
- agent/transport/crypto.go
- agent/transport/crypto_middleware.go
- agent/transport/stats_middleware.go
- agent/transport/peer.go
- agent/transport/log.go
- agent/transport/doc.go
- agent/transport/init.go
- agent/transport/*_test.go

Sub-packages (move as-is):
- distrib/*.go (12 files)
- crypto/*.go (6 files, JWS/JWE only)

From v2 root:
- reliable_message_queue.go

From core (extract):
- Message types from core/messages.go
- core/confirmation.go (ConfirmationAccumulator)

### Files moving to tdns-mp

SDE + sync engine:
- syncheddataengine.go
- hsyncengine.go
- hsync_transport.go
- hsync_utils.go
- hsync_beat.go
- hsync_hello.go

Role handlers:
- combiner_msg_handler.go
- combiner_peer.go
- combiner_chunk.go
- combiner_utils.go
- signer_msg_handler.go
- signer_peer.go
- signer_transport.go

Agent coordination:
- agent_authorization.go
- agent_discovery.go
- agent_utils.go
- agent_policy.go
- agent_structs.go (AgentRegistry, etc.)
- gossip.go
- provider_groups.go

Database:
- db_hsync.go
- db_combiner_publish_instructions.go

API handlers:
- apihandler_agent.go
- apihandler_agent_router.go
- apihandler_combiner.go

Config (MP parts):
- MultiProviderConf, MsgQs from config.go
- MP-related parts of parseconfig.go
- MP-related parts of main_initfuncs.go

CLI commands (from v2/cli/):
- agent_*_cmds.go
- combiner_*_cmds.go
- signer_*_cmds.go
- MP-specific debug commands

Application binaries:
- cmdv2/agentv2/
- cmdv2/combinerv2/
- cmdv2/authv2/

## Risks and Considerations

1. **Three repos = more build complexity.** Coordinating
   versions across three go.mod files. Mitigated by go.mod
   replace directives during development.

2. **config.go split.** Currently one large file with both
   DNS and MP config. Must be cleanly divided. MsgQs and
   MultiProviderConf move to tdns-mp (or tdns-transport
   for MsgQs).

3. **main_initfuncs.go split.** Role initialization mixes
   DNS setup (zone loading, query handler registration)
   with MP setup (transport manager, peer registration).
   Must be split into DNS init (tdns) + MP init (tdns-mp).

4. **CLI command split.** v2/cli/ has ~100 files mixing DNS
   and MP commands. Need to identify which are pure DNS
   (zone, rrset, debug) vs MP (agent, combiner, signer,
   resync, peer, gossip).

5. **CHUNK RR stays in tdns** even though only transport
   uses it. It's a DNS wire format type — any DNS library
   should parse it.

6. **No external consumers currently.** All transport usage
   is internal. cmdv2/ binaries use Config API, never import
   transport directly. Full freedom to restructure.

7. **core/messages.go extraction.** This file mixes DNS
   message types with transport message types. Need careful
   separation — transport structs to tdns-transport, DNS
   types stay in tdns/core.

## Implementation Order

### Phase 1: tdns-transport extraction

Lowest risk, cleanest boundaries:
1. Create tdns-transport repo
2. Move agent/transport/, distrib/, crypto/ as-is
3. Extract message types from core/messages.go
4. Move reliable_message_queue.go
5. Update import paths, verify build

### Phase 2: tdns-mp extraction

Higher complexity, requires config split:
1. Create tdns-mp repo
2. Move SDE, HsyncEngine, message handlers
3. Move agent coordination (gossip, provider groups, etc.)
4. Split config.go and main_initfuncs.go
5. Move role-specific CLI commands
6. Move application binaries (cmdv2/agent, combiner, auth)
7. Update import paths, verify build

### Phase 3: Cleanup

1. Remove dead imports from tdns
2. Verify tdns builds and works standalone (IMR, dog, etc.)
3. Verify tdns-transport builds with only tdns dependency
4. Verify tdns-mp builds with both dependencies
5. Update all design docs

## Complexity Analysis (Rough Estimate)

### Overall assessment: MEDIUM-HIGH

The extraction is doable but not trivial. The main
complexity is not in the transport layer itself (which is
already clean) but in the **integration plumbing** —
Config.Internal, main_initfuncs.go, and the ZoneData
struct that spans all three concerns.

### What's clean (low effort)

**agent/transport/ package** — already self-contained,
zero imports of tdns root, only imports core/ for message
types. Can move to tdns-transport almost as-is. Same for
distrib/ and crypto/ (JWS/JWE).

**core/messages.go** — pure structs with json tags.
Zero coupling to transport or MP infrastructure. Trivial
to extract into tdns-transport.

**CLI commands** — clearly split: ~33 files pure DNS,
~18 files MP-specific (agent_*, combiner_*, hsync_*,
distrib_*). The MP commands move to tdns-mp.

### What's tangled (high effort)

**Config.Internal** (~50 fields, 15 MP-specific mixed
with ~35 DNS fields). This is the main coupling point.
MsgQs, TransportManager, AgentRegistry, CombinerState,
DistributionCache, LeaderElectionManager all live here
alongside RefreshZoneCh, QueryHandlers, KeyDB, etc.

Prerequisite: split InternalConf into InternalDnsConf
(stays in tdns) and InternalMpConf (moves to tdns-mp).
~300 lines of refactoring + updating all access sites.

**main_initfuncs.go** — MainInit() mixes DNS setup
(zone parsing, channel creation, KeyDB) with MP setup
(TransportManager, PayloadCrypto, peer registration)
sequentially. StartAgent/StartCombiner/StartAuth are
role-specific but each mixes DNS init with MP init.

Need to split into: DNS init (tdns) called first, then
MP init (tdns-mp) layered on top.

**ZoneData struct** (in structs.go) — has fields for
all roles: AgentContributions, PersistContributions,
OnFirstLoad callbacks, LeaderElectionManager ref. These
are MP concerns embedded in a DNS data structure.

**SDE** — syncheddataengine.go has zero transport imports
(good!) but uses MsgQs channels via parameter injection
and has one hard reference to
TransportManager.EnqueueForSpecificAgent(). Need a small
interface abstraction (MessageEnqueuer) to decouple.

### Concrete numbers

| What | Count |
|---|---|
| Total .go files in v2/ | ~190 |
| Files moving to tdns-transport | ~35 |
| Files moving to tdns-mp | ~55 |
| Files staying in tdns | ~100 |
| Files importing agent/transport | 35 |
| Files referencing TransportManager | 28 |
| Files referencing MsgQs | ~4 |
| Config.Internal MP fields | ~15 |
| Config.Internal DNS fields | ~35 |
| CLI files (DNS) | ~33 |
| CLI files (MP) | ~18 |

### Effort estimate by phase

**Phase 0: Prerequisite refactoring** — 1 week
- Split Config.Internal into DNS vs MP structs
- Extract ZoneData MP fields into separate struct
- Define interface abstractions (MessageEnqueuer, etc.)
- All within current single repo, no extraction yet

**Phase 1: tdns-transport extraction** — 1-2 weeks
- Move agent/transport/, distrib/, crypto/
- Extract message types from core/messages.go
- Move reliable_message_queue.go
- Update import paths across all three repos
- Verify build

**Phase 2: tdns-mp extraction** — 2-3 weeks
- Move SDE, HsyncEngine, message handlers
- Move agent coordination (gossip, provider groups)
- Split main_initfuncs.go into DNS init + MP init
- Move role-specific CLI commands
- Move application binaries (agentv2, combinerv2, authv2)
- Move API handlers for agent/combiner
- Move db_hsync and combiner persistence
- Update import paths, verify build

**Phase 3: Cleanup and verification** — 1 week
- Verify tdns builds standalone (IMR, dog, CLI tools)
- Verify tdns-transport builds with only tdns dependency
- Verify tdns-mp builds with both dependencies
- Verify non-MP apps can use tdns-transport independently
- Update design docs, remove dead code

**Total estimated effort: 5-7 weeks**

### Risk factors that could increase effort

1. **Hidden coupling** — grep found 35 files importing
   agent/transport. Some may have subtle dependencies
   not yet identified.

2. **Circular type references** — if types in tdns
   reference types that move to tdns-transport or
   tdns-mp, need careful interface extraction.

3. **Test coverage** — tests may assume single-repo
   structure. Integration tests especially may need
   rework.

4. **go.mod coordination** — three repos means version
   management. During development, replace directives
   help but add friction.

### Risk factors that reduce effort

1. **No external consumers** — all transport usage is
   internal. No backwards compatibility concerns.

2. **Dependency injection already in place** — transport
   package already uses interfaces and closures, not
   globals.

3. **Clean message types** — core/messages.go is pure
   structs, trivial to relocate.

4. **CLI commands clearly separated** — agent/combiner
   commands are in their own files, not mixed with DNS
   commands.

## Next Steps

1. Create Linear project for tracking
2. Begin Phase 0 (prerequisite refactoring within
   current repo)
3. Phase 1 (tdns-transport extraction)
4. Phase 2 (tdns-mp extraction)
5. Phase 3 (cleanup)
