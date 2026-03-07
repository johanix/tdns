# Transport Refactoring: Unified Message Handling Across Roles

**Date**: 2026-02-25
**Status**: Plan — pending implementation
**Predecessor**: `2026-02-17-transport-unification-and-message-symmetry.md` (Phases 1–2b, 5 complete)
**Linear project**: Transport Refactoring: Unified Message Handling
**Issues**: DNS-104 through DNS-114

## Problem Statement

The transport/message-router infrastructure grew organically from agent-only
to supporting three roles (agent, combiner, signer). The result is:

- Three different router init functions producing different middleware chains
- Two different ChunkHandler types (`ChunkNotifyHandler` vs `CombinerChunkHandler`)
- Dual authorization (middleware layer + hsync_transport layer) — root cause of DNS-103
- Unregistered message types cause SERVFAIL instead of a proper error response
- PING short-circuited in transport, never reaches message handler
- Combiner drops BEATs on the floor after ACKing them (no counting, no liveness tracking)
- `AgentQs` named as if agent-only; combiner/signer have no message queues
- Inconsistent response key naming (`ping_response` vs `sync_response`)
- No stats middleware for combiner/signer roles

## Design Principles

1. **One TransportManager for all roles.** Role differences are expressed
   through handler registration and processing backends, not through
   different TM types or code forks.
2. **Default handler for unknown messages** (like the DNS handler stack).
   No message type must ever trigger SERVFAIL. Unsupported types get
   `REFUSED` + a clear error payload.
3. **Single authorization point.** Authorization runs once in the
   middleware chain. No second check deeper in the stack.
4. **Symmetric message paths.** All roles have message queues (`MsgQs`).
   What consumes from those queues differs per role.
5. **Every message is counted.** Stats middleware runs for all roles.
6. **PING traverses the full path.** No transport-layer shortcuts.
7. **Be liberal in what you accept.** All roles register handlers for
   reasonable message types. If an agent sends a HELLO to a signer, the
   signer handles it gracefully (even if the agent shouldn't have sent it).

## Handler Registration Matrix

After refactoring, each role supports these incoming message types:

| Message   | Agent | Combiner | Signer | Notes |
|-----------|-------|----------|--------|-------|
| PING      | yes   | yes      | yes    | All roles |
| BEAT      | yes   | yes      | yes    | All roles — liveness tracking |
| HELLO     | yes   | yes      | yes    | Liberal accept; combiner/signer may not act on it much |
| SYNC      | yes   | yes      | no     | Agent↔agent and agent→combiner |
| UPDATE    | no    | yes      | no     | New: agent→combiner contributions (see §Split SYNC) |
| RFI       | yes   | no       | no     | Agent-only |
| CONFIRM   | yes   | yes      | no     | Agent + combiner |
| KEYSTATE  | yes   | no       | yes    | Agent + signer (key lifecycle) |
| RELOCATE  | yes   | no       | no     | Agent-only (DDoS mitigation) |

Anything not registered → default handler → `REFUSED` + error payload + logged + counted.

## Split SYNC into SYNC + UPDATE

### Rationale

SYNC is used for two distinct purposes:
- **Agent→Agent** (SYNC): Bidirectional data synchronization. The remote
  agent merges records into its zone data repo. Genuinely a "sync".
- **Agent→Combiner** (UPDATE): Unidirectional data contribution. The
  combiner applies policy, accepts/rejects records, bumps serial. This
  is an "update" in the DNS UPDATE (RFC 2136) sense.

The processing paths are completely different. A distinct message type
makes handler registration clean, log messages self-documenting, and
allows the payload formats to diverge if needed (e.g., combiner may
want approval metadata).

### Naming

`UPDATE` — chosen for its DNS precedent (RFC 2136) and because the
combiner's `ProcessUpdate()` already uses ClassINET/ClassNONE/ClassANY
semantics matching DNS UPDATE.

### Migration

No backwards compatibility needed (no installed base). The agent simply
sends `UPDATE` to combiners and `SYNC` to other agents. The combiner
registers a handler for `UPDATE` (not `SYNC`). The payload structure
can start identical and diverge later.

**Implementation note**: This split can happen at any step after the
foundation is in place. It doesn't block the other refactoring steps.

---

## Implementation Steps

Each step builds independently and can be verified before moving to the next.

### Step 1: Default handler for DNSMessageRouter (DNS-104) — DONE

Add a default/fallback handler to `DNSMessageRouter`. When `Route()` finds
no registered handler for a message type:

1. Call the default handler instead of returning an error
2. Default handler:
   - Logs: `"<role>: unsupported message type <type> from <peer>"`
   - Creates error response: `{type: "error", status: "unsupported",
     message: "message type <type> not supported"}`
   - Stores in `ctx.Data["response"]` (new unified key, see Step 2)
   - Returns nil (not an error — handled gracefully)
3. `SendResponseMiddleware` sends the response with `RcodeRefused`
4. Metrics: increment `UnhandledTypes` counter (already exists)

**Files**: `dns_message_router.go`, `handlers.go` (SendResponseMiddleware)

### Step 2: Unified response key (DNS-105) — DONE

Replace `ping_response` and `sync_response` with a single `response` key
in `ctx.Data`. All handlers store their response payload as
`ctx.Data["response"]`. `SendResponseMiddleware` checks one key.

The response rcode is stored separately as `ctx.Data["response_rcode"]`
(default: `RcodeSuccess`). The default handler (Step 1) sets
`response_rcode` to `RcodeRefused`.

**Files**: `handlers.go` (all Handle* functions + SendResponseMiddleware),
`combiner_chunk.go` (CombinerHandleSync)

### Step 3: Eliminate dual authorization — DNS-103 fix (DNS-106) — DONE

**Priority**: Third step (not urgent — current code works, just architecturally wrong)

Authorization happens **once**, in the `AuthorizationMiddleware`.

1. The middleware's `IsPeerAuthorized` check becomes the single source
   of truth. It must cover both current criteria:
   - Peer-based: `isConfiguredPeer(senderID)` or `isInAuthorizedPeers(senderID)`
   - Zone-based: peer has access to the claimed zone
2. Delete the authorization checks in `routeBeatMessage` (hsync_transport.go ~line 493-521)
   and `routeSyncMessage` (hsync_transport.go ~line 602)
3. Downstream code trusts `ctx.Authorized == true`
4. Register `AuthorizationMiddleware` for the **signer router** too
   (currently missing — only agent and combiner have it)

**Files**: `hsync_transport.go`, `crypto_middleware.go`, `router_init.go`

### Step 4: Rename AgentQs → MsgQs (DNS-107) — DONE

**Priority**: MEDIUM (naming consistency, prerequisite for Step 7)

Mechanical rename across the codebase:
- `AgentQs` → `MsgQs`
- `agentQs` → `msgQs`
- All channel field names stay the same (Hello, Beat, Msg, etc.)

**Files**: `config.go`, `hsync_transport.go`, `hsyncengine.go`,
`main_initfuncs.go`, `apihandler_agent.go`, `syncheddataengine.go`

### Step 5: Merge ChunkHandler types (DNS-108) — DONE

**Priority**: MEDIUM (single entry point for all roles)

Unify `CombinerChunkHandler` into `ChunkNotifyHandler`. Both do:
1. Extract distribution ID + sender from QNAME
2. Get CHUNK payload (EDNS0 or query fallback)
3. Decrypt (if SecureWrapper configured)
4. Parse message type
5. Create MessageContext
6. Route through router with SendResponseMiddleware

Differences to resolve:
- QNAME format parsing (slight variation)
- CHUNK query fallback (agent fetches from sender, combiner uses config address)
- `combiner_chunk.go:RouteViaRouter` vs `chunk_notify_handler.go:RouteViaRouter`

After merge: one `ChunkNotifyHandler`, parameterized for role-specific
bits (e.g., peer address lookup). `RegisterSignerChunkHandler` and
`RegisterCombinerChunkHandler` both create a `ChunkNotifyHandler`.

**Sub-steps**:
- **5a**: Unify QNAME parsing into `extractDistributionIDAndSender` — DONE
  Both ChunkHandler types now use identically-named method with same semantics.
  Renamed `controlZone` → `senderID` throughout combiner_chunk.go.
- **5b**: Unify CHUNK payload extraction (EDNS0 + query fallback) — DONE
  Both ChunkHandler types now use same two-step pattern: `extractChunkPayload` (EDNS0) →
  `fetchChunkViaQuery` (query mode with callback). Combiner now uses `GetPeerAddress` callback
  instead of direct `Conf.Combiner.FindAgent`, and gains NOTIFY-source fallback like agent.
  Renamed `extractChunkQueryEndpoint` → `extractChunkQueryEndpointFromMsg` to match agent.
- **5c**: Unify decryption logic — DONE
  Both now use `SecureWrapper.UnwrapIncomingFromPeer(payload, senderID)` with
  `SecureWrapper != nil` guard. Strict per-peer decryption prevents DoS via QNAME forgery.
  Agent retains its discovery trigger and combiner-key fallback (agent-specific extras).
- **5d**: Unify RouteViaRouter — DONE
  Both now follow identical structure: extract distID+sender → get payload → decrypt →
  parse message type + zone → create MessageContext (with RemoteAddr, zone in ctx.Data,
  SignatureReason="decrypted_by_router") → route via SendResponseMiddleware + Router.Route.
  Agent retains its extras (transport, on_confirmation_received, incoming_message, beat zone
  extraction) as role-specific ctx.Data entries.
- **5e**: Move combiner business logic to standalone functions — DONE
  All business logic extracted from `CombinerChunkHandler` methods into standalone functions:
  `ParseAgentMsgNotify` (parse sync payload), `CombinerProcessUpdate` (apply updates with
  ClassINET/ClassNONE/ClassANY), `NewCombinerSyncHandler` (factory returning `MessageHandlerFunc`),
  `checkContentPolicy`/`checkNSNamespacePolicy` (take `protectedNamespaces` param),
  `recordCombinerError` (takes `*ErrorJournal` param). Original methods remain as thin
  delegates so existing callers still work — 5f will remove them.
- **5f**: Delete CombinerChunkHandler, wire RegisterCombiner/SignerChunkHandler to ChunkNotifyHandler — DONE
  Deleted `CombinerChunkHandler` struct and all its methods/delegates. Replaced with lightweight
  `CombinerState` struct (ErrorJournal, ProtectedNamespaces, unexported chunkHandler). Both
  `RegisterCombinerChunkHandler` and `RegisterSignerChunkHandler` now create `ChunkNotifyHandler`
  instances with `FetchChunkQuery` callback (for combiner/signer which lack DNSTransport).
  Added `FetchChunkQuery` callback field to `ChunkNotifyHandler` + fallback in `fetchChunkViaQuery`.
  `config.go`: `CombinerHandler` → `CombinerState`. `signer_transport.go`: trimmed (registration
  moved to combiner_chunk.go). All 6 binaries build clean.

### Step 6: Unified TransportManager (DNS-109) — DONE

**Priority**: MEDIUM (prerequisite for Step 7)

All three roles now instantiate the same `TransportManager` type. Feature
composition is via config (nil-driven), not role-switching. The combiner's
separate `CombinerTransport` is deleted; combiner creates a `TransportManager`
with minimal config (static peers in PeerRegistry, no MsgQs/AgentRegistry).

Also: signer config changed from singular `multi_provider.agent` to plural
`multi_provider.agents[]` (list) for multi-agent support (load distribution
and fault isolation across provider sets).

Changes:
- `config.go`: `MultiProviderConf.Agent *PeerConf` → `.Agents []*PeerConf`;
  removed `CombinerTransport` from `InternalConf`
- `main_initfuncs.go`: Combiner creates `TransportManager` + registers peers
  via `PeerRegistry.Add`. Signer agent registration is now a loop.
- `agent_authorization.go`: `isConfiguredPeer` adds combiner.agents[] and
  signer multi-provider.agents[] loops
- `apihandler_combiner.go`: Uses `TransportManager.SendPing`/`SendSyncWithFallback`
  + `PeerRegistry.Get`/`All` instead of `CombinerTransport` wrappers
- `hsync_transport.go`: `ReliableMessageQueue` creation conditional on `AgentRegistry != nil`
- `signer_transport.go`: `initSignerCrypto` loads keys for all agents (loop)
- `apihandler_auth.go`, `hsync_utils.go`, `apihandler_agent.go`: All adapted
  for `mp.Agents` list
- **Deleted**: `combiner_transport.go` (274 lines)

**Files**: `config.go`, `hsync_transport.go`, `main_initfuncs.go`,
`agent_authorization.go`, `apihandler_combiner.go`, `signer_transport.go`,
`apihandler_auth.go`, `hsync_utils.go`, `apihandler_agent.go`

### Step 7: MsgQs + RouteToMsgHandler for all roles (DNS-110) — DONE

**Priority**: MEDIUM (symmetric message delivery)

1. ~~Rename `RouteToHsyncEngine` → `RouteToMsgHandler`~~
2. ~~Register this middleware for **all roles** (not just agent)~~
3. ~~All roles get `MsgQs` channels wired up~~
4. ~~Role-specific message consumers:~~
   - **Agent**: HsyncEngine (existing, unchanged)
   - **Combiner**: `CombinerMsgHandler` goroutine — processes beats
     (peer liveness tracking via PeerRegistry), receives HELLO
   - **Signer**: `SignerMsgHandler` goroutine — processes beats
     (peer liveness via PeerRegistry), receives HELLO

The combiner's beat handling goes from "drop on floor" to "track peer
liveness". The signer gains peer awareness.

**Note**: At this step, combiner SYNC remains **synchronous** via the
existing `CombinerHandleSync` path. The async conversion is Step 10.

**Files changed**: `handlers.go`, `router_init.go`, `main_initfuncs.go`,
`combiner_chunk.go`, new `combiner_msg_handler.go`, new `signer_msg_handler.go`

### Step 8: PING through full message path (DNS-116) — DONE

**Priority**: LOW (correctness, not blocking)

PING previously stopped at the handler — it never reached MsgQs.

1. ~~`HandlePing` additionally sets `ctx.Data["message_type"] = "ping"`~~
2. ~~`RouteToMsgHandler` routes to `MsgQs.Ping` (new channel)~~
3. ~~Role-specific handlers receive and count it, update peer liveness~~
4. ~~The DNS response is still sent synchronously by `SendResponseMiddleware`~~
   (PING response must be synchronous for round-trip measurement)

Also added `routePingMessage` to TransportManager which updates PeerRegistry
liveness (LastBeatReceived + PeerStateOperational). CombinerMsgHandler and
SignerMsgHandler both consume `MsgQs.Ping`.

**Files changed**: `handlers.go`, `config.go`, `hsync_transport.go`,
`main_initfuncs.go`, `combiner_msg_handler.go`, `signer_msg_handler.go`

### Step 9: Stats middleware for all roles (DNS-117) — DONE

**Priority**: LOW (observability)

~~Register `StatsMiddleware` in `InitializeCombinerRouter` and
`InitializeSignerRouter`. Currently only the agent router has it.~~

All three roles now register `StatsMiddleware` (between signature
verification and logging). Added `PeerRegistry` field to both
`CombinerRouterConfig` and `SignerRouterConfig`. Wired `tm.PeerRegistry`
at call sites in `main_initfuncs.go`.

**Files changed**: `router_init.go`, `main_initfuncs.go`

### Step 10: Async combiner SYNC (DNS-118) — DONE

Converted combiner SYNC processing from synchronous inline to async two-phase:

1. ~~`NewCombinerSyncHandler` returns immediate "pending" ACK in DNS response~~
2. ~~Sets `ctx.Data["message_type"] = "sync"` to trigger RouteToMsgHandler routing~~
3. ~~Message flows: IncomingChan → StartIncomingMessageRouter → routeSyncMessage → MsgQs.Msg~~
4. ~~`CombinerMsgHandler` picks up sync, runs `CombinerProcessUpdate()`, sends
   detailed CONFIRM NOTIFY back to agent via `tm.DNSTransport.Confirm()`~~

Agent-side changes:
- ~~Added `ConfirmPending` to `parseConfirmStatus` (was falling through to ConfirmFailed)~~
- ~~`deliverToCombiner` skips MsgQs.Confirmation for PENDING status~~
- ~~`routeSyncMessage` guards `sendImmediateConfirmation` behind `agentRegistry != nil`~~

Agent already handles async confirmations via HandleConfirmation → OnConfirmationReceived.

**Files changed**: `handler.go`, `combiner_chunk.go`, `combiner_msg_handler.go`,
`hsync_transport.go`, `main_initfuncs.go`

### Step 11: Introduce UPDATE message type (DNS-114)

**Priority**: LOW (can happen after foundation is in place)

Split agent→combiner contributions from SYNC:
1. Define `MessageType("update")` constant
2. Agent sends UPDATE (not SYNC) to combiners
3. Combiner registers handler for UPDATE (current `CombinerHandleSync`
   logic, possibly renamed)
4. SYNC remains for agent↔agent only
5. Payload format can diverge later if needed

**Files**: `dns_message_router.go` (constant), `handlers.go` or
`combiner_chunk.go` (handler), agent sending code, `router_init.go`

### Step 12: Decouple TransportManager from role-specific globals (DNS-115) — DONE

**Priority**: MEDIUM (extensibility for external apps)

TransportManager methods read the global `Conf` variable at runtime with
hardcoded `if Conf.Agent / Conf.Combiner / Conf.MultiProvider` branches.
This prevents external apps (tdns-kdc, tdns-krs) from using TM without
modifying authorization code.

Fix: inject callbacks at config time:
1. `AuthorizedPeers func() []string` — replaces `isConfiguredPeer` +
   `isInAuthorizedPeers` with single role-agnostic callback
2. `MessageRetention func(operation string) int` — replaces `Conf.Agent`
   check in distribution cache closure
3. `GetImrEngine func() *Imr` — replaces `Conf.Internal.ImrEngine` in
   `DiscoverAndRegisterAgent` (late-binding closure since IMR starts async)

Result: `agent_authorization.go`, `hsync_transport.go`, and
`agent_discovery.go` have zero references to global `Conf`.

**Files changed**: `hsync_transport.go`, `agent_authorization.go`,
`agent_discovery.go`, `main_initfuncs.go`

---

## Verification Strategy

Each step should be verified with:
1. `cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make` — builds
2. Ping works: `agent combiner ping`, `agent ping`, `combiner agent ping`
3. Beat works: agent→combiner, agent→agent, agent→signer (after Step 3)
4. Sync works: agent→combiner, agent→agent
5. Unsupported message to any role → clean REFUSED (after Step 1)
6. No SERVFAIL for any message type to any role

## File Reference

| Component | Current File |
|-----------|-------------|
| DNSMessageRouter | `v2/agent/transport/dns_message_router.go` |
| Router Init (all roles) | `v2/agent/transport/router_init.go` |
| Handlers | `v2/agent/transport/handlers.go` |
| Agent ChunkHandler | `v2/agent/transport/chunk_notify_handler.go` |
| Combiner ChunkHandler | `v2/combiner_chunk.go` |
| Signer transport | `v2/signer_transport.go` |
| TransportManager | `v2/hsync_transport.go` |
| Config (AgentQs) | `v2/config.go` |
| Authorization middleware | `v2/agent/transport/crypto_middleware.go` |
| Stats middleware | `v2/agent/transport/stats_middleware.go` |
| Main init | `v2/main_initfuncs.go` |
