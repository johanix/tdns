# Architecture Roadmap: Transport Unification & Message Symmetry

**Date**: 2026-02-17

## Design Principles

1. **Transport agnosticism**: All communication (agent-to-agent, combiner-to-agent) must work over any available transport (DNS or API). No message type should be transport-specific.
2. **Two categories, uniform infrastructure**: Messages split into *data plane* (SYNC, RFI, CONFIRM — tied to SynchedDataEngine) and *control plane* (HELLO, BEAT, PING, RELOCATE — agent lifecycle). Both categories use the same transport infrastructure uniformly.
3. **Keep current message types**: The 7 message types are the right granularity. Don't merge control-plane messages into SYNC variants.
4. **No backwards compatibility**: There is no installed base.

## Current State

**Agent**: Full infrastructure — TransportManager with API+DNS transports, DNSMessageRouter with middleware (auth, crypto, stats, logging), PeerRegistry, ReliableMessageQueue.

**Combiner**: Separate monolithic handler (`combiner_chunk.go`, ~900 lines), inline switch for 3 message types (ping, beat, sync), no middleware, no Transport interface, receive-only (cannot send).

**Asymmetries to fix**:

| Gap | Issue |
|-----|-------|
| PING: no auth check | Security gap — anyone can ping |
| PING: no API transport | Returns "not implemented" |
| RFI: no API transport | No endpoint defined |
| RELOCATE: no auth check | Security gap |
| BEAT: DistributionID dropped | Can't track beat delivery |
| Combiner: can't send | Blocks combiner resync |
| Combiner: separate code path | Bug fixes don't propagate |

---

## Phase 1: Message Symmetry & Uniform Transport

### 1a: Fill transport gaps — DONE (DNS-88)

Ensure every message type works over both DNS and API:

- **PING over API**: Implemented `APITransport.Ping()` — POST to `/ping` with nonce echo
- **RFI over API**: `Sync()` now propagates `req.MessageType` and `req.RfiType` (no separate endpoint needed)
- **Auth for RELOCATE**: Added authorization check in `routeRelocateMessage()` (PING already had auth via router middleware)

### 1b: Uniform DistributionID propagation — DONE (DNS-89)

- `routeBeatMessage()` propagates `msg.DistributionID` into `AgentMsgReport`
- `routeHelloMessage()` propagates `msg.DistributionID` into `AgentMsgReport`
- Added `DistributionID` field to `AgentMsgReport` struct

### 1c: Unify combiner onto DNSMessageRouter

Broken into 4 sub-steps to minimize risk. Each step builds and can be verified independently.

#### 1c-i: Extract handler functions — DONE (DNS-90)

Move `handlePing`, `handleBeat`, and sync processing into standalone functions matching the router's `HandlerFunc` signature. The old `HandleChunkNotify` switch calls the new functions — behavior unchanged.

- `CombinerHandlePing(ctx *transport.MessageContext)` — parses ping, echoes nonce via `ctx.Data["ping_response"]`
- `CombinerHandleBeat(ctx *transport.MessageContext)` — parses beat, stores confirm via `ctx.Data["sync_response"]`
- `CombinerHandleSync(ctx *transport.MessageContext)` — calls `parseAgentMsgNotify` + `ProcessUpdate`, stores confirmation with size guard

#### 1c-ii: Add `InitializeCombinerRouter()` — DONE (DNS-91)

New function in `router_init.go` that registers combiner handlers with a `DNSMessageRouter`. Middleware chain: authorization (optional), crypto/signature (optional), logging. No `RouteToHsyncEngine` (combiner processes synchronously). Accepts handler closures via `CombinerRouterConfig` so it doesn't import the `tdns` package. Router exists but isn't wired yet.

#### 1c-iii: Wire combiner to router — DONE (DNS-92)

- Added `Router *transport.DNSMessageRouter` field to `CombinerChunkHandler`
- Added `RouteViaRouter(ctx, req)` — extracts distID, gets payload, decrypts, creates `MessageContext`, routes through router with `SendResponseMiddleware`
- `CreateNotifyHandlerFunc()` now dispatches to `RouteViaRouter` when `Router` is set, falls back to `HandleChunkNotify` when nil
- `main_initfuncs.go` creates router, calls `InitializeCombinerRouter` with handler closures, sets `combinerHandler.Router`
- Old `HandleChunkNotify` switch is now dead code (still present for 1c-iv cleanup)

#### 1c-iv: Delete dead code

Remove old switch, inline dispatch, legacy `"type"` field handling, dual-format parsing. No backwards compatibility.

### 1d: Give combiner sending capability

- Combiner gets a DNS transport (for sending CHUNK messages to agents)
- Combiner gets an API transport (for sending to agent REST endpoints)
- Use the same `Transport` interface and fallback logic agents use
- This enables Phase 2 (combiner resync)

**Files involved**:

- `agent/transport/api.go` — Add Ping, RFI support
- `agent/transport/dns.go` — Verify all message types send DistributionID
- `agent/transport/handlers.go` — Add combiner-specific handler variants
- `agent/transport/router_init.go` — New `InitializeCombinerRouter()` function
- `combiner_chunk.go` — Refactor to use router (most of file changes)
- `hsync_transport.go` — DistributionID propagation in routeBeatMessage
- `main_initfuncs.go` — Combiner initialization uses router + transport

## Phase 2: Combiner Resync

With the combiner now able to send messages via the Transport interface:

- New `RfiType: "FULL"` — requests both local AND remote data from agent
- Agent handles FULL RFI by running the same path as `EnqueueForCombiner()` (which already sends combined local+remote data)
- Combiner startup: discover agents from HSYNC RRsets, send RFI FULL to each
- Combiner restart detection: agents detect combiner restart via beat failure and automatically re-send

## Phase 3: tdns-nm compilation fix

Mechanical work after architecture settles:

- Update imports for moved packages
- Adapt to new callback signatures
- KDC/KRS can optionally adopt the unified router

## Phase 4: Persistence

- Agent-side: serialize zone data repo (local + remote contributions) to file
- Load on startup; resync only for deltas
- Combiner persistence deferred — combiner can always resync via Phase 2

## Phase 5: TransportManager refactoring

- Extract PeerRegistry and DNSMessageRouter as independent components
- TransportManager becomes a composition of these + transport-specific logic
- Combiner uses router + registry without full TransportManager

---

## Verification

After Phase 1:

- All message types work over both DNS and API transports
- Combiner receives messages via the same router/middleware as agent
- `agent distrib list` shows DistributionID for all message types (including beats)
- PING requires authorization

After Phase 2:

- `combiner resync` command triggers RFI FULL to all known agents
- Combiner restart automatically recovers state from agents
- `combiner distrib list` shows RFI FULL distributions

Build: `cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make`
