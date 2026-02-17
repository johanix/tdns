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

### 1a: Fill transport gaps

Ensure every message type works over both DNS and API:

- **PING over API**: Implement `APITransport.Ping()` — POST to `/ping`
- **RFI over API**: Add `/rfi` endpoint (or route through `/sync` with MessageType discrimination)
- **Auth for PING/RELOCATE**: Add zone context or require agent authorization

### 1b: Uniform DistributionID propagation

- All incoming CHUNK messages already have a distribution ID from the qname
- Ensure `routeBeatMessage()` propagates `msg.DistributionID` (same fix pattern as DNS-87 for sync)
- Ensure all handlers can access the distribution ID for logging/tracking

### 1c: Unify combiner onto DNSMessageRouter

Broken into 4 sub-steps to minimize risk. Each step builds and can be verified independently.

#### 1c-i: Extract handler functions

Move `handlePing`, `handleBeat`, and sync processing into standalone functions matching the router's `HandlerFunc` signature. The old `HandleChunkNotify` switch calls the new functions — behavior unchanged.

#### 1c-ii: Add `InitializeCombinerRouter()`

New function in `router_init.go` that registers combiner handlers (`CombinerHandleSync`, `CombinerHandleBeat`, `CombinerHandlePing`) with a `DNSMessageRouter`. Same middleware chain as agent (auth, crypto, stats, logging). Router exists but isn't wired yet.

#### 1c-iii: Wire combiner to router

Replace `HandleChunkNotify()` dispatch with `ChunkNotifyHandler.RouteViaRouter()`. The router handles message type dispatch, middleware, and handler invocation. Old switch becomes dead code.

**Verification**: Test all 3 message types (ping, beat, sync) via DNS transport to combiner.

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
