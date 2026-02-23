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

#### 1c-iv: Delete dead code — DONE (DNS-93)

Removed old dispatch and response infrastructure (346 lines net deleted):

- `HandleChunkNotify` — old switch dispatch, replaced by `RouteViaRouter`
- `handlePing`, `sendPingResponse` — old ping handler chain
- `handleBeat`, `sendBeatResponse` — old beat handler chain
- `sendConfirmResponse`, `sendGenericEdns0Response`, `sendErrorResponse` — old response helpers
- Legacy `"type"` field fallback in `DetermineMessageType` (router_init.go)
- Legacy `sender_id`/`zone`/`records` field fallbacks in `parseAgentMsgNotify`
- `CreateNotifyHandlerFunc` no longer falls back to `HandleChunkNotify` (router is required)
- `RouteViaRouter` unknown-message-type path now returns `fmt.Errorf` (SendResponseMiddleware sends SERVFAIL)

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

## Phase 2: Combiner Resync — DONE

With the combiner now able to send messages via the Transport interface:

- API handler `agent-resync` in `APIcombinerDebug()`
- CLI command `combiner agent resync [--zone] [--agent]`
- Authorization fix: combiner identity injected into `authorized_peers` at startup
- Renamed `IsAgentAuthorized` → `IsPeerAuthorized` across codebase

## Phase 2b: Unify Simple Message Handlers

### Problem

Every message type has **multiple receiver implementations**:

| Message | Implementations | Files |
|---------|----------------|-------|
| PING | 3 receivers | `chunk_notify_handler.go:handlePing`, `handlers.go:HandlePing`, `combiner_chunk.go:CombinerHandlePing` |
| BEAT | 3 receivers | legacy path → IncomingChan, `handlers.go:HandleBeat`, `combiner_chunk.go:CombinerHandleBeat` |
| HELLO | 2 receivers | legacy path → IncomingChan, `handlers.go:HandleHello` |
| RELOCATE | 2 receivers | legacy path → IncomingChan, `handlers.go:HandleRelocate` |
| CONFIRM | 2 receivers | `chunk_notify_handler.go:handleConfirmation`, `handlers.go:HandleConfirmation` |

Design principle: one implementation per message, shared by both agent and combiner routers.

### Design: Unified handlers with optional callbacks

Every handler has two parts:
1. **Response construction** — always the same (parse message, construct confirmation/echo)
2. **Side effects** — varies by role (agent routes to hsyncengine, combiner does zone updates)

Response construction belongs in the shared handler. Side effects are injected via `ctx.Data` and processed by subsequent middleware (`RouteToHsyncEngine` for agents, nothing for combiners).

### Sub-steps

#### 2b-i: Fix HandlePing to use DnsPingConfirmPayload

The router-based `HandlePing` in `handlers.go` must produce the exact same response as the working `handlePing` in `chunk_notify_handler.go`. Uses `DnsPingConfirmPayload` with `Status: "ok"`, `SenderID`, `Nonce`, `DistributionID`, `Timestamp`.

The `local_id` needed for `SenderID` is passed via `ctx.Data["local_id"]` (set by both agent `RouteViaRouter` and combiner `RouteViaRouter`).

**Changes**: `handlers.go:HandlePing` — use `DnsPingConfirmPayload` with `ctx.Data["local_id"]`. `combiner_chunk.go:RouteViaRouter` — add `ctx.Data["local_id"] = h.LocalID`.

#### 2b-ii: Delete duplicate ping handlers

Once `HandlePing` works correctly:
- Delete `chunk_notify_handler.go:handlePing()` (legacy agent path)
- Delete `combiner_chunk.go:CombinerHandlePing()` (combiner-specific)
- Both `InitializeAgentRouter()` and `InitializeCombinerRouter()` register the same `HandlePing`

**Changes**:
- `chunk_notify_handler.go` — remove `handlePing()`, route ping through router in legacy dispatch
- `combiner_chunk.go` — remove `CombinerHandlePing()`
- `router_init.go` — `InitializeCombinerRouter()` registers `HandlePing` instead of `cfg.HandlePing`
- `CombinerRouterConfig` — remove `HandlePing` field
- `main_initfuncs.go` — remove `HandlePing: combinerHandler.CombinerHandlePing` from config

#### 2b-iii: Unify beat handler

`HandleBeat` does:
1. Parse beat payload, validate type
2. Store `incoming_message` in context (for optional hsyncengine routing)
3. Construct generic confirm response (`status: "ok"`, `message: "beat acknowledged"`)
4. Store in `ctx.Data["sync_response"]`

Agent's `RouteToHsyncEngine` middleware picks up the message from context. Combiner doesn't have that middleware. Same handler, different middleware chains.

**Changes**:
- `handlers.go:HandleBeat` — add confirm response construction
- `combiner_chunk.go` — remove `CombinerHandleBeat()`
- `router_init.go` — `InitializeCombinerRouter()` registers `HandleBeat`
- `CombinerRouterConfig` — remove `HandleBeat` field
- `main_initfuncs.go` — remove `HandleBeat: combinerHandler.CombinerHandleBeat`

#### 2b-iv: Unify hello, relocate, confirm handlers

These already only exist in the agent router path (`handlers.go`). No combiner duplicates. But the legacy path in `chunk_notify_handler.go` still has separate dispatch. Once the router is the only path, these are already unified.

**Changes**: `chunk_notify_handler.go` — remove legacy dispatch for hello/relocate/confirm, route all through router.

#### 2b-v: Clean up legacy dispatch in chunk_notify_handler.go

After 2b-ii through 2b-iv, `HandleChunkNotify()` (the legacy path) should be dead code for all message types. Delete it.

**Changes**: `chunk_notify_handler.go` — remove `HandleChunkNotify()` and related legacy helpers. `RouteViaRouter()` is now the only entry point — remove fallback to `HandleChunkNotify`.

### Files modified

| File | Change |
|------|--------|
| `agent/transport/handlers.go` | Fix HandlePing response format; add confirm response to HandleBeat |
| `agent/transport/chunk_notify_handler.go` | Remove handlePing, handleConfirmation, HandleChunkNotify (legacy path) |
| `agent/transport/router_init.go` | CombinerRouterConfig uses shared handlers; remove per-handler fields |
| `combiner_chunk.go` | Remove CombinerHandlePing, CombinerHandleBeat; add local_id to RouteViaRouter context |
| `main_initfuncs.go` | Use shared HandlePing/HandleBeat instead of combiner-specific handlers |

### Verification

1. `agent combiner ping` (agent→combiner) still works
2. `combiner agent ping` (combiner→agent) works (currently broken, fixed by 2b-i)
3. `agent ping` (agent→agent) works
4. Beat messages work in all directions
5. Hello/Relocate/Confirm work for agents
6. Build succeeds

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

## Phase 6: Unify SYNC Handler

SYNC is the most complex message type because processing differs significantly between agent and combiner:

- **Agent receives SYNC**: Routes to `SynchedDataEngine` via `IncomingChan`, which applies records to `ZoneDataRepo`, sends confirmations back, and optionally forwards to other peers. The handler just ACKs and routes.
- **Combiner receives SYNC**: Calls `ProcessUpdate()` to apply additions/deletions to `CombinerData` and `AgentContributions`, then returns a detailed confirmation with per-RR applied/removed/rejected lists, with a 3500-byte size guard.

The response formats also differ: agent SYNC sends a simple confirm; combiner SYNC sends a detailed confirm with per-RR tracking.

### Design approach (deferred — needs more analysis)

Options:
- (a) Single `HandleSync` with a callback for the processing step (agent passes route-to-hsyncengine, combiner passes ProcessUpdate)
- (b) Single `HandleSync` that always routes to a channel; combiner gets its own "hsyncengine equivalent" goroutine
- (c) Keep two handlers but share the response construction via a helper

This needs careful design because SYNC is the core data path and any abstraction must not add latency or complexity. Deferred to after Phase 5 when TransportManager is cleaner.

## Phase 7: Inline Phase-1 Confirmation in NOTIFY Response

### Problem

The current two-phase SYNC confirmation uses two separate outbound NOTIFY(CHUNK) messages back to the originator:

1. **Phase 1 (immediate)**: Remote agent receives SYNC, validates it, sends back an immediate confirmation via a separate NOTIFY(CHUNK) — "I received and accepted your SYNC"
2. **Phase 2 (deferred)**: After the remote combiner processes the data, a second NOTIFY(CHUNK) carries the final confirmation (accepted or rejected with `RejectedItems`)

Phase 1 is generated synchronously during NOTIFY processing — the result is known before the DNS response is sent. There's no reason this confirmation can't ride the NOTIFY **response** (via EDNS0 options, the same pattern the combiner already uses in `sendGenericEdns0Response`) instead of requiring a separate outbound message.

### Design: Try inline, fall back to explicit

The optimization is NOT to replace the explicit NOTIFY confirmation — it's to **try the inline response first** and fall back:

1. Remote agent processes incoming SYNC NOTIFY
2. Remote agent packs phase-1 confirmation into the NOTIFY **response** (EDNS0 payload)
3. If the originating agent receives the response → phase 1 confirmed, no separate NOTIFY needed
4. If the response is blocked (middleboxes dropping unknown EDNS0 options, packet too large, etc.) → originating agent gets no response → retries the same SYNC
5. Remote agent receives the **duplicate SYNC** → detects it's a retransmission (same DistributionID, already processed) → realizes the inline response didn't get through → falls back to sending an **explicit NOTIFY(CHUNK) confirmation** (current model)

This is strictly an optimization: one fewer round-trip in the common case, with automatic fallback when the inline response path is broken.

### Why both paths are needed

Devices exist that drop DNS packets with unknown or encrypted EDNS0 options. If the phase-1 confirmation only rides the NOTIFY response and that response is dropped, the originating agent never learns the SYNC was received. The duplicate-detection + fallback ensures delivery.

### Effort estimate

~100-150 lines. The EDNS0 response packing already exists (`sendGenericEdns0Response` pattern). The main new code is:
- Pack confirmation into NOTIFY response in the agent's CHUNK handler
- Duplicate SYNC detection (by DistributionID) in the receiving agent
- Fallback to explicit NOTIFY on duplicate detection

### Dependency

Independent of multi-signer work. Can be done whenever transport unification reaches this level of refinement.

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

After Phase 2b:

- All control-plane messages (PING, BEAT, HELLO, RELOCATE) use one shared handler
- Agent and combiner routers register the same handler functions
- No duplicate message handling code
- Legacy `HandleChunkNotify` path deleted
- `combiner agent ping` (combiner→agent) works

After Phase 6:

- SYNC also unified (single handler with role-specific processing callback)
- All 7 message types: one sender, one receiver

After Phase 7:

- Phase-1 SYNC confirmation arrives in NOTIFY response (one fewer round-trip)
- Duplicate SYNC (same DistributionID) triggers fallback to explicit NOTIFY confirmation
- Phase-2 confirmation unchanged (always explicit NOTIFY)
- Works correctly through middleboxes that drop unknown EDNS0 options

Build: `cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make`
