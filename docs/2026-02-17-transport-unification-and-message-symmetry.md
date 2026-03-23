# Architecture Roadmap: Transport Unification & Message Symmetry

**Date**: 2026-02-17

## Design Principles

1. **Transport agnosticism**: All communication
   (agent-to-agent, combiner-to-agent) must work over any
   available transport (DNS or API). No message type should be
   transport-specific.
2. **Two categories, uniform infrastructure**: Messages split
   into *data plane* (SYNC, RFI, CONFIRM — tied to
   SynchedDataEngine) and *control plane* (HELLO, BEAT, PING,
   RELOCATE — agent lifecycle). Both categories use the same
   transport infrastructure uniformly.
3. **Keep current message types**: The 7 message types are the
   right granularity. Don't merge control-plane messages into
   SYNC variants.
4. **No backwards compatibility**: There is no installed base.

## Current State (as of 2026-02-25)

**Agent**: Full infrastructure — TransportManager with API+DNS
transports, DNSMessageRouter with middleware (auth, crypto,
stats, logging), PeerRegistry, ReliableMessageQueue.

**Combiner**: Unified onto DNSMessageRouter (Phases 1c–2b
complete). Receives messages via the same middleware chain as
the agent. Has outbound transport capability (DNS + API) for
sending to agents. Single-function handlers for PING, BEAT,
HELLO, RELOCATE, CONFIRM shared with agent. SYNC still has a
separate `CombinerHandleSync` (deferred — see Phase 6).

**Original asymmetries** (all fixed):

| Gap | Resolution |
|-----|-----------|
| PING: no auth check | Auth middleware registered in `InitializeCombinerRouter()` |
| PING: no API transport | `APITransport.Ping()` implemented (api.go:254) |
| RFI: no API transport | `Sync()` propagates `MessageType`/`RfiType` (api.go:166) |
| RELOCATE: no auth check | Auth middleware covers all message types via router |
| BEAT: DistributionID dropped | `routeBeatMessage()` propagates `DistributionID` (hsync_transport.go:552) |
| Combiner: can't send | `NewCombinerTransport()` created at startup (main_initfuncs.go:559) |
| Combiner: separate code path | `RouteViaRouter` dispatches all message types through shared middleware |

---

## Phase 1: Message Symmetry & Uniform Transport

### 1a: Fill transport gaps — DONE (DNS-88)

Ensure every message type works over both DNS and API:

- **PING over API**: Implemented `APITransport.Ping()` —
  POST to `/ping` with nonce echo
- **RFI over API**: `Sync()` now propagates
  `req.MessageType` and `req.RfiType` (no separate endpoint
  needed)
- **Auth for RELOCATE**: Added authorization check in
  `routeRelocateMessage()` (PING already had auth via router
  middleware)

### 1b: Uniform DistributionID propagation — DONE (DNS-89)

- `routeBeatMessage()` propagates `msg.DistributionID` into
  `AgentMsgReport`
- `routeHelloMessage()` propagates `msg.DistributionID` into
  `AgentMsgReport`
- Added `DistributionID` field to `AgentMsgReport` struct

### 1c: Unify combiner onto DNSMessageRouter

Broken into 4 sub-steps to minimize risk. Each step builds
and can be verified independently.

#### 1c-i: Extract handler functions — DONE (DNS-90)

Move `handlePing`, `handleBeat`, and sync processing into
standalone functions matching the router's `HandlerFunc`
signature. The old `HandleChunkNotify` switch calls the new
functions — behavior unchanged.

- `CombinerHandlePing(ctx *transport.MessageContext)` —
  parses ping, echoes nonce via `ctx.Data["ping_response"]`
- `CombinerHandleBeat(ctx *transport.MessageContext)` —
  parses beat, stores confirm via `ctx.Data["sync_response"]`
- `CombinerHandleSync(ctx *transport.MessageContext)` — calls
  `parseAgentMsgNotify` + `ProcessUpdate`, stores
  confirmation with size guard

#### 1c-ii: Add `InitializeCombinerRouter()` — DONE (DNS-91)

New function in `router_init.go` that registers combiner
handlers with a `DNSMessageRouter`. Middleware chain:
authorization (optional), crypto/signature (optional),
logging. No `RouteToHsyncEngine` (combiner processes
synchronously). Accepts handler closures via
`CombinerRouterConfig` so it doesn't import the `tdns`
package. Router exists but isn't wired yet.

#### 1c-iii: Wire combiner to router — DONE (DNS-92)

- Added `Router *transport.DNSMessageRouter` field to
  `CombinerChunkHandler`
- Added `RouteViaRouter(ctx, req)` — extracts distID, gets
  payload, decrypts, creates `MessageContext`, routes through
  router with `SendResponseMiddleware`
- `CreateNotifyHandlerFunc()` now dispatches to
  `RouteViaRouter` when `Router` is set, falls back to
  `HandleChunkNotify` when nil
- `main_initfuncs.go` creates router, calls
  `InitializeCombinerRouter` with handler closures, sets
  `combinerHandler.Router`
- Old `HandleChunkNotify` switch is now dead code (still
  present for 1c-iv cleanup)

#### 1c-iv: Delete dead code — DONE (DNS-93)

Removed old dispatch and response infrastructure (346 lines
net deleted):

- `HandleChunkNotify` — old switch dispatch, replaced by
  `RouteViaRouter`
- `handlePing`, `sendPingResponse` — old ping handler chain
- `handleBeat`, `sendBeatResponse` — old beat handler chain
- `sendConfirmResponse`, `sendGenericEdns0Response`,
  `sendErrorResponse` — old response helpers
- Legacy `"type"` field fallback in `DetermineMessageType`
  (router_init.go)
- Legacy `sender_id`/`zone`/`records` field fallbacks in
  `parseAgentMsgNotify`
- `CreateNotifyHandlerFunc` no longer falls back to
  `HandleChunkNotify` (router is required)
- `RouteViaRouter` unknown-message-type path now returns
  `fmt.Errorf` (SendResponseMiddleware sends SERVFAIL)

### 1d: Give combiner sending capability — DONE

- `NewCombinerTransport()` creates outbound transport with
  DNS/NOTIFY + API capability (`main_initfuncs.go:559`)
- Stored as `conf.Internal.CombinerTransport`, used for
  `combiner agent resync` and similar commands
- `APITransport` supports all message types: Hello, Beat,
  Sync (+ RFI), Ping, Relocate, Confirm

## Phase 2: Combiner Resync — DONE

With the combiner now able to send messages via the Transport
interface:

- API handler `agent-resync` in `APIcombinerDebug()`
- CLI command `combiner agent resync [--zone] [--agent]`
- Authorization fix: combiner identity injected into
  `authorized_peers` at startup
- Renamed `IsAgentAuthorized` → `IsPeerAuthorized` across
  codebase

## Phase 2b: Unify Simple Message Handlers — DONE

### Problem (resolved)

Every message type previously had **multiple receiver
implementations** (now unified):

| Message | Was | Now |
|---------|-----|-----|
| PING | 3 receivers | 1 — `handlers.go:HandlePing` |
| BEAT | 3 receivers | 1 — `handlers.go:HandleBeat` |
| HELLO | 2 receivers | 1 — `handlers.go:HandleHello` |
| RELOCATE | 2 receivers | 1 — `handlers.go:HandleRelocate` |
| CONFIRM | 2 receivers | 1 — `handlers.go:HandleConfirmation` |

Design principle: one implementation per message, shared by
both agent and combiner routers.

### Design: Unified handlers with optional callbacks

Every handler has two parts:
1. **Response construction** — always the same (parse
   message, construct confirmation/echo)
2. **Side effects** — varies by role (agent routes to
   hsyncengine, combiner does zone updates)

Response construction belongs in the shared handler. Side
effects are injected via `ctx.Data` and processed by
subsequent middleware (`RouteToHsyncEngine` for agents,
nothing for combiners).

### Sub-steps

#### 2b-i: Fix HandlePing to use DnsPingConfirmPayload — DONE

The router-based `HandlePing` in `handlers.go` must produce
the exact same response as the working `handlePing` in
`chunk_notify_handler.go`. Uses `DnsPingConfirmPayload` with
`Status: "ok"`, `SenderID`, `Nonce`, `DistributionID`,
`Timestamp`.

The `local_id` needed for `SenderID` is passed via
`ctx.Data["local_id"]` (set by both agent `RouteViaRouter`
and combiner `RouteViaRouter`).

**Changes**: `handlers.go:HandlePing` — use
`DnsPingConfirmPayload` with `ctx.Data["local_id"]`.
`combiner_chunk.go:RouteViaRouter` — add
`ctx.Data["local_id"] = h.LocalID`.

#### 2b-ii: Delete duplicate ping handlers — DONE

Once `HandlePing` works correctly:
- Delete `chunk_notify_handler.go:handlePing()` (legacy agent
  path)
- Delete `combiner_chunk.go:CombinerHandlePing()`
  (combiner-specific)
- Both `InitializeAgentRouter()` and
  `InitializeCombinerRouter()` register the same `HandlePing`

**Changes**:
- `chunk_notify_handler.go` — remove `handlePing()`, route
  ping through router in legacy dispatch
- `combiner_chunk.go` — remove `CombinerHandlePing()`
- `router_init.go` — `InitializeCombinerRouter()` registers
  `HandlePing` instead of `cfg.HandlePing`
- `CombinerRouterConfig` — remove `HandlePing` field
- `main_initfuncs.go` — remove
  `HandlePing: combinerHandler.CombinerHandlePing` from
  config

#### 2b-iii: Unify beat handler — DONE

`HandleBeat` does:
1. Parse beat payload, validate type
2. Store `incoming_message` in context (for optional
   hsyncengine routing)
3. Construct generic confirm response (`status: "ok"`,
   `message: "beat acknowledged"`)
4. Store in `ctx.Data["sync_response"]`

Agent's `RouteToHsyncEngine` middleware picks up the message
from context. Combiner doesn't have that middleware. Same
handler, different middleware chains.

**Changes**:
- `handlers.go:HandleBeat` — add confirm response
  construction
- `combiner_chunk.go` — remove `CombinerHandleBeat()`
- `router_init.go` — `InitializeCombinerRouter()` registers
  `HandleBeat`
- `CombinerRouterConfig` — remove `HandleBeat` field
- `main_initfuncs.go` — remove
  `HandleBeat: combinerHandler.CombinerHandleBeat`

#### 2b-iv: Unify hello, relocate, confirm handlers — DONE

These already only exist in the agent router path
(`handlers.go`). No combiner duplicates. But the legacy path
in `chunk_notify_handler.go` still has separate dispatch.
Once the router is the only path, these are already unified.

**Changes**: `chunk_notify_handler.go` — remove legacy
dispatch for hello/relocate/confirm, route all through
router.

#### 2b-v: Clean up legacy dispatch in chunk_notify_handler.go — DONE

After 2b-ii through 2b-iv, `HandleChunkNotify()` (the legacy
path) should be dead code for all message types. Delete it.

**Changes**: `chunk_notify_handler.go` — remove
`HandleChunkNotify()` and related legacy helpers.
`RouteViaRouter()` is now the only entry point — remove
fallback to `HandleChunkNotify`.

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
2. `combiner agent ping` (combiner→agent) works (currently
   broken, fixed by 2b-i)
3. `agent ping` (agent→agent) works
4. Beat messages work in all directions
5. Hello/Relocate/Confirm work for agents
6. Build succeeds

## Phase 3: tdns-nm compilation fix — N/A

No `tdns-nm` component exists in the codebase. If KDC/KRS
adopt the unified router, that work is tracked separately.

## Phase 4: Persistence — NOT IMPLEMENTED

- Agent-side: serialize zone data repo (local + remote
  contributions) to file
- Load on startup; resync only for deltas
- Combiner persistence deferred — combiner can always resync
  via Phase 2

## Phase 5: TransportManager refactoring — DONE

`TransportManager` (`hsync_transport.go:32`) is already a
composition of independent components:
- `APITransport *transport.APITransport`
- `DNSTransport *transport.DNSTransport`
- `ChunkHandler *transport.ChunkNotifyHandler`
- `Router *transport.DNSMessageRouter`
- `PeerRegistry *transport.PeerRegistry`

`PeerRegistry` and `Router` are instantiated separately in
`NewTransportManager()` and composed in. The combiner uses a
separate `CombinerTransport` (a `TransportManager`) plus the
`DNSMessageRouter` wired directly into
`CombinerChunkHandler`.

## Phase 6: Unify SYNC Handler — DEFERRED

SYNC is the most complex message type because processing
differs significantly between agent and combiner:

- **Agent receives SYNC** (`handlers.go:HandleSync`): Routes
  to `SynchedDataEngine` via `IncomingChan`, which applies
  records to `ZoneDataRepo`, sends confirmations back, and
  optionally forwards to other peers. The handler just ACKs
  and routes.
- **Combiner receives SYNC**
  (`combiner_chunk.go:CombinerHandleSync`): Calls
  `ProcessUpdate()` to apply additions/deletions to
  `CombinerData` and `AgentContributions`, then returns a
  detailed confirmation with per-RR
  applied/removed/rejected lists, with a 3500-byte size
  guard.

The response formats also differ: agent SYNC sends a simple
confirm; combiner SYNC sends a detailed confirm with per-RR
tracking. Code comment in `router_init.go:278` explicitly
notes this is deferred to Phase 6.

### Design approach (deferred — needs more analysis)

Options:
- (a) Single `HandleSync` with a callback for the processing
  step (agent passes route-to-hsyncengine, combiner passes
  ProcessUpdate)
- (b) Single `HandleSync` that always routes to a channel;
  combiner gets its own "hsyncengine equivalent" goroutine
- (c) Keep two handlers but share the response construction
  via a helper

This needs careful design because SYNC is the core data path
and any abstraction must not add latency or complexity.

## Phase 7: Inline Phase-1 Confirmation in NOTIFY Response

### Problem

The current two-phase SYNC confirmation uses two separate
outbound NOTIFY(CHUNK) messages back to the originator:

1. **Phase 1 (immediate)**: Remote agent receives SYNC,
   validates it, sends back an immediate confirmation via a
   separate NOTIFY(CHUNK) — "I received and accepted your
   SYNC"
2. **Phase 2 (deferred)**: After the remote combiner
   processes the data, a second NOTIFY(CHUNK) carries the
   final confirmation (accepted or rejected with
   `RejectedItems`)

Phase 1 is generated synchronously during NOTIFY
processing — the result is known before the DNS response is
sent. There's no reason this confirmation can't ride the
NOTIFY **response** (via EDNS0 options) instead of requiring
a separate outbound message.

### Design: Try inline, fall back to explicit

The optimization is NOT to replace the explicit NOTIFY
confirmation — it's to **try the inline response first** and
fall back:

1. Remote agent processes incoming SYNC NOTIFY
2. Remote agent packs phase-1 confirmation into the NOTIFY
   **response** (EDNS0 payload)
3. If the originating agent receives the response → phase 1
   confirmed, no separate NOTIFY needed
4. If the response is blocked (middleboxes dropping unknown
   EDNS0 options, packet too large, etc.) → originating
   agent gets no response → retries the same SYNC
5. Remote agent receives the **duplicate SYNC** → detects
   it's a retransmission (same DistributionID, already
   processed) → realizes the inline response didn't get
   through → falls back to sending an **explicit
   NOTIFY(CHUNK) confirmation** (current model)

This is strictly an optimization: one fewer round-trip in
the common case, with automatic fallback when the inline
response path is broken.

### Why both paths are needed

Devices exist that drop DNS packets with unknown or encrypted
EDNS0 options. If the phase-1 confirmation only rides the
NOTIFY response and that response is dropped, the originating
agent never learns the SYNC was received. The
duplicate-detection + fallback ensures delivery.

### Current state (partially in place)

The response-side infrastructure already exists:
- `SendResponseMiddleware` (`handlers.go:423`) packs a CHUNK
  EDNS0 payload into the NOTIFY response for all message
  types
- `extractConfirmFromResponse()` (`dns.go:854`) extracts the
  EDNS0 CHUNK option from the response
- `dns.go:829` returns `Retryable=true` when no EDNS0
  confirmation is found — the reliable queue will retry

What is **not yet implemented**:
- **Duplicate DistributionID detection** on the receiver:
  when the same distID arrives twice, the receiver currently
  re-processes the SYNC instead of recognising it as a
  retransmission caused by a lost inline response
- **Fallback to explicit NOTIFY**: on duplicate detection,
  the receiver should send an explicit NOTIFY(CHUNK)
  confirmation back rather than relying on another inline
  EDNS0 attempt

Without these two pieces, the `Retryable=true` path just
causes a bare SYNC retry — no deduplication, no explicit
NOTIFY fallback.

### Effort estimate

~100-150 lines. The EDNS0 response packing already exists.
The main new code is:
- Duplicate SYNC detection (by DistributionID) in the
  receiving agent
- Fallback to explicit NOTIFY on duplicate detection

### Dependency

Independent of multi-signer work. Can be done whenever
transport unification reaches this level of refinement.

---

## Verification

Phases 1–2b and 5 are complete. Current state:

- All message types work over both DNS and API transports
- Combiner receives messages via the same router/middleware
  as agent
- `agent distrib list` shows DistributionID for all message
  types (including beats)
- PING requires authorization
- `combiner resync` command triggers RFI FULL to all known
  agents
- All control-plane messages (PING, BEAT, HELLO, RELOCATE)
  use one shared handler
- No duplicate message handling code for control-plane types
- Legacy `HandleChunkNotify` path deleted
- `combiner agent ping` (combiner→agent) works

Still pending:

- Phase 4: Agent zone data persistence across restarts
- Phase 6: SYNC handler unification (combiner still has
  separate `CombinerHandleSync`)
- Phase 7: Inline phase-1 SYNC confirmation (EDNS0 response
  packing is in place; duplicate DistributionID detection and
  explicit-NOTIFY fallback are not)

Build: `cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make`
