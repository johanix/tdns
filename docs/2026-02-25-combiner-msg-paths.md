# Combiner Incoming Message Paths: PING, BEAT, SYNC

**Date**: 2026-02-25
**Status**: Analysis / reference documentation

## Overview

This document traces the full path of incoming PING, BEAT, and SYNC messages
through the **combiner** role, from DNS wire arrival to response transmission.

The combiner processes all three message types **synchronously** within the
router handler — unlike the agent, which routes messages through channels to
the HsyncEngine for asynchronous processing.

---

## Common Entry Path (all message types)

All agent-to-combiner messages use NOTIFY(CHUNK) as the DNS transport.

```
1. DNS packet arrives on wire (UDP/TCP)
   └─ dns.Server.ListenAndServe()                          do53.go

2. dns.Server calls authDNSHandler(w, r)
   └─ createAuthDnsHandler()                                do53.go:187

3. Dispatch by Opcode
   └─ case dns.OpcodeNotify:                                do53.go:213
       ├─ qtype = r.Question[0].Qtype  (= core.TypeCHUNK)
       ├─ handlers = getNotifyHandlers(conf, qtype)         do53.go:221
       │   finds CombinerChunkHandler registered via
       │   RegisterCombinerChunkHandler()                    combiner_chunk.go:674
       └─ handler(ctx, &DnsNotifyRequest{...})              do53.go:233
           → CombinerChunkHandler.RouteViaRouter()          combiner_chunk.go:133
```

### RouteViaRouter (shared prologue)

```
4. Extract distribution ID + sender from QNAME              combiner_chunk.go:144
   QNAME format: {distid}.{sender-controlzone}
   e.g. "698b1b0b.agent.alpha.dnslab."
   → distributionID = "698b1b0b"
   → controlZone    = "agent.alpha.dnslab."

5. Get CHUNK payload                                         combiner_chunk.go:154
   ├─ Try EDNS0 option code 65004 first                     combiner_chunk.go:251
   └─ Fallback: CHUNK query to sender                       combiner_chunk.go:260-278
       (uses agent address from combiner config)

6. Decrypt payload (if SecureWrapper configured)             combiner_chunk.go:166-174
   └─ SecureWrapper.UnwrapIncoming(controlZone, payload)

7. Determine message type from JSON payload                  combiner_chunk.go:177
   └─ transport.DetermineMessageType(payload)               router_init.go:370-393
       parses JSON "MessageType" field → "ping" / "beat" / "sync"

8. Create MessageContext                                     combiner_chunk.go:187-196
   msgCtx.PeerID        = controlZone (sender identity)
   msgCtx.ChunkPayload  = decrypted payload
   msgCtx.Data["local_id"] = combiner identity

9. Wrap with SendResponseMiddleware(w, msg)                  combiner_chunk.go:199
   └─ Route through combiner's DNSMessageRouter             combiner_chunk.go:201
       router.Route(msgCtx, msgType)
```

The combiner router was initialized by `InitializeCombinerRouter()` in
`router_init.go:228` with middleware chain:

1. **Authorization** (outermost)
2. **Signature verification** (if crypto configured)
3. **Logging**

Note: **No `RouteToHsyncEngine` middleware** — the combiner processes
everything synchronously within the handler.

---

## PING

```
router.Route(msgCtx, "ping")
└─ HandlePing()                                             handlers.go:63

HandlePing():
  1. Parse DnsPingPayload from ctx.ChunkPayload              handlers.go:78
     → extracts: Nonce, SenderID
  2. Validate nonce is non-empty                              handlers.go:86
  3. Build DnsPingConfirmPayload:                             handlers.go:94-101
     {type: "ping_confirm", sender_id: <combiner-id>,
      nonce: <echo>, status: "ok"}
  4. Store in ctx.Data["ping_response"]                       handlers.go:109

SendResponseMiddleware (unwinding):                           handlers.go:438-443
  checks ctx.Data["ping_response"] → found
  └─ sendChunkResponse(w, msg, payload, RcodeSuccess)        handlers.go:480-500
      ├─ Build dns.Msg reply with RcodeSuccess
      ├─ Add EDNS0 OPT with CHUNK option (code 65004)
      │   containing the JSON ping_confirm payload
      └─ w.WriteMsg(resp) — DNS response sent on wire
```

**No HsyncEngine involvement.** PING is fully self-contained within the
router handler. The response echoes the nonce back to the sender.

---

## BEAT

```
router.Route(msgCtx, "beat")
└─ HandleBeat()                                              handlers.go:146

HandleBeat():
  1. Parse IncomingMessage from ctx.ChunkPayload              handlers.go:152-158
     → extracts: SenderID, message type
  2. Store ctx.Data["message_type"] = "beat"                  handlers.go:164
     Store ctx.Data["incoming_message"] = beatMsg             handlers.go:165
     (these go unused — no RouteToHsyncEngine middleware)
  3. Build confirm response:                                   handlers.go:169-181
     {type: "confirm", distribution_id: ...,
      status: "ok", message: "beat acknowledged"}
  4. Store in ctx.Data["sync_response"]                       handlers.go:186

SendResponseMiddleware (unwinding):                           handlers.go:446-449
  checks ctx.Data["sync_response"] → found
  └─ sendChunkResponse(w, msg, payload, RcodeSuccess)
      └─ DNS response with EDNS0 CHUNK confirmation on wire
```

**No HsyncEngine involvement.** The combiner acknowledges the beat but does
NOT update any agent registry, track beat intervals, or change agent state.
The `ctx.Data["incoming_message"]` is set by `HandleBeat()` but never consumed
because the combiner router has no `RouteToHsyncEngine` middleware.

---

## SYNC

```
router.Route(msgCtx, "sync")
└─ CombinerHandleSync()                                      combiner_chunk.go:585
   (registered as cfg.HandleSync in InitializeCombinerRouter)

CombinerHandleSync():
  1. Parse sync payload via parseAgentMsgNotify()             combiner_chunk.go:589
     → CombinerSyncRequest{SenderID, Zone, Records, DistributionID}

  2. ProcessUpdate(syncReq)                                    combiner_chunk.go:596
     ProcessUpdate():                                          combiner_chunk.go:406-569
     a. Look up zone: Zones.Get(zonename)                     :422
     b. For each RR in Records:
        ├─ dns.NewRR(rrStr) — parse                           :443
        ├─ Check AllowedLocalRRtypes                          :452
        ├─ Check owner == zone apex                           :462
        ├─ checkContentPolicy (NS namespace protection)       :471
        └─ Route by RR class:
           ├─ ClassINET → addOwnerRRs (additions)             :481
           ├─ ClassNONE → deleteOwnerRRs (specific removal)   :485
           └─ ClassANY  → bulkDeleteOwner (rrset removal)     :493
     c. Apply additions: zd.AddCombinerDataNG()               :506
     d. Apply removals:  zd.RemoveCombinerDataNG()            :516
     e. Apply bulk deletes: zd.RemoveCombinerDataByRRtype()   :525
     f. Bump serial: zd.BumpSerialOnly()                      :559
     g. Return CombinerSyncResponse with applied/removed/rejected

  3. Build JSON confirmation payload                           combiner_chunk.go:601-654
     {type: "confirm", distribution_id, zone, status, message,
      applied_count, removed_count, rejected_count,
      applied_records[], removed_records[], rejected_items[]}
     Size guard: truncate record lists if >3500 bytes         :646

  4. Store in ctx.Data["sync_response"]                        combiner_chunk.go:656

SendResponseMiddleware (unwinding):                            handlers.go:446-449
  checks ctx.Data["sync_response"] → found
  └─ sendChunkResponse(w, msg, confirmPayload, RcodeSuccess)
      └─ DNS response with detailed per-RR confirmation on wire
```

SYNC is the only message type that modifies zone data. The zone update and
serial bump happen **synchronously before the DNS response is sent**, so
the sending agent receives a confirmation that includes the actual
applied/removed/rejected results.

---

## Architecture Comparison: Agent vs Combiner

| Aspect | Agent (incoming) | Combiner (incoming) |
|--------|-----------------|---------------------|
| **Entry point** | Same: DnsEngine → NOTIFY handler | Same |
| **CHUNK handler** | `ChunkHandler.RouteViaRouter()` with `RouteToHsyncEngine` middleware | `CombinerChunkHandler.RouteViaRouter()` — **no** `RouteToHsyncEngine` |
| **PING** | Shared `HandlePing()` — synchronous response | Same `HandlePing()` — synchronous response |
| **BEAT** | `HandleBeat()` → `RouteToHsyncEngine` → `IncomingChan` → `routeBeatMessage()` → auth check → `agentQs.Beat` → `HsyncEngine` → `HeartbeatHandler` | `HandleBeat()` → response only, **message dropped** |
| **SYNC** | `HandleSync()` → `RouteToHsyncEngine` → `IncomingChan` → `routeSyncMessage()` → auth check → `agentQs.Msg` → `HsyncEngine` → `MsgHandler` + `sendImmediateConfirmation()` | `CombinerHandleSync()` → **synchronous** `ProcessUpdate()` → inline confirmation |
| **State updates** | Updates AgentRegistry, PeerRegistry, agent state (INTRODUCED/OPERATIONAL) | None — no agent state tracking |
| **Response** | BEAT/SYNC: simple ack; detailed confirmation comes later via separate NOTIFY | All responses are inline in the DNS reply EDNS0 |

### Key Asymmetry

The agent has a **two-hop path**: router handler → middleware → channel →
TransportManager → auth check → HsyncEngine channel → handler. This enables
asynchronous processing and two-phase confirmations (immediate "pending" +
later "final").

The combiner does everything **inline in the router handler** and returns
the complete result in the DNS response. The combiner never touches
HsyncEngine, AgentRegistry, or any channel-based processing for incoming
messages.

### Consequence for BEAT

On the agent side, incoming beats update agent state (OPERATIONAL), track
beat intervals, and drive the state machine. On the combiner, incoming
beats are acknowledged but **have no effect** — the combiner does not
maintain an agent registry or track peer liveness.

This is an architectural gap: if the combiner ever needs to know whether
an agent is alive (e.g. for deciding whether to include its contributions
in zone builds), it has no beat-based liveness data to work with.
