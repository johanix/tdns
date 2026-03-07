# Agent Incoming Message Paths: PING, BEAT, SYNC

**Date:** 2026-02-25
**Status:** Analysis / Architectural Reference

## Overview

All three message types (PING, BEAT, SYNC) arrive as DNS NOTIFY messages with
qtype CHUNK (65015), carrying JSON payloads in EDNS0 option 65004. The message
type is determined by parsing the JSON `MessageType` field, not from DNS headers.

## Common Path (all message types)

```
DNS wire
  └─ DnsEngine()                                    do53.go:34
     └─ createAuthDnsHandler()                      do53.go:187
        └─ case OpcodeNotify:                       do53.go:213
           └─ getNotifyHandlers(TypeCHUNK)          registration.go:176
              └─ TransportManager.RegisterChunkNotifyHandler()
                                                    hsync_transport.go:328
                 └─ ChunkNotifyHandler.RouteViaRouter()
                    chunk_notify_handler.go:331
                    ├─ extractDistributionID(qname)               :345
                    ├─ extractSenderHintFromQname(qname)          :352
                    ├─ extractChunkPayload(EDNS0 65004)           :355
                    ├─ SecureWrapper.UnwrapIncomingFromPeer()      :367
                    ├─ parsePayload() → determines MessageType    :411
                    └─ SendResponseMiddleware wraps:               :460
                       └─ DNSMessageRouter.Route(msgType)
                          dns_message_router.go:196
```

## Middleware Chain

Registered in `InitializeRouter()` (router_init.go:49). Executed outermost to innermost:

1. **AuthorizationMiddleware** — crypto_middleware.go:237 — checks `IsPeerAuthorized(senderID, zone)`
2. **SignatureMiddleware** — crypto_middleware.go:64 — verifies JWS/JWE, decrypts payload
3. **StatsMiddleware** — stats_middleware.go — records peer statistics
4. **LoggingMiddleware** — crypto_middleware.go:282 — logs processing
5. **RouteToHsyncEngine** — handlers.go:511 — forwards beat/sync to hsyncengine channels

Then the type-specific handler runs.

## PING Path

```
HandlePing                                          handlers.go:63
  ├─ Parse DnsPingPayload (nonce, sender identity)
  ├─ Build DnsPingConfirmPayload (echo nonce back, status "ok")
  ├─ Store in ctx.Data["ping_response"]
  └─ NOT routed to hsyncengine (no "message_type" set)

SendResponseMiddleware                              handlers.go:425
  └─ sees ctx.Data["ping_response"]                 handlers.go:438
     └─ sendChunkResponse()                         handlers.go:480
        └─ NOTIFY response with payload in EDNS0 opt 65004
```

PING is handled entirely in the transport layer. It never reaches the hsyncengine.

## BEAT Path

```
HandleBeat                                          handlers.go:146
  ├─ Validate type == "beat"
  ├─ Set ctx.Data["message_type"] = "beat"
  ├─ Build confirm JSON ("beat acknowledged")
  └─ Store in ctx.Data["sync_response"]

SendResponseMiddleware                              handlers.go:425
  └─ sees ctx.Data["sync_response"]                 handlers.go:446
     └─ sendChunkResponse()                         handlers.go:480
        └─ NOTIFY response with confirm in EDNS0 opt 65004

RouteToHsyncEngine middleware                       handlers.go:511
  └─ sees message_type == "beat" → IncomingChan     handlers.go:523
     └─ StartIncomingMessageRouter                  hsync_transport.go:348
        └─ routeIncomingMessage                     hsync_transport.go:370
           └─ routeBeatMessage                      hsync_transport.go:477
              ├─ Parse DnsBeatPayload
              ├─ Authorization check (zones)        hsync_transport.go:493-521
              ├─ Update PeerRegistry/AgentRegistry → OPERATIONAL
              └─ Send AgentMsgReport to agentQs.Beat    :567
```

## SYNC Path

```
HandleSync                                          handlers.go:194
  ├─ Reject if peer has zero shared zones
  ├─ Validate type == "sync"
  ├─ Set ctx.Data["message_type"] = "sync"
  ├─ Build confirm JSON ("sync received from <peer>")
  └─ Store in ctx.Data["sync_response"]

SendResponseMiddleware                              handlers.go:425
  └─ sees ctx.Data["sync_response"]                 handlers.go:446
     └─ sendChunkResponse()                         handlers.go:480
        └─ NOTIFY response with confirm in EDNS0 opt 65004

RouteToHsyncEngine middleware                       handlers.go:511
  └─ sees message_type == "sync" → IncomingChan     handlers.go:523
     └─ StartIncomingMessageRouter                  hsync_transport.go:348
        └─ routeIncomingMessage                     hsync_transport.go:370
           └─ routeSyncMessage                      hsync_transport.go:575
              ├─ Parse DnsSyncPayload (zone, records, distID)
              ├─ IsPeerAuthorized check             hsync_transport.go:602
              ├─ Build AgentMsgPostPlus → agentQs.Msg   :641
              └─ go sendImmediateConfirmation()     :647  (second-phase)
```

## Summary Table

| Aspect                  | PING              | BEAT              | SYNC              |
|-------------------------|-------------------|-------------------|-------------------|
| Response ctx key        | `ping_response`   | `sync_response`   | `sync_response`   |
| Response content        | DnsPingConfirmPayload (nonce echo) | confirm ("beat acknowledged") | confirm ("sync received") |
| Routed to hsyncengine?  | No                | Yes               | Yes               |
| Second-phase confirm?   | No                | No                | Yes (sendImmediateConfirmation) |
| Auth in middleware?      | Yes               | Yes               | Yes               |
| Auth again in hsync?     | No                | Yes (routeBeatMessage :493) | Yes (routeSyncMessage :602) |

## Known Architectural Issues

### 1. Dual Authorization

BEAT and SYNC are authorized once by `AuthorizationMiddleware` in the router
middleware chain, then authorized **again** inside `routeBeatMessage` /
`routeSyncMessage` in hsync_transport.go. The second check at
hsync_transport.go:493-521 is where the "REJECTED DNS beat — not authorized
(zones: [])" error comes from (see DNS-103).

The middleware-level auth and the hsync_transport-level auth use different
criteria — the middleware checks peer identity, while hsync_transport checks
zone-based authorization. When the zone list is empty (e.g. for signers that
don't share zones in the traditional sense), the second check fails even though
the first passed.

### 2. Inconsistent Response Key Naming

PING uses `ping_response`, BEAT and SYNC both use `sync_response`. A beat
confirmation is not a "sync response" — this is confusing and error-prone.

### 3. Response Sent Before Processing

The DNS response is sent in `SendResponseMiddleware` (outer layer), but actual
business logic processing happens asynchronously via `IncomingChan` →
`routeIncomingMessage`. The sender receives "ok" before the agent has actually
processed the beat/sync. This means the DNS-level "confirm" is only an
acknowledgment of receipt, not of processing.

For SYNC, there is an additional `sendImmediateConfirmation` sent after
processing begins, creating a two-phase confirmation pattern — but this second
confirmation is sent via a new outgoing DNS message, not as part of the original
DNS response.

### 4. PING Doesn't Reach hsyncengine

PING is handled entirely in the transport layer and never reaches the
hsyncengine. While this makes sense for a simple connectivity check, the three
"sibling" message types follow fundamentally different processing depths.

### 5. Split Processing Between Two Packages

Message parsing and DNS response happen in `agent/transport/`, while business
logic (peer state updates, zone authorization, queue routing) happens in the
main `v2/` package via `hsync_transport.go`. The boundary between these two
layers is the `IncomingChan` channel, with `RouteToHsyncEngine` acting as the
bridge middleware.
