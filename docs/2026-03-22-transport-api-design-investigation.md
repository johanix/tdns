# Transport API Design Investigation

Date: 2026-03-22
Status: RESEARCH ONLY — no code changes until after repo split

## Purpose

Before extracting tdns-transport as a reusable library,
investigate how its public API should look. Two areas
need comparison with established patterns in the TLD
registry / REST API space.

## (A) Confirmation Model: Two-Step Confirm vs Alternatives

### What we have now

Immediate ACK ("PENDING") followed by async CONFIRM
NOTIFY with the actual result. This is a push-based
callback over DNS:

```
Agent → Combiner:  UPDATE message
Combiner → Agent:  immediate "PENDING" ACK
  (combiner processes async)
Combiner → Agent:  CONFIRM NOTIFY with result
```

### Patterns used elsewhere

**1. Webhook / callback registration**
Client registers a callback URL. Server POSTs result
when ready. Used by: Stripe, GitHub, many payment APIs.

- Pro: clean async, client controls where results go
- Con: client must be reachable, URL management overhead
- Our equivalent: we push via DNS NOTIFY, which is
  essentially a DNS-native webhook

**2. Polling with location header**
Server returns `202 Accepted` + a status URL. Client
polls until result appears. Used by: Azure ARM, AWS
CloudFormation, ICANN CZDS.

- Pro: simple, client-driven, no callback infra needed
- Con: chatty, latency = poll interval, wasted requests
- Our equivalent: RFI mechanism (agent can ask combiner
  "what happened to my update?") but not currently used
  as a polling pattern

**3. Long-poll / SSE / WebSocket**
Hold connection open until result arrives. Used by:
Cloudflare API for deployments, various real-time APIs.

- Pro: low latency, no polling waste
- Con: connection management, timeout handling, not
  natural for DNS

**4. EPP (Extensible Provisioning Protocol)**
Used by domain registries (Verisign, etc.). Synchronous
request-response over persistent TCP. Slow operations
return a "pending" response code (1001) and the result
arrives later via EPP poll messages.

- Pro: well-proven in domain industry
- Con: requires persistent connection, poll-based
- Our equivalent: very similar! We return PENDING and
  push the result, which is arguably better than EPP's
  poll model

**5. RDAP + REST registrar APIs**
Newer registry APIs. Mostly synchronous. Some operations
(transfers, disputes) use status polling.

### Assessment

Our current model (immediate PENDING + async CONFIRM
push) is actually well-designed for the DNS context:

- No polling overhead
- No persistent connection required
- Push-based, so low latency
- Natural fit for NOTIFY mechanism

**Key limitation of our push model:** it requires both
sides to be reachable. This is fine for DNS nameservers
(they must be reachable by definition) but would not
work for clients behind NATs. The poll model's main
advantage is that it works through NATs — the client
initiates all connections, server never needs to reach
back.

For tdns-transport as a general-purpose library, this
matters: not all future consumers will be nameservers.
A KRS behind a NAT can send requests to a KDC but
can't receive unsolicited NOTIFY pushes. Supporting
both push (current) and poll (fallback for NAT'd
clients) may be needed.

**Possible improvements to investigate:**
- Support both push and poll confirmation models, with
  the client choosing based on its reachability
- Should the PENDING ACK carry an estimated completion
  time? (REST APIs sometimes include Retry-After)
- Should there be a timeout/expiry on pending operations?
  (What if CONFIRM never arrives?)
- Should there be an explicit "cancel" mechanism?
- Should the client be able to register interest in
  specific notification types? (subscription model)

## (B) Message Type Model: Domain Verbs vs CRUD Semantics

### What we have now

Domain-specific message types:
- hello, beat, sync, update, rfi, ping
- keystate, edits, config, audit, status-update

These are verbs specific to the multi-provider domain.

### REST CRUD model

Generic operations on resources:
- GET (read), POST (create), PUT (replace),
  PATCH (modify), DELETE (remove)

Applied to our domain:
- `GET zone/data` ≈ rfi edits, rfi keystate
- `POST zone/update` ≈ update (new contribution)
- `PATCH zone/records` ≈ ClassINET add / ClassNONE delete
- `DELETE zone/records` ≈ ClassANY remove

### Hybrid model (verbs + resources)

Keep some domain verbs but make the framework generic:
- Transport layer defines: MessageType (string) +
  Resource (string) + Operation (enum: query/mutate/notify)
- Apps register handlers for (MessageType, Resource) pairs
- Framework handles routing, confirmation, retry

Example registrations:
- MP app: ("update", "zone/*") → HandleUpdate
- KDC app: ("distribute", "key/*") → HandleKeyDistribution
- Any app: ("ping", "*") → HandlePing

### Assessment

For tdns-transport as a reusable library, the message
type system should be:

1. **Generic at the framework level** — MessageType is
   just a string, apps define their own types
2. **Typed at the app level** — each app has its own
   constants and handler registrations
3. **Common infrastructure messages built-in** — ping,
   hello, beat could be provided by the framework since
   peer liveness is a transport concern

This is essentially what we have now in the router
(handlers register for MessageType strings) but the
built-in message types are MP-specific. The change
would be:
- Framework provides: ping, hello (peer introduction)
- Framework defines: MessageType registration API
- Apps provide: everything domain-specific

### Questions to resolve

1. Should beat/heartbeat be a framework feature or
   app-level? (Argument for framework: peer liveness
   is transport-level. Argument against: beat payload
   carries gossip, which is MP-specific.)

2. Should confirmation semantics be built into the
   framework? (Probably yes — reliable delivery is a
   transport concern, not app-specific.)

3. Should the framework enforce request-response
   pairing or allow fire-and-forget? (Both — let the
   app choose per message type.)

4. How much of the peer state machine (NEEDED → KNOWN
   → INTRODUCING → OPERATIONAL) is generic vs
   MP-specific?

## Relationship to Repo Split

These design questions inform how tdns-transport's
public API should look, but **no code changes should
happen until after the repo split**. The split should
proceed with the current message type model. API
redesign is a separate effort that happens after
tdns-transport exists as its own repo.

Priority order:
1. Fix current brokenness
2. Repo split (current API preserved)
3. API redesign within tdns-transport (this doc)
