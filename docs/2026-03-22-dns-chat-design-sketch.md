# DNS-Based Secure Messaging: Design Sketch

Date: 2026-03-22
Status: IDEA — creative exploration, not committed work

## Purpose

A DNS-based secure messaging application built on top of
tdns-transport. Demonstrates that the CHUNK/JOSE transport
framework is general-purpose — not just for DNS operations.

Messages are distributed through a network of DNS servers,
signed with JWKs published in DNS, and delivered to
recipients via gossip-like propagation.

## Architecture Overview

```
Sender                                      Receiver
  |                                            |
  |  CHUNK message (signed, encrypted)         |
  |  to any server in the mesh                 |
  v                                            |
Server A  --gossip-->  Server B  --gossip-->  Server C
                                               |
                                               |  message delivered
                                               |  (poll or push)
                                               v
                                            Receiver
```

## Identity Model: Member Zones

Identity is DNS-native. No separate PKI.

A **member zone** is a DNS zone that contains JWK records
for its members. Example:

```
chat.example.com.
  alice.chat.example.com.  JWK  { "kty": "EC", ... }
  bob.chat.example.com.    JWK  { "kty": "EC", ... }
```

- A user's identity is their DNS name
- Their public key is their JWK record
- Anyone can look up a user's key via DNS
- Multiple member zones = federation (users in different
  zones can message each other)
- The zone operator controls membership (add/remove JWKs)

**Verification**: when a server receives a message, it
looks up the sender's JWK in DNS and verifies the
signature. Unsigned or unverifiable messages are dropped.

## Message Format

```json
{
   "id": "uuid-v4",
   "from": "alice.chat.example.com.",
   "to": "bob.chat.example.com.",
   "timestamp": "2026-03-22T14:30:00Z",
   "ttl": 3600,
   "content": "encrypted-payload",
   "signature": "JWS-signature-over-all-above"
}
```

- **id**: UUID, unique per message, used for confirmation
  and deduplication
- **from**: sender's DNS identity (FQDN)
- **to**: recipient's DNS identity (FQDN)
- **ttl**: seconds until message expires, server drops
  undelivered messages after TTL
- **content**: encrypted with recipient's public JWK
  (only recipient can read it)
- **signature**: sender signs the entire message with
  their private JWK (servers verify sender identity)

## Message Propagation

Messages propagate through the server mesh using a
gossip-like protocol, similar to the existing beat/gossip
mechanism in tdns-transport.

### Routing

Servers don't need full routing tables. Simple approach:

1. Server receives message for recipient X
2. If X is connected to this server → deliver
3. If not → propagate to all peers (with dedup via
   message UUID)

More sophisticated routing (if needed later):
- Servers track which peers have which connected users
- Gossip this information in beats
- Route directly to the right peer

### Deduplication

Each server maintains a seen-message cache (UUID →
timestamp). Messages already seen are dropped. Cache
entries expire after message TTL.

### Confirmation Flow

```
Recipient's server  →  propagate back through mesh  →
  Sender's server  →  Sender

Confirmation message:
{
   "type": "confirm",
   "message_id": "uuid-of-original",
   "status": "delivered"
}
```

Once all servers see the confirmation, they drop the
message from their propagation queue. This is the same
reliable delivery pattern as multi-provider CONFIRM.

## Message Delivery to Recipients

### How Telegram et al. do it

All major messaging platforms (Telegram, Signal,
WhatsApp) use **persistent full-duplex connections**
(TCP or WebSocket). The server pushes messages over
the existing connection. When the app is backgrounded,
they fall back to OS push notifications (APNs/FCM)
to wake the app.

### Our constraints

DNS is request-response, not persistent. We don't have
WebSockets or long-lived TCP connections in the DNS
model. Our options:

### Option 1: Long-poll (RECOMMENDED for initial impl)

Recipient sends a DNS query to their server. Server
holds the query open until either:
- A message arrives → respond with the message
- Timeout (e.g. 30s) → respond with empty, client
  immediately re-polls

This is identical to Telegram's Bot API `getUpdates`
mechanism. It works through NATs, is simple to
implement, and gives near-real-time delivery (~0-30s
latency depending on timing).

**Implementation**: new DNS query type where qname
encodes the recipient identity. Server matches against
pending messages. Response carries CHUNK payload with
the message(s).

### Option 2: Push via NOTIFY

If the recipient runs a daemon (is a server, or runs
a lightweight receiver), the server sends a NOTIFY
with the message as a CHUNK payload. Same mechanism
as multi-provider CONFIRM.

Better latency (instant), but requires recipient
reachability. Does not work through NATs.

### Option 3: Hybrid (RECOMMENDED for production)

Recipient declares its delivery preference:
- **poll**: "I will poll you" (NAT-friendly, default)
- **push**: "Send me NOTIFYs at this address"
  (low latency, requires reachability)

Stored as a DNS record or communicated at registration.
Server uses the appropriate mechanism per recipient.

## Group Messaging

Member zones naturally define groups. Two models:

**Zone-as-group**: send a message with `"to":
"chat.example.com."` (the zone apex). Server delivers
to all members of that zone. Simple, works with
existing infrastructure.

**Explicit groups**: a TXT or custom record at a name
within the zone lists group members. Messages to that
name go to listed members only.

## Server Requirements

A chat server is a tdns-transport application that:

1. Imports tdns + tdns-transport
2. Registers message handlers for: send, poll, confirm
3. Participates in server mesh via existing peer
   discovery (HSYNC3 or configured peers)
4. Maintains a message queue per connected user
5. Propagates messages to peers via gossip
6. Verifies sender JWK signatures on receipt
7. Encrypts stored messages with recipient's JWK

Estimated implementation size: modest. Most of the
heavy lifting (CHUNK transport, JOSE crypto, peer
management, gossip) is already in tdns-transport.

## Security Properties

- **End-to-end encrypted**: content encrypted with
  recipient's JWK, only recipient can decrypt
- **Sender authenticated**: JWK signature verified by
  every server in the chain
- **No server-side plaintext**: servers route encrypted
  blobs, cannot read content
- **Ephemeral**: messages expire after TTL, no
  permanent storage
- **Identity via DNS**: no separate account system, no
  passwords, identity = DNS name + published JWK
- **Federation via DNS**: cross-zone messaging works
  because JWK lookup is just a DNS query

## Comparison to Existing Systems

| | Signal | Telegram | DNS Chat |
|---|---|---|---|
| Identity | Phone number | Phone number | DNS name |
| PKI | Signal servers | Telegram servers | DNS (JWK records) |
| Transport | WebSocket | MTProto/TCP | DNS CHUNK/JOSE |
| Delivery | Push (persistent conn) | Push (persistent conn) | Poll or push (DNS) |
| E2E encryption | Yes (Signal Protocol) | Optional (MTProto) | Yes (JWK/JOSE) |
| Server sees content | No | Yes (non-secret chats) | No |
| Federation | No | No | Yes (cross-zone) |
| Persistence | Store-and-forward | Cloud storage | Ephemeral (TTL) |

## Name Suggestions

- **murmur** — messages propagate like murmurs through
  the network of servers
- **dnschat** — straightforward
- **whisper** — encrypted, ephemeral messaging
- **relay** — messages relayed through DNS mesh

## Mobile App: The Killer Demo

The most compelling demonstration would be a **mobile
phone app**. Infrastructure-to-infrastructure messaging
is useful but invisible. A phone app makes it tangible.

### Transport: DNS-over-TCP as Persistent Connection

We already use TCP for DNS. A long-lived TCP connection
between the phone app and its "home" nameserver is
essentially the same architecture as Signal (WebSocket)
or WhatsApp (TCP/XMPP) — just speaking DNS on the wire.

RFC 7766 encourages TCP connection reuse and imposes
no protocol-level maximum timeout. We control both
client and server, so we set whatever timeout we want.

```
Phone App  ----TCP (long-lived)---->  Home Server
                                        |
                                      mesh gossip
                                        |
               Other Servers  <-------->+
```

### Connection Lifecycle

1. **Connect**: app opens TCP to home server, sends
   HELLO with identity + JWK signature
2. **Idle**: connection stays open. Server pushes
   incoming messages as NOTIFY+CHUNK down the TCP
   connection. App sends messages as NOTIFY+CHUNK up.
3. **Ping**: periodic keepalive (existing ping mechanism)
   to detect dead connections and keep NAT mappings alive
4. **Disconnect**: OS kills connection (background,
   sleep, network switch). Server queues messages.
5. **Reconnect**: app reconnects, sends "catch-up" query
   ("give me everything since timestamp X"). Server
   drains queue, then resumes push mode.

### Comparison to Signal/Telegram Architecture

| | Signal | Telegram | DNS Chat Mobile |
|---|---|---|---|
| Wire protocol | WebSocket | MTProto/TCP | DNS/TCP |
| Connection | Persistent WS | Persistent TCP | Persistent TCP |
| Push mechanism | Server writes to WS | Server writes to TCP | Server sends NOTIFY+CHUNK |
| Catch-up | Reconnect + drain | Reconnect + resend unACKed | Reconnect + poll since timestamp |
| Background wake | APNs/FCM | APNs/FCM | APNs/FCM (future, optional) |

The architecture is essentially identical. The difference
is that our wire protocol is DNS, which means:
- Every message is a valid DNS transaction
- Existing DNS infrastructure (firewalls, monitoring)
  sees normal DNS traffic
- No new ports, no new protocols to whitelist

### Mobile OS Constraints

- **iOS**: background TCP connections are killed after
  ~30 seconds of inactivity. Must use periodic keepalive
  or accept reconnect-and-drain model. APNs integration
  needed for production use.
- **Android**: more lenient with background connections
  but battery optimization may kill them. FCM integration
  for reliable background delivery.
- **Both**: foreground use with persistent TCP works fine.
  Background delivery is the hard part, same as for
  every other messaging app.

### MVP Scope

A proof-of-concept mobile app needs:
1. TCP connection management (connect, keepalive,
   reconnect)
2. Send message (NOTIFY+CHUNK to home server)
3. Receive message (server pushes NOTIFY+CHUNK)
4. Catch-up on reconnect (poll since last seen timestamp)
5. Simple UI: contact list (from member zone), message
   thread, send box

Does NOT need for MVP:
- APNs/FCM integration (foreground-only is fine)
- Group chat (1:1 is enough to demonstrate)
- File transfer
- Read receipts

### Technology

- **iOS**: Swift, using Network.framework for TCP
- **Android**: Kotlin, using java.nio or Netty for TCP
- **Cross-platform**: Flutter or React Native with a
  native TCP module
- **DNS parsing**: minimal — only needs to construct
  and parse NOTIFY+CHUNK messages, not a full resolver

## Open Questions

1. Should servers store messages for offline recipients
   or only deliver to currently-connected users?
   (Store-and-forward up to TTL seems right.)

2. Maximum message size? CHUNK can handle large payloads
   but chat messages should be small. Cap at 4KB? 16KB?

3. Should read receipts be a thing? (Easy to add as
   another confirmation type, but privacy implications.)

4. File/image transfer? Could work via CHUNK but feels
   like scope creep for a proof-of-concept.

5. Key rotation? User publishes new JWK, old one removed.
   In-flight messages encrypted with old key can't be
   decrypted. Need a transition period with both keys?

## Value as a Framework Demonstration

This app exercises every layer of tdns-transport:

- **CHUNK transport**: message payloads
- **JOSE crypto**: signing + encryption
- **Message routing**: custom message types (send,
  poll, confirm)
- **Peer management**: server mesh discovery
- **Gossip propagation**: message distribution
- **Confirmation semantics**: delivery confirmation
- **DNS identity**: JWK lookup for sender verification

It proves the framework handles a domain completely
unrelated to DNS operations, which is the strongest
possible argument for tdns-transport as a general-
purpose communication layer.
