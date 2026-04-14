# Multi-Provider Advanced Topics

This document covers topics beyond the basic quickstart setup:
how providers synchronize zone data between themselves, how
delegation information is kept in sync with the parent zone,
and how provider-controlled zones are managed.

## Contents

1. **Parent Synchronization** -- Automatically updating the
   delegation information (NS, DS, glue) in the parent zone
   of a customer zone.

2. **Provider Zones** -- Combiner management of zones
   controlled by the provider, where contents need to be
   managed in sync with customer zones (e.g., _signal KEY
   records for SIG(0) trust bootstrap).

3. **Provider-to-Provider Synchronization** -- The data flow
   from signer to local agent to remote agents to remote
   combiners. Double confirmations with per-record details.

4. **Agent-to-Agent Coordination** -- The gossip protocol,
   provider group computation, leader election, and group
   state management.


## 1. Parent Synchronization

When a child zone's delegation data changes (NS records, glue
addresses, or DS records), the parent zone must be updated.
TDNS automates this via two mechanisms, both driven by the
DSYNC RRset published in the parent zone.

### 1.1 The DSYNC RRset

The parent zone publishes a DSYNC RRset at `_dsync.<parent>.`
that advertises which synchronization schemes it supports and
where to send updates. The format is:

```
_dsync.parent. IN DSYNC <type> <scheme> <port> <target>
```

Where:
- **type** is the RR type being synchronized (CDS, CSYNC,
  CDNSKEY, or ANY)
- **scheme** is NOTIFY, UPDATE, SCANNER, or API
- **port** is the TCP/UDP port of the target
- **target** is the FQDN of the receiving server

Example:

```
_dsync.example.com. IN DSYNC CDS   NOTIFY 5354 notifications.example.com.
_dsync.example.com. IN DSYNC CSYNC NOTIFY 5354 notifications.example.com.
_dsync.example.com. IN DSYNC ANY   UPDATE 5354 updates.example.com.
```

This tells child zone operators: "to synchronize CDS or CSYNC,
send a generalized NOTIFY to notifications.example.com:5354.
To synchronize any record type, send a SIG(0)-signed UPDATE
to updates.example.com:5354."

### 1.2 The UPDATE Scheme (Child Side)

The UPDATE scheme is the more capable mechanism. The child
agent constructs a DNS UPDATE message, signs it with a SIG(0)
key, and sends it directly to the parent's UPDATE receiver.

**Flow:**

1. The agent detects a change to delegation data (NS, glue,
   or DS) in the customer zone.
2. The agent looks up the parent's DSYNC RRset via its IMR
   to find the UPDATE target address and port.
3. The agent constructs a DNS UPDATE message containing the
   adds and removes needed to bring the parent's delegation
   in sync.
4. The agent signs the UPDATE with its active SIG(0) key.
5. The agent sends the signed UPDATE to the parent's UPDATE
   receiver.

**SIG(0) Key Bootstrap:**

Before the parent will accept signed UPDATEs, it must trust
the child's SIG(0) key. The bootstrap flow is:

1. The elected leader agent generates a SIG(0) keypair (or
   uses an existing one) and sends a Publish instruction to
   the combiner.
2. The combiner publishes the KEY record at the zone apex
   and optionally at `_signal` names under each NS target
   in provider zones (see section 2).
3. The agent sends a self-signed UPDATE containing the KEY
   RR to the parent's UPDATE receiver.
4. The parent verifies the key via consistent-lookup: it
   queries all of the child's nameservers and checks that
   they all return the same KEY record.
5. Once verified, the parent marks the key as trusted and
   begins accepting signed UPDATEs from that key.
6. The agent polls the parent's KeyState EDNS(0) option to
   confirm trust has been established, then proceeds with
   the actual delegation sync.

**Agent configuration** (in tdns-agent.yaml):

```yaml
delegationsync:
   leader-election-ttl: 60m
   child:
      schemes: [ update ]
      update:
         keygen:
            mode:      internal
            algorithm: ED25519
```

The `mode: internal` setting means the agent generates SIG(0)
keys internally. The `algorithm` controls which algorithm is
used.

### 1.3 The NOTIFY Scheme (Child Side)

The NOTIFY scheme is simpler but requires the parent to run a
scanner. The child publishes CDS and/or CSYNC records at the
zone apex, then sends a generalized NOTIFY to the parent's
NOTIFY receiver. The parent's scanner picks up the NOTIFY,
queries the child for the published records, verifies them,
and applies the changes.

**Flow:**

1. The agent detects a change to delegation data.
2. The agent publishes a CSYNC record (for NS/glue changes)
   or a CDS record (for DS changes) at the zone apex.
3. The agent sends a NOTIFY with the appropriate QTYPE
   (CSYNC or CDS) to the parent's NOTIFY receiver address
   (from the DSYNC RRset).
4. The parent's scanner queries the child for the published
   records, validates them (DNSSEC if available), and applies
   the changes to the parent zone.

### 1.4 Scheme Selection

The agent selects the best scheme by intersecting the parent's
advertised schemes (from the DSYNC RRset) with its own
configured schemes (`delegationsync.child.schemes`). UPDATE is
preferred over NOTIFY when both are available, as it is more
immediate and does not require a scanner on the parent side.


## 2. Parent-Side Configuration

### 2.1 Automatic DSYNC Publication

When tdns-auth is configured as a parent zone primary with
`delegation-sync-parent` in the zone options, it automatically
publishes DSYNC RRsets based on the `delegationsync.parent`
configuration:

```yaml
delegationsync:
   parent:
      schemes: [ notify, update ]
      notify:
         types:      [ CDS, CSYNC ]
         port:       5354
         target:     notifications.{ZONENAME}
         addresses:  [ 198.51.100.1 ]
      update:
         types:      [ ANY ]
         port:       5354
         target:     updates.{ZONENAME}
         addresses:  [ 198.51.100.1 ]
         keygen:
            mode:      internal
            algorithm: ED25519
```

The `{ZONENAME}` template is expanded at runtime to the actual
zone name. The server creates DSYNC RRs at `_dsync.<zone>.`
and publishes A/AAAA glue records for the target names.

### 2.2 UPDATE Receiver

The tdns-agent (or tdns-auth) can act as the UPDATE receiver.
When it receives a SIG(0)-signed UPDATE for a child delegation:

1. It validates the SIG(0) signature against its truststore.
2. It applies local policy (allowed RR types, rate limits).
3. It writes the delegation data via a delegation backend.

**Delegation backends** control where and how the data is
stored:

- **direct** -- Modifies the in-memory zone directly. Used
  when the receiving server is the authoritative primary.
- **db** -- Stores delegation data in a SQLite database.
  Used when the receiver is not the zone primary.
- **zonefile** -- Stores in the database and generates
  per-child zone file fragments in a directory. Supports
  an optional notify-command (e.g., `rndc reload`) to
  trigger the actual primary to reload.

Backend configuration:

```yaml
delegation-backends:
   - name:       files-example
     type:       zonefile
     directory:  /var/lib/tdns/delegations/example
```

Zones reference backends by name:

```yaml
zones:
   - name:     example.com.
     options:  [ delegation-sync-parent ]
     delegation-backend: files-example
```

### 2.3 NOTIFY Receiver

The tdns-agent can also act as the NOTIFY receiver for
generalized NOTIFY messages. When it receives a NOTIFY(CDS)
or NOTIFY(CSYNC), it triggers the configured scanner to
query the child zone and process the published records.

### 2.4 Key Trust Management

When a child sends a self-signed UPDATE containing its SIG(0)
KEY, the parent must verify the key before trusting it. The
verification method is controlled by the keybootstrap config:

```yaml
keybootstrap:
   consistent-lookup:
      iterations:  3
      interval:    60
      nameservers: all
```

This configures the parent to query all of the child's
nameservers 3 times at 60-second intervals. If the KEY is
consistently present at all nameservers across all
iterations, it is accepted as trusted.


## 3. Provider Zones

In a multi-provider setup, each provider typically controls
one or more zones of their own (e.g., `alpha.example.net.`).
These "provider zones" may need to contain records that are
managed in sync with customer zone state -- most notably,
`_signal` KEY records used for SIG(0) key bootstrap.

### 3.1 _signal KEY Records

When a child zone's agent publishes its SIG(0) key, the
combiner places the KEY not only at the customer zone apex
but also at special `_signal` owner names under each NS
target that falls within a provider zone:

```
_sig0key.child.example.com._signal.ns1.alpha.example.net.  KEY  ...
```

This allows the parent to discover the child's SIG(0) key
by looking at the NS targets -- each provider's nameserver
advertises the key under a well-known `_signal` name.

### 3.2 Combiner Provider Zone Management

The combiner is configured with a list of provider zones it
manages:

```yaml
multi-provider:
   provider-zones:
      - zone:            alpha.example.net.
        allowed-rrtypes: [ KEY ]
```

When the agent sends a Publish instruction with
`locations: ["at-ns"]`, the combiner:

1. Determines which NS targets belong to the local provider.
2. Computes the `_signal` owner name for each.
3. Publishes the KEY RRs at those names in the provider zone.
4. Bumps the provider zone serial.

When NS records change (providers added or removed), the
combiner resyncs: it diffs the current NS set against the
stored set and adds/removes `_signal` KEYs accordingly.


## 4. Provider-to-Provider Synchronization

When one provider's agent makes a change (e.g., adds an NS
record), that change must propagate to all other providers'
combiners so the zone is consistent everywhere.

### 4.1 Data Flow

```
Local Signer
     |  signs zone
     v
Local Agent
     |  SYNC message (DNS CHUNK)
     v
Remote Agent(s)
     |  forwards to its combiner
     v
Remote Combiner(s)
     |  applies changes, re-serves zone
     v
Remote Signer(s)
     |  re-signs
     v
Remote Auth Servers
```

### 4.2 SYNC Messages

The local agent sends zone updates to remote agents via SYNC
messages carried in DNS NOTIFY with CHUNK EDNS(0) payloads
over TCP. Each SYNC message contains:

- The zone name
- A list of RRset operations (add/remove) with full RR data
- The sender's identity and a message ID

### 4.3 Double Confirmation

TDNS uses a two-phase confirmation system:

**Phase 1 -- Immediate ACK:** The remote agent acknowledges
receipt of the SYNC message. This confirms the data was
received but not yet applied.

**Phase 2 -- Confirmation with Details:** After the remote
combiner processes the update, it sends a confirmation back
with per-record status:

- **ACCEPTED** -- Record was applied successfully
- **REJECTED** -- Record was rejected by policy
- **DUPLICATE** -- Record already existed (no-op)

The local agent tracks confirmation state per record and per
remote agent. The ReliableMessageQueue retries unconfirmed
messages with exponential backoff until all remote agents
have confirmed.


## 5. Agent-to-Agent Coordination

### 5.1 The Gossip Protocol

Agents maintain an NxN state matrix for each provider group.
Each agent reports its view of every other agent's state
(UNKNOWN, NEEDED, KNOWN, OPERATIONAL). This matrix is
exchanged via gossip piggy-backed on the regular BEAT
heartbeat messages.

On every BEAT round-trip:
- The outgoing BEAT carries the sender's gossip state.
- The BEAT response carries the responder's gossip state
  back via CHUNK EDNS(0) on the same TCP connection.

Gossip merge uses latest-timestamp-wins: if a received entry
has a newer timestamp than the local entry, it replaces it.

When all cells in the matrix show OPERATIONAL, the group
fires the OnGroupOperational callback. When any cell drops
below OPERATIONAL, OnGroupDegraded fires and the group
leader is invalidated.

### 5.2 Provider Groups

Provider groups are computed deterministically from the
HSYNC3 records in the zone. All zones that share the same
set of provider identities form a group, identified by a
truncated SHA-256 hash of the sorted identity set.

Groups are recomputed whenever HSYNC3 data changes (e.g.,
a provider is added or removed from a zone).

### 5.3 Leader Election

Each provider group elects a leader via a three-phase
protocol: CALL, VOTE, CONFIRM. Elections are broadcast via
dedicated election messages (not piggybacked on BEAT).

Key properties:
- Only the lexicographically smallest group member initiates
  an election when OnGroupOperational fires. This prevents
  concurrent overlapping elections.
- Election results propagate to non-participating agents via
  the gossip protocol.
- The leader has a configurable TTL (default 60 minutes).
  Re-election is triggered automatically before expiry.
- If the group degrades (a member becomes unreachable), the
  leader is invalidated immediately.

The leader is responsible for parent-facing operations
(delegation sync, key publication) on behalf of the entire
provider group.
