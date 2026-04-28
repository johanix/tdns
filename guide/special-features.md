# TDNS Special Features and Extensions

This document describes TDNS features that go beyond basic
authoritative and recursive DNS service.

## Contents

1. **Automatic Delegation Synchronization** -- Keeping parent
   zone delegation data in sync with child zone changes.
2. **DNS Transport Signaling** -- Enabling resolvers to
   discover and use encrypted transports (DoT, DoQ, DoH)
   when communicating with authoritative servers.
3. **Experimental Record Types** -- DSYNC, DELEG, TSYNC, and
   the records that tdns defines as infrastructure for other
   components (HSYNC3, HSYNCPARAM, JWK, CHUNK).

For multi-provider DNSSEC see the
[tdns-mp Guide](../../tdns-mp/guide/README.md).


## 1. Automatic Delegation Synchronization

When a child zone's delegation data changes -- NS records,
glue addresses, or DS records -- the parent zone must be
updated to reflect the change. Traditionally this is a
manual process. TDNS automates it.

The mechanism is built on two components:

- The **DSYNC** record type (RFC 9859), published by the
  parent to advertise which synchronization schemes it
  supports and where to send updates.
- **SIG(0) key management**, used to authenticate DNS UPDATE
  messages sent from child to parent.

TDNS supports two synchronization schemes:

- **UPDATE** -- The child agent constructs a DNS UPDATE
  message, signs it with a SIG(0) key, and sends it to
  the parent's designated UPDATE receiver. This is
  immediate and does not require a scanner on the parent
  side.

- **NOTIFY** -- The child agent publishes CDS or CSYNC
  records at the zone apex and sends a generalized NOTIFY
  to the parent. The parent's scanner picks up the NOTIFY,
  queries the child, verifies the records, and applies the
  changes.

Both tdns-auth (as parent primary) and tdns-agent (as child
agent) implement their respective roles. See the
[Multi-Provider Advanced Topics](../../tdns-mp/guide/multi-provider-advanced.md)
document, sections 1 and 2, for configuration details
including DSYNC publication, delegation backends, and key
bootstrap. Those sections are written in a multi-provider
context but apply equally to the single-provider tdns-agent.


## 2. DNS Transport Signaling

DNS has traditionally been limited to unencrypted UDP and TCP
(Do53). Modern transports -- DNS over TLS (DoT), DNS over
QUIC (DoQ), and DNS over HTTPS (DoH) -- provide integrity
protection and confidentiality. The challenge is discovery:
how does a resolver know that a particular authoritative
server supports DoQ?

TDNS implements transport signaling to solve this.

### 2.1 Authoritative Side: Publishing Transport Signals

When a zone has the `add-transport-signal` option enabled,
tdns-auth synthesizes SVCB records at `_dns.<nameserver>`
for each nameserver identity and includes them in the
Additional section of every response.

Configuration:

```yaml
service:
   name:        TDNS-AUTH
   identities:  [ ns1.example.com., ns2.example.com. ]
   transport:
      type:   svcb
      signal: "doq:30,dot:20,do53:1"
```

The `type` field selects the record type used for signaling:

- `svcb` -- Use SVCB records (recommended, standards-track)
- `tsync` -- Use TSYNC records (experimental alternative)
- `none` -- Disable transport signal synthesis

The `signal` field is a comma-separated list of
`protocol:weight` pairs. Higher weight means the server
prefers that transport. Supported protocols are `doq`, `dot`,
`doh`, and `do53`.

The resulting SVCB record looks like:

```
_dns.ns1.example.com. 10800 IN SVCB 1 . local65280="doq:30,dot:20,do53:1"
```

The transport preference is carried in SVCB SvcParam key
65280 (a private-use key). The record is added to the
Additional section of responses, alongside the OPT record.
If the zone is DNSSEC-signed, the RRSIG for the SVCB is
included as well.

The signal is only added when:
- The zone has `add-transport-signal` in its options
- The signal is not already in the Answer section
- The client has not opted out via EDNS(0)

### 2.2 Resolver Side: Consuming Transport Signals

When tdns-imr receives a response with an SVCB (or TSYNC)
record in the Additional section, it:

1. Extracts the transport signal from the `_dns.<server>`
   owner name.
2. Parses the `protocol:weight` values from SvcParam key
   65280.
3. Updates the server's connection preferences in the
   referral cache.
4. Promotes the server's connection mode to "opportunistic",
   meaning the resolver will attempt encrypted transports
   on subsequent queries to that server.

This is entirely opportunistic -- if the encrypted transport
fails, the resolver falls back to Do53. No configuration
is needed on the resolver side for basic signal processing;
it is enabled by default.

### 2.3 Active Transport Discovery

By default, the IMR only processes transport signals that
arrive passively in the Additional section. Two options
enable active discovery:

- `query-for-transport` -- When a transport signal is
  observed in the Additional section, the IMR issues an
  explicit query for `_dns.<server>` to get the full
  signal record. This is opportunistic: only triggered
  when a signal is first seen.

- `always-query-for-transport` -- The IMR queries for
  transport signals whenever it discovers a new
  authoritative server, regardless of whether a signal
  was observed. This is more aggressive and generates
  additional queries.

Additional options:

- `transport-signal-type` -- Selects which record type to
  query for: `svcb` (default) or `tsync`.
- `query-for-transport-tlsa` -- Also queries for TLSA
  records (port 853) when transport signals are found,
  enabling certificate verification for DoT/DoQ.

Configuration (in tdns-imr.yaml):

```yaml
imrengine:
   options:
      - query-for-transport
      - query-for-transport-tlsa
```

### 2.4 The TSYNC Record (Experimental)

TSYNC (type code 65284) is an experimental alternative to
SVCB for transport signaling. It carries the same transport
preference information but in a different format with
additional fields:

```
_dns.ns1.example.com. IN TSYNC . "transport=doq:30,dot:20" "v4=192.0.2.1" "v6=2001:db8::1"
```

Fields:
- **alias** -- FQDN for indirection (like CNAME target),
  or `.` for direct reference
- **transports** -- Transport signal in `protocol:weight`
  format
- **v4addr** -- Comma-separated IPv4 addresses
- **v6addr** -- Comma-separated IPv6 addresses

TSYNC embeds address hints directly in the record, while
SVCB relies on separate A/AAAA records or SvcParam
ipv4hint/ipv6hint. The IMR handles both formats
transparently.


## 3. Experimental Record Types

TDNS implements several record types beyond the standard set.
The dog tool (`dogv2`) can query and display all of them
natively -- dig cannot decode the private-use types.

Some of these record types are defined and parsed in tdns
but used only as infrastructure by other components -- most
notably tdns-mp (for multi-provider coordination) and
tdns-transport (for the JOSE-based message transport). They
are listed below for completeness; tdns itself does not act
on their semantics.

### DSYNC (RFC 9859)

Delegation synchronization record. Published by the parent
to advertise synchronization schemes for child zones. Now
standardized; see section 1 above.

### DELEG

Experimental record type for enhanced delegation information.
TDNS supports reading, parsing, and serving zones containing
DELEG records, and receiving them via zone transfer.

### TSYNC (type 65284)

Experimental transport signaling record. See section 2.4
above.

### HSYNC3 (type 65285)

Per-provider identity record for multi-provider coordination.
One record per provider in the zone. Defined and parsed in
tdns; used by [tdns-mp](../../tdns-mp/guide/README.md) to
discover peer agents and compute provider groups.

### HSYNCPARAM (type 65286)

Zone-wide multi-provider policy record. Carries key=value
pairs controlling NS management, parent sync, signer
authorization, etc. Defined and parsed in tdns; used by
[tdns-mp](../../tdns-mp/guide/README.md).

### JWK

JSON Web Key record (a direct DNS representation of RFC 7517
JWKs), used to publish the public encryption keys of agents
and other multi-provider components. Defined and parsed in
tdns; used by [tdns-mp](../../tdns-mp/guide/README.md) for
agent discovery and by
[tdns-transport](../../tdns-transport/) for the keys that
secure CHUNK payloads.

### CHUNK

Experimental record type that carries JWS(JWE(JWT)) payloads
in JOSE format -- a signed (RFC 7515) and encrypted
(RFC 7516) JWT (RFC 7519). Defined and parsed in tdns; the
actual transport implementation lives in
[tdns-transport](../../tdns-transport/) and the protocol
that uses it is implemented in
[tdns-mp](../../tdns-mp/guide/README.md).
