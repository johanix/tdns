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
4. **Post-Quantum Algorithm Support** -- ML-DSA, SLH-DSA,
   Falcon, MAYO and SNOVA for both SIG(0) and DNSSEC, via
   the dnssec-algorithms registry on top of a forked
   miekg/dns.
5. **Automatic Key Rollover** -- Pointer to the dedicated
   [key-rollover](key-rollover.md) guide and its
   [timing-equations](rollover-timing-equations.md)
   companion. The engine reuses the delegation-sync
   transports from §1 and the SIG(0) PQ support from §4.

For multi-provider DNSSEC see the
[tdns-mp Guide](../../tdns-mp/guide/README.md).


## 1. Automatic Delegation Synchronization

When a child zone's delegation data changes -- NS records,
glue addresses, or DS records -- the parent zone must be
updated to reflect the change. Traditionally this is a
manual process. TDNS automates it on both sides: tdns-agent
(or tdns-auth running as the child's primary) detects the
change and pushes it to the parent; tdns-auth on the parent
side receives the push, verifies it, and applies it to a
configurable delegation backend. tdns-agent can also act as
a **proxy** for a child whose primary is DSYNC-unaware
(BIND/Knot/NSD), forwarding the primary's CDS/CSYNC signals
to the parent on its behalf (section 1.6).

The mechanism is built on three components:

- The **DSYNC** record type (RFC 9859), published by the
  parent to advertise which synchronization schemes it
  supports and where to send updates.
- **SIG(0) key management**, used to authenticate DNS UPDATE
  messages sent from child to parent.
- A pluggable **delegation backend** on the parent side that
  decides where applied changes are persisted.

TDNS supports two synchronization schemes, and the same
parent zone can advertise both at once:

- **UPDATE** -- The child constructs a DNS UPDATE message,
  signs it with a SIG(0) key, and sends it to the parent's
  designated UPDATE receiver. The change is immediate and
  does not require any scanner on the parent.

- **NOTIFY** -- The child publishes CDS or CSYNC records at
  its zone apex and sends a generalized NOTIFY for the
  corresponding RRtype to the parent's NOTIFY target. The
  parent's scanner picks up the NOTIFY, queries the child
  for the advertised records, verifies them, and applies
  the resulting DS or delegation changes.


### 1.1 Parent: publishing DSYNC

A parent zone advertises its delegation-sync capabilities
by adding the zone option `delegation-sync-parent` (zone
option `OptDelSyncParent`). When set, tdns-auth synthesises
the necessary DSYNC RRs at the well-known owner name
`_dsync.<zonename>` based on the global
`delegationsync.parent.*` configuration:

```yaml
delegationsync:
   parent:
      schemes: [ notify, update ]
      notify:
         types:     [ CDS, CSYNC ]
         target:    notifications.{ZONENAME}
         port:      5354
         addresses: [ 127.0.0.1, "::1" ]
      update:
         types:     [ ANY ]
         target:    updates.{ZONENAME}
         port:      5354
         addresses: [ 127.0.0.1, "::1" ]
         keygen:
            algorithm: ED25519
         key-verification:
            mechanisms:      [ truststore, dnssec ]
            max-attempts:    5
            retry-interval:  30s
            require-dnssec:  false
      bootstrap:
         methods: at-apex,unsigned,manual
```

The publication code (`PublishDsyncRRs`, in
[tdns/v2/ops_dsync.go](../v2/ops_dsync.go)) creates one
DSYNC RR per scheme, accompanied by A/AAAA glue for the
target FQDNs. For the UPDATE target it additionally
publishes an SVCB record carrying a SIG(0) **bootstrap**
SvcParam (key 65282) that tells children which SIG(0)
key-bootstrap methods the parent accepts -- typically
`at-apex` (RFC 9615-style apex publication), `unsigned`
(opportunistic trust-on-first-use), or `manual`. Publication
happens via the OnFirstLoad callback, so the records appear
on initial zone load without operator action beyond enabling
the zone option.

The parent also runs a SIG(0) key preparation step
(`ParentSig0KeyPrep`) so that the UPDATE receiver always
has an active keypair available for replies that need to
be signed (KeyState responses, for example).


### 1.2 Parent: the UPDATE receiver

When the `update` scheme is enabled, tdns-auth listens on
the addresses+ports declared above and routes inbound
UPDATE messages through `UpdateResponder` (see
[tdns/v2/updateresponder.go](../v2/updateresponder.go)).
SIG(0) verification runs ahead of the responder; if the
signature is missing, invalid, or signed by an unknown key,
the UPDATE is rejected before any policy is evaluated.

Trust evaluation is controlled by the
`update.key-verification` block:

- `mechanisms` -- which sources are consulted to decide
  whether the signing key is trusted. `truststore` looks
  for a locally accepted KEY; other mechanisms include
  DNSSEC-validated KEY lookup at the child apex
  (RFC 9615 "at-apex" bootstrap).
- `max-attempts` / `retry-interval` -- how aggressively the
  receiver retries DNS lookups when the signing key is not
  yet known. This lets a fresh child key (just published)
  succeed without a manual import.
- `require-dnssec` -- if true, the child zone's signing key
  must be reachable through a validating DNSSEC chain.

A verified UPDATE for a delegated child zone becomes a
`CHILD-UPDATE` request (zone_updater.go) that is handed to
the parent's `DelegationBackend` (see 1.4).


### 1.3 Parent: the generalized-NOTIFY scanner

When the `notify` scheme is enabled, tdns-auth listens on
the configured addresses+ports and accepts NOTIFY messages
of the advertised types (CDS, CSYNC). `NotifyResponder`
([tdns/v2/notifyresponder.go](../v2/notifyresponder.go))
checks that the zone really advertises NOTIFY for the
incoming Qtype (via `advertisesDsyncNotify`) and then
enqueues a scan request on the scanner queue.

The scanner engine
([tdns/v2/scanner.go](../v2/scanner.go)) processes scan
requests asynchronously and also runs on a configurable
periodic interval:

```yaml
scanner:
   interval: 3600              # seconds
   options:
      - at-apex                # RFC 8078 bootstrap support
      - at-ns                  # RFC 9615 signaling support
      # - no-dnssec-validation # lab/testbed only
   at-apex:
      checks:   3
      interval: 600
```

For each scan the engine:

- Queries the child's authoritative nameservers
  (preferring TCP) for the relevant RRset (CDS or CSYNC).
- Requires that all NS for the child return the same
  RRset -- partial consistency is treated as a transient
  state and rejected.
- Validates DNSSEC where possible. For first-time CDS
  bootstrap with no existing DS, the `at-apex` option
  permits an opportunistic accept after `checks` repeated
  matches separated by `interval` seconds (RFC 8078).
- For CDS: converts each CDS to its DS form (RFC 7344) and
  detects the algorithm-0 removal sentinel.
- For CSYNC: extracts the type bitmap, honours `IMMEDIATE`
  and `USESOAMIN` flags (RFC 7477), and verifies the
  child's SOA serial does not change during the scan to
  catch in-flight zone updates.
- Diffs the verified records against what the
  DelegationBackend already holds and emits adds/removes.

Successful scan results produce CHILD-UPDATE requests that
flow through the same backend pipeline as direct UPDATEs.


### 1.4 Parent: delegation backends

Once a CHILD-UPDATE has been authorized (either by SIG(0)
on the UPDATE path, or by the scanner on the NOTIFY path),
the change is applied through a pluggable **delegation
backend**. Each parent zone that accepts child updates
**must** declare which backend it uses; config-parse
rejects the zone otherwise. There is no silent default.

Zones opt in by combining a zone-level switch with a
named backend reference:

```yaml
zones:
   example.com.:
      type:                primary
      delegation-sync-parent: true
      allow-child-updates:   true
      delegationbackend:     files-dnslab
```

Named backends live at the top level of the daemon's
config:

```yaml
delegationbackends:
   - name:           files-dnslab
     type:           zonefile
     directory:      /var/lib/tdns/delegations/dnslab
     notify-command: /usr/bin/notify-hook.sh

   - name: inline
     type: direct

   - name: tracking
     type: db
```

Three backend types are implemented:

- **`direct`** -- applies the update to the parent zone's
  in-memory tree and persists by rewriting the zone source
  file. The zone is marked dirty during the write and
  clean on success. If the zone has no source file (loaded
  via XFR, generated, etc.) the persist step is skipped
  silently; in-memory state is still updated. Best fit for
  small or medium parent zones managed as flat files.

- **`db`** -- writes to a SQLite table keyed on
  `(parent, child, owner, rrtype)`, with idempotent
  replace semantics. Does **not** touch the in-memory
  zone, so served data only reflects the change after a
  zone reload. Best fit when the database is the source
  of truth and the served zone is rebuilt from it.

- **`zonefile`** -- hybrid: writes to the database (for
  durable state) and emits per-delegation fragment files
  into `directory`, optionally executing `notify-command`
  after each write. Requires the `directory:` field. Best
  fit when an external provisioning pipeline assembles
  the parent zone from fragments.

The backend is also the canonical answer for "what does
the parent currently believe about this delegation?" The
NOTIFY scanner consults the backend when computing the
diff between newly-observed CDS/CSYNC and current state,
so backend state and served state stay reconcilable even
when they live in physically different stores.

Backend state can be inspected with the CLI:

```sh
tdns-cli auth delegation list   --zone example.com.
tdns-cli auth delegation show   --zone example.com. --child sub.example.com.
```


### 1.5 Child: pushing changes

On the child side, a zone with `delegation-sync-child`
enabled runs through `SetupZoneSync` (also wired via
OnFirstLoad). This:

- Calls `DelegationSyncSetup` to ensure the child has an
  active SIG(0) keypair, and arranges for the public KEY
  to be published according to the parent's advertised
  bootstrap methods.
- Subscribes the zone to the engine that watches for
  changes in delegation-relevant RRsets (NS, glue, DNSKEY
  → DS) and dispatches them via `DelegationSyncher`.

`DelegationSyncher` consumes `DelegationSyncQ` and routes
each change to `SyncZoneDelegation`, which discovers the
parent's DSYNC RRset and sends either a SIG(0)-signed
UPDATE, a generalized NOTIFY(CDS/CSYNC), or both -- driven
by what the parent advertises and by per-policy preference.
The same dispatch logic is reused by the auto-rollover
engine; see section 5 for the full picture.


### 1.6 Agent: proxying for a DSYNC-unaware primary

The child side above assumes the child's primary speaks
DSYNC. Many do not: a stock BIND9, Knot, or NSD primary
will never discover the parent's DSYNC RRset and will never
push a DS or delegation change to the parent. But such a
primary *can* publish a CDS/CDNSKEY (RFC 7344) or CSYNC
(RFC 7477) in the zone -- the standard, vendor-neutral way
for a child to signal "please sync me."

tdns-agent bridges that gap. Configure it as a **secondary**
for the zone with the `delegation-sync-proxy` option. On
every incoming AXFR/IXFR the agent diffs the new zone
against the one it was serving and, when a
delegation-relevant RRset changed, forwards the matching
generalized NOTIFY to the parent's advertised NOTIFY
receiver on the primary's behalf. The parent's scanner then
queries the child and applies the change, exactly as for a
DSYNC-native child. The primary is never modified.

The change-to-NOTIFY mapping:

| Change in the transfer            | NOTIFY forwarded |
|-----------------------------------|------------------|
| CDS RRset changed                 | NOTIFY(CDS)      |
| DNSKEY RRset changed              | NOTIFY(CDS)      |
| CSYNC RRset changed               | NOTIFY(CSYNC)    |
| NS RRset or glue (A/AAAA) changed | NOTIFY(CSYNC)    |

A NOTIFY is a contentless "come re-scan me" signal, so the
proxy never reads or signs the CDS/CSYNC -- the parent reads
them itself. That is why the proxy needs no SIG(0) key and
why a `CDS 0 0 0 00` ("delete DS", RFC 8078) is handled like
any other CDS change. The trigger is content-edge-triggered,
so a change fires exactly once and a slow parent is never
re-NOTIFYd on subsequent refreshes.

The three delegation-sync roles, side by side:

- `delegation-sync-parent` -- I am the parent: publish a
  DSYNC RRset and receive UPDATE / NOTIFY from children
  (sections 1.1-1.4).
- `delegation-sync-child` -- I am the child and author my
  own zone: detect my delegation changes and push them up
  (section 1.5).
- `delegation-sync-proxy` -- I am a secondary for a
  DSYNC-unaware primary: forward the primary's CDS/CSYNC
  signals up on its behalf (this section).

The proxy forwards via whichever scheme the parent
advertises: NOTIFY (the parent re-scans the child), or a
signed DNS UPDATE (the agent sends the delegation records
directly, which also covers unsigned zones). The UPDATE
scheme needs a SIG(0) key the parent trusts -- the agent
generates it and the operator publishes its KEY at the
primary (a one-time `zone proxy-key` bootstrap). For the
full operator how-to -- configuration, the UPDATE
KEY-bootstrap, limitations, and verification -- see
[Agent as a DSYNC proxy](agent-dsync-proxy.md).


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
The dog tool (`dog`) can query and display all of them
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


## 4. Post-Quantum Algorithm Support

Post-quantum (PQ) DNSSEC and SIG(0) support has moved to its own guide:
**[pq-dnssec.md](pq-dnssec.md)**. It covers the three-layer architecture
(forked miekg/dns + the `dnssec-algorithms` module + generated
compile-time registration), the supported algorithms and their KSK/ZSK
suitability, per-platform builds, the `algs.list`-based registration
model, the `dns.Algorithm` interface, and PQ policy/rollover.

> The material that used to live here is superseded by that guide. In
> particular the old "blank import" registration model and the
> `dns.Algorithm` interface signature described in earlier revisions of
> this section are **out of date** — see pq-dnssec.md for the current
> `algs.list`/generator model and the correct interface.


## 5. Automatic Key Rollover

TDNS includes a fully automated KSK rollover engine that
reuses the delegation-sync mechanics from §1 (DSYNC
discovery, parallel UPDATE+NOTIFY dispatch, SIG(0)-signed
parent UPDATEs) and the PQ algorithm support from §4 (the
SIG(0) key the engine uses to sign parent UPDATEs can
itself be a PQ key, with no extra configuration).

Because the topic is large enough to need a dedicated
operator manual -- covering the policy YAML, the
`auto-rollover` CLI, the status output, DSYNC-aware
dispatch and verification, fast vs. slow cadences, worked
examples, and the failure model -- it lives in its own
document:

- [Automatic DNSSEC Key Rollovers](key-rollover.md) --
  the operator-facing guide.
- [Rollover Timing Equations](rollover-timing-equations.md)
  -- the canonical cache-flush invariants and timing
  math that the engine must satisfy.
