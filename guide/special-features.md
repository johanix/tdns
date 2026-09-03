# TDNS Special Features and Extensions

This document describes TDNS features that go beyond basic
authoritative and recursive DNS service.

## Contents

1. [**Automatic Delegation Synchronization**](#1-automatic-delegation-synchronization)
   -- Keeping parent zone delegation data in sync with child
   zone changes: the NOTIFY and UPDATE schemes, delegation
   backends, the agent-as-proxy path, the
   [DSYNC API scheme](#17-the-dsync-api-scheme-https-for-children-that-cannot-sign)
   for children that cannot sign a DNS message, and
   [publishing a customer's bootstrap records](#18-secondary-publishing-a-customers-bootstrap-records-at-the-_signal-names)
   at the RFC 9615 `_signal` names.
2. [**DNS Transport Signaling**](#2-dns-transport-signaling)
   -- Enabling resolvers to discover and use encrypted
   transports (DoT, DoQ, DoH) when communicating with
   authoritative servers.
3. [**Experimental Record Types**](#3-experimental-record-types)
   -- DSYNC, DELEG, TSYNC, and the records that tdns defines
   as infrastructure for other components (HSYNC3,
   HSYNCPARAM, JWK, CHUNK).
4. [**Post-Quantum Algorithm Support**](pq-dnssec.md)
   -- ML-DSA, SLH-DSA, Falcon, MAYO and SNOVA for both SIG(0)
   and DNSSEC, via the dnssec-algorithms registry on top of a
   forked miekg/dns. **(Moved to its own guide,
   [pq-dnssec.md](pq-dnssec.md).)**
5. [**Automatic Key Rollover**](key-rollover.md)
   -- The dedicated [key-rollover](key-rollover.md) guide and
   its [timing-equations](rollover-timing-equations.md)
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
by adding the zone option `childsync` (zone
option `OptDelSyncParent`). When set, tdns-auth synthesises
the necessary DSYNC RRs at the well-known owner name
`_dsync.<zonename>` based on the global
`delegationsync.parent.*` configuration:

```yaml
delegationsync:
   policies:
      default:
         bootstrap:
            mechanisms:     [ at-apex, at-ns ]
            require-dnssec: true
            manual:         false
            allow-unvalidated-upload: false
   parent:
      schemes: [ notify, update ]      # and/or `api`, see 1.7
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
```

A zone selects a policy with `delegationpolicy: <name>` (omit binds
`default`; an unknown name quarantines the zone). The publication
code (`PublishDsyncRRs`, in
[tdns/v2/ops_dsync.go](../v2/ops_dsync.go)) creates one
DSYNC RR per scheme, accompanied by A/AAAA glue for the
target FQDNs. For the UPDATE target it additionally
publishes an SVCB record carrying a SIG(0) **bootstrap**
SvcParam (key 65282) **derived from the bound policy** —
`at-apex` / `at-ns` when `require-dnssec` is true,
`unsigned` when mechanisms are set but `require-dnssec` is
false, and `manual` when that flag is set. Publication
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

Trust evaluation is controlled by the zone's bound
`delegationpolicy`:

- `bootstrap.mechanisms` -- where to look for the child's KEY
  (`at-apex` at the child apex; `at-ns` at the RFC 9615
  `_signal` name). Empty means do not verify automatically.
- `bootstrap.retry` -- how aggressively the receiver retries
  DNS lookups when the signing key is not yet known.
- `bootstrap.require-dnssec` -- if true, the looked-up KEY
  must be DNSSEC-validated.
- `bootstrap.manual` / `bootstrap.allow-unvalidated-upload`
  -- whether an operator may install trust out of band, and
  whether an untrusted signer may upload a KEY at all.

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
      options:             [ childsync, allow-child-updates ]
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

On the child side, a zone with `parentsync`
enabled runs through `SetupZoneSync` (also wired via
OnFirstLoad). This:

- Calls `DelegationSyncSetup` to ensure the child has an
  active SIG(0) keypair, and arranges for the public KEY
  to be published according to the bootstrap method
  negotiated with the parent (below).
- Subscribes the zone to the engine that watches for
  changes in delegation-relevant RRsets (NS, glue, DNSKEY
  → DS) and dispatches them via `DelegationSyncher`.

`DelegationSyncher` consumes `DelegationSyncQ` and routes
each change to `SyncZoneDelegation`, which discovers the
parent's DSYNC RRset and sends either a SIG(0)-signed
UPDATE, a generalized NOTIFY(CDS/CSYNC), an HTTPS POST over
the API scheme ([1.7](#17-the-dsync-api-scheme-https-for-children-that-cannot-sign)),
or several -- driven by what the parent advertises and by
per-policy preference.
The same dispatch logic is reused by the auto-rollover
engine; see section 5 for the full picture.

#### Choosing a SIG(0) bootstrap method

Before the child can send a signed UPDATE, the parent has
to come to trust its SIG(0) key. Which route is used is
**negotiated, not configured on one side**: the parent
advertises what it will accept in the bootstrap SVCB
([1.1](#11-parent-publishing-dsync)), the child declares
what it is willing to rely on, and the strongest survivor
of the intersection wins — `at-apex` > `at-ns` >
`unsigned` > `manual`.

```yaml
delegationsync:
   child:
      schemes: [ notify, update ]
      update:
         keygen:
            algorithm: ED25519
         bootstrap:
            methods: [ at-apex, at-ns ]
```

Four rules matter more than the list itself:

- **An empty intersection refuses.** It never silently
  degrades to a weaker method. A parent advertising only
  `unsigned` or only `manual` is therefore refused by the
  default child, which is the opt-in working as intended:
  this decision is what authorises everything the child
  later signs.
- **An absent advertisement falls back to this list**, so a
  parent that publishes no bootstrap SVCB — every non-TDNS
  parent — is bootstrapped exactly as before. A *failed*
  lookup is not the same thing and does not fall back: it
  is an error, and the bootstrap is retried rather than
  proceeding on a guess.
- **An advertisement that cannot be authenticated is
  ignored**, and the configured list is used instead. The
  SVCB and the DSYNC record that named its target must both
  be DNSSEC-validated; `delegationsync.child.update.allow-insecure`
  waives that for a lab, but nothing waives a **bogus**
  verdict — a failed chain of trust is never treated as an
  unsigned one.
- **`methods:` omitted means `[ at-apex, at-ns ]`**, and
  `at-ns` is then filtered out per zone when this server
  cannot satisfy it. It needs the child's KEY at
  `_sig0key.<child>._signal.<ns>`, which is possible only
  when the server is primary for a zone one of those signal
  names falls in. An agent proxying for a primary
  ([1.6](#16-agent-proxying-for-a-dsync-unaware-primary))
  never qualifies — those names live in the *nameserver's*
  zone, which a secondary does not control — so a proxy
  drops `at-ns` on every path, BADKEY recovery included.

The parent-side half of the same negotiation — how a zone's
policy decides what it advertises — is
[1.1](#11-parent-publishing-dsync).


### 1.6 Agent: proxying for a DSYNC-unaware primary

The child side above assumes the child's primary speaks
DSYNC. Many do not: a stock BIND9, Knot, or NSD primary
will never discover the parent's DSYNC RRset and will never
push a DS or delegation change to the parent. But such a
primary *can* publish a CDS/CDNSKEY (RFC 7344) or CSYNC
(RFC 7477) in the zone -- the standard, vendor-neutral way
for a child to signal "please sync me."

tdns-agent bridges that gap. Configure it as a **secondary**
for the zone with the `parentsync-proxy` option. On
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

- `childsync` -- I am the parent: publish a
  DSYNC RRset and receive UPDATE / NOTIFY from children
  (sections 1.1-1.4).
- `parentsync` -- I am the child and author my
  own zone: detect my delegation changes and push them up
  (section 1.5).
- `parentsync-proxy` -- I am a secondary for a
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


### 1.7 The DSYNC API scheme: HTTPS for children that cannot sign

The NOTIFY and UPDATE schemes above are both DNS, and the
UPDATE scheme needs the child to hold a SIG(0) key the
parent trusts. Many provisioning systems can POST JSON and
cannot sign a DNS message; today that means falling back to
a registrar web form.

The **API scheme** (`SchemeAPI`, DSYNC scheme 4) is for
those children. It is a fallback, not a preference: the
UPDATE scheme is the one to reach for when the child can
manage it.

#### What the parent publishes

Three records, in one update:

```
_dsync.example.      7200 IN DSYNC CDS   API 443 dsync-api.example.
_dsync.example.      7200 IN DSYNC CSYNC API 443 dsync-api.example.
dsync-api.example.   7200 IN URI   1 1 "https://dsync-api.example:443/dsync/v1"
dsync-api.example.   7200 IN TXT   "tdns-child-api-v1.0"
```

Unlike NOTIFY and UPDATE, **the DSYNC target here is not a
host you send DNS to** -- it is a name at which the service
description lives. The URI carries the endpoint and the TXT
says what dialect it speaks; the URI's own host resolves by
ordinary means. Address records at the target are therefore
optional, where the other two schemes require them.

The TXT is whitespace-separated tokens. The first is the
dialect identifier -- protocol and version in one opaque
string, matched literally -- and any that follow are
SVCB-style `key=value` parameters, all optional and ignored
if unrecognised. Several TXT records at the name is how a
parent advertises more than one dialect at once, which is
the version-migration story. A child that recognises none of
them does not use the endpoint and does not send its
credential there.

Parent configuration:

```yaml
delegationsync:
   parent:
      schemes: [ notify, update, api ]
      api:
         types:    [ CDS, CSYNC ]
         target:   dsync-api.{ZONENAME}
         baseurl:  "https://{TARGET}:{PORT}/dsync/v1"
         port:     443
         dialect:  tdns-child-api-v1.0
         listen:   [ "0.0.0.0:443" ]
         cert:     /etc/tdns/dsync-api.crt
         key:      /etc/tdns/dsync-api.key
```

The listener is its **own socket, with its own router and
its own middleware** -- not a subtree of the management API.
A registrant's provisioning script is not a trusted
operator, and the surest guarantee that its credential
cannot reach operator endpoints is that those endpoints are
not on the socket it connects to. TLS is mandatory; tdns
refuses to serve this endpoint without a certificate.

Note the guard in [§1.1](#11-parent-publishing-dsync): an
existing DSYNC RRset is left alone, so adding `api` to a
zone that already publishes DSYNC does nothing until the
RRset is removed and republished.

#### Authentication: `<username, key>`, not a shared key

Requests authenticate with HTTP Basic over TLS. Not the
management API's single `apiserver.apikey`, and the reason
is authorization rather than authentication strength: a
shared key names nobody, and a policy that cannot name the
principal cannot be granular.

Credentials are issued by the operator, over the management
API:

```sh
tdns-cli auth dsync-api credential add    --zone example. --user child1.example.
tdns-cli auth dsync-api credential list   --zone example.
tdns-cli auth dsync-api credential disable --zone example. --user child1.example.
tdns-cli auth dsync-api credential delete --zone example. --user child1.example.
```

Client-certificate credentials are a second way in, not a replacement.
Mint the leaf with `tdns-cli cert csr` / `cert sign`, then:

```sh
tdns-cli auth dsync-api cert-credential add \
    --zone example. --mech tls-pkix --identity child1.example.
tdns-cli auth dsync-api cert-credential add \
    --zone example. --mech tls-pin --cert /path/to/child.crt \
    --principal child1.example.
```

`credential list` and `cert-credential list` show both kinds. The child
configures a nested `tls:` block instead of `username`/`key`. The parent
opts in with `delegationsync.parent.api.client-auth`. Enabling or
disabling that block changes the TLS handshake and needs a process
restart; a config reload updates the middleware but not the
`CertificateRequest`.

`add` generates the key, prints it **once**, and stores only
a hash. There is no way to read it back; if it is lost,
delete the credential and issue another. Prefer `disable`
over `delete` when the question "who had access, and when"
might be asked later -- disabling stops the credential
working and keeps the record.

Usernames are normalised as domain names (case-folded, given
a trailing dot) even when they are not domain names, so
`bob` and `bob.` are one account rather than two.
Provisioning is out of band by definition: a child that
could bootstrap a credential in band could sign a DNS
message, and would use the UPDATE scheme.

#### Authorization: the same `updatepolicy.child`

This is the part that keeps the feature small. The
authenticated **principal** is substituted for the SIG(0)
signer name, and the zone's existing child update policy is
applied unchanged:

```yaml
zones:
   - name:    example.
     options: [ childsync, allow-child-updates ]
     delegationbackend: direct
     updatepolicy:
        child:
           type:    selfsub
           rrtypes: [ A, AAAA, NS, DS ]
```

Under that policy, principal `child1.example.` may change
`A/AAAA/NS/DS` at or below `child1.example.` and nowhere
else -- whether the change arrives as a SIG(0)-signed UPDATE
or as an authenticated POST. One policy, one meaning, two
transports.

The principal defaults to the username. A credential may
carry an explicit `--principal` when the account should have
a human-readable name (`acme-registrar` acting for
`child1.example.`).

#### The endpoints

```
GET  /dsync/v1/delegation/{child}    what the parent currently holds
POST /dsync/v1/delegation/{child}    declare the desired delegation
```

Declarative, not imperative: the child states what its
delegation should be and the parent computes the change.
That mirrors the UPDATE scheme's replace mode, is idempotent
under retry, and keeps the zone-update statement vocabulary
off an untrusted surface.

```json
{"child": "child1.example.",
 "rrsets": [
   {"owner": "child1.example.",     "type": "NS", "rrs": ["child1.example. 3600 IN NS ns1.child1.example."]},
   {"owner": "ns1.child1.example.", "type": "A",  "rrs": ["ns1.child1.example. 3600 IN A 192.0.2.1"]},
   {"owner": "child1.example.",     "type": "DS", "rrs": []}
 ]}
```

Each entry names owner *and* type explicitly, because glue
lives at the nameserver names while NS lives at the child --
a body keyed by type alone could not say which A records to
remove. An entry with an empty `rrs` **removes** that RRset;
an RRset **not mentioned is left alone**. That distinction
is what makes the endpoint safe for a client that manages
only DS: omitting NS must not wipe the delegation.

Changes are applied through the configured **delegation
backend** ([§1.4](#14-parent-delegation-backends)), like any
other child update. `200` means applied, persisted and being
served -- the same promise the UPDATE scheme makes.

| Status | Meaning |
|---|---|
| 200 | applied, durable, being served |
| 400 | malformed body, unparseable RRs, owner not below the child, unmanaged type |
| 401 | missing or bad credentials (no body: unknown user, wrong key, disabled and expired are indistinguishable by design) |
| 403 | authenticated, but `updatepolicy.child` refuses |
| 404 | no hosted parent zone for that child, or it does not offer this scheme |
| 409 | zone frozen |
| 503 | apply timed out, or the updater is unavailable |

The endpoint manages `NS`, `DS`, `A` and `AAAA`. That is
decided by the endpoint, not by
`updatepolicy.child.rrtypes`: a parent that allows TXT in
its child policy still does not want this endpoint used to
manage arbitrary text records at a delegation point. Both
gates apply.

#### Child side

```yaml
delegationsync:
   child:
      schemes: [ notify, update, api ]     # preference order; api last
      api:
         cafile: /etc/tdns/dsync-api-ca.crt
         credentials:
            - parent:   example.
              username: child1.example.
              key:      "the key printed by credential add"
```

A child with no credential for a parent that offers only
`api` logs one clear line and stops. Retrying cannot make a
credential appear.

#### Why this scheme is stricter than the others

The credential is a **bearer token**, and that is the one
exposure the UPDATE scheme does not have. A child fooled
into sending a SIG(0)-signed update to the wrong server
leaks nothing: the message is signed, the wrong server
cannot use it, and the change simply does not happen. A
child fooled into POSTing here hands an attacker a working
credential.

So, on the child side:

- **The DSYNC, URI and TXT lookups must DNSSEC-validate.**
  This is a prerequisite, not a recommendation -- which
  means **the scheme requires a signed parent zone**, and is
  a real constraint on who can use the fallback.
- **https only**, with full certificate validation. Use
  `cafile` for a private CA (`tdns-cli cert ca` mints one);
  it *adds* roots rather than removing verification, and
  avoids installing that CA into the host's system trust
  store where it would gain authority over every TLS
  connection the host makes. There is no switch to disable
  verification.
- **Redirects are refused outright.** Go strips
  `Authorization` across hosts, so a cross-host redirect is
  a silent auth failure rather than a leak -- but a
  same-host redirect still carries the credential, and a
  redirect here means something is wrong either way.
- **A credential is scoped to one parent** and is never sent
  to another.

`delegationsync.child.api.allow-insecure` relaxes the first
two of those -- plaintext endpoints *and* unvalidated
discovery, deliberately as a single switch, because they are
the same protection seen from two sides and an operator who
disables one while believing the other still holds has none.
It does not disable certificate validation. It is a lab
convenience and never a production setting.

### 1.8 Secondary: publishing a customer's bootstrap records at the `_signal` names

Everything above is about a child getting its delegation data
to its parent. This section is the other end of the same
problem: how a child that cannot yet be validated gets its
*first* trust anchor -- or its first SIG(0) key -- to a
parent that has no reason to believe it.

RFC 9615 answers that with a name in a zone the parent
already trusts. The child's bootstrap records are published
not in the child's zone but in the zone of each of the
child's **nameservers**, at
`_dsboot.<child>._signal.<ns>` -- so a parent can fetch them
over the child's own delegation and validate them under the
nameserver's keys, not the child's.
`draft-ietf-dnsop-delegation-mgmt-via-ddns` reuses the shape
for the SIG(0) bootstrap, at `_sig0key.<child>._signal.<ns>`.

Someone has to actually put the records there, and it is not
the child -- it is whoever operates the nameserver. tdns-auth
does that job on a **secondary** with the
`use-hsyncparam` option:

```yaml
zones:
   - name:      customer.example.
     type:      secondary
     primaries: [ { addr: 192.0.2.1:53, key: NOKEY } ]
     options:   [ use-hsyncparam ]
```

The instruction comes from the customer, in the HSYNCPARAM
record at their zone's apex
(`draft-leon-dnsop-signaling-zone-owner-intent`, §3). Two of
its keys are flags addressed to every provider serving the
zone: `pubkey` asks for the apex SIG(0) `KEY` at the
`_sig0key` name, `pubcds` for the apex `CDS`/`CDNSKEY` at the
`_dsboot` name. After each transfer, for each flag present,
the server re-owns the matching apex RRset to the signal name
under every apex NS of the customer zone and publishes it
into whichever zone **this server holds as primary**. An NS
served by somebody else is skipped. The write is
change-gated, so an unchanged re-transfer does nothing.

The alternative these flags replace is scanning: without an
explicit signal a provider would have to trawl its customer
zones for CDS-shaped content and guess that publication was
intended (RFC 9615 §3.1). The flag makes the intent the zone
owner's, stated once, in a record designed to carry it.

Why an option, given the customer already asked? Because
honouring the request writes records into a zone *you* are
authoritative for. That is the nameserver operator's
decision, so it is off by default. It changes nothing about
parsing or serving HSYNCPARAM, which is unconditional, and it
is unrelated to `multi-provider`: the role model those
records carry -- `servers`, `signers`, `auditors`, delegated
NS management -- belongs to
[tdns-mp](../../tdns-mp/guide/README.md), and tdns-auth reads
just these two flags. Configuration details are in
[config-tdns-auth.md](config-tdns-auth.md#use-hsyncparam).

The child side of the same mechanism needs no option: when a
tdns-auth child's own bootstrap ceremony selects the `at-ns`
method, publishing its KEY at the `_signal` name *is* the
intent, and the method is offered in the first place only
when at least one of the zone's nameservers is served here as
primary.


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

Zone-wide policy record for signaling zone-owner intent to
DNS providers. Carries key=value pairs controlling NS
management, parent sync, signer authorization, and
publication of bootstrap records. Defined and parsed in
tdns. The role and NS-management keys are used by
[tdns-mp](../../tdns-mp/guide/README.md); the `pubkey` and
`pubcds` flags are acted on by tdns-auth itself, on a
secondary with `use-hsyncparam` (§1.8).

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
