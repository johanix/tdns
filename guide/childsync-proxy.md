# Operator guide: tdns-agent fronting a parent zone (`childsync-proxy`)

`childsync-proxy` makes a tdns-agent that is a **secondary of a parent zone**
perform the parent's half of delegation sync on behalf of a primary that knows
nothing about DSYNC: BIND, Knot, or a registry's provisioning pipeline. The
agent advertises the DSYNC service in the parent zone, receives the children's
NOTIFY, DNS UPDATE and DSYNC API traffic, applies the parent's policy, and
pushes every approved change **to the parent primary** instead of into its own
copy of the zone -- which the next transfer would replace.

It is the mirror of [`parentsync-proxy`](agent-dsync-proxy.md), the child-side
proxy, seen from the other end of the delegation. The design is
`docs/2026-09-08-childsync-proxy.md`.

## When to use this

- The parent zone's primary cannot do delegation sync itself, and you want
  children to be able to update their own delegations (NS, DS, glue) through
  the standard DSYNC schemes.
- You can give one tdns-agent a **secondary copy** of the parent zone and a
  way to write into it: a TSIG key the primary's update policy accepts, or a
  provisioning system that reads a shared database.

The agent is **not** in the parent's NS set and answers no ordinary query. The
only query it answers is a child's KeyState inquiry, which is part of the
UPDATE scheme.

## Topology

```
   child.example.                              example. (the parent)
   +--------------+                            +---------------------------+
   | child primary|                            | parent primary  (BIND/...)|
   |  (any impl)  |                            |  DSYNC-unaware            |
   +------+-------+                            +------+--------------+-----+
          |                                     AXFR/ |        DDNS  |
          |  NOTIFY(CDS/CSYNC)                 NOTIFY |      (TSIG)  | ^
          |  DNS UPDATE (SIG(0))                      v              v |
          |  DSYNC API (HTTPS)                 +--------------------------+
          +--------------------------------->  |  tdns-agent              |
                                               |  secondary of example.   |
             KeyState inquiry (KEY, SIG(0)) -> |  option: childsync-proxy |
                                               +--------------------------+
                                                     ^
                          the parent zone's DSYNC RRset points HERE
```

## Requirements

- tdns-agent, with the parent zone configured as `type: secondary`.
- The option `childsync-proxy` on that zone. It implies `childsync`; writing
  both is legal. On anything but an agent secondary the zone is quarantined
  with a config error.
- `allow-child-updates` on the zone and a `delegationbackend` whose store is
  not `direct` -- the agent's copy of the zone is replaced at the next
  transfer, so approved updates must be **recorded in a store and delivered by
  a writer** (next section).
- The `childsync:` block, as on tdns-auth: the schemes to offer and their
  targets and addresses. `notify.addresses`, `update.addresses` and
  `api.addresses` are the **agent's** addresses: they are what gets published
  at the targets.
- For the UPDATE scheme, a delegation policy (`delegationpolicy:`) and the
  child SIG(0) keys in the agent's truststore, exactly as on tdns-auth. The
  receiver's own SIG(0) key is generated in the agent's keystore and
  published at the parent primary by the proxy.
- For the API scheme, `childsync.api.listen`, a certificate, and credentials
  (`tdns-cli dsync-api credential ...`). The agent starts the DSYNC API
  listener on its own socket, as tdns-auth does.

## Delegation backends: a store and a writer

A delegation backend answers two independent questions: **where** the intended
delegation state is kept, and **how** it reaches the parent zone. Both are
axes in the config; the old one-word type names are shorthand for pairs.

```yaml
delegationbackends:
  - name: parent-primary
    store:  sqlite            # sqlite | direct | external-db   (default sqlite)
    writer: ddns              # none | zonefile | ddns          (default none)
    ddns:
      targets: []             # default: this zone's configured primaries
      key: agent-to-primary   # TSIG key name from the keystore
      allow-insecure: false   # permit an unsigned UPDATE. Lab only.
      retry-interval: 5s
      max-attempts: 5
```

| `type:` | is |
|---|---|
| `db` | `store: sqlite, writer: none` |
| `direct` | `store: direct, writer: none` |
| `zonefile` | `store: sqlite, writer: zonefile` |
| `upstream` | `store: sqlite, writer: ddns` |
| `external-db` | `store: external-db, writer: none` |

Writing `type:` together with `store:` or `writer:` is an error, not a
precedence rule. `store: direct` accepts only `writer: none`.

The three writers:

- **`ddns`** -- an RFC 2136 UPDATE over TCP, TSIG-signed, to `ddns.targets` or
  the zone's own primaries. The primary must accept it (below). This is the
  automatic path; the push engine retries a transport failure or a SERVFAIL
  with backoff and stops on a REFUSED or NOTAUTH, which is the primary's
  policy saying no.
- **`zonefile`** -- per-child `$INCLUDE` fragments plus an optional command,
  for a parent zone generated from files. Runs inline.
- **`none`** (also spelled `manual`) -- nothing is delivered. The agent
  records every approved update and prints what the primary lacks; you apply
  it by hand or from the external store.

### At the primary: bound what the agent may write

The agent holds DDNS write authority over the parent zone. Bound it at the
primary to the delegation names and the agent's own advertisement names. BIND:

```
update-policy {
    grant agent-to-primary zonesub  NS DS A AAAA;
    grant agent-to-primary name _dsync.example.  DSYNC URI TXT;
    grant agent-to-primary subdomain _dsync.example.  A AAAA SVCB KEY;
};
```

Not `allow-update { key ...; }`, which grants the whole zone, apex SOA and NS
included. Knot: an `acl` with `action: update` and an `update-owner` /
`update-type` restriction to the same effect.

The agent bounds itself as well: the writer refuses, before it builds a
message, any owner that is not a delegation point of the parent (or below one)
or one of its own advertisement names. That is defence in depth against a
permissive primary, not the load-bearing gate.

## A complete agent configuration

```yaml
keystore:
  # the TSIG key the primary's update-policy names
  # (tdns-cli keystore tsig add agent-to-primary ...)

childsync:
  schemes: [ notify, update, api ]
  notify:
    target: notifications.{ZONENAME}
    port: 53
    addresses: [ 192.0.2.53 ]          # the AGENT's address
    types: [ CDS, CSYNC ]
  update:
    target: updates.{ZONENAME}
    port: 53
    addresses: [ 192.0.2.53 ]
    types: [ ANY ]
  api:
    target: api.{ZONENAME}
    port: 8443
    addresses: [ 192.0.2.53 ]
    listen: [ 192.0.2.53:8443 ]
    cert: /etc/tdns/dsync-api.crt
    key: /etc/tdns/dsync-api.key
  policies:
    registry-strict:
      mechanisms: [ at-apex, at-ns ]
      require-dnssec: true

delegationbackends:
  - name: parent-primary
    store: sqlite
    writer: ddns
    ddns:
      key: agent-to-primary

zones:
  - name: example.
    type: secondary
    primaries: [ { addr: 192.0.2.1:53, key: xfr-key } ]
    options: [ childsync-proxy, allow-child-updates ]
    delegationbackend: parent-primary
    delegationpolicy: registry-strict
    updatepolicy:
      child:
        type: selfsub
        rrtypes: [ NS, A, AAAA, DS, KEY ]
```

## What happens

**Cold start.** The agent transfers the parent zone. If the zone carries no
DSYNC RRset, the proxy computes the whole advertisement -- DSYNC records, the
API service description, the targets' addresses, the bootstrap SVCB, and the
UPDATE receiver's SIG(0) KEY (generated in the keystore) -- and pushes it to
the primary. The primary applies it, bumps its serial and NOTIFYs the agent;
the next transfer brings the records back, the difference goes empty, and the
zone's warning clears. Children can now discover and use the service. The
NOTIFY receiver refuses NOTIFY until the advertisement has landed in the
transferred zone: that is the honest answer, not a defect.

**First load also seeds the store.** For every delegation the served zone
carries, if the store has no rows for that child, what the zone holds is
written in, marked `observed`. The scanner reads a child's current delegation
from the store, so an unseeded store would have made every first diff run
against nothing.

**A child's DNS UPDATE.** Received, SIG(0)-validated against the truststore,
checked against `updatepolicy.child`, the delegation policy and the coherence
checks -- the parent's own code, unchanged -- and then **recorded** in the
store. The child hears NOERROR: that means "accepted and recorded by the
parent's delegation service", as it always has for the `db` and `zonefile`
backends. The push engine then computes the difference between the store and
the served zone for that child and pushes it. Several updates for one child
collapse into one push.

**A child's NOTIFY(CDS/CSYNC).** The scanner reads the current delegation
from the (seeded) store, scans the child, and produces the same kind of
update; from there the path is the same.

**Every refresh.** The proxy reconciles the advertisement, and asks the push
engine to reconcile every child the store knows against the served zone. This
recovers a push dropped on a full queue, one the primary silently declined, an
operator's edit at the primary that contradicts recorded intent, and a
restart. A child with **no rows in the store is never touched**: an empty
store can never empty a parent zone.

## Operating it

```
tdns-cli zone childsync proxy-status -z example.
tdns-cli zone childsync advert       -z example.
tdns-cli zone childsync reconcile    -z example.
tdns-cli zone childsync delegation   -z example. [--child alpha.example.]
```

`proxy-status` reports the advertisement's state and the push engine's:

| state | meaning |
|---|---|
| `ready` | the served zone carries the whole advertisement and the agent holds the receiver key |
| `publishing` | a difference exists and has been handed to the push engine |
| `waiting-for-publication` | a difference exists and nothing delivers it; `advert` prints the nsupdate block |
| `foreign-key` | a KEY the agent does not hold is published at the UPDATE target; no competing key is minted, remove it |
| `no-zone-data` | the parent zone has not been transferred yet |

Pushes that did not land are listed per child with the attempt count, the
last error and whether it is terminal. A terminal one (REFUSED, NOTAUTH, a
refusal by the agent's own bound) is an operator problem: fix the primary's
policy or the configuration, then `reconcile`. A non-terminal one is retried
on the next refresh without any action.

Every degraded state is also a `delegation-sync-warning` on the zone, visible
in `zone list` and `zone status`. It is not service-impacting: the zone keeps
serving and keeps receiving.

## The manual path

With `writer: none`, `advert` (and `proxy-status`) print an nsupdate script:

```
server 192.0.2.1:53
zone example.
update add _dsync.example.	7200	IN	DSYNC	CDS	NOTIFY 5302 notifications.example.
...
send
```

Approved child updates are recorded in the store; `zone childsync delegation`
shows what the store holds for a child, and the parent primary is updated by
whatever reads the store. With `store: sqlite` that is you.

## Handing off to a provisioning system: `store: external-db`

A registry that provisions delegations from its own pipeline reads them from
a **shared MariaDB** instead. The store holds the delegation handoff and
nothing else: the agent's keystore, truststore and journal stay in its local
sqlite database.

```yaml
delegationbackends:
  - name: registry-handoff
    store:  external-db
    writer: none                 # the consumer updates the zone
    external-db:
      driver: mysql
      dsn: "tdns:@tcp(db.example.net:3306)/reg"
      password: "..."            # or in the DSN; never echoed by the config API
      tls: true                  # default on for a non-loopback host
      ca-file: /etc/tdns/db-ca.pem
      table-prefix: tdns_        # default
      auto-migrate: false        # default: the DBA runs the DDL below
      max-open-conns: 8
      timeout: 5s
```

The store is built into **tdns-agent only**. Naming it on any other binary is
a config error that says so.

With `store: external-db` the delegation service is only as available as the
database: a child update that cannot be recorded is **refused**, never
answered NOERROR, because acceptance means recorded. That is the one respect
in which it is less forgiving than sqlite.

### The schema

Three tables. The first two are written only by tdns; the third only by the
consumer. Once a consumer reads them, their shape is a contract.

<!-- DDL rendered from v2/externaldb/schema.go; a test keeps it in sync -->
```sql
CREATE TABLE IF NOT EXISTS tdns_delegation (
    parent      VARCHAR(255) CHARACTER SET ascii NOT NULL,
    child       VARCHAR(255) CHARACTER SET ascii NOT NULL,
    owner       VARCHAR(255) CHARACTER SET ascii NOT NULL,
    rrtype      VARCHAR(16)  CHARACTER SET ascii NOT NULL,
    rr          TEXT NOT NULL,
    rr_hash     BINARY(32) NOT NULL,
    origin      VARCHAR(16) NOT NULL,
    revision    BIGINT      NOT NULL,
    updated_at  DATETIME(3) NOT NULL,
    PRIMARY KEY (parent, owner, rrtype, rr_hash),
    KEY (parent, child),
    KEY (revision),
    CONSTRAINT tdns_chk_origin CHECK (origin IN ('observed','asserted'))
);

CREATE TABLE IF NOT EXISTS tdns_delegation_log (
    revision    BIGINT AUTO_INCREMENT PRIMARY KEY,
    change_id   BINARY(16)   NOT NULL,
    parent      VARCHAR(255) CHARACTER SET ascii NOT NULL,
    child       VARCHAR(255) CHARACTER SET ascii NOT NULL,
    op          VARCHAR(16)  NOT NULL,
    owner       VARCHAR(255) CHARACTER SET ascii NOT NULL,
    rrtype      VARCHAR(16)  CHARACTER SET ascii NOT NULL,
    rr          TEXT,
    channel     VARCHAR(16)  NOT NULL,
    principal   VARCHAR(255),
    applied_at  DATETIME(3)  NOT NULL,
    KEY (change_id),
    KEY (parent, revision),
    CONSTRAINT tdns_chk_op CHECK (op IN ('add','del-rr','del-rrset'))
);

CREATE TABLE IF NOT EXISTS tdns_delegation_ack (
    consumer    VARCHAR(64)  CHARACTER SET ascii NOT NULL,
    parent      VARCHAR(255) CHARACTER SET ascii NOT NULL,
    revision    BIGINT       NOT NULL,
    status      VARCHAR(16)  NOT NULL,
    detail      TEXT,
    acked_at    DATETIME(3)  NOT NULL,
    PRIMARY KEY (consumer, parent)
);

```

- `tdns_delegation` is the **current intended state**: what the parent zone
  should contain, one row per record, with `origin` (`asserted` by a child, or
  `observed` in the served zone by the first-load seeding) and the log
  `revision` that last touched it.
- `tdns_delegation_log` is the **append-only truth**: one row per action,
  grouped by `change_id` -- one per applied child update -- and ordered by
  `revision`. `channel` says where it came from (`update`, `dsync-api`,
  `scanner`, `adopt`, `internal`).
- `tdns_delegation_ack` is the consumer's watermark.

### The consumer contract

- Read `tdns_delegation_log` incrementally: `WHERE revision > <watermark>
  ORDER BY revision`, applying **whole `change_id` groups**; a group is never
  observable half-written, because tdns writes it in one transaction. Or read
  `tdns_delegation` for a full rebuild; it is derivable from the log, and if
  the two ever disagree the log wins.
- Write your progress to `tdns_delegation_ack` (`consumer`, `parent`,
  `revision`, `status`, `detail`).
- Never write the other two tables. Grants enforce this:

```sql
-- tdns
GRANT SELECT, INSERT, UPDATE, DELETE ON reg.tdns_delegation     TO 'tdns'@'%';
GRANT SELECT, INSERT                 ON reg.tdns_delegation_log TO 'tdns'@'%';
GRANT SELECT                         ON reg.tdns_delegation_ack TO 'tdns'@'%';
-- the provisioning consumer
GRANT SELECT                         ON reg.tdns_delegation     TO 'prov'@'%';
GRANT SELECT                         ON reg.tdns_delegation_log TO 'prov'@'%';
GRANT SELECT, INSERT, UPDATE         ON reg.tdns_delegation_ack TO 'prov'@'%';
```

Nobody has `DELETE` on the log. It grows without bound, and pruning is a DBA
operation with a retention policy, not something either program does.
Monitoring the ack watermark is the consumer operator's job.

At startup tdns **verifies** the schema -- tables present, expected columns
present -- and on a mismatch marks the zone with a config error naming the
discrepancy. The daemon and its other zones keep running.

## Failure modes

| failure | behaviour |
|---|---|
| primary unreachable | backoff, bounded attempts, then a warning; the store keeps the intent; every refresh retries |
| primary answers REFUSED or NOTAUTH | stop at once, warning naming the rcode and EDE: an operator problem |
| push queue full | logged and dropped; the next refresh re-derives the delta |
| agent restarts with pushes in flight | the first refresh reconciles |
| a foreign KEY at the UPDATE target | `foreign-key`, warning, no competing key; NOTIFY and API still work |
| advertisement never lands | `waiting-for-publication`; NOTIFY is refused until it does |
| operator edits a delegation at the primary | re-asserted for children the store knows; unknown children left alone |
| external store unreachable | child updates are refused, never answered NOERROR; warning on the zone |
| external store schema mismatch | config error on the zone at startup; the daemon keeps running |
| consumer falls behind or stops | nothing breaks in tdns; the log grows and the ack stops advancing |

## Limitations

- **One writing agent per parent zone.** Two agents with writers would fight
  over divergent stores. Additional agents may run with `writer: none` as
  warm standby.
- **A child that deletes its whole delegation** is pushed once, from the
  update; the refresh reconcile does not re-push it if that push failed,
  because a child with no rows is by design never touched. Run `reconcile`
  after fixing the cause, or re-send the child's update.
- The refresh reconcile reads the store once per known child. On a parent
  with very many children that is the cost of every refresh.
- Only the `mysql` driver ships. The dialect shim is where PostgreSQL would go.
- `childsync.update.target` must be a name below the apex. The proxy mints
  no receiver KEY at the apex, so with the target there the UPDATE scheme is
  advertised but cannot be signed; the log says so on every reconcile.
- `childsync` **without** `childsync-proxy` on an agent secondary publishes
  the advertisement into the agent's own copy, which the next transfer
  replaces. The zone gets a config warning and `tdns-cli agent config check`
  reports it.
