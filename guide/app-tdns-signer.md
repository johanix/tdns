# tdns-signer -- bump-on-the-wire DNSSEC signer

`tdns-signer` signs a zone it does not own. It transfers an unsigned zone in
from a primary, signs it, and serves and transfers the signed result onward:

```
tdns-auth (or any primary)          unsigned zone, from a file,
    |                               DNS UPDATE, or the management API
    |  AXFR + NOTIFY
    v
tdns-signer                         signs; holds the DNSSEC keys
    |
    |  AXFR + NOTIFY
    v
published secondaries              serve the signed zone
```

This separates the two jobs cleanly. The primary deals with zone content
arriving in whatever form it arrives in, and never holds a private key. The
signer holds the keys, runs the rollovers, and has one input: a zone transfer.

## It is tdns-auth under another name

`tdns-signer` is the same program as `tdns-auth`, built as a second binary.
The signing it does is not new: a zone declared `type: secondary` with the
`inline-signing` option has always been able to sign content it did not
originate — it is the one sanctioned exception to a secondary being immutable.
Two `tdns-auth` instances could do this today.

What the separate binary buys is **configuration that does not collide**. The
config path is derived from the binary name, so:

| | reads |
|---|---|
| `tdns-auth` | `/etc/tdns/tdns-auth.yaml` |
| `tdns-signer` | `/etc/tdns/tdns-signer.yaml` |

with no `--config` on either, and no parallel `/etc` tree. It also gives the
two daemons distinct process names, which matters more than it sounds: tdns
daemons write no pidfile, so NetBSD `rc.subr` identifies a daemon by matching
`$procname` against the running command. Two instances of one binary are
indistinguishable to it, and either rc script's `stop` matches both.

Because it is the same program, every `tdns-auth` option works here, and
`tdns-cli auth ...` manages it (point an `apiservers` entry at its API — see
[Driving several instances of one daemon](multi-instance-cli.md)).

## Configuring a signer zone

The two lines that make it a signer:

```yaml
zones:
   - name:            example.com.
     type:            secondary      # never originates zone CONTENT
     options:
        - inline-signing             # but does originate the SIGNATURES
     dnssecpolicy:    default
     upstreams:
        - addr: "127.0.0.1:5354"     # where the unsigned zone comes from
          key:  NOKEY
     allow-notify:                   # so changes arrive promptly
        - prefix: "127.0.0.1/32"
          key:    NOKEY
     downstreams:                    # who may pull the SIGNED zone
        - prefix: "192.0.2.0/24"
          key:    downstream-xfr
     notify:                         # who to tell once it is signed
        - addr: "192.0.2.10:53"
          key:  downstream-xfr
```

Without `inline-signing` the zone is served exactly as received — unsigned.
With it and no `dnssecpolicy:`, the option is dropped and the zone goes to
ERROR.

Complete examples: `cmdv2/signer/tdns-signer.sample.yaml` and
`cmdv2/signer/signer-zones.sample.yaml`.

## Ordering: why a downstream never sees an unsigned zone

On every refresh the server transfers the zone in, signs it **synchronously**,
publishes the signed result, and only then sends NOTIFY to `notify:`. The
signing is not queued behind the publish, so there is no window in which a
downstream that reacts instantly to the NOTIFY can pull an unsigned or
partially signed zone.

The periodic re-signer (`resignerengine.interval`) is separate, and is about
signature *freshness*, not about new content.

## Running it beside tdns-auth on one host

Everything that cannot be shared must differ between the two configs:

```
db.file                 apiserver.addresses      listeners.addresses
log.file                apiserver.apikey         include: targets
dynamiczones.configfile / .zonedirectory
```

Sharing `db.file` would mean sharing the keystore, and so every private key.
Sharing `apiserver.apikey` removes the only thing that stops a command aimed
at one daemon from being accepted by the other.

**One collision does not fail loudly.** If both daemons set
`listeners.udp-sockets` greater than 1 and listen on the same address, on a
platform with a load-balancing reuseport option (Linux, FreeBSD, or NetBSD
with the out-of-tree `SO_REUSEPORT_LB` patch), the kernel forms *one*
load-balance group across the two daemons and splits arriving queries between
them. No error is logged; roughly half the queries reach the wrong server. The
default of 1 uses a plain bind, where an address collision fails at start-up as
it should. Only raise it on a daemon whose listen addresses are its own.

## Keys and rollovers

The signer holds the DNSSEC keys, so the keystore, the rollover engine and
`tdns-cli ... keystore` / `auto-rollover` all act on the signer, not on the
primary. See [the keystore guide](keystore.md) and
[Automatic DNSSEC Rollovers](key-rollover.md); nothing about them is special
here, beyond remembering which daemon to point the CLI at.

The one thing worth planning: a KSK rollover involves the parent zone, and the
signer is the thing that knows the keys. If you use delegation sync, configure
it on the signer.

## Verifying a pipeline

With the primary on port 5364 and the signer on 5365:

```bash
# the primary serves the zone unsigned
dig @127.0.0.1 -p 5364 +dnssec SOA example.com.     # no RRSIG

# the signer serves the same zone, signed
dig @127.0.0.1 -p 5365 +dnssec SOA example.com.     # RRSIG present
dig @127.0.0.1 -p 5365 DNSKEY example.com.          # KSK + ZSK

# and hands the signed zone onward
dig @127.0.0.1 -p 5365 AXFR example.com.
```

Change something on the primary and confirm it arrives signed:

```bash
dig @127.0.0.1 -p 5364 TXT new.example.com.         # on the primary
dig @127.0.0.1 -p 5365 +dnssec TXT new.example.com. # signed, on the signer
```

A transfer refused with `zone status loading` immediately after start-up is
normal: the zone is not advertised as ready until its first publish completes.
It clears in about a second.
