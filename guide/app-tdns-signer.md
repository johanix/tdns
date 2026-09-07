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

## Why not just sign on the primary?

tdns-auth can sign its own zones, so a signer is only worth running when the
two ends should differ. The usual reason is **asymmetric hardware**.

Put the authoritative server where the zone data is — which may be modest
hardware, an appliance or a small board — and put the signer on a host chosen
for the signing work. The signer can then use an algorithm set the primary
could not carry: the post-quantum algorithms in particular (Falcon, MAYO,
SNOVA, SQIsign, ML-DSA — see [post-quantum DNSSEC](pq-dnssec.md)) are far more
expensive to sign with than ECDSA or Ed25519, in CPU and in key and signature
size.

So the signer's algorithm selection (`cmdv2/signer/algs.list`) is **expected to
differ** from the primary's, and usually to be larger. If the two were
constrained to the same set there would be little reason to split them at all.

What the signer's selection must cover is every algorithm named by a DNSSEC
policy it is asked to apply — not whatever the primary happens to have linked.
A policy naming an algorithm the binary did not link quarantines that zone at
load, naming the algorithm.

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

Because it is the same program, every `tdns-auth` option works here.

Manage it with **`tdns-cli`**, pointed at the signer by a CLI config of its
own. `tdns-cli` resolves `auth` to the `apiservers` entry named `tdns-auth`,
so the signer's CLI config gives that name the signer's API:

```yaml
# /etc/tdns/tdns-signer-cli.yaml
apiservers:
   - name:       tdns-auth
     baseurl:    https://127.0.0.1:8990/api/v1   # the SIGNER's API
     apikey:     ...
     authmethod: X-API-Key
```

```bash
tdns-cli --config /etc/tdns/tdns-signer-cli.yaml auth zone list
tdns-cli --config /etc/tdns/tdns-signer-cli.yaml auth keystore dnssec list -z example.com.
```

Two configs, and `--config` on every signer command. That is the cost of
running two daemons of the same type, and it is worth being deliberate about:
the failure it prevents is silent. A single config whose `tdns-auth` entry
points at one daemon while you believe it points at the other drives the wrong
server and reports success.

> `tdns-ncli` exists to remove the `--config`, by making the instance a command
> word (`tdns-ncli signer zone list`). It is a **prototype** — not yet tested
> enough to be the management tool — so it is an experiment to try, not the
> recommendation here. See
> [Driving several instances of one daemon](multi-instance-cli.md).

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
     notify:                         # who to tell once it is published
        - addr: "192.0.2.10:53"
          key:  downstream-xfr
```

Without `inline-signing` the zone is served exactly as received — unsigned.
With it and no `dnssecpolicy:`, the option is dropped and the zone goes to
ERROR.

Complete examples: `cmdv2/signer/tdns-signer.sample.yaml` and
`cmdv2/signer/signer-zones.sample.yaml`.

## Ordering, and a window you need to know about

On a first load the zone is not advertised as ready until it has been signed,
so nothing can be pulled before then.

**On every later refresh there is a window during which the zone is published
but not yet re-signed, and a downstream can transfer it.** This is tdns
issue [#512][512] — a property of every inline-signing secondary, not of this
binary — and the fix is [#514][514]. If you run a signer with downstreams,
run it on a build that carries #514.

The window is proportional to zone size, because the whole zone is re-signed
after each changed refresh: milliseconds on a small zone, over a minute on a
100k-name zone. Queries are protected (the responder returns SERVFAIL rather
than an unsigned answer); transfers are not.

[512]: https://github.com/johanix/tdns/issues/512
[514]: https://github.com/johanix/tdns/pull/514

The periodic re-signer (`resignerengine.interval`) is separate, and is about
signature *freshness*, not about new content.

## Do not enable inbound updates on a signer

A signer's content comes from its primary. `StartSigner` is `StartAuth`, so
the DNS UPDATE handler is running and `allow-updates` on a signer zone would
be accepted — but it is a second, competing source of content: the next
refresh overwrites whatever was written, and if the refresh fails the write
survives as a divergence from the primary that nothing reconciles. The sample
does not set it; do not add it.

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

The signer holds the DNSSEC keys, so the keystore and the rollover engine act
on the signer, not on the primary — and so must the CLI. Use the signer's own
CLI config, as above:

```bash
tdns-cli --config /etc/tdns/tdns-signer-cli.yaml auth keystore dnssec list -z example.com.
tdns-cli --config /etc/tdns/tdns-signer-cli.yaml auth zone dnssec auto-rollover status -z example.com.
```

See [the keystore guide](keystore.md) and
[Automatic DNSSEC Rollovers](key-rollover.md); nothing about them is special
here, beyond addressing the signer rather than the primary. Forgetting
`--config` here is the expensive case: the keystore and the rollovers are the
signer's whole job, and the command will happily read or act on the
authoritative server's keystore instead.

The one thing worth planning: a KSK rollover involves the parent zone, and the
signer is the thing that knows the keys. If you use delegation sync, configure
it on the signer.

## Verifying a pipeline

With the primary on port 5364 and the signer on 5365:

```bash
# the primary serves the zone unsigned
dig @127.0.0.1 -p 5364 +dnssec SOA example.com.     # no RRSIG

# the signer serves the same zone, signed
dig @127.0.0.1 -p 5365 +dnssec SOA example.com.     # RRSIG present: signing is on
dig @127.0.0.1 -p 5365 DNSKEY example.com.          # KSK + ZSK

# and hands the signed zone onward
dig @127.0.0.1 -p 5365 AXFR example.com.
```

Change something on the primary and confirm it arrives signed:

```bash
dig @127.0.0.1 -p 5364 TXT new.example.com.         # on the primary
dig @127.0.0.1 -p 5365 +dnssec TXT new.example.com. # signed, on the signer
```

**Ask about the RRset you changed, not about the SOA.** The apex SOA is signed
throughout the window described above, so a signed SOA says nothing about
whether the rest of the zone has caught up: a mid-flight AXFR can carry a signed
SOA over tens of thousands of unsigned RRsets, and it is logged as a complete
transfer. Measured on a 100k-name zone: 25 seconds after the first NOTIFY, a
transfer returned 337k records of an eventual 475k. Polling the SOA RRSIG is
what made an earlier check of this look green.

The two `dig`s above are the right shape because they name the record that
changed. Nothing below a delegation is signed either, and legitimately so, so
"are there unsigned RRsets in this transfer" is not the question — "is the RRset
I just changed signed yet" is.

A transfer refused with `zone status loading` immediately after start-up is
normal: the zone is not advertised as ready until its first publish completes.
It clears in about a second.
