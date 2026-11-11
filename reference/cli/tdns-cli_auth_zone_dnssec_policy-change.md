## tdns-cli auth zone dnssec policy-change

Bind a zone to a new DNSSEC policy for a gradual ZSK or KSK algorithm rollover

### Synopsis

Bind a zone toward a new DNSSEC policy so ONE role's algorithm rolls over
GRADUALLY. Unlike "zone dnssec policy-set" (which retires the old key
synchronously — unsafe for an algorithm change), this only binds the
target; the roll itself is gradual.

ZSK: only the algorithm of FUTURE-generated ZSKs changes; the existing
FIFO key pipeline drains in order, oldest first. Requires
dnssec.completeness: relaxed. After binding, the algorithm rolls on the
normal ZSK cadence — OR run

  auto-rollover asap -z <zone> --zsk

to promote the next standby now. Run it again after each promotion to
drain faster; a repeat while a request is pending changes nothing.

KSK: the auto-rollover engine (rollover.method multi-ds or
double-signature) carries it as a double-signature rollover: a
new-algorithm KSK is minted straight into active, the DNSKEY RRset is
double-signed, the DS at the parent is replaced by the new-algorithm DS
once every resolver can hold the double-signed RRset, and the old KSK
is removed once the parent has confirmed the swap and the drain window
(parent DS TTL included) has elapsed (RFC 6781 §4.1.4). The engine starts it on its next
tick. Watch it with "auto-rollover status -z <zone> --ksk"; abort it
before the parent confirms with "auto-rollover cancel -z <zone> --ksk
--alg-roll".

A CSK or both-role algorithm change, a KSK change without an engine, or
a second policy-change while a roll of either role is in flight, is
refused.

```
tdns-cli auth zone dnssec policy-change [flags]
```

### Options

```
  -h, --help            help for policy-change
  -p, --policy string   Target DNSSEC policy name
  -z, --zone string     Zone
```

### Options inherited from parent commands

```
      --config string   config file (default is /etc/tdns/tdns-cli.yaml)
  -d, --debug           debug output
  -F, --force           force operation
  -H, --headers         show headers
  -Z, --pzone string    parent zone name
  -v, --verbose         verbose output
      --version         print version and supported algorithms, then exit
```

### SEE ALSO

* [tdns-cli auth zone dnssec](tdns-cli_auth_zone_dnssec.md)	 - Zone DNSSEC operations: signing, policy, and automated rollover

