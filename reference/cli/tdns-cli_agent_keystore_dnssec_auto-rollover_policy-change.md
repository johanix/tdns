## tdns-cli agent keystore dnssec auto-rollover policy-change

Bind a zone to a new DNSSEC policy for a gradual ZSK algorithm rollover

### Synopsis

Bind a zone toward a new DNSSEC policy so its ZSK algorithm rolls over
GRADUALLY. Unlike "zone set-policy" (which retires the old key
synchronously — unsafe for an algorithm change), this only sets the
algorithm of FUTURE-generated ZSKs: the existing FIFO key pipeline drains
in order, oldest first.

This command does NOT perform the roll. After binding, the algorithm
rolls on the normal ZSK cadence — OR run

  auto-rollover asap -z <zone> --zsk

to promote the next standby now (repeat to accelerate through the
already-propagated old-alg standbys to the new algorithm).

Requires dnssec.completeness: relaxed. A KSK / CSK / both-role algorithm
change, or a second policy-change while a roll is in flight, is refused.

```
tdns-cli agent keystore dnssec auto-rollover policy-change [flags]
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
  -H, --headers         show headers
      --ksk             Render only the KSK section (status / when); ignored by other subcommands
  -Z, --pzone string    parent zone name
  -v, --verbose         verbose output
      --zsk             Render only the ZSK section (status / when); ignored by other subcommands
```

### SEE ALSO

* [tdns-cli agent keystore dnssec auto-rollover](tdns-cli_agent_keystore_dnssec_auto-rollover.md)	 - Manage and inspect automated KSK rollover (scheduled + manual-ASAP)

