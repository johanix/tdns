## tdns-cli auth zone dnssec auto-rollover asap

Schedule a manual KSK rollover at the earliest safe moment

### Synopsis

Asks the daemon to compute ComputeEarliestRollover and persist
manual_rollover_* on the zone row. The rollover worker fires
AtomicRollover when t_earliest is reached. Rejects the request once
that rollover has fired and is in progress, or if the pipeline has no
standby SEP key. A repeat while a request is still pending keeps the
earlier of the pending and the newly computed time: asking again never
delays the roll.

Online-only: scheduling against a stopped daemon is meaningless
(the manual_rollover_* row would never be read).

With --zsk: the next worker tick promotes the oldest standby ZSK. A ZSK
reaches standby once it has been published for kasp.propagation-delay
plus the served DNSKEY TTL, so it never signs before resolvers can hold
it. With no standby yet, the request stays pending and fires when one
arrives. A repeat while a request is pending changes nothing; run it
again after each promotion to drain the pipeline faster.

```
tdns-cli auth zone dnssec auto-rollover asap [flags]
```

### Options

```
  -h, --help          help for asap
  -z, --zone string   Zone
```

### Options inherited from parent commands

```
      --config string   config file (default is /etc/tdns/tdns-cli.yaml)
  -d, --debug           debug output
  -F, --force           force operation
  -H, --headers         show headers
      --ksk             Render only the KSK section (status / when); ignored by other subcommands
  -Z, --pzone string    parent zone name
  -v, --verbose         verbose output
      --version         print version and supported algorithms, then exit
      --zsk             Render only the ZSK section (status / when); ignored by other subcommands
```

### SEE ALSO

* [tdns-cli auth zone dnssec auto-rollover](tdns-cli_auth_zone_dnssec_auto-rollover.md)	 - Manage and inspect automated KSK rollover (scheduled + manual-ASAP)

