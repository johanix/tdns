## tdns-cli auth keystore dnssec auto-rollover asap

Schedule a manual KSK rollover at the earliest safe moment

### Synopsis

Asks the daemon to compute ComputeEarliestRollover and persist
manual_rollover_* on the zone row. The rollover worker fires
AtomicRollover when t_earliest is reached. Rejects the request if a
rollover is already in progress or the pipeline has no standby SEP key.

Online-only: scheduling against a stopped daemon is meaningless
(the manual_rollover_* row would never be read).

```
tdns-cli auth keystore dnssec auto-rollover asap [flags]
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
  -H, --headers         show headers
      --ksk             Render only the KSK section (status / when); ignored by other subcommands
  -Z, --pzone string    parent zone name
  -v, --verbose         verbose output
      --zsk             Render only the ZSK section (status / when); ignored by other subcommands
```

### SEE ALSO

* [tdns-cli auth keystore dnssec auto-rollover](tdns-cli_auth_keystore_dnssec_auto-rollover.md)	 - Manage and inspect automated KSK rollover (scheduled + manual-ASAP)

