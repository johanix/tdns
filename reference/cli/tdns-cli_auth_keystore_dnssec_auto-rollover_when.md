## tdns-cli auth keystore dnssec auto-rollover when

Compute the earliest moment a rollover could safely fire (no state change)

### Synopsis

Asks the running daemon when the next rollover will fire and the
earliest it could fire if requested. Side-effect free; does not request
a rollover. Use 'auto-rollover asap' to actually schedule one.

Reports the KSK schedule by default (parent-DS gated). Use --zsk for the
ZSK schedule (zone-local, no parent gates — bounded only by standby
readiness), or --ksk to be explicit. The two flags are mutually exclusive.

Default mode talks to the daemon's API server (no daemon config needed
on the CLI host). Use --offline to compute locally against the keystore
file when the daemon is down — this requires --config with the daemon's
config file so the CLI can find db.file and the zone's policy.

```
tdns-cli auth keystore dnssec auto-rollover when [flags]
```

### Options

```
  -h, --help          help for when
      --offline       Compute locally against keystore file (postmortem use; daemon is down)
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

