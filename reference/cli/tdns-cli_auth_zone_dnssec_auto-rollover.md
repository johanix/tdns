## tdns-cli auth zone dnssec auto-rollover

Manage and inspect automated KSK rollover (scheduled + manual-ASAP)

### Synopsis

Subcommands operate on local keystore state for a zone:

  when      — compute the earliest safe rollover moment (no state change)
  asap      — schedule a manual rollover at that earliest moment
  cancel    — clear a pending manual rollover request
  status    — print phase + per-key state for the zone
  reset     — clear last_rollover_error on one key after operator action
  unstick   — skip the softfail-delay and probe the parent on the next tick
  validate  — re-parse policy from YAML and report which §4 invariants pass/fail

### Options

```
  -h, --help   help for auto-rollover
      --ksk    Render only the KSK section (status / when); ignored by other subcommands
      --zsk    Render only the ZSK section (status / when); ignored by other subcommands
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
  -z, --zone string     zone name
```

### SEE ALSO

* [tdns-cli auth zone dnssec](tdns-cli_auth_zone_dnssec.md)	 - Zone DNSSEC operations: signing, policy, and automated rollover
* [tdns-cli auth zone dnssec auto-rollover asap](tdns-cli_auth_zone_dnssec_auto-rollover_asap.md)	 - Schedule a manual KSK rollover at the earliest safe moment
* [tdns-cli auth zone dnssec auto-rollover cancel](tdns-cli_auth_zone_dnssec_auto-rollover_cancel.md)	 - Cancel a pending manual KSK rollover request
* [tdns-cli auth zone dnssec auto-rollover reset](tdns-cli_auth_zone_dnssec_auto-rollover_reset.md)	 - Clear last_rollover_error for one key (after operator intervention)
* [tdns-cli auth zone dnssec auto-rollover status](tdns-cli_auth_zone_dnssec_auto-rollover_status.md)	 - Print rollover state for a zone (KSK and ZSK)
* [tdns-cli auth zone dnssec auto-rollover unstick](tdns-cli_auth_zone_dnssec_auto-rollover_unstick.md)	 - Skip the softfail-delay and probe the parent on the next tick
* [tdns-cli auth zone dnssec auto-rollover validate](tdns-cli_auth_zone_dnssec_auto-rollover_validate.md)	 - Validate a zone's rollover policy against §4 cache-flush invariants
* [tdns-cli auth zone dnssec auto-rollover when](tdns-cli_auth_zone_dnssec_auto-rollover_when.md)	 - Compute the earliest moment a rollover could safely fire (no state change)

