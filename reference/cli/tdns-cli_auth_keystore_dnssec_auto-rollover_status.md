## tdns-cli auth keystore dnssec auto-rollover status

Print rollover state for a zone (KSK and ZSK)

### Synopsis

Prints rollover state for the zone with an OK / ACTIVE / SOFTFAIL
headline and per-key tables for KSKs and ZSKs.

Default mode talks to the daemon's API server (no daemon config needed
on the CLI host). Use --offline to render against the keystore file
when the daemon is down — that requires --config with the daemon's
config file so the CLI can find db.file and the zone's policy.

Use --ksk or --zsk to print only the KSK block or only the ZSK block
(the two flags are mutually exclusive). These flags are inherited
from the auto-rollover parent and accepted by every subcommand for
consistency.

The DS range line lists SEP keyids (same numbering as the KSK table and
as DS digest key tags at the parent).

Use -v / --verbose to show rollover_index spans behind the keyid lists
and the policy summary.

```
tdns-cli auth keystore dnssec auto-rollover status [flags]
```

### Options

```
  -h, --help          help for status
      --offline       Render against keystore file (postmortem use; daemon is down)
  -v, --verbose       Show full last_error text and policy summary
  -z, --zone string   Zone
```

### Options inherited from parent commands

```
      --config string   config file (default is /etc/tdns/tdns-cli.yaml)
  -d, --debug           debug output
  -H, --headers         show headers
      --ksk             Render only the KSK section (status / when); ignored by other subcommands
  -Z, --pzone string    parent zone name
      --zsk             Render only the ZSK section (status / when); ignored by other subcommands
```

### SEE ALSO

* [tdns-cli auth keystore dnssec auto-rollover](tdns-cli_auth_keystore_dnssec_auto-rollover.md)	 - Manage and inspect automated KSK rollover (scheduled + manual-ASAP)

