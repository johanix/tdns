## tdns-cli auth keystore dnssec auto-rollover reset

Clear last_rollover_error for one key (after operator intervention)

### Synopsis

Asks the daemon to clear the last_rollover_error column on a single
key's RolloverKeyState row. Use after diagnosing and fixing a
hard-failed rollover so status output isn't misleading.

Default mode talks to the daemon's API server. Use --offline to write
directly to the keystore file when the daemon is down (postmortem
use). The CLI checks the daemon-sentinel row in the keystore and
refuses to run --offline if it sees a live daemon process; pass
--force to override (you must ensure the daemon is genuinely
stopped first).

```
tdns-cli auth keystore dnssec auto-rollover reset [flags]
```

### Options

```
      --force         With --offline: override the daemon-alive check
  -h, --help          help for reset
      --keyid int     Key ID to reset (RFC 4034 keytag)
      --offline       Write directly to keystore file (postmortem use; daemon is down)
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

