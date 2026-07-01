## tdns-cli agent keystore dnssec ds-push

Compute DS RRset from keystore and push to parent (UPDATE-only in this offline mode)

### Synopsis

Loads tdns config (same as other CLI commands using -c), opens the local keystore DB,
and pushes the whole DS RRset to the parent. Requires imrengine in config.

Offline mode: this CLI invocation builds a stub *ZoneData with no rollover policy
attached, so PushDSRRsetForRollover falls through to the legacy single-scheme
UPDATE path (whole-DS replacement, signed with the zone's active SIG(0) key).
The auto / prefer-* / force-* dsync-scheme-preference values are honored only
inside the daemon's rollover engine, where the policy is loaded from
dnssecpolicies. To exercise NOTIFY pushes, run the daemon and let
RolloverAutomatedTick drive the push.

Use --dry-run to print the DS set and the UPDATE without sending.

```
tdns-cli agent keystore dnssec ds-push [flags]
```

### Options

```
      --dry-run       Print DS RRset and UPDATE only; do not send
  -h, --help          help for ds-push
  -z, --zone string   Child zone (owner of DS RRset)
```

### Options inherited from parent commands

```
      --config string   config file (default is /etc/tdns/tdns-cli.yaml)
  -d, --debug           debug output
  -H, --headers         show headers
  -Z, --pzone string    parent zone name
  -v, --verbose         verbose output
```

### SEE ALSO

* [tdns-cli agent keystore dnssec](tdns-cli_agent_keystore_dnssec.md)	 - Prefix command, only usable via sub-commands

