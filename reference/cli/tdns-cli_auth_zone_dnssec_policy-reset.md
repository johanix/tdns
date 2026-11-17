## tdns-cli auth zone dnssec policy-reset

Reset a zone's DNSSEC keys to its config policy, per role (dry-run without --confirm)

### Synopsis

Force a zone onto its config dnssecpolicy: for each key role whose algorithm no
longer matches config, drop and regenerate that role's keys and re-sign; any
role whose algorithm is already correct is kept. It also clears the runtime
override and records the config policy as applied.

This is a break-glass tool for test/lab zones. It exists because an abrupt
policy switch that changes a KSK/ZSK algorithm is otherwise refused (that needs
a key rollover that is not built). If the KSK algorithm changes it BREAKS THE
CHAIN OF TRUST: the parent DS will not match the new KSK until you re-publish it
(a ZSK-only change keeps the KSK and the DS). NOT for production.

Run WITHOUT --confirm for a DRY RUN that previews what it would do (which roles
would roll, whether the parent DS would break) and changes nothing; add
--confirm to apply. A single --zone only (no wildcards, no bulk).

```
tdns-cli auth zone dnssec policy-reset [flags]
```

### Options

```
      --confirm       Apply the reset; without it the command is a dry-run that only previews what would happen
  -h, --help          help for policy-reset
  -z, --zone string   Zone to reset the DNSSEC policy for
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

