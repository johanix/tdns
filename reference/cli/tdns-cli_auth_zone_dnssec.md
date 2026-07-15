## tdns-cli auth zone dnssec

Zone DNSSEC operations: signing, policy, and automated rollover

### Options

```
  -h, --help   help for dnssec
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

* [tdns-cli auth zone](tdns-cli_auth_zone.md)	 - Prefix command, not usable by itself
* [tdns-cli auth zone dnssec auto-rollover](tdns-cli_auth_zone_dnssec_auto-rollover.md)	 - Manage and inspect automated KSK rollover (scheduled + manual-ASAP)
* [tdns-cli auth zone dnssec nsec](tdns-cli_auth_zone_dnssec_nsec.md)	 - Prefix command, not usable by itself
* [tdns-cli auth zone dnssec policy-change](tdns-cli_auth_zone_dnssec_policy-change.md)	 - Bind a zone to a new DNSSEC policy for a gradual ZSK algorithm rollover
* [tdns-cli auth zone dnssec policy-set](tdns-cli_auth_zone_dnssec_policy-set.md)	 - Set a zone's DNSSEC policy at runtime (persists as an override, not in YAML)
* [tdns-cli auth zone dnssec resign](tdns-cli_auth_zone_dnssec_resign.md)	 - Re-sign zone from scratch with currently-active keys (drops all existing RRSIGs)
* [tdns-cli auth zone dnssec sign](tdns-cli_auth_zone_dnssec_sign.md)	 - Request signing of a zone (additive: cover gaps with active keys)

