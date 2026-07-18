## tdns-cli auth zone dnssec policy-set

Set a zone's DNSSEC policy at runtime (persists as an override, not in YAML)

### Synopsis

Apply a DNSSEC policy to a zone in the running server. The change is stored
as a per-zone override in the keystore and survives restart, but does NOT
update the zone's dnssec_policy in the YAML config — update that separately
to make the new policy the permanent base. If the new policy uses different
key algorithms, the old keys are retired (their signatures kept until the
KeyStateWorker removes them) and new keys take over; the zone stays signed
throughout.

```
tdns-cli auth zone dnssec policy-set [flags]
```

### Options

```
  -h, --help            help for policy-set
  -p, --policy string   DNSSEC policy name to apply
  -z, --zone string     Zone to set the DNSSEC policy for
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

