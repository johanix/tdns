## tdns-cli auth keystore dnssec purge

Delete keys in 'removed' state, keeping the 3 most recent per zone

### Synopsis

Delete keys in 'removed' state from the keystore, keeping the 3
most recent per zone (by insert order). Use --zone all to apply to
every zone with removed keys at once.

Dry-run by default: prints the keys that would be deleted and exits
without modifying anything. Pass --force to actually delete.

```
tdns-cli auth keystore dnssec purge [flags]
```

### Options

```
      --force         Actually delete; otherwise dry-run
  -h, --help          help for purge
  -z, --zone string   Zone to purge ('all' for every zone)
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

* [tdns-cli auth keystore dnssec](tdns-cli_auth_keystore_dnssec.md)	 - Prefix command, only usable via sub-commands

