## tdns-cli auth keystore tsig purge

Delete unreferenced api-origin TSIG keys owned by api

### Synopsis

Dry-run by default: lists purge candidates (origin=api, owner=api,
zero zone references) and deletes nothing. Pass --force to delete all
candidates, or --interactive to prompt per key.

```
tdns-cli auth keystore tsig purge [flags]
```

### Options

```
      --force         Actually delete; otherwise dry-run
  -h, --help          help for purge
      --interactive   Prompt per purge candidate
  -y, --yes           Skip confirmation when used with --force
```

### Options inherited from parent commands

```
      --config string   config file (default is /etc/tdns/tdns-cli.yaml)
  -d, --debug           debug output
  -H, --headers         show headers
  -Z, --pzone string    parent zone name
  -v, --verbose         verbose output
  -z, --zone string     zone name
```

### SEE ALSO

* [tdns-cli auth keystore tsig](tdns-cli_auth_keystore_tsig.md)	 - Manage global TSIG keys in the keystore

