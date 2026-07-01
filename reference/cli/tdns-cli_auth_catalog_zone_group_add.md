## tdns-cli auth catalog zone group add

Add a group to a zone

```
tdns-cli auth catalog zone group add --cat <catalog-zone> --zone <zone-name> --group <group-name> [flags]
```

### Options

```
      --cat string     Catalog zone name (required)
      --group string   Group name (required)
  -h, --help           help for add
      --zone string    Member zone name (required)
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

* [tdns-cli auth catalog zone group](tdns-cli_auth_catalog_zone_group.md)	 - Manage group associations for zones

