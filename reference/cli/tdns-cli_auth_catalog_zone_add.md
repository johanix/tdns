## tdns-cli auth catalog zone add

Add a zone to the catalog with optional groups

```
tdns-cli auth catalog zone add --cat <catalog-zone> --zone <zone-name> [--groups <group1,group2,...>] [flags]
```

### Options

```
      --cat string       Catalog zone name (required)
      --groups strings   Optional: comma-separated list of groups to add to the zone
  -h, --help             help for add
      --zone string      Member zone name (required)
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

* [tdns-cli auth catalog zone](tdns-cli_auth_catalog_zone.md)	 - Manage member zones in catalog

