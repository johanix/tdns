## tdns-cli auth catalog zone delete

Remove a zone from the catalog

```
tdns-cli auth catalog zone delete --cat <catalog-zone> --zone <zone-name> [flags]
```

### Options

```
      --cat string    Catalog zone name (required)
  -h, --help          help for delete
      --zone string   Member zone name (required)
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

