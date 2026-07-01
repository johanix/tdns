## tdns-cli auth catalog notify remove

Remove a notify address from a catalog zone

```
tdns-cli auth catalog notify remove --cat <catalog-zone> --addr <IP:port> [flags]
```

### Options

```
      --addr string   Notify address in IP:port format (required)
      --cat string    Catalog zone name (required)
  -h, --help          help for remove
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

* [tdns-cli auth catalog notify](tdns-cli_auth_catalog_notify.md)	 - Manage notify addresses for catalog zones

