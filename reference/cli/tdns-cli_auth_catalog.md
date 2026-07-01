## tdns-cli auth catalog

Manage catalog zones (RFC 9432)

### Synopsis

Create and manage catalog zones, add/remove member zones and groups.

### Options

```
  -h, --help   help for catalog
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

* [tdns-cli auth](tdns-cli_auth.md)	 - Interact with tdns-auth (authoritative) via API
* [tdns-cli auth catalog create](tdns-cli_auth_catalog_create.md)	 - Create a new catalog zone
* [tdns-cli auth catalog delete](tdns-cli_auth_catalog_delete.md)	 - Delete an entire catalog zone
* [tdns-cli auth catalog group](tdns-cli_auth_catalog_group.md)	 - Manage groups in catalog
* [tdns-cli auth catalog notify](tdns-cli_auth_catalog_notify.md)	 - Manage notify addresses for catalog zones
* [tdns-cli auth catalog zone](tdns-cli_auth_catalog_zone.md)	 - Manage member zones in catalog

