## tdns-cli auth zone reload

Request re-loading a zone

```
tdns-cli auth zone reload [flags]
```

### Options

```
  -e, --error            wait for reload to complete and report any parse errors
  -h, --help             help for reload
      --timeout string   how long to wait for reload when --error is set (e.g. 10s, 2m) (default "10s")
```

### Options inherited from parent commands

```
      --config string   config file (default is /etc/tdns/tdns-cli.yaml)
  -d, --debug           debug output
  -F, --force           force operation
  -H, --headers         show headers
  -Z, --pzone string    parent zone name
  -v, --verbose         verbose output
  -z, --zone string     zone name
```

### SEE ALSO

* [tdns-cli auth zone](tdns-cli_auth_zone.md)	 - Prefix command, not usable by itself

