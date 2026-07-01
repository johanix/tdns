## tdns-cli auth zone resign

Re-sign zone from scratch with currently-active keys (drops all existing RRSIGs)

```
tdns-cli auth zone resign [flags]
```

### Options

```
  -h, --help   help for resign
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

