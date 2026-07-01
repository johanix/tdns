## tdns-cli auth del sync

Make an API call to request TDNSD to send a DDNS update to sync parent delegation info with child data

```
tdns-cli auth del sync [flags]
```

### Options

```
  -h, --help            help for sync
  -S, --scheme string   Scheme to use for synchronization of delegation
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

* [tdns-cli auth del](tdns-cli_auth_del.md)	 - Delegation prefix command. Only usable via sub-commands.

