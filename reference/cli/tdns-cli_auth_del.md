## tdns-cli auth del

Delegation prefix command. Only usable via sub-commands.

### Options

```
  -h, --help   help for del
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
* [tdns-cli auth del export](tdns-cli_auth_del_export.md)	 - Export delegation data from a parent zone's backend to a zone file
* [tdns-cli auth del status](tdns-cli_auth_del_status.md)	 - Make an API call to request TDNSD to analyse whether delegation is in sync or not
* [tdns-cli auth del sync](tdns-cli_auth_del_sync.md)	 - Make an API call to request TDNSD to send a DDNS update to sync parent delegation info with child data

