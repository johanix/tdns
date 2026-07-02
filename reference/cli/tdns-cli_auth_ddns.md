## tdns-cli auth ddns

Send a DDNS update. Only usable via sub-commands.

### Options

```
  -h, --help              help for ddns
  -k, --keyfile string    name of file with private SIG(0) key
  -P, --pprimary string   Address:port of parent primary nameserver
  -p, --primary string    Address:port of child primary namserver
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
* [tdns-cli auth ddns roll](tdns-cli_auth_ddns_roll.md)	 - Send a DDNS update to roll the SIG(0) key used to sign updates
* [tdns-cli auth ddns upload](tdns-cli_auth_ddns_upload.md)	 - Send a DDNS update to upload the initial SIG(0) public key to parent

