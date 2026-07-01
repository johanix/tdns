## tdns-cli auth ddns upload

Send a DDNS update to upload the initial SIG(0) public key to parent

```
tdns-cli auth ddns upload [flags]
```

### Options

```
  -h, --help   help for upload
```

### Options inherited from parent commands

```
      --config string     config file (default is /etc/tdns/tdns-cli.yaml)
  -d, --debug             debug output
  -H, --headers           show headers
  -k, --keyfile string    name of file with private SIG(0) key
  -P, --pprimary string   Address:port of parent primary nameserver
  -p, --primary string    Address:port of child primary namserver
  -Z, --pzone string      parent zone name
  -v, --verbose           verbose output
  -z, --zone string       zone name
```

### SEE ALSO

* [tdns-cli auth ddns](tdns-cli_auth_ddns.md)	 - Send a DDNS update. Only usable via sub-commands.

