## tdns-cli auth keystore tsig setowner

Change owner on an api-origin TSIG key

```
tdns-cli auth keystore tsig setowner [flags]
```

### Options

```
  -h, --help           help for setowner
      --name string    TSIG key name
      --owner string   New owner label
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

* [tdns-cli auth keystore tsig](tdns-cli_auth_keystore_tsig.md)	 - Manage global TSIG keys in the keystore

