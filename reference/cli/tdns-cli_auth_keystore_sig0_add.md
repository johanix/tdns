## tdns-cli auth keystore sig0 add

Add a new SIG(0) key pair to the keystore

### Synopsis

Add a new SIG(0) key pair to the keystore. Required arguments are the name of the file
containing either the private or the public SIG(0) key and the name of the zone.

```
tdns-cli auth keystore sig0 add [flags]
```

### Options

```
  -f, --file string   Name of file containing either pub or priv SIG(0) data
  -h, --help          help for add
  -z, --zone string   Zone to add SIG(0) key for
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

* [tdns-cli auth keystore sig0](tdns-cli_auth_keystore_sig0.md)	 - Prefix command, only usable via sub-commands

