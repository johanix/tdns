## tdns-cli auth keystore dnssec import

Add a new DNSSEC key pair to the keystore

```
tdns-cli auth keystore dnssec import [flags]
```

### Options

```
  -f, --file string   Name of file containing either pub or priv SIG(0) data
  -h, --help          help for import
  -z, --zone string   Zone to import DNSSEC key for
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

* [tdns-cli auth keystore dnssec](tdns-cli_auth_keystore_dnssec.md)	 - Prefix command, only usable via sub-commands

