## tdns-cli auth keystore dnssec rollover

Perform a manual DNSSEC key rollover (standby→active, active→retired)

```
tdns-cli auth keystore dnssec rollover [flags]
```

### Options

```
  -h, --help             help for rollover
      --keytype string   Key type to roll over (ZSK|KSK) (default "ZSK")
  -z, --zone string      Zone to perform rollover for
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

