## tdns-cli agent keystore dnssec setstate

Set the state of and existing DNSSEC key pair in the TDNSD keystore

```
tdns-cli agent keystore dnssec setstate [flags]
```

### Options

```
  -h, --help           help for setstate
      --keyid int      Key ID of key to delete
      --state string   New statei of key
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

* [tdns-cli agent keystore dnssec](tdns-cli_agent_keystore_dnssec.md)	 - Prefix command, only usable via sub-commands

