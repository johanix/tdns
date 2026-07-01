## tdns-cli auth keystore dnssec generate

Generate a new DNSSEC key pair and add it to the keystore

```
tdns-cli auth keystore dnssec generate [flags]
```

### Options

```
  -a, --algorithm string   Algorithm to use for DNSSEC key generation (use the 'algorithms' subcommand to list what the server supports)
  -h, --help               help for generate
      --keytype string     Key type to generate (KSK|ZSK|CSK)
      --state string       Inital key state (created|published|active|retired)
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

* [tdns-cli auth keystore dnssec](tdns-cli_auth_keystore_dnssec.md)	 - Prefix command, only usable via sub-commands

