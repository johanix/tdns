## tdns-cli auth keystore sig0 generate

Generate a new SIG(0) key pair and add it to the keystore

```
tdns-cli auth keystore sig0 generate [flags]
```

### Options

```
  -a, --algorithm string   Algorithm to use for SIG(0) key generation (use the 'algorithms' subcommand to list what the server supports)
  -h, --help               help for generate
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

* [tdns-cli auth keystore sig0](tdns-cli_auth_keystore_sig0.md)	 - Prefix command, only usable via sub-commands

