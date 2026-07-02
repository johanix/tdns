## tdns-cli agent keystore

Prefix command to access different features of the keystore

### Synopsis

The keystore holds SIG(0), DNSSEC, and global TSIG keys.
The CLI contains functions for listing, adding, deleting, and
changing the state of keys.

```
tdns-cli agent keystore [flags]
```

### Options

```
  -h, --help   help for keystore
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

* [tdns-cli agent](tdns-cli_agent.md)	 - TDNS Agent commands
* [tdns-cli agent keystore dnssec](tdns-cli_agent_keystore_dnssec.md)	 - Prefix command, only usable via sub-commands
* [tdns-cli agent keystore sig0](tdns-cli_agent_keystore_sig0.md)	 - Prefix command, only usable via sub-commands
* [tdns-cli agent keystore tsig](tdns-cli_agent_keystore_tsig.md)	 - Manage global TSIG keys in the keystore

