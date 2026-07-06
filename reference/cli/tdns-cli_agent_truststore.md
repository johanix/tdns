## tdns-cli agent truststore

Prefix command to access different features of the truststore

### Synopsis

The truststore is where SIG(0) public keys for child zones are kept.
The CLI contains functions for listing trusted SIG(0) keys, adding and
deleting child keys as well as changing the trust state of individual keys.

### Options

```
  -h, --help   help for truststore
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
* [tdns-cli agent truststore sig0](tdns-cli_agent_truststore_sig0.md)	 - Prefix command, only usable via sub-commands

