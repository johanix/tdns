## tdns-cli agent truststore sig0 untrust

Declare a child SIG(0) public key in the keystore as untrusted

```
tdns-cli agent truststore sig0 untrust [flags]
```

### Options

```
  -h, --help        help for untrust
      --keyid int   Keyid of child SIG(0) key to change trust for
```

### Options inherited from parent commands

```
  -c, --child string    Name of child SIG(0) key
      --config string   config file (default is /etc/tdns/tdns-cli.yaml)
  -d, --debug           debug output
  -H, --headers         show headers
  -Z, --pzone string    parent zone name
  -v, --verbose         verbose output
  -z, --zone string     zone name
```

### SEE ALSO

* [tdns-cli agent truststore sig0](tdns-cli_agent_truststore_sig0.md)	 - Prefix command, only usable via sub-commands

