## tdns-cli agent keystore tsig generate

Generate a new TSIG key and add it to the keystore

```
tdns-cli agent keystore tsig generate [flags]
```

### Options

```
      --algorithm string   HMAC algorithm (default "hmac-sha256")
  -h, --help               help for generate
      --name string        TSIG key name
      --owner string       Owner label (default api) (default "api")
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

* [tdns-cli agent keystore tsig](tdns-cli_agent_keystore_tsig.md)	 - Manage global TSIG keys in the keystore

