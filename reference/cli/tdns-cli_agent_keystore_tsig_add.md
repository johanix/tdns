## tdns-cli agent keystore tsig add

Add a TSIG key with a known secret

```
tdns-cli agent keystore tsig add [flags]
```

### Options

```
      --algorithm string     HMAC algorithm (default "hmac-sha256")
      --force                Overwrite on secret/algorithm conflict
  -h, --help                 help for add
      --name string          TSIG key name
      --owner string         Owner label (default api) (default "api")
      --secret string        Inline TSIG secret (base64). WARNING: visible in shell history / process list; prefer --secret-file
      --secret-file string   File containing the base64 TSIG secret; preferred over --secret
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

