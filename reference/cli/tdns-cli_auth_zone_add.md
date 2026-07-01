## tdns-cli auth zone add

Add a dynamic secondary zone at runtime (persists across restart)

```
tdns-cli auth zone add [flags]
```

### Options

```
  -h, --help                      help for add
      --options strings           Zone options (comma-separated)
      --primaries strings         Primary (upstream) addresses [host:port], comma-separated
      --primary-key string        Primary TSIG key name applied to all primaries (NOKEY for none) (default "NOKEY")
      --tsig-algo string          Inline TSIG algorithm (default hmac-sha256)
      --tsig-name string          Inline TSIG key name; created in keystore if absent and applied to keyless primaries
      --tsig-secret string        Inline TSIG secret (base64). WARNING: visible in shell history / process list; prefer --tsig-secret-file
      --tsig-secret-file string   File containing the inline TSIG secret (base64); preferred over --tsig-secret
  -z, --zone string               Zone to add
```

### Options inherited from parent commands

```
      --config string   config file (default is /etc/tdns/tdns-cli.yaml)
  -d, --debug           debug output
  -F, --force           force operation
  -H, --headers         show headers
  -Z, --pzone string    parent zone name
  -v, --verbose         verbose output
```

### SEE ALSO

* [tdns-cli auth zone](tdns-cli_auth_zone.md)	 - Prefix command, not usable by itself

