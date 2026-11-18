## tdns-cli auth zone add

Add a dynamic zone at runtime: secondary, or template-constrained primary (persists across restart)

```
tdns-cli auth zone add [flags]
```

### Options

```
  -h, --help                      help for add
      --options strings           Zone options (comma-separated; secondary zones — primaries take options from the template)
      --primaries strings         Primary (upstream) addresses [host:port], comma-separated (secondary zones)
      --primary-key string        Primary TSIG key name applied to all primaries (NOKEY for none) (default "NOKEY")
      --template string           Config template (must carry dynamiczones: true): a primary's whole config, a secondary's outbound settings (downstreams, notify). Default: the server's default-template for the zone type
      --transfer-src strings      Source address(es) to bind for this zone's outbound transfers (IP only, one per family)
      --tsig-algo string          Inline TSIG algorithm (default hmac-sha256)
      --tsig-name string          Inline TSIG key name; created in keystore if absent and applied to keyless primaries (secondary) or keyless downstreams (primary)
      --tsig-secret string        Inline TSIG secret (base64). WARNING: visible in shell history / process list; prefer --tsig-secret-file
      --tsig-secret-file string   File containing the inline TSIG secret (base64); preferred over --tsig-secret
      --type string               Zone type: secondary (default) or primary (needs a template: --template, or the server's default-template for primaries) (default "secondary")
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
      --version         print version and supported algorithms, then exit
```

### SEE ALSO

* [tdns-cli auth zone](tdns-cli_auth_zone.md)	 - Prefix command, not usable by itself

