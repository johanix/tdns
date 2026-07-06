## tdns-cli auth imr

IMR (Internal Recursive Resolver) cache commands

### Options

```
  -h, --help   help for imr
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

* [tdns-cli auth](tdns-cli_auth.md)	 - Interact with tdns-auth (authoritative) via API
* [tdns-cli auth imr dump-tuning](tdns-cli_auth_imr_dump-tuning.md)	 - Show effective IMR tuning values (backoff policy, family, discovery, etc.)
* [tdns-cli auth imr dump-zone-backoffs](tdns-cli_auth_imr_dump-zone-backoffs.md)	 - Show zone-scoped lame-delegation backoffs (per zone, per address)
* [tdns-cli auth imr flush](tdns-cli_auth_imr_flush.md)	 - Flush IMR cache entries at and below qname
* [tdns-cli auth imr query](tdns-cli_auth_imr_query.md)	 - Query the IMR cache (cache-only, no external queries)
* [tdns-cli auth imr reset](tdns-cli_auth_imr_reset.md)	 - Flush entire IMR cache and re-prime (preserves root NS)
* [tdns-cli auth imr show](tdns-cli_auth_imr_show.md)	 - Show IMR cache entries related to agent discovery

