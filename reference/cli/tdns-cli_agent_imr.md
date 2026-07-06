## tdns-cli agent imr

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

* [tdns-cli agent](tdns-cli_agent.md)	 - TDNS Agent commands
* [tdns-cli agent imr dump-tuning](tdns-cli_agent_imr_dump-tuning.md)	 - Show effective IMR tuning values (backoff policy, family, discovery, etc.)
* [tdns-cli agent imr dump-zone-backoffs](tdns-cli_agent_imr_dump-zone-backoffs.md)	 - Show zone-scoped lame-delegation backoffs (per zone, per address)
* [tdns-cli agent imr flush](tdns-cli_agent_imr_flush.md)	 - Flush IMR cache entries at and below qname
* [tdns-cli agent imr query](tdns-cli_agent_imr_query.md)	 - Query the IMR cache (cache-only, no external queries)
* [tdns-cli agent imr reset](tdns-cli_agent_imr_reset.md)	 - Flush entire IMR cache and re-prime (preserves root NS)
* [tdns-cli agent imr show](tdns-cli_agent_imr_show.md)	 - Show IMR cache entries related to agent discovery

