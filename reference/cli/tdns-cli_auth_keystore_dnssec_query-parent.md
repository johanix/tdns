## tdns-cli auth keystore dnssec query-parent

Query configured parent-agent for child DS (poll until match or timeout)

### Synopsis

Uses rollover.parent-agent from the zone's dnssec policy (addr:port), or --parent-agent.
Queries that address over TCP for the zone's DS RRset and compares to the keystore-derived
expected set (ComputeTargetDSSetForZone, §7.5). Default poll schedule uses policy confirm-* timings,
or 2s / 60s / 1h when those are unset.

--once performs a single query and exits (no backoff loop).

```
tdns-cli auth keystore dnssec query-parent [flags]
```

### Options

```
  -h, --help                  help for query-parent
      --once                  Single TCP query; do not poll
      --parent-agent string   Override policy rollover.parent-agent (host:port)
  -z, --zone string           Child zone (owner of DS RRset)
```

### Options inherited from parent commands

```
      --config string   config file (default is /etc/tdns/tdns-cli.yaml)
  -d, --debug           debug output
  -H, --headers         show headers
  -Z, --pzone string    parent zone name
  -v, --verbose         verbose output
```

### SEE ALSO

* [tdns-cli auth keystore dnssec](tdns-cli_auth_keystore_dnssec.md)	 - Prefix command, only usable via sub-commands

