## tdns-cli auth zone zonemd verify

Recompute the zone's digest and compare it with what is published

### Synopsis

Digest the zone as it is currently served and compare the result with the
apex ZONEMD, the way a recipient would.

Costs one full pass over the zone, which for a large zone is not free; that is
why it is a separate verb from "status".

```
tdns-cli auth zone zonemd verify [flags]
```

### Options

```
  -h, --help            help for verify
      --ignore-serial   digest against the serial each ZONEMD names rather than the SOA's (a diagnostic for a zone whose serial moved after it was digested, NOT a laxer check)
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
  -z, --zone string     zone name
```

### SEE ALSO

* [tdns-cli auth zone zonemd](tdns-cli_auth_zone_zonemd.md)	 - Inspect and verify a zone's ZONEMD (RFC 8976)

