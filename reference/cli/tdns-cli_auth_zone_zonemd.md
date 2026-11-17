## tdns-cli auth zone zonemd

Inspect and verify a zone's ZONEMD (RFC 8976)

### Synopsis

A zone with the publish-zonemd option carries a message digest of its own
contents at the apex, recomputed inside every publish.

"status" reports what the zone publishes without recomputing anything.
"verify" digests the zone and reports whether the published value describes it,
which is what a recipient of an AXFR will do.

### Options

```
  -h, --help   help for zonemd
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

* [tdns-cli auth zone](tdns-cli_auth_zone.md)	 - Prefix command, not usable by itself
* [tdns-cli auth zone zonemd status](tdns-cli_auth_zone_zonemd_status.md)	 - Show the zone's published ZONEMD and its configuration
* [tdns-cli auth zone zonemd verify](tdns-cli_auth_zone_zonemd_verify.md)	 - Recompute the zone's digest and compare it with what is published

