## tdns-cli auth zone childsync

Parent-side child delegation sync commands

### Options

```
  -h, --help   help for childsync
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
* [tdns-cli auth zone childsync advert](tdns-cli_auth_zone_childsync_advert.md)	 - Print what the parent primary still lacks of the DSYNC advertisement, as an nsupdate block
* [tdns-cli auth zone childsync proxy-status](tdns-cli_auth_zone_childsync_proxy-status.md)	 - Report a childsync-proxy's advertisement and push state
* [tdns-cli auth zone childsync publish](tdns-cli_auth_zone_childsync_publish.md)	 - Publish the DSYNC RRset into the zone
* [tdns-cli auth zone childsync reconcile](tdns-cli_auth_zone_childsync_reconcile.md)	 - Reconcile the advertisement and the known children against the served zone now
* [tdns-cli auth zone childsync unpublish](tdns-cli_auth_zone_childsync_unpublish.md)	 - Unpublish the DSYNC RRset from the zone

