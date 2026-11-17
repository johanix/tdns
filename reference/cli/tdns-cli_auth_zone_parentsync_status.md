## tdns-cli auth zone parentsync status

Show whether a delegation change can reach the parent, and by which scheme

### Synopsis

For a zone with parentsync (a zone syncing its own delegation) or
parentsync-proxy (a tdns-agent secondary syncing on behalf of its primary),
report whether a delegation change can reach the parent right now, by which
scheme, and if not, why not:

  - the parent, and whether its DSYNC RRset validated;
  - every scheme in parentsync.schemes, in preference order: usable (with
    its target) or skipped (with the reason);
  - detail for the configured schemes: for UPDATE on a parentsync-proxy zone
    the KEY-bootstrap state and the records to publish at the primary (what
    "zone proxy-key" used to print), for UPDATE on a parentsync zone its
    SIG(0) key and what the parent holds for it, for NOTIFY whether the zone
    publishes CDS and CSYNC, for API whether a credential is configured;
  - whether the parent's delegation is in sync with the zone, as
    "parentsync delta" computes it, and the zone's delegation-sync-warning.

Nothing on the zone is changed, with one exception: on a parentsync-proxy zone
waiting for its KEY to be published, the agent's SIG(0) keypair is generated
if it has none -- as the agent's next sync would -- so that there are records
to print.

```
tdns-cli auth zone parentsync status [flags]
```

### Options

```
  -h, --help   help for status
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

* [tdns-cli auth zone parentsync](tdns-cli_auth_zone_parentsync.md)	 - Child-side parent delegation sync commands

