## tdns-cli auth zone parentsync

Child-side parent delegation sync commands

### Options

```
  -h, --help   help for parentsync
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
* [tdns-cli auth zone parentsync bootstrap](tdns-cli_auth_zone_parentsync_bootstrap.md)	 - Bootstrap the SIG(0) key with the parent
* [tdns-cli auth zone parentsync delta](tdns-cli_auth_zone_parentsync_delta.md)	 - Compute delta between parent delegation data and child zone data
* [tdns-cli auth zone parentsync inquire](tdns-cli_auth_zone_parentsync_inquire.md)	 - Inquire the parent about the current SIG(0) key state
* [tdns-cli auth zone parentsync roll-key](tdns-cli_auth_zone_parentsync_roll-key.md)	 - Roll the SIG(0) key with the parent
* [tdns-cli auth zone parentsync status](tdns-cli_auth_zone_parentsync_status.md)	 - Show whether a delegation change can reach the parent, and by which scheme
* [tdns-cli auth zone parentsync sync](tdns-cli_auth_zone_parentsync_sync.md)	 - Sync delegation data in parent zone via DDNS UPDATE

