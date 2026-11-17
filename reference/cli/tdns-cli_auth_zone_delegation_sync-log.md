## tdns-cli auth zone delegation sync-log

Show what this parent received from its children, and what it did with it

### Synopsis

Show the delegation-sync log: one line per UPDATE from a child, per scan a
NOTIFY started, per scan a poll started that found something or could not
process the child, per NOTIFY refused before any scan, and per DSYNC API write.
Newest first.

"applied" means the parent's delegation data changed. A change a scan decided
on is "queued" or "apply failed" until it has landed.

With -z, only that parent; with --child, only that child. The log is kept in
memory: it starts empty when the server starts, and holds the most recent
childsync.sync-log events (default 10000).

```
tdns-cli auth zone delegation sync-log [flags]
```

### Options

```
      --child string   Only this child zone
  -h, --help           help for sync-log
      --json           Print the report as JSON
      --limit int      At most this many events; 0 for all (default 50)
      --since string   Only events since: a duration back from now (10m) or an RFC 3339 time
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

* [tdns-cli auth zone delegation](tdns-cli_auth_zone_delegation.md)	 - Inspect the delegation data a parent zone holds for its children

