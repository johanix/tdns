## tdns-cli auth zone sync

Spool the zone out to disk (alias for write, no freeze/thaw)

### Synopsis

Write the zone's current content to its file, without freezing it.

Identical to "zone write". Both fold any persisted change deltas into the file
and drop them, so the file becomes the whole truth again.

Use "zone freeze" instead when you want the file to be authoritative and
updates refused until you thaw.

```
tdns-cli auth zone sync [flags]
```

### Options

```
  -h, --help   help for sync
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

