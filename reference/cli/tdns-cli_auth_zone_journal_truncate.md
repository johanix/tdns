## tdns-cli auth zone journal truncate

Drop the journal's tail, keeping the chain through --serial

### Synopsis

Keep the journal up to and including the delta that ends at --serial, drop the rest.

A journal is a chain: each delta continues where the previous one ended, and a
chain with a gap cannot be replayed at all. So only a suffix can be removed —
there is deliberately no way to delete one record from the middle. To undo a
single record, append a correction with an ordinary "zone update" instead.

```
tdns-cli auth zone journal truncate [flags]
```

### Options

```
  -h, --help            help for truncate
      --serial uint32   Keep the chain through the delta ending at this serial (required)
  -z, --zone string     Zone name
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
```

### SEE ALSO

* [tdns-cli auth zone journal](tdns-cli_auth_zone_journal.md)	 - Inspect and manage a zone's delta journal

