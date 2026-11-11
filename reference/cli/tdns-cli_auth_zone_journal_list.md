## tdns-cli auth zone journal list

List the journal's deltas and the records in them

```
tdns-cli auth zone journal list [flags]
```

### Options

```
  -h, --help           help for list
      --instructions   Print as replayable ADD/DEL instructions instead of a summary
      --out string     Write the instruction form to this file instead of stdout
  -z, --zone string    Zone name
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

