## tdns-cli auth zone journal

Inspect and manage a zone's delta journal

### Synopsis

The delta journal holds zone changes that have not yet reached the zone file.

It is written when an update is published and replayed over the file on load, so
a restart loses nothing. "zone sync" folds it into the file and empties it.

On an inline-signing secondary it is instead applied to every full transfer,
where it keeps the zone's own CDS, CDNSKEY and CSYNC. "zone sync" leaves it
alone there.

### Options

```
  -h, --help   help for journal
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
* [tdns-cli auth zone journal list](tdns-cli_auth_zone_journal_list.md)	 - List the journal's deltas and the records in them
* [tdns-cli auth zone journal purge](tdns-cli_auth_zone_journal_purge.md)	 - Discard the whole journal, saving its content first
* [tdns-cli auth zone journal status](tdns-cli_auth_zone_journal_status.md)	 - Summarise the journal, and whether it will replay on restart
* [tdns-cli auth zone journal truncate](tdns-cli_auth_zone_journal_truncate.md)	 - Drop the journal's tail, keeping the chain through --serial

