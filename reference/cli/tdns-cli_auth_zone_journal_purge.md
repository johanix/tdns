## tdns-cli auth zone journal purge

Discard the whole journal, saving its content first

### Synopsis

Discard every delta, after writing what they hold to {zonefile}.{serial}.purged
as ADD/DEL instructions. Nothing is lost silently: replay what you want back with

  tdns-cli ... zone update from-file --file {zonefile}.{serial}.purged --zone <zone> --via api

A journal that would replay cleanly holds changes that exist nowhere else, so
purging one needs --force. Prefer "zone sync", which folds the same changes into
the zone file and loses nothing. A journal that would NOT replay needs no flag:
its changes are already absent from what the zone serves.

On an inline-signing secondary, purging needs --force as well: it takes the
zone's own CDS, CDNSKEY and CSYNC out at the next full transfer.

```
tdns-cli auth zone journal purge [flags]
```

### Options

```
      --force         Discard a journal that would otherwise replay cleanly
  -h, --help          help for purge
      --out string    Write the instruction form to this file instead of stdout
  -z, --zone string   Zone name
```

### Options inherited from parent commands

```
      --config string   config file (default is /etc/tdns/tdns-cli.yaml)
  -d, --debug           debug output
  -H, --headers         show headers
  -Z, --pzone string    parent zone name
  -v, --verbose         verbose output
      --version         print version and supported algorithms, then exit
```

### SEE ALSO

* [tdns-cli auth zone journal](tdns-cli_auth_zone_journal.md)	 - Inspect and manage a zone's delta journal

