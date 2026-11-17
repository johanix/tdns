## tdns-cli auth zone update delname

Delete every RRset at an owner name

### Synopsis

Delete all records at a name. At the zone apex, SOA and NS are retained --
deleting those would dismantle the zone rather than a name within it.

  tdns-cli ... zone update delname --zone alpha.dnslab. --via api \
      --name foo.alpha.dnslab.

```
tdns-cli auth zone update delname [flags]
```

### Options

```
      --force           Apply a nameserver removal even if the parent does not confirm it (--via api only)
  -h, --help            help for delname
  -K, --key string      SIG(0) keyfile to use for signing (.private/.key basename)
      --name string     Owner name
  -S, --server string   Server to send the update to (addr:port)
      --signer string   Name of signer (key used to sign the update; defaults to --zone)
      --via string      Transport: "api" or "ddns" (required)
  -z, --zone string     Zone to update
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

* [tdns-cli auth zone update](tdns-cli_auth_zone_update.md)	 - Create and ultimately send a DNS UPDATE msg for zone auth data

