## tdns-cli auth zone update addrr

Add one or more RRs to a zone

### Synopsis

Add resource records to a primary zone.

  tdns-cli ... zone update addrr --zone alpha.dnslab. --via api \
      --rr "foo.alpha.dnslab. 3600 IN A 1.2.3.4"

```
tdns-cli auth zone update addrr [flags]
```

### Options

```
      --force            Apply a nameserver removal even if the parent does not confirm it (--via api only)
  -h, --help             help for addrr
  -K, --key string       SIG(0) keyfile to use for signing (.private/.key basename)
      --rr stringArray   Resource record in presentation format (repeatable)
  -S, --server string    Server to send the update to (addr:port)
      --signer string    Name of signer (key used to sign the update; defaults to --zone)
      --via string       Transport: "api" or "ddns" (required)
  -z, --zone string      Zone to update
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

