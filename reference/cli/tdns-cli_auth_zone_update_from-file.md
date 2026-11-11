## tdns-cli auth zone update from-file

Apply an ADD/DEL instruction file to a zone

### Synopsis

Apply a list of update instructions from a file.

  ADD foo.alpha.dnslab. 3600 IN A 1.2.3.4
  DEL bar.alpha.dnslab. IN A 5.6.7.8

This is the format "zone journal purge" and "zone journal list --instructions"
produce, so a file the server wrote can be edited down to the changes you want
and fed straight back:

  tdns-cli ... zone update from-file --file /var/dns/zones/alpha.2026081704.purged \
      --zone alpha.dnslab. --via api

Comments (";" or "#") and blank lines are ignored. Everything that survives is
applied as ONE update — there is no half-applied outcome.

```
tdns-cli auth zone update from-file [flags]
```

### Options

```
      --file string     Instruction file to apply (required)
      --force           Apply a nameserver removal even if the parent does not confirm it (--via api only)
  -h, --help            help for from-file
  -K, --key string      SIG(0) keyfile to use for signing (.private/.key basename)
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

