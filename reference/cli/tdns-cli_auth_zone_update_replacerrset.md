## tdns-cli auth zone update replacerrset

Atomically replace an RRset with the supplied RRs

### Synopsis

Replace an entire RRset in one transaction. The RRset to replace is inferred
from the owner and type of the supplied records, so they must all describe the
same one; mixed owners or types are refused rather than guessed at.

This is a single atomic operation, not a delete followed by an add: the empty
intermediate RRset is never published and no secondary can observe it.

  tdns-cli ... zone update replacerrset --zone alpha.dnslab. --via api \
      --rr "foo.alpha.dnslab. IN A 1.2.3.4" \
      --rr "foo.alpha.dnslab. IN A 2.3.4.5"

To remove an RRset entirely, use delrrset -- replacerrset with no records is an
error, not a silent delete.

```
tdns-cli auth zone update replacerrset [flags]
```

### Options

```
      --force            Apply a nameserver removal even if the parent does not confirm it (--via api only)
  -h, --help             help for replacerrset
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

