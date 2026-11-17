## tdns-cli agent keystore dnssec check

Check the key invariants (pub, sign, ds against the state and the served zone)

### Synopsis

Check the invariants of the keystore's key rows and of the served zone:
sign implies pub and a private key, ds only on SEP keys, one signing key per
role and algorithm, the served DNSKEY RRset equals the pub rows, the RRSIGs
are by the sign keys, the served CDS follows the ds rows, no row lacks its
flags, and the flags match the state. One zone with --zone, or every zone in
the keystore. Exits non-zero when a violation is found.

```
tdns-cli agent keystore dnssec check [flags]
```

### Options

```
  -h, --help          help for check
  -z, --zone string   Zone to check (default: every zone in the keystore)
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

* [tdns-cli agent keystore dnssec](tdns-cli_agent_keystore_dnssec.md)	 - Prefix command, only usable via sub-commands

