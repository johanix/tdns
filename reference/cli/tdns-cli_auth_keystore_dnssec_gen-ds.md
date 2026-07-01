## tdns-cli auth keystore dnssec gen-ds

Generate DS records for a zone's KSK(s) from the keystore

### Synopsis

Generate DS (Delegation Signer) records for a zone's KSK (Key Signing Key) DNSKEY records stored in the keystore. The command queries the keystore for DNSKEY records for the specified zone, filters for KSKs (keys with the SEP bit set), and generates DS records using SHA-256 and SHA-384 digest algorithms. If --keyid is not specified, DS records are generated for all KSKs in the zone.

```
tdns-cli auth keystore dnssec gen-ds [flags]
```

### Options

```
  -h, --help          help for gen-ds
      --keyid int     Key ID of specific KSK to generate DS for (optional, if not specified, generates for all KSKs)
  -z, --zone string   Zone to generate DS records for
```

### Options inherited from parent commands

```
      --config string   config file (default is /etc/tdns/tdns-cli.yaml)
  -d, --debug           debug output
  -H, --headers         show headers
  -Z, --pzone string    parent zone name
  -v, --verbose         verbose output
```

### SEE ALSO

* [tdns-cli auth keystore dnssec](tdns-cli_auth_keystore_dnssec.md)	 - Prefix command, only usable via sub-commands

