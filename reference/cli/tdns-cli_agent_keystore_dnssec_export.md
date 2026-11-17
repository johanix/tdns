## tdns-cli agent keystore dnssec export

Export a DNSSEC key pair from the keystore as BIND-style .private/.key files

### Synopsis

Write the DNSSEC key pair for (zone, keyid) to two files in BIND filename
convention: K<zone>+<alg-num>+<keyid>.private and .key (zone-file DNSKEY RR).
The private half is written as PKCS#8 PEM, or as bind's Private-key-format
v1.3 with --format bind. The resulting pair is directly consumable by
'keystore dnssec import'.

```
tdns-cli agent keystore dnssec export [flags]
```

### Options

```
      --format string   Private key format to write: pem (PKCS#8, as stored) or bind (Private-key-format v1.3) (default "pem")
  -h, --help            help for export
      --keyid int       Key ID of key to export
  -o, --outdir string   Directory to write .private and .key files to (default ".")
  -z, --zone string     Zone the key belongs to
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

