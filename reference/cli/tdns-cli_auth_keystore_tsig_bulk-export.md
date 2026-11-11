## tdns-cli auth keystore tsig bulk-export

Export TSIG keys from the keystore to a directory

### Synopsis

Export TSIG keys to --dest as BIND-convention key files plus a manifest
that carries what those files cannot (key state, rollover timestamps).

Selection is additive: --key takes one exact name, --keys takes a name and
everything below it, and both may be repeated. Subtree matching is on label
boundaries, so --keys pq.dnslab does not match notpq.dnslab. With no selector at
all, the whole class is exported.

Re-exporting into a directory MERGES: entries for keys not covered by this
run are left in place, so several exports can populate one directory.

```
tdns-cli auth keystore tsig bulk-export [flags]
```

### Options

```
      --dest string        Directory to write keys and manifest to
  -h, --help               help for bulk-export
      --key stringArray    TSIG key name to include (repeatable)
      --keys stringArray   Include this name and everything below it (repeatable)
```

### Options inherited from parent commands

```
      --config string   config file (default is /etc/tdns/tdns-cli.yaml)
  -d, --debug           debug output
  -H, --headers         show headers
  -Z, --pzone string    parent zone name
  -v, --verbose         verbose output
      --version         print version and supported algorithms, then exit
  -z, --zone string     zone name
```

### SEE ALSO

* [tdns-cli auth keystore tsig](tdns-cli_auth_keystore_tsig.md)	 - Manage global TSIG keys in the keystore

