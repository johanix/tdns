## tdns-cli auth keystore sig0 bulk-export

Export SIG(0) keys from the keystore to a directory

### Synopsis

Export SIG(0) keys to --dest as BIND-convention key files plus a manifest
that carries what those files cannot (key state, rollover timestamps).

Selection is additive: --zone takes one exact name, --zones takes a name and
everything below it, and both may be repeated. Subtree matching is on label
boundaries, so --zones pq.dnslab does not match notpq.dnslab. With no selector at
all, the whole class is exported.

Re-exporting into a directory MERGES: entries for keys not covered by this
run are left in place, so several exports can populate one directory.

```
tdns-cli auth keystore sig0 bulk-export [flags]
```

### Options

```
      --dest string         Directory to write keys and manifest to
      --format string       Private key format to write: pem (PKCS#8, as stored) or bind (Private-key-format v1.3) (default "pem")
  -h, --help                help for bulk-export
  -z, --zone stringArray    Zone to include (repeatable)
      --zones stringArray   Include this zone and everything below it (repeatable)
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

* [tdns-cli auth keystore sig0](tdns-cli_auth_keystore_sig0.md)	 - Prefix command, only usable via sub-commands

