## tdns-cli auth keystore sig0 bulk-import

Import SIG(0) keys from a directory into the keystore

### Synopsis

Import every SIG(0) key described by --src/manifest.yaml.

A key that is not in the keystore is inserted. A key that is already there
with identical content is left alone. A key that is already there with
DIFFERENT content is reported and SKIPPED: the running keystore outranks a
file that may be arbitrarily stale, and silently overwriting it is how a stale
export un-rolls a rolled key.

--force flips that last case to overwrite, which is what you want when
recovering a keystore you know to be wrong.

```
tdns-cli auth keystore sig0 bulk-import [flags]
```

### Options

```
      --force        Overwrite keystore entries that differ (default: report and skip them)
  -h, --help         help for bulk-import
      --src string   Directory to read keys and manifest from
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

* [tdns-cli auth keystore sig0](tdns-cli_auth_keystore_sig0.md)	 - Prefix command, only usable via sub-commands

