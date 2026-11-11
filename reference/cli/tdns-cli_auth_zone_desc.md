## tdns-cli auth zone desc

Describe a single zone in full, including DNSSEC applied-policy state and policy detail

### Synopsis

Print a detailed, multi-line record for one zone: everything "zone list -v"
shows (type, store, options, primaries, notify, error/warning state, effective
DNSSEC policy and override info) plus two DNSSEC sections not otherwise visible
from the CLI:

  1. the last-applied policy record recorded in the keystore (applied policy
     name, source config|command, and when it was applied); and
  2. the currently-bound policy's detail — mode, KSK/ZSK (or CSK) algorithms,
     key lifetimes and RRSIG validity.

An unsigned zone or an unresolvable policy degrades gracefully rather than
failing. Does not change anything; read-only.

```
tdns-cli auth zone desc [flags]
```

### Options

```
  -h, --help          help for desc
  -z, --zone string   Zone to describe
```

### Options inherited from parent commands

```
      --config string   config file (default is /etc/tdns/tdns-cli.yaml)
  -d, --debug           debug output
  -F, --force           force operation
  -H, --headers         show headers
  -Z, --pzone string    parent zone name
  -v, --verbose         verbose output
      --version         print version and supported algorithms, then exit
```

### SEE ALSO

* [tdns-cli auth zone](tdns-cli_auth_zone.md)	 - Prefix command, not usable by itself

