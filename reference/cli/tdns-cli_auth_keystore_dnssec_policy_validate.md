## tdns-cli auth keystore dnssec policy validate

Validate a YAML fragment with a dnssec.policies: block

### Synopsis

Reads a YAML file that contains the same dnssec.policies: structure as tdns-auth
config (policy names as keys, algorithm / ksk / zsk / csk / optional rollover+ttls+clamping).
Runs the same validation as runtime config load. Exits non-zero on any error.

```
tdns-cli auth keystore dnssec policy validate [flags]
```

### Options

```
  -f, --file string   YAML file path
  -h, --help          help for validate
```

### Options inherited from parent commands

```
      --config string   config file (default is /etc/tdns/tdns-cli.yaml)
  -d, --debug           debug output
  -H, --headers         show headers
  -Z, --pzone string    parent zone name
  -v, --verbose         verbose output
  -z, --zone string     zone name
```

### SEE ALSO

* [tdns-cli auth keystore dnssec policy](tdns-cli_auth_keystore_dnssec_policy.md)	 - DNSSEC policy utilities

