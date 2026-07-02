## tdns-cli agent keystore tsig import

Import TSIG keys from a BIND or NSD config snippet

### Synopsis

Scan a config file for TSIG key blocks (not a full config parser).
Default: import new keys and skip conflicts. --force overwrites all conflicts;
--interactive prompts per conflict (two-phase round-trip).

```
tdns-cli agent keystore tsig import [flags]
```

### Options

```
  -f, --file string     File containing TSIG key declarations
      --force           Overwrite all secret/algorithm conflicts
      --format string   Key syntax: bind or nsd (default "bind")
  -h, --help            help for import
      --interactive     Prompt per conflict before overwriting
      --owner string    Owner label for imported keys (default "api")
  -v, --verbose         List per-key disposition
```

### Options inherited from parent commands

```
      --config string   config file (default is /etc/tdns/tdns-cli.yaml)
  -d, --debug           debug output
  -H, --headers         show headers
  -Z, --pzone string    parent zone name
  -z, --zone string     zone name
```

### SEE ALSO

* [tdns-cli agent keystore tsig](tdns-cli_agent_keystore_tsig.md)	 - Manage global TSIG keys in the keystore

