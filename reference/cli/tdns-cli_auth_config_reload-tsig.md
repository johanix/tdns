## tdns-cli auth config reload-tsig

Reconcile keys.tsig into the TSIG keystore (config reload-tsig)

### Synopsis

Re-read keys.tsig from the config file and reconcile into the DB-backed
TSIG keystore. Secret conflicts are withheld by default; use --force to
overwrite all conflicts, or --interactive to prompt per conflict.

```
tdns-cli auth config reload-tsig [flags]
```

### Options

```
      --force         overwrite all secret/algorithm conflicts with keys.tsig
  -h, --help          help for reload-tsig
      --interactive   prompt per conflict before overwriting
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

* [tdns-cli auth config](tdns-cli_auth_config.md)	 - Commands to reload config, reload zones, etc

