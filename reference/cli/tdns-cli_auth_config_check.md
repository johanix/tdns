## tdns-cli auth config check

Validate the tdns-auth config and correlate it with the running daemon

### Synopsis

Validate a tdns-auth configuration file for completeness and internal
consistency, and (unless --offline) correlate it against the running daemon to
report drift between the file on disk and what the server actually loaded.

Target config resolution:
  1. an explicit path (positional arg or --serverconfig)
  2. otherwise, online, the path the daemon reports via GET /config/paths
  3. otherwise the compiled-in default (/etc/tdns/tdns-auth.yaml)

Exit status is non-zero if any check FAILs (WARNs do not fail the run).

```
tdns-cli auth config check [config-file] [flags]
```

### Options

```
  -h, --help                  help for check
      --offline               do not contact the daemon; run static checks only
      --serverconfig string   path to the tdns-auth config file to check (default: ask the daemon, else the configured/compiled-in default)
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

* [tdns-cli auth config](tdns-cli_auth_config.md)	 - Commands to reload config, reload zones, etc

