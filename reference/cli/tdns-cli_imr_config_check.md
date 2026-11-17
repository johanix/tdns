## tdns-cli imr config check

Validate the tdns-imr config and correlate it with the running daemon

### Synopsis

Validate a tdns-imr configuration file for completeness and internal
consistency, and (unless --offline) check that the daemon is reachable and its
apiserver matches the file.

tdns-imr exposes no GET /config/paths endpoint, so the target file is the
positional arg / --serverconfig, else the compiled-in default
(/etc/tdns/tdns-imr.yaml).

Exit status is non-zero if any check FAILs (WARNs do not fail the run).

```
tdns-cli imr config check [config-file] [flags]
```

### Options

```
  -h, --help                  help for check
      --offline               do not contact the daemon; run static checks only
      --serverconfig string   path to the tdns-imr config file to check (default: /etc/tdns/tdns-imr.yaml)
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

* [tdns-cli imr config](tdns-cli_imr_config.md)	 - Validate or generate a tdns-imr configuration

