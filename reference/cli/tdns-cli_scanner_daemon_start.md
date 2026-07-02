## tdns-cli scanner daemon start

Start the axfr-statusd daemon

### Synopsis

Start the axfr-statusd daemon. If it was already running, then this is a no-op.

```
tdns-cli scanner daemon start [flags]
```

### Options

```
  -h, --help          help for start
  -W, --maxwait int   Max seconds to wait until declaring start to have failed (default 5)
      --slurp         Slurp stdout/stderr for errors (debug tool only)
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

* [tdns-cli scanner daemon](tdns-cli_scanner_daemon.md)	 - Only useful via sub-commands

