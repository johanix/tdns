## tdns-cli scanner daemon restart

Stop and then start the management daemon

```
tdns-cli scanner daemon restart [flags]
```

### Options

```
      --clear string   Truncate the specified log file before starting
  -h, --help           help for restart
      --update         Update the server binary from /tmp/{binary} to /usr/local/libexec/ before starting
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

