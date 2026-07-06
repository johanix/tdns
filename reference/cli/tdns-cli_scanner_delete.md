## tdns-cli scanner delete

Delete scan job(s)

### Synopsis

Delete a specific scan job by job ID, or all jobs if --all is used

```
tdns-cli scanner delete [job-id] [flags]
```

### Options

```
      --all    Delete all jobs
  -h, --help   help for delete
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

* [tdns-cli scanner](tdns-cli_scanner.md)	 - Interact with tdns-scanner via API

