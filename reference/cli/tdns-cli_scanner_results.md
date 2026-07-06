## tdns-cli scanner results

Get results of a completed scan job

### Synopsis

Get detailed results of a completed scan job by job ID. Use --delete to delete the job after retrieving results.

```
tdns-cli scanner results [job-id] [flags]
```

### Options

```
      --delete   Delete the job after retrieving results
  -h, --help     help for results
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

