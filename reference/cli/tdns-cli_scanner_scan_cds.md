## tdns-cli scanner scan cds

Send CDS scan request with ScanTuple data to tdns-scanner

### Synopsis

Send CDS scan request for one or more zones. Zones can be specified as arguments or via --zone flag.

```
tdns-cli scanner scan cds [zone...] [flags]
```

### Options

```
  -h, --help   help for cds
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

* [tdns-cli scanner scan](tdns-cli_scanner_scan.md)	 - Send scan requests to tdns-scanner

