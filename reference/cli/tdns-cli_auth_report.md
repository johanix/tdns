## tdns-cli auth report

Send a report and (optionally) discover DSYNC via the internal resolver (imr)

```
tdns-cli auth report <qname> [flags]
```

### Options

```
  -D, --details string   Report details
      --ede int          Manual override of EDE code (513-523 locally defined)
  -h, --help             help for report
      --port int         Manual override of DSYNC port
  -S, --sender string    Report sender
      --target string    Manual override of DSYNC target
  -T, --tsig             TSIG sign the report (default true)
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

* [tdns-cli auth](tdns-cli_auth.md)	 - Interact with tdns-auth (authoritative) via API

