## tdns-cli imr config status

Report the running tdns-imr daemon's status, including priming and forward upstreams

### Synopsis

Query the running tdns-imr daemon's /config status endpoint and report:
overall health (active server errors), whether the resolver cache is primed
and how, and the configured stub and forward zones with per-upstream
reachability (fed by the startup probe and live queries), plus the
process's descriptor and goroutine counts (tdns#443).

```
tdns-cli imr config status [flags]
```

### Options

```
  -h, --help   help for status
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

