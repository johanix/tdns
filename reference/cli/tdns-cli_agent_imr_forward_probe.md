## tdns-cli agent imr forward probe

Probe the forward upstreams now (same probe as at startup) and report per upstream

### Synopsis

Send a recursive SOA query for the forward zone to every one of its
upstreams (or one zone's) and report the outcome per upstream. The probe updates
the live reachability state, so a recovered upstream clears its DEGRADED
error and a newly dead one raises it.

```
tdns-cli agent imr forward probe [zone] [flags]
```

### Options

```
  -h, --help   help for probe
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

* [tdns-cli agent imr forward](tdns-cli_agent_imr_forward.md)	 - Inspect and probe the IMR's forward zones

