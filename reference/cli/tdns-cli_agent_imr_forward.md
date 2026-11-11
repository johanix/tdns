## tdns-cli agent imr forward

Inspect and probe the IMR's forward zones

### Options

```
  -h, --help   help for forward
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

* [tdns-cli agent imr](tdns-cli_agent_imr.md)	 - IMR (Internal Recursive Resolver) cache commands
* [tdns-cli agent imr forward list](tdns-cli_agent_imr_forward_list.md)	 - List the configured forward zones and their upstreams
* [tdns-cli agent imr forward probe](tdns-cli_agent_imr_forward_probe.md)	 - Probe the forward upstreams now (same probe as at startup) and report per upstream
* [tdns-cli agent imr forward status](tdns-cli_agent_imr_forward_status.md)	 - Show per-upstream reachability, counters and last success/error

