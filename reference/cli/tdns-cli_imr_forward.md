## tdns-cli imr forward

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

* [tdns-cli imr](tdns-cli_imr.md)	 - Interact with tdns-imr via API
* [tdns-cli imr forward list](tdns-cli_imr_forward_list.md)	 - List the configured forward zones and their upstreams
* [tdns-cli imr forward probe](tdns-cli_imr_forward_probe.md)	 - Probe the forward upstreams now (same probe as at startup) and report per upstream
* [tdns-cli imr forward status](tdns-cli_imr_forward_status.md)	 - Show per-upstream reachability, counters and last success/error

