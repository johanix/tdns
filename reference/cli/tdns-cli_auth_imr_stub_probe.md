## tdns-cli auth imr stub probe

Probe the stub servers now and report per (server, address, transport)

### Synopsis

Send an RD=0 SOA query for the stub zone to every (server, address,
advertised transport) tuple and report rcode, AA bit and RTT. Strictly
report-only: nothing is recorded into the resolver's server state, so a
probe can never put a stub server into backoff.

```
tdns-cli auth imr stub probe [zone] [flags]
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

* [tdns-cli auth imr stub](tdns-cli_auth_imr_stub.md)	 - Inspect and probe the IMR's stub zones

