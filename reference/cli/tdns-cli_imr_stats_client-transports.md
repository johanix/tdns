## tdns-cli imr stats client-transports

Show which transports clients use to reach this resolver

### Synopsis

Show, per client address, how many queries arrived over each transport
(Do53 over UDP and TCP, DoT, DoQ, DoH) and when each was last used, since the
resolver started or the counters were last reset.

-c selects clients by address or prefix, and may be given more than once; with
none, all clients are shown. --reset clears the counters after showing them --
ALL of them, every client and the evicted totals, whatever -c selected -- so
the next run covers a new period.

The counters must be switched on in the resolver's configuration
(imrengine.client-stats.enabled), which takes effect at restart. They record
client addresses, never query names.

```
tdns-cli imr stats client-transports [flags]
```

### Options

```
  -c, --client strings   Client address or prefix; may be repeated
  -h, --help             help for client-transports
      --json             Print the report as JSON
      --reset            Clear ALL counters after showing them
      --sort string      Sort by addr, total or last (default "addr")
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

* [tdns-cli imr stats](tdns-cli_imr_stats.md)	 - Show IMR statistics

