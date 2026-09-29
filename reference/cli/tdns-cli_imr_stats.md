## tdns-cli imr stats

Show IMR statistics

### Synopsis

Show DNS query and large-KSK telemetry statistics.

```
tdns-cli imr stats [flags]
```

### Options

```
  -h, --help   help for stats
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
* [tdns-cli imr stats auth-servers](tdns-cli_imr_stats_auth-servers.md)	 - Show which transports this resolver uses to reach each auth server
* [tdns-cli imr stats auth-transports](tdns-cli_imr_stats_auth-transports.md)	 - Show per-transport query counters for auth servers in a zone
* [tdns-cli imr stats client-stats](tdns-cli_imr_stats_client-stats.md)	 - Show which transports clients use to reach this resolver
* [tdns-cli imr stats large-ksk](tdns-cli_imr_stats_large-ksk.md)	 - Show large-KSK IMR DS and DNSKEY lookup statistics
* [tdns-cli imr stats transport-stats](tdns-cli_imr_stats_transport-stats.md)	 - Show per-server transport-usage stats for a running tdns-imr

