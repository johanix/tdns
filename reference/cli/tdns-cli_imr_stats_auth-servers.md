## tdns-cli imr stats auth-servers

Show which transports this resolver uses to reach each auth server

### Synopsis

Show, per authoritative server, how many of the resolver's queries were
answered over each transport (Do53 over UDP and TCP, DoT, DoQ, DoH), how many
attempts failed (FAIL), how many Do53/UDP answers were truncated and retried
over TCP (TC), and when the server last answered -- next to the transport
signal the server gave (OOTS), so that the two can be compared. "none" means
the server gave no signal.

Selection gives each encrypted transport its signalled weight as a percentage
of the queries, and Do53 the rest. --pct shows each transport's share of the
server's answers instead of a count, which compares directly with the signal.
A client that asks for privacy moves queries off Do53 whatever the signal says.

Each server is one row, however many zones it serves (ZONES); the per-zone
listing of the same counters is "auth-transports". A stub zone's server is
counted apart from the same name found by resolution, and is marked (stub).

-s selects servers by name, and may be given more than once: a name selects
that server and every server below it. With none, all servers are shown.
--reset clears the counters after showing them -- ALL of them, every server,
whatever -s selected, including those auth-transports shows -- so the next run
covers a new period.

```
tdns-cli imr stats auth-servers [flags]
```

### Options

```
  -h, --help             help for auth-servers
      --json             Print the report as JSON
      --pct              Show each transport's share of the server's answers instead of counts
      --reset            Clear ALL auth-server counters after showing them
  -s, --server strings   Server name, selecting it and every server below it; may be repeated
      --sort string      Sort by name, total or last (default "name")
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

