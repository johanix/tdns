## tdns-cli imr stats auth-transports

Show which transports this resolver uses to reach each auth server

### Synopsis

Show, per authoritative server, how many of the resolver's queries were
answered over each transport (Do53 over UDP and TCP, DoT, DoQ, DoH), how many
attempts failed (FAIL), how many Do53/UDP answers were truncated and retried
over TCP (TC), and when the server last answered -- next to the transport
signal the server gave (OOTS), so that the two can be compared.

OOTS is the signal as the server gave it: only the transports it named, with
their weights. "none" means it gave none. "alpn:" is an SVCB with an ALPN list
and no weights (each counts as 100), and "set:" an operator's override (imr set
server transport). A stub's row shows its configured signal. A weight of 1 is
marked (ignored): selection uses only weights above 1. Nor is the do53 weight
a share: Do53 gets what the encrypted weights leave of 100.

--pct shows each transport's share of the row's answers instead of a count,
and adds EXPECTED: the shares selection gives a query without PRIVACY (with
--privacy, at the row's level). Without PRIVACY, each encrypted transport gets
its weight as a percentage and Do53 the rest; with PRIVACY (opportunistic or
strict) only the encrypted transports are drawn, in proportion to their
weights. A server's shares still differ from EXPECTED when:
  - its zone has several nameservers. Each server's pick for a query competes
    with the others' on round-trip time, so a pick of a slower transport tends
    to lose the query to another server: the shares lean to the faster ones;
  - few names are asked for. A name always gets the same pick at a server;
  - queries fail and fall back, and when answers come from the cache (they
    send no query).

--privacy shows one row per class of query under each server: "none", "opp."
and "strict" for a client's PRIVACY level, and "internal" for the resolver's
own lookups (DNSKEY and DS for validation, nameserver addresses, transport
signals, priming, and lookups by the scanner, the DSYNC code and the in-process
"imr query"). "tdns-cli imr query", sent over the API, counts as a client's
query without PRIVACY: "none". FAIL and TC are the server's, on its first row.

Each server is one row, however many zones it serves (ZONES); [zone] shows only
the servers of that zone. The per-zone listing of the same counters, attempted
and failed per transport included, is "transport-stats". A stub zone's server
is counted apart from the same name found by resolution, and is marked (stub).

-s selects servers by name, and may be given more than once: a name selects
that server and every server below it. With none, all servers are shown.
--reset clears the counters after showing them -- ALL of them, every server,
whatever [zone] and -s selected, including those transport-stats shows -- so
the next run covers a new period.

```
tdns-cli imr stats auth-transports [zone] [flags]
```

### Options

```
  -h, --help             help for auth-transports
      --json             Print the report as JSON
      --pct              Show each transport's share of the row's answers instead of counts, and what selection would give (EXPECTED)
      --privacy          One row per class of query: a client's PRIVACY level (none, opp., strict) or internal
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

