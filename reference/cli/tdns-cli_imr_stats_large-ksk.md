## tdns-cli imr stats large-ksk

Show large-KSK IMR DS and DNSKEY lookup statistics

### Synopsis

Counters for evaluating direct-TCP DNSKEY fetching when parent DS
signals a large KSK algorithm (dnssec.large_algorithms).

DS RRsets are counted when cached from referrals; large-alg DS RRs are
counted individually per algorithm. DNSKEY lookups are counted at the
start of each outbound DNSKEY query; forced-TCP means do53-tcp was
selected from the start (not UDP-to-TCP fallback).

```
tdns-cli imr stats large-ksk [flags]
```

### Options

```
  -h, --help   help for large-ksk
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

* [tdns-cli imr stats](tdns-cli_imr_stats.md)	 - Show IMR statistics

