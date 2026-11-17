## tdns-cli imr stats large-ksk

Show large-KSK IMR DS and DNSKEY lookup statistics

### Synopsis

Counters for evaluating DNSKEY transport bypass when parent DS
signals a large KSK algorithm (dnssec.large-algorithms) or when
dnssec.dnskey-query-transport forces it.

DS RRsets are counted when cached from referrals; large-alg DS RRs are
counted individually per algorithm. DNSKEY lookups are counted at the
start of each outbound DNSKEY query; bypassed means the query skipped
probabilistic transport selection per dnssec.dnskey-query-transport and
used the server's best advertised transport instead (encrypted preferred,
else do53-tcp, never UDP).

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
      --version         print version and supported algorithms, then exit
  -z, --zone string     zone name
```

### SEE ALSO

* [tdns-cli imr stats](tdns-cli_imr_stats.md)	 - Show IMR statistics

