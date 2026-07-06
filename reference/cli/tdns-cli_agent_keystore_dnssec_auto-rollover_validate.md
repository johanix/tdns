## tdns-cli agent keystore dnssec auto-rollover validate

Validate a zone's rollover policy against §4 cache-flush invariants

### Synopsis

Re-parses the YAML config the daemon is running and runs every §4
cache-flush invariant check (E5, E10, E11) against the dnssecpolicy
attached to the named zone. Reports PASS / FAIL / WARN per invariant
with operator-actionable suggestions.

Online (default): contacts the daemon for its config-file path and the
zone's active policy name, then reads the YAML directly. Useful for
checking a candidate change before reload.

Offline (--serverconfig PATH): skips the daemon and reads PATH. The
zone's policy must be either supplied via --policy or inferable from
the YAML's zones: block (when --zone matches a configured zone).

DS_TTL handling: the runtime engine uses the parent's observed DS
RRset TTL. validate doesn't have that observation, so it uses the
ttls.parent-ds policy override if set, OR --parent-ds-ttl <duration> if
supplied. Without either, E10/E11 are skipped (and the report says
so).

```
tdns-cli agent keystore dnssec auto-rollover validate [flags]
```

### Options

```
  -h, --help                   help for validate
      --parent-ds-ttl string   Hypothetical parent DS RRset TTL (e.g. 1h) for E10/E11; overrides ttls.parent-ds
      --policy string          Override the dnssecpolicy name to validate (offline mode only)
      --serverconfig string    Read this YAML file instead of asking the daemon (offline)
  -z, --zone string            Zone
```

### Options inherited from parent commands

```
      --config string   config file (default is /etc/tdns/tdns-cli.yaml)
  -d, --debug           debug output
  -H, --headers         show headers
      --ksk             Render only the KSK section (status / when); ignored by other subcommands
  -Z, --pzone string    parent zone name
  -v, --verbose         verbose output
      --zsk             Render only the ZSK section (status / when); ignored by other subcommands
```

### SEE ALSO

* [tdns-cli agent keystore dnssec auto-rollover](tdns-cli_agent_keystore_dnssec_auto-rollover.md)	 - Manage and inspect automated KSK rollover (scheduled + manual-ASAP)

