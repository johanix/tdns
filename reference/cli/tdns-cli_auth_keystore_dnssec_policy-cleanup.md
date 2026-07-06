## tdns-cli auth keystore dnssec policy-cleanup

Remove a zone's retired keys (and their RRSIGs) now, keeping active keys

### Synopsis

After a DNSSEC policy change, the old keys are retired but kept (with their
signatures) so the zone stays validatable while the new keys take over —
leaving the zone briefly double-signed. policy-cleanup collapses that window
early: it removes the retired keys and strips their RRSIGs immediately,
keeping the active keys. Unlike 'clear' (which deletes ALL keys and
regenerates), this only touches retired keys.

Accelerating removal means a resolver still caching only an old (now-removed)
DNSKEY briefly cannot validate until it re-queries; the active keys already
serve. Normally you can just wait for the KeyStateWorker to age the retired
keys out after propagation_delay.

```
tdns-cli auth keystore dnssec policy-cleanup [flags]
```

### Options

```
      --force         Skip confirmation prompt
  -h, --help          help for policy-cleanup
  -z, --zone string   Zone to clean up retired keys for
```

### Options inherited from parent commands

```
      --config string   config file (default is /etc/tdns/tdns-cli.yaml)
  -d, --debug           debug output
  -H, --headers         show headers
  -Z, --pzone string    parent zone name
  -v, --verbose         verbose output
```

### SEE ALSO

* [tdns-cli auth keystore dnssec](tdns-cli_auth_keystore_dnssec.md)	 - Prefix command, only usable via sub-commands

