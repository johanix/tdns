## tdns-cli auth zone proxy-key

Show the delegation-sync-proxy UPDATE state and the KEY to publish at the primary

### Synopsis

For a zone with the delegation-sync-proxy option (a tdns-agent acting as a
secondary for a DSYNC-unaware primary), report whether the agent can proxy
DNS UPDATEs to the parent, and — when waiting — print the exact records to
add at the primary apex (the agent's KEY RR and an HSYNCPARAM pubkey flag).
States: update-unsupported / ready / foreign-key / waiting-for-key.

```
tdns-cli auth zone proxy-key [flags]
```

### Options

```
  -h, --help          help for proxy-key
  -z, --zone string   Zone to report proxy-key state for
```

### Options inherited from parent commands

```
      --config string   config file (default is /etc/tdns/tdns-cli.yaml)
  -d, --debug           debug output
  -F, --force           force operation
  -H, --headers         show headers
  -Z, --pzone string    parent zone name
  -v, --verbose         verbose output
```

### SEE ALSO

* [tdns-cli auth zone](tdns-cli_auth_zone.md)	 - Prefix command, not usable by itself

