## tdns-cli auth scanner poll

Switch the poll scan of all children on or off, or show whether it is on

### Synopsis

Without an argument, or with "status", shows whether tdns-auth polls the
children of its parent zones.

"on" and "off" switch polling while tdns-auth runs, overriding
scanner.poll.enabled until "follow-config" or a restart; the switch is not
persisted. "on" takes effect at the next round, within scanner.interval. "off"
also stops a round in progress from starting any more children.

```
tdns-cli auth scanner poll [on|off|status|follow-config] [flags]
```

### Options

```
  -h, --help   help for poll
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

* [tdns-cli auth scanner](tdns-cli_auth_scanner.md)	 - Control tdns-auth's built-in CDS/CSYNC scanner

