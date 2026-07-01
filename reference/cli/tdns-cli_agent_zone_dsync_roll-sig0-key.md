## tdns-cli agent zone dsync roll-sig0-key

Send dsync rollover command to the agent

```
tdns-cli agent zone dsync roll-sig0-key [flags]
```

### Options

```
  -a, --algorithm string   Algorithm for the new SIG(0) key (use the 'algorithms' subcommand to list what the server supports)
  -h, --help               help for roll-sig0-key
```

### Options inherited from parent commands

```
      --config string   config file (default is /etc/tdns/tdns-cli.yaml)
  -d, --debug           debug output
  -F, --force           force operation
  -H, --headers         show headers
  -Z, --pzone string    parent zone name
  -v, --verbose         verbose output
  -z, --zone string     zone name
```

### SEE ALSO

* [tdns-cli agent zone dsync](tdns-cli_agent_zone_dsync.md)	 - Prefix command, not useable by itself

