## tdns-cli agent config reload-zones

Send reload-zones command to tdns-agent

```
tdns-cli agent config reload-zones [flags]
```

### Options

```
      --confirm   apply even if the reload would strand a signed zone by a same-name DNSSEC policy algorithm change
  -h, --help      help for reload-zones
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

* [tdns-cli agent config](tdns-cli_agent_config.md)	 - Commands to reload config, reload zones, etc

