## tdns-cli agent config

Commands to reload config, reload zones, etc

### Options

```
  -h, --help   help for config
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

* [tdns-cli agent](tdns-cli_agent.md)	 - TDNS Agent commands
* [tdns-cli agent config check](tdns-cli_agent_config_check.md)	 - Validate the tdns-agent config and correlate it with the running daemon
* [tdns-cli agent config mwe](tdns-cli_agent_config_mwe.md)	 - Generate a minimal working example config (+ certs, zones) for tdns-agent
* [tdns-cli agent config reload](tdns-cli_agent_config_reload.md)	 - Send config reload command to tdns-agent
* [tdns-cli agent config reload-tsig](tdns-cli_agent_config_reload-tsig.md)	 - Reconcile keys.tsig into the TSIG keystore (config reload-tsig)
* [tdns-cli agent config reload-zones](tdns-cli_agent_config_reload-zones.md)	 - Send reload-zones command to tdns-agent
* [tdns-cli agent config status](tdns-cli_agent_config_status.md)	 - Send config status command to tdns-agent

