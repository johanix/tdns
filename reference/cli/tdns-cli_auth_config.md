## tdns-cli auth config

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
  -z, --zone string     zone name
```

### SEE ALSO

* [tdns-cli auth](tdns-cli_auth.md)	 - Interact with tdns-auth (authoritative) via API
* [tdns-cli auth config reload](tdns-cli_auth_config_reload.md)	 - Send config reload command to tdns-auth
* [tdns-cli auth config reload-tsig](tdns-cli_auth_config_reload-tsig.md)	 - Reconcile keys.tsig into the TSIG keystore (config reload-tsig)
* [tdns-cli auth config reload-zones](tdns-cli_auth_config_reload-zones.md)	 - Send reload-zones command to tdns-auth
* [tdns-cli auth config status](tdns-cli_auth_config_status.md)	 - Send config status command to tdns-auth

