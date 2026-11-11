## tdns-cli auth config reload

Send config reload command to tdns-auth

```
tdns-cli auth config reload [flags]
```

### Options

```
      --confirm   apply even if the reload would strand a signed zone by a same-name DNSSEC policy algorithm change
  -h, --help      help for reload
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

* [tdns-cli auth config](tdns-cli_auth_config.md)	 - Commands to reload config, reload zones, etc

