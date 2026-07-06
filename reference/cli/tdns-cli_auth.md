## tdns-cli auth

Interact with tdns-auth (authoritative) via API

### Options

```
  -h, --help   help for auth
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

* [tdns-cli](tdns-cli.md)	 - tdns-cli is a tool used to interact with the tdnsd nameserver via API
* [tdns-cli auth catalog](tdns-cli_auth_catalog.md)	 - Manage catalog zones (RFC 9432)
* [tdns-cli auth config](tdns-cli_auth_config.md)	 - Commands to reload config, reload zones, etc
* [tdns-cli auth daemon](tdns-cli_auth_daemon.md)	 - Only useful via sub-commands
* [tdns-cli auth db](tdns-cli_auth_db.md)	 - Manage the auth daemon's SQLite database
* [tdns-cli auth ddns](tdns-cli_auth_ddns.md)	 - Send a DDNS update. Only usable via sub-commands.
* [tdns-cli auth debug](tdns-cli_auth_debug.md)	 - Debug commands against the configured daemon
* [tdns-cli auth del](tdns-cli_auth_del.md)	 - Delegation prefix command. Only usable via sub-commands.
* [tdns-cli auth imr](tdns-cli_auth_imr.md)	 - IMR (Internal Recursive Resolver) cache commands
* [tdns-cli auth keystore](tdns-cli_auth_keystore.md)	 - Prefix command to access different features of the keystore
* [tdns-cli auth notify](tdns-cli_auth_notify.md)	 - The 'notify' command is only usable via defined sub-commands
* [tdns-cli auth ping](tdns-cli_auth_ping.md)	 - Send an API ping request and present the response
* [tdns-cli auth report](tdns-cli_auth_report.md)	 - Send a report and (optionally) discover DSYNC via the internal resolver (imr)
* [tdns-cli auth stop](tdns-cli_auth_stop.md)	 - Send stop command to the daemon
* [tdns-cli auth truststore](tdns-cli_auth_truststore.md)	 - Prefix command to access different features of the truststore
* [tdns-cli auth zone](tdns-cli_auth_zone.md)	 - Prefix command, not usable by itself

