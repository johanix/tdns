## tdns-cli agent keystore tsig export

Print a TSIG key's secret (default) or a full BIND/NSD key block, to stdout

### Synopsis

Print a TSIG key's base64 secret to stdout with NO trailing newline and
nothing else, so it can be captured inline in another command (e.g. via
shell backticks or $(...)) to TSIG-sign a dog query or transfer:

    dog @srv -y name.:$(tdns-cli auth keystore tsig export name) zone. axfr

With --bind or --nsd, print a complete BIND9 or NSD key block instead
(still on stdout). Errors go to stderr so stdout stays clean for capture.

```
tdns-cli agent keystore tsig export <keyname> [flags]
```

### Options

```
      --bind   Output a complete BIND9 key { ... } block
  -h, --help   help for export
      --nsd    Output a complete NSD key: block
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

* [tdns-cli agent keystore tsig](tdns-cli_agent_keystore_tsig.md)	 - Manage global TSIG keys in the keystore

