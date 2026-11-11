## tdns-cli auth config mwe

Generate a minimal working example config (+ certs, zones) for tdns-auth

### Synopsis

Generate a Minimal Working Example configuration for tdns-auth.

Writes a single self-contained YAML to <dir>/tdns-auth.yaml (or, if that
file already exists, to <dir>/tdns-auth.yaml.mwe so nothing is
clobbered). Also generates, unless already present:

  - a self-signed cert/key pair under <dir>/certs (for the API server and the
    encrypted DNS transports)
  - two example primary zones — one unsigned, one signed — using two different
    zone templates, with generated zone files under <dir>/zones
  - a commented-out secondary zone using a third template

The DNS engine listens on IPv4 and IPv6 localhost; extra listen addresses are
shown commented out. The generated tree is designed to pass
`tdns-cli auth config check`.

```
tdns-cli auth config mwe [flags]
```

### Options

```
      --dir string   base directory for the generated config, certs and zones (default "/etc/tdns")
  -h, --help         help for mwe
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

