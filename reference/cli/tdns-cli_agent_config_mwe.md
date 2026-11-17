## tdns-cli agent config mwe

Generate a minimal working example config (+ certs, zones) for tdns-agent

### Synopsis

Generate a Minimal Working Example configuration for tdns-agent.

Writes a single self-contained YAML to <dir>/tdns-agent.yaml (or, if that
file already exists, to <dir>/tdns-agent.yaml.mwe so nothing is
clobbered). Also generates, unless already present:

  - a self-signed cert/key pair under <dir>/certs (for the API server and the
    encrypted DNS transports)
  - two secondary zone templates and a commented-out secondary zone

tdns-agent is secondary-only and never signs, so the generated config declares
no zones and no dnssec: block; the agent starts clean and you add secondaries
by uncommenting the example.

The DNS engine listens on IPv4 and IPv6 localhost; extra listen addresses are
shown commented out. The generated tree is designed to pass
`tdns-cli agent config check`.

```
tdns-cli agent config mwe [flags]
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

* [tdns-cli agent config](tdns-cli_agent_config.md)	 - Commands to reload config, reload zones, etc

