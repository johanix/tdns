## tdns-cli imr config mwe

Generate a minimal working example config (+ cert) for tdns-imr

### Synopsis

Generate a Minimal Working Example configuration for tdns-imr.

Writes a single self-contained YAML to <dir>/tdns-imr.yaml (or <dir>/tdns-imr.yaml.mwe
if that file already exists), and generates a self-signed cert/key pair under
<dir>/certs unless one is already there. The resolver listens on IPv4 and IPv6
localhost; DNSSEC validation is disabled so it resolves out of the box (the
config shows, commented, how to turn it into a validating resolver). The
generated tree passes `tdns-cli imr config check`.

```
tdns-cli imr config mwe [flags]
```

### Options

```
      --dir string   base directory for the generated config and cert (default "/etc/tdns")
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

* [tdns-cli imr config](tdns-cli_imr_config.md)	 - Validate or generate a tdns-imr configuration

