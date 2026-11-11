## tdns-cli cert init

One-shot local provisioning: CA (if absent) + server cert for the local tdns-auth

### Synopsis

Reads the local tdns-auth config, creates a private CA if one does not
exist yet, and issues a server certificate written to the exact
listeners.certfile/keyfile paths the config already names — no config
editing needed, just restart the daemon. SANs are derived from the
config's listen addresses plus this host's name (and loopback). The leaf
carries both serverAuth and clientAuth EKU so the same daemon can also
present it as a client certificate under mutual XoT.

Re-running is safe: an existing CA is reused; existing cert/key files are
only replaced with --force.

```
tdns-cli cert init [flags]
```

### Options

```
      --algorithm string      key algorithm: ed25519 | ecdsa-p256 | rsa2048 (default "ed25519")
      --ca-dir string         CA directory (default: /etc/tdns/ca as root, else cwd)
      --ca-name string        CA name (CN and file base name) (default "tdns-ca")
      --force                 overwrite existing cert/key files
  -h, --help                  help for init
      --name string           server cert CN and primary SAN (default: hostname)
      --serverconfig string   path to the tdns-auth config (default: /etc/tdns/tdns-auth.yaml)
      --validity int          server cert validity in days (default 397)
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

* [tdns-cli cert](tdns-cli_cert.md)	 - Minimal internal PKI for XoT/TLS provisioning (private trust domains only)

