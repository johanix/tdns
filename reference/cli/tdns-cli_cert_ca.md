## tdns-cli cert ca

Create a self-signed CA (pathlen 0: signs leaves only)

```
tdns-cli cert ca [flags]
```

### Options

```
      --algorithm string   key algorithm: ed25519 | ecdsa-p256 | rsa2048 (default "ed25519")
      --force              overwrite existing files
  -h, --help               help for ca
      --name string        subject CN (and default file base name)
      --out-dir string     output directory (default: cwd; cert ca as root: /etc/tdns/ca)
      --validity int       validity in days (default 3650)
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

