## tdns-cli cert sign

Sign a CSR with the CA (SANs are taken from the CSR)

```
tdns-cli cert sign [flags]
```

### Options

```
      --algorithm string   key algorithm: ed25519 | ecdsa-p256 | rsa2048 (default "ed25519")
      --ca string          path to the CA certificate (PEM)
      --ca-key string      path to the CA signing key (PEM)
      --client             include clientAuth EKU (a mutual-XoT downstream wants both)
      --csr string         path to the CSR (PEM) to sign
      --emit-pin           print the SPKI pin after issuing
      --emit-tlsa string   print a TLSA 3-1-1 RR for this owner name after issuing
      --force              overwrite existing files
  -h, --help               help for sign
      --out-dir string     output directory (default: cwd; cert ca as root: /etc/tdns/ca)
      --server             include serverAuth EKU (default true; use --server=false for a client-only cert) (default true)
      --tlsa-port uint16   port for the --emit-tlsa owner name (default 853)
      --validity int       validity in days (default 397)
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

