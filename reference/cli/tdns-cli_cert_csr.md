## tdns-cli cert csr

Generate a certificate signing request (key never leaves this host)

### Synopsis

Generate a certificate signing request. By default a fresh key is
generated next to the CSR. With --key an EXISTING private key (PKCS#8, or
legacy openssl EC/RSA PEM) signs the CSR instead — the upgrade-in-place
path for turning a self-signed cert into a CA-signed one: the key (and so
the SPKI) is unchanged, which keeps configured pins and published TLSA
records valid. --from-cert copies CN and SANs from an existing
certificate so the replacement matches what it replaces.

```
tdns-cli cert csr [flags]
```

### Options

```
      --algorithm string   key algorithm: ed25519 | ecdsa-p256 | rsa2048 (default "ed25519")
      --dns strings        DNS SANs (comma-separated or repeated)
      --force              overwrite existing files
      --from-cert string   copy CN and SANs from this existing certificate (PEM)
  -h, --help               help for csr
      --ip strings         IP SANs (comma-separated or repeated)
      --key string         reuse this EXISTING private key (PKCS#8 or legacy openssl EC/RSA PEM) instead of generating one — keeps the SPKI, so pins/TLSA stay valid
      --name string        subject CN (and default file base name)
      --out-dir string     output directory (default: cwd; cert ca as root: /etc/tdns/ca)
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

