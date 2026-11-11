## tdns-cli cert

Minimal internal PKI for XoT/TLS provisioning (private trust domains only)

### Synopsis

Minimal internal PKI for provisioning XoT/TLS certificates.

Scope: a provisioning convenience for a PRIVATE trust domain (your own
primaries and secondaries) — not general CA tooling. No CRL, no OCSP, no
renewal automation, no certificate database. State is plain PEM files plus
an append-only issued.log next to the CA key.

Typical flows:
  cert init  — one command: CA (if absent) + a server cert for the local
               tdns-auth, written to the paths its config already names.
  cert ca / cert leaf — mint the CA and individual certs by hand.
  cert csr / cert sign — split provisioning: the remote side generates the
               key+CSR locally (key never travels), the CA side signs.

### Options

```
  -h, --help   help for cert
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

* [tdns-cli](tdns-cli.md)	 - tdns-cli is a tool used to interact with the TDNS applications via a mgmt API
* [tdns-cli cert ca](tdns-cli_cert_ca.md)	 - Create a self-signed CA (pathlen 0: signs leaves only)
* [tdns-cli cert csr](tdns-cli_cert_csr.md)	 - Generate a certificate signing request (key never leaves this host)
* [tdns-cli cert init](tdns-cli_cert_init.md)	 - One-shot local provisioning: CA (if absent) + server cert for the local tdns-auth
* [tdns-cli cert leaf](tdns-cli_cert_leaf.md)	 - Generate a key and a CA-signed end-entity certificate
* [tdns-cli cert pin](tdns-cli_cert_pin.md)	 - Print the base64 SPKI SHA-256 pin of a certificate
* [tdns-cli cert show](tdns-cli_cert_show.md)	 - Human-readable certificate summary (subject, SANs, EKU, validity, pin)
* [tdns-cli cert show-cmds](tdns-cli_cert_show-cmds.md)	 - List the whole command tree below this command, one line per command
* [tdns-cli cert sign](tdns-cli_cert_sign.md)	 - Sign a CSR with the CA (SANs are taken from the CSR)

