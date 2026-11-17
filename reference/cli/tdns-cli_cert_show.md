## tdns-cli cert show

Human-readable certificate summary (subject, SANs, EKU, validity, pin)

```
tdns-cli cert show <cert.pem> [flags]
```

### Options

```
  -h, --help   help for show
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

