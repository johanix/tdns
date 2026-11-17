## tdns-cli auth dsync-api cert-credential enable

Re-enable a disabled certificate credential

```
tdns-cli auth dsync-api cert-credential enable [flags]
```

### Options

```
      --cert string       Leaf certificate file; hashed for tls-pin
  -h, --help              help for enable
      --identity string   DNS name (tls-pkix) or pin (tls-pin)
      --mech string       tls-pin or tls-pkix (required)
      --pin string        Literal 44-character standard-encoding base64 SPKI pin (tls-pin)
  -z, --zone string       Parent zone the credential is scoped to
```

### Options inherited from parent commands

```
      --config string   config file (default is /etc/tdns/tdns-cli.yaml)
  -d, --debug           debug output
  -H, --headers         show headers
  -Z, --pzone string    parent zone name
  -v, --verbose         verbose output
      --version         print version and supported algorithms, then exit
```

### SEE ALSO

* [tdns-cli auth dsync-api cert-credential](tdns-cli_auth_dsync-api_cert-credential.md)	 - Manage DSYNC API certificate credentials

