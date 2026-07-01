## tdns-cli util generate tlsa

Generate a TLSA record (usage 3 1 1) from a PEM certificate

```
tdns-cli util generate tlsa <domain> <cert.pem> [flags]
```

### Options

```
  -h, --help           help for tlsa
  -p, --port uint16    Service port for the TLSA owner name (default 443)
      --proto string   Protocol for the TLSA owner name (e.g. tcp) (default "tcp")
  -t, --ttl uint32     TTL for the resulting TLSA RR (default 3600)
```

### Options inherited from parent commands

```
      --config string   config file (default is /etc/tdns/tdns-cli.yaml)
  -d, --debug           debug output
  -H, --headers         show headers
  -Z, --pzone string    parent zone name
  -v, --verbose         verbose output
  -z, --zone string     zone name
```

### SEE ALSO

* [tdns-cli util generate](tdns-cli_util_generate.md)	 - Generate DNS records or encodings

