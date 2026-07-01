## tdns-cli util base32 encode

Encode JSON data to base32 domain format

### Synopsis

Encode JSON data from stdin to base32 domain format.

```
tdns-cli util base32 encode [flags]
```

### Options

```
  -c, --cookie string   Cookie prefix for chunk identification (default "c0")
  -h, --help            help for encode
  -s, --suffix string   Domain suffix to append (FQDN, must end with a dot) (default "example.com.")
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

* [tdns-cli util base32](tdns-cli_util_base32.md)	 - Convert data to/from base32 encoding and domain format

