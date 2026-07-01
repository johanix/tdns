## tdns-cli util base32 decode

Decode base32 domain data to JSON

### Synopsis

Decode base32 domain data from stdin to JSON.

```
tdns-cli util base32 decode [flags]
```

### Options

```
  -c, --cookie string   Cookie prefix for chunk identification (default "c0")
  -h, --help            help for decode
  -p, --pretty          Pretty-print JSON output
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

