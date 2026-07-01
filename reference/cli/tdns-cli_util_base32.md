## tdns-cli util base32

Convert data to/from base32 encoding and domain format

### Synopsis

This command converts data to or from base32 encoding and domain format.
It can read from standard input or from a file.

Examples:
  echo '{"name":"example","value":123}' | tdns base32 encode --suffix=example.com.
  cat domains.txt | tdns base32 decode

### Options

```
  -h, --help   help for base32
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

* [tdns-cli util](tdns-cli_util.md)	 - Daemon-agnostic utility commands (base32, jwt, generate, keys)
* [tdns-cli util base32 decode](tdns-cli_util_base32_decode.md)	 - Decode base32 domain data to JSON
* [tdns-cli util base32 encode](tdns-cli_util_base32_encode.md)	 - Encode JSON data to base32 domain format

