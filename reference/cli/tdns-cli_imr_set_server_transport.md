## tdns-cli imr set server transport

Override transport signal for a server (debug)

### Synopsis

Manually override the transport signal for an authoritative server.
This is a debug command useful for testing different transport distributions.

Examples:
  # Force 100% DoT
  imr set server transport --server ns1.example.com. --signal "dot:100"
  
  # Test mixed distribution
  imr set server transport --server ns1.example.com. --signal "doq:20,dot:100,do53:3"
  
  # Reset to original signal
  imr set server transport --server ns1.example.com. --reset

```
tdns-cli imr set server transport [flags]
```

### Options

```
  -h, --help            help for transport
  -r, --reset           Reset to default (do53 only)
  -s, --server string   Server name (e.g., ns1.example.com.)
  -t, --signal string   Transport signal (e.g., "doq:20,dot:100,do53:3")
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

* [tdns-cli imr set server](tdns-cli_imr_set_server.md)	 - Set server parameters

