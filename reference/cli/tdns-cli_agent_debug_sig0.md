## tdns-cli agent debug sig0

SIG(0) key helper commands (local)

```
tdns-cli agent debug sig0 [flags]
```

### Options

```
  -a, --algorithm string   Algorithm to use for SIG(0) (use the 'algorithms' subcommand to list what the server supports)
  -h, --help               help for sig0
  -r, --rrtype string      rrtype to use for SIG(0)
```

### Options inherited from parent commands

```
      --config string   config file (default is /etc/tdns/tdns-cli.yaml)
  -d, --debug           debug output
  -H, --headers         show headers
  -Z, --pzone string    parent zone name
      --qname string    qname of rrset to examine
      --qtype string    qtype of rrset to examine
  -v, --verbose         verbose output
  -z, --zone string     zone name
```

### SEE ALSO

* [tdns-cli agent debug](tdns-cli_agent_debug.md)	 - Debug commands against the configured daemon
* [tdns-cli agent debug sig0 generate](tdns-cli_agent_debug_sig0_generate.md)	 - 

