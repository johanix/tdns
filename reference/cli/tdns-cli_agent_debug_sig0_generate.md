## tdns-cli agent debug sig0 generate



```
tdns-cli agent debug sig0 generate [flags]
```

### Options

```
  -h, --help   help for generate
```

### Options inherited from parent commands

```
  -a, --algorithm string   Algorithm to use for SIG(0) (use the 'algorithms' subcommand to list what the server supports)
      --config string      config file (default is /etc/tdns/tdns-cli.yaml)
  -d, --debug              debug output
  -H, --headers            show headers
  -Z, --pzone string       parent zone name
      --qname string       qname of rrset to examine
      --qtype string       qtype of rrset to examine
  -r, --rrtype string      rrtype to use for SIG(0)
  -v, --verbose            verbose output
  -z, --zone string        zone name
```

### SEE ALSO

* [tdns-cli agent debug sig0](tdns-cli_agent_debug_sig0.md)	 - SIG(0) key helper commands (local)

