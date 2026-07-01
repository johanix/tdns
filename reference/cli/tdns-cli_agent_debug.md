## tdns-cli agent debug

Debug commands against the configured daemon

```
tdns-cli agent debug [flags]
```

### Options

```
  -h, --help           help for debug
      --qname string   qname of rrset to examine
      --qtype string   qtype of rrset to examine
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

* [tdns-cli agent](tdns-cli_agent.md)	 - TDNS Agent commands
* [tdns-cli agent debug lav](tdns-cli_agent_debug_lav.md)	 - Lookup and validate a child RRset
* [tdns-cli agent debug rrset](tdns-cli_agent_debug_rrset.md)	 - 
* [tdns-cli agent debug show-rrsetcache](tdns-cli_agent_debug_show-rrsetcache.md)	 - List cached RRsets
* [tdns-cli agent debug show-ta](tdns-cli_agent_debug_show-ta.md)	 - List known DNSSEC trust anchors
* [tdns-cli agent debug sig0](tdns-cli_agent_debug_sig0.md)	 - SIG(0) key helper commands (local)
* [tdns-cli agent debug validate-rrset](tdns-cli_agent_debug_validate-rrset.md)	 - 

