## tdns-cli auth debug

Debug commands against the configured daemon

```
tdns-cli auth debug [flags]
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

* [tdns-cli auth](tdns-cli_auth.md)	 - Interact with tdns-auth (authoritative) via API
* [tdns-cli auth debug lav](tdns-cli_auth_debug_lav.md)	 - Lookup and validate a child RRset
* [tdns-cli auth debug rrset](tdns-cli_auth_debug_rrset.md)	 - 
* [tdns-cli auth debug show-rrsetcache](tdns-cli_auth_debug_show-rrsetcache.md)	 - List cached RRsets
* [tdns-cli auth debug show-ta](tdns-cli_auth_debug_show-ta.md)	 - List known DNSSEC trust anchors
* [tdns-cli auth debug sig0](tdns-cli_auth_debug_sig0.md)	 - SIG(0) key helper commands (local)
* [tdns-cli auth debug validate-rrset](tdns-cli_auth_debug_validate-rrset.md)	 - 

