## tdns-cli agent keystore dnssec clear

Permanently delete all DNSSEC keys for a zone (KeyStateWorker will regenerate as needed)

```
tdns-cli agent keystore dnssec clear [flags]
```

### Options

```
      --force         Skip confirmation prompt
  -h, --help          help for clear
  -z, --zone string   Zone to clear all DNSSEC keys for
```

### Options inherited from parent commands

```
      --config string   config file (default is /etc/tdns/tdns-cli.yaml)
  -d, --debug           debug output
  -H, --headers         show headers
  -Z, --pzone string    parent zone name
  -v, --verbose         verbose output
```

### SEE ALSO

* [tdns-cli agent keystore dnssec](tdns-cli_agent_keystore_dnssec.md)	 - Prefix command, only usable via sub-commands

