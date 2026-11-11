## tdns-cli auth zone parentsync bootstrap

Bootstrap the SIG(0) key with the parent

```
tdns-cli auth zone parentsync bootstrap [flags]
```

### Options

```
  -h, --help            help for bootstrap
      --scheme string   Bootstrap scheme (only "update" is implemented) (default "update")
```

### Options inherited from parent commands

```
      --config string   config file (default is /etc/tdns/tdns-cli.yaml)
  -d, --debug           debug output
  -F, --force           force operation
  -H, --headers         show headers
  -Z, --pzone string    parent zone name
  -v, --verbose         verbose output
      --version         print version and supported algorithms, then exit
  -z, --zone string     zone name
```

### SEE ALSO

* [tdns-cli auth zone parentsync](tdns-cli_auth_zone_parentsync.md)	 - Child-side parent delegation sync commands

