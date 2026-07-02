## tdns-cli auth del export

Export delegation data from a parent zone's backend to a zone file

```
tdns-cli auth del export [flags]
```

### Options

```
  -h, --help             help for export
      --outfile string   Destination file path (required)
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

* [tdns-cli auth del](tdns-cli_auth_del.md)	 - Delegation prefix command. Only usable via sub-commands.

