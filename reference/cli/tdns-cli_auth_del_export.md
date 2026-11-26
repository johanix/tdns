## tdns-cli auth del export

Export a parent zone's delegation data as zone file text

### Synopsis

Export a parent zone's delegation data as zone file text.

The daemon returns the data. With --outfile it is written to that file
on this host, with your permissions; without it, it goes to stdout.

```
tdns-cli auth del export [flags]
```

### Options

```
  -h, --help             help for export
      --outfile string   Write the data to this file on this host (default: stdout)
```

### Options inherited from parent commands

```
      --config string   config file (default is /etc/tdns/tdns-cli.yaml)
  -d, --debug           debug output
  -H, --headers         show headers
  -Z, --pzone string    parent zone name
  -v, --verbose         verbose output
      --version         print version and supported algorithms, then exit
  -z, --zone string     zone name
```

### SEE ALSO

* [tdns-cli auth del](tdns-cli_auth_del.md)	 - Delegation prefix command. Only usable via sub-commands.

