## tdns-cli imr daemon reload

Reload config from file

### Synopsis

Reload config from file (the assumption is that something in the config has changed).
Right now this doesn't do much, but later on various services will be able to restart.

```
tdns-cli imr daemon reload [flags]
```

### Options

```
  -h, --help   help for reload
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

* [tdns-cli imr daemon](tdns-cli_imr_daemon.md)	 - Only useful via sub-commands

