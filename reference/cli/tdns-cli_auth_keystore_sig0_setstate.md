## tdns-cli auth keystore sig0 setstate

Set the state of and existing SIG(0) key pair in the TDNSD keystore

```
tdns-cli auth keystore sig0 setstate [flags]
```

### Options

```
  -h, --help           help for setstate
      --keyid int      Key ID of key to delete
      --state string   New state of key (created|published|active|retired)
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

* [tdns-cli auth keystore sig0](tdns-cli_auth_keystore_sig0.md)	 - Prefix command, only usable via sub-commands

