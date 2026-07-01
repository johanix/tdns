## tdns-cli auth zone update create

Create and ultimately send a DNS UPDATE msg for zone auth data

### Synopsis

Will query for details about the DNS UPDATE via (add|del|show|set-ttl) commands.
When the message is complete it may be signed and sent by the 'send' command. After a
message has been send the loop will start again with a new, empty message to create.
Loop ends on the command "QUIT"

The zone to update is mandatory to specify on the command line with the --zone flag.

```
tdns-cli auth zone update create [flags]
```

### Options

```
  -h, --help            help for create
  -K, --key string      SIG(0) keyfile to use for signing (.private/.key basename)
  -S, --server string   Server to send the update to (addr:port)
      --signer string   Name of signer (key used to sign the update; defaults to --zone)
  -z, --zone string     Zone to update
```

### Options inherited from parent commands

```
      --config string   config file (default is /etc/tdns/tdns-cli.yaml)
  -d, --debug           debug output
  -F, --force           force operation
  -H, --headers         show headers
  -Z, --pzone string    parent zone name
  -v, --verbose         verbose output
```

### SEE ALSO

* [tdns-cli auth zone update](tdns-cli_auth_zone_update.md)	 - Create and ultimately send a DNS UPDATE msg for zone auth data

