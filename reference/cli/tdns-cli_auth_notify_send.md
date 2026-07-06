## tdns-cli auth notify send

The 'notify send' command is only usable via defined sub-commands

### Options

```
  -h, --help   help for send
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

* [tdns-cli auth notify](tdns-cli_auth_notify.md)	 - The 'notify' command is only usable via defined sub-commands
* [tdns-cli auth notify send cds](tdns-cli_auth_notify_send_cds.md)	 - Send a Notify(CDS) to parent of zone
* [tdns-cli auth notify send csync](tdns-cli_auth_notify_send_csync.md)	 - Send a Notify(CSYNC) to parent of zone
* [tdns-cli auth notify send dnskey](tdns-cli_auth_notify_send_dnskey.md)	 - Send a Notify(DNSKEY) to other signers of zone (multi-signer setup)
* [tdns-cli auth notify send soa](tdns-cli_auth_notify_send_soa.md)	 - Send a normal Notify(SOA) to someone

