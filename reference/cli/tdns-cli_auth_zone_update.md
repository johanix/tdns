## tdns-cli auth zone update

Create and ultimately send a DNS UPDATE msg for zone auth data

### Options

```
  -h, --help   help for update
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

* [tdns-cli auth zone](tdns-cli_auth_zone.md)	 - Prefix command, not usable by itself
* [tdns-cli auth zone update addrr](tdns-cli_auth_zone_update_addrr.md)	 - Add one or more RRs to a zone
* [tdns-cli auth zone update create](tdns-cli_auth_zone_update_create.md)	 - Create and ultimately send a DNS UPDATE msg for zone auth data
* [tdns-cli auth zone update delname](tdns-cli_auth_zone_update_delname.md)	 - Delete every RRset at an owner name
* [tdns-cli auth zone update delrr](tdns-cli_auth_zone_update_delrr.md)	 - Delete one specific RR from a zone
* [tdns-cli auth zone update delrrset](tdns-cli_auth_zone_update_delrrset.md)	 - Delete an entire RRset (owner + type) from a zone
* [tdns-cli auth zone update from-file](tdns-cli_auth_zone_update_from-file.md)	 - Apply an ADD/DEL instruction file to a zone
* [tdns-cli auth zone update replacerrset](tdns-cli_auth_zone_update_replacerrset.md)	 - Atomically replace an RRset with the supplied RRs

