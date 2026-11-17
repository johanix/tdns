## tdns-cli auth zone

Prefix command, not usable by itself

### Options

```
  -F, --force   force operation
  -h, --help    help for zone
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

* [tdns-cli auth](tdns-cli_auth.md)	 - Interact with tdns-auth (authoritative) via API
* [tdns-cli auth zone add](tdns-cli_auth_zone_add.md)	 - Add a dynamic zone at runtime: secondary, or template-constrained primary (persists across restart)
* [tdns-cli auth zone bump](tdns-cli_auth_zone_bump.md)	 - Bump SOA serial and epoch (if any) in the daemon's version of the zone
* [tdns-cli auth zone childsync](tdns-cli_auth_zone_childsync.md)	 - Parent-side child delegation sync commands
* [tdns-cli auth zone delegation](tdns-cli_auth_zone_delegation.md)	 - Inspect the delegation data a parent zone holds for its children
* [tdns-cli auth zone delete](tdns-cli_auth_zone_delete.md)	 - Delete a dynamic (API-managed) zone
* [tdns-cli auth zone desc](tdns-cli_auth_zone_desc.md)	 - Describe a single zone in full, including DNSSEC applied-policy state and policy detail
* [tdns-cli auth zone dnssec](tdns-cli_auth_zone_dnssec.md)	 - Zone DNSSEC operations: signing, policy, and automated rollover
* [tdns-cli auth zone freeze](tdns-cli_auth_zone_freeze.md)	 - Freeze a zone (i.e. stop accepting DDNS updates to the zone data)
* [tdns-cli auth zone journal](tdns-cli_auth_zone_journal.md)	 - Inspect and manage a zone's delta journal
* [tdns-cli auth zone list](tdns-cli_auth_zone_list.md)	 - List configured zones
* [tdns-cli auth zone list-dynamic](tdns-cli_auth_zone_list-dynamic.md)	 - List dynamic zones (catalog members + API-managed) and their provisioning state
* [tdns-cli auth zone modify](tdns-cli_auth_zone_modify.md)	 - Modify a dynamic (API-managed) zone's primary, options or template
* [tdns-cli auth zone name](tdns-cli_auth_zone_name.md)	 - Inspect what a zone publishes at a single owner name
* [tdns-cli auth zone parentsync](tdns-cli_auth_zone_parentsync.md)	 - Child-side parent delegation sync commands
* [tdns-cli auth zone readfake](tdns-cli_auth_zone_readfake.md)	 - Create a fake zone from a compiled in string
* [tdns-cli auth zone reload](tdns-cli_auth_zone_reload.md)	 - Request re-loading a zone
* [tdns-cli auth zone sync](tdns-cli_auth_zone_sync.md)	 - Spool the zone out to disk (alias for write, no freeze/thaw)
* [tdns-cli auth zone thaw](tdns-cli_auth_zone_thaw.md)	 - Thaw a zone (i.e. accept DDNS updates to the zone data again)
* [tdns-cli auth zone update](tdns-cli_auth_zone_update.md)	 - Create and ultimately send a DNS UPDATE msg for zone auth data
* [tdns-cli auth zone write](tdns-cli_auth_zone_write.md)	 - Write a zone to disk
* [tdns-cli auth zone zonemd](tdns-cli_auth_zone_zonemd.md)	 - Inspect and verify a zone's ZONEMD (RFC 8976)

