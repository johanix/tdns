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
  -z, --zone string     zone name
```

### SEE ALSO

* [tdns-cli auth](tdns-cli_auth.md)	 - Interact with tdns-auth (authoritative) via API
* [tdns-cli auth zone add](tdns-cli_auth_zone_add.md)	 - Add a dynamic secondary zone at runtime (persists across restart)
* [tdns-cli auth zone bump](tdns-cli_auth_zone_bump.md)	 - Bump SOA serial and epoch (if any) in tdns-auth version of zone
* [tdns-cli auth zone delete](tdns-cli_auth_zone_delete.md)	 - Delete a dynamic (API-managed) zone
* [tdns-cli auth zone dsync](tdns-cli_auth_zone_dsync.md)	 - Prefix command, not useable by itself
* [tdns-cli auth zone freeze](tdns-cli_auth_zone_freeze.md)	 - Freeze a zone (i.e. stop accepting DDNS updates to the zone data)
* [tdns-cli auth zone list](tdns-cli_auth_zone_list.md)	 - List configured zones
* [tdns-cli auth zone list-dynamic](tdns-cli_auth_zone_list-dynamic.md)	 - List dynamic zones (catalog members + API-managed) and their provisioning state
* [tdns-cli auth zone modify](tdns-cli_auth_zone_modify.md)	 - Modify a dynamic (API-managed) zone's primary or options
* [tdns-cli auth zone nsec](tdns-cli_auth_zone_nsec.md)	 - Prefix command, not usable by itself
* [tdns-cli auth zone proxy-key](tdns-cli_auth_zone_proxy-key.md)	 - Show the delegation-sync-proxy UPDATE state and the KEY to publish at the primary
* [tdns-cli auth zone readfake](tdns-cli_auth_zone_readfake.md)	 - Create a fake zone from a compiled in string
* [tdns-cli auth zone reload](tdns-cli_auth_zone_reload.md)	 - Request re-loading a zone
* [tdns-cli auth zone resign](tdns-cli_auth_zone_resign.md)	 - Re-sign zone from scratch with currently-active keys (drops all existing RRSIGs)
* [tdns-cli auth zone set-policy](tdns-cli_auth_zone_set-policy.md)	 - Set a zone's DNSSEC policy at runtime (persists as an override, not in YAML)
* [tdns-cli auth zone sign](tdns-cli_auth_zone_sign.md)	 - Request signing of a zone (additive: cover gaps with active keys)
* [tdns-cli auth zone thaw](tdns-cli_auth_zone_thaw.md)	 - Thaw a zone (i.e. accept DDNS updates to the zone data again)
* [tdns-cli auth zone update](tdns-cli_auth_zone_update.md)	 - Create and ultimately send a DNS UPDATE msg for zone auth data
* [tdns-cli auth zone write](tdns-cli_auth_zone_write.md)	 - Write a zone to disk

