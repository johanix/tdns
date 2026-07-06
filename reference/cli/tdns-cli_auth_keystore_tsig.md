## tdns-cli auth keystore tsig

Manage global TSIG keys in the keystore

### Synopsis

Global TSIG keystore (no --zone). Keys are DB-backed with origin=api
for keys created here; config keys are managed via keys.tsig.

### Options

```
  -h, --help   help for tsig
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

* [tdns-cli auth keystore](tdns-cli_auth_keystore.md)	 - Prefix command to access different features of the keystore
* [tdns-cli auth keystore tsig add](tdns-cli_auth_keystore_tsig_add.md)	 - Add a TSIG key with a known secret
* [tdns-cli auth keystore tsig delete](tdns-cli_auth_keystore_tsig_delete.md)	 - Delete an api-origin TSIG key
* [tdns-cli auth keystore tsig export](tdns-cli_auth_keystore_tsig_export.md)	 - Print a TSIG key's secret (default) or a full BIND/NSD key block, to stdout
* [tdns-cli auth keystore tsig generate](tdns-cli_auth_keystore_tsig_generate.md)	 - Generate a new TSIG key and add it to the keystore
* [tdns-cli auth keystore tsig import](tdns-cli_auth_keystore_tsig_import.md)	 - Import TSIG keys from a BIND or NSD config snippet
* [tdns-cli auth keystore tsig list](tdns-cli_auth_keystore_tsig_list.md)	 - List TSIG keys (no secrets)
* [tdns-cli auth keystore tsig purge](tdns-cli_auth_keystore_tsig_purge.md)	 - Delete unreferenced api-origin TSIG keys owned by api
* [tdns-cli auth keystore tsig setowner](tdns-cli_auth_keystore_tsig_setowner.md)	 - Change owner on an api-origin TSIG key

