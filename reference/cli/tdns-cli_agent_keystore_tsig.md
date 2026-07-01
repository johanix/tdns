## tdns-cli agent keystore tsig

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

* [tdns-cli agent keystore](tdns-cli_agent_keystore.md)	 - Prefix command to access different features of the keystore
* [tdns-cli agent keystore tsig add](tdns-cli_agent_keystore_tsig_add.md)	 - Add a TSIG key with a known secret
* [tdns-cli agent keystore tsig delete](tdns-cli_agent_keystore_tsig_delete.md)	 - Delete an api-origin TSIG key
* [tdns-cli agent keystore tsig generate](tdns-cli_agent_keystore_tsig_generate.md)	 - Generate a new TSIG key and add it to the keystore
* [tdns-cli agent keystore tsig import](tdns-cli_agent_keystore_tsig_import.md)	 - Import TSIG keys from a BIND or NSD config snippet
* [tdns-cli agent keystore tsig list](tdns-cli_agent_keystore_tsig_list.md)	 - List TSIG keys (no secrets)
* [tdns-cli agent keystore tsig purge](tdns-cli_agent_keystore_tsig_purge.md)	 - Delete unreferenced api-origin TSIG keys owned by api
* [tdns-cli agent keystore tsig setowner](tdns-cli_agent_keystore_tsig_setowner.md)	 - Change owner on an api-origin TSIG key

