## tdns-cli auth keystore dnssec

Prefix command, only usable via sub-commands

```
tdns-cli auth keystore dnssec [flags]
```

### Options

```
  -h, --help   help for dnssec
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

* [tdns-cli auth keystore](tdns-cli_auth_keystore.md)	 - Prefix command to access different features of the keystore
* [tdns-cli auth keystore dnssec add](tdns-cli_auth_keystore_dnssec_add.md)	 - Add a new DNSSEC key pair to the keystore
* [tdns-cli auth keystore dnssec algorithms](tdns-cli_auth_keystore_dnssec_algorithms.md)	 - List the DNSSEC algorithms the server supports
* [tdns-cli auth keystore dnssec clear](tdns-cli_auth_keystore_dnssec_clear.md)	 - Permanently delete all DNSSEC keys for a zone (KeyStateWorker will regenerate as needed)
* [tdns-cli auth keystore dnssec delete](tdns-cli_auth_keystore_dnssec_delete.md)	 - Delete DNSSEC key pair from TDNSD keystore
* [tdns-cli auth keystore dnssec ds-push](tdns-cli_auth_keystore_dnssec_ds-push.md)	 - Compute DS RRset from keystore and push to parent (UPDATE-only in this offline mode)
* [tdns-cli auth keystore dnssec export](tdns-cli_auth_keystore_dnssec_export.md)	 - Export a DNSSEC key pair from the keystore as BIND-style .private/.key files
* [tdns-cli auth keystore dnssec gen-ds](tdns-cli_auth_keystore_dnssec_gen-ds.md)	 - Generate DS records for a zone's KSK(s) from the keystore
* [tdns-cli auth keystore dnssec generate](tdns-cli_auth_keystore_dnssec_generate.md)	 - Generate a new DNSSEC key pair and add it to the keystore
* [tdns-cli auth keystore dnssec import](tdns-cli_auth_keystore_dnssec_import.md)	 - Add a new DNSSEC key pair to the keystore
* [tdns-cli auth keystore dnssec list](tdns-cli_auth_keystore_dnssec_list.md)	 - List all DNSSEC key pairs in the keystore
* [tdns-cli auth keystore dnssec policies](tdns-cli_auth_keystore_dnssec_policies.md)	 - List the DNSSEC policies the server loaded (including any in error)
* [tdns-cli auth keystore dnssec policy](tdns-cli_auth_keystore_dnssec_policy.md)	 - DNSSEC policy utilities
* [tdns-cli auth keystore dnssec policy-cleanup](tdns-cli_auth_keystore_dnssec_policy-cleanup.md)	 - Remove a zone's retired keys (and their RRSIGs) now, keeping active keys
* [tdns-cli auth keystore dnssec purge](tdns-cli_auth_keystore_dnssec_purge.md)	 - Delete keys in 'removed' state, keeping the 3 most recent per zone
* [tdns-cli auth keystore dnssec query-parent](tdns-cli_auth_keystore_dnssec_query-parent.md)	 - Query configured parent-agent for child DS (poll until match or timeout)
* [tdns-cli auth keystore dnssec rollover](tdns-cli_auth_keystore_dnssec_rollover.md)	 - Perform a manual DNSSEC key rollover (standby→active, active→retired)
* [tdns-cli auth keystore dnssec setstate](tdns-cli_auth_keystore_dnssec_setstate.md)	 - Set the state of and existing DNSSEC key pair in the TDNSD keystore

