## tdns-cli agent keystore dnssec

Prefix command, only usable via sub-commands

```
tdns-cli agent keystore dnssec [flags]
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
  -z, --zone string     zone name
```

### SEE ALSO

* [tdns-cli agent keystore](tdns-cli_agent_keystore.md)	 - Prefix command to access different features of the keystore
* [tdns-cli agent keystore dnssec add](tdns-cli_agent_keystore_dnssec_add.md)	 - Add a new DNSSEC key pair to the keystore
* [tdns-cli agent keystore dnssec algorithms](tdns-cli_agent_keystore_dnssec_algorithms.md)	 - List the DNSSEC algorithms the server supports
* [tdns-cli agent keystore dnssec auto-rollover](tdns-cli_agent_keystore_dnssec_auto-rollover.md)	 - Manage and inspect automated KSK rollover (scheduled + manual-ASAP)
* [tdns-cli agent keystore dnssec clear](tdns-cli_agent_keystore_dnssec_clear.md)	 - Permanently delete all DNSSEC keys for a zone (KeyStateWorker will regenerate as needed)
* [tdns-cli agent keystore dnssec delete](tdns-cli_agent_keystore_dnssec_delete.md)	 - Delete DNSSEC key pair from TDNSD keystore
* [tdns-cli agent keystore dnssec ds-push](tdns-cli_agent_keystore_dnssec_ds-push.md)	 - Compute DS RRset from keystore and push to parent (UPDATE-only in this offline mode)
* [tdns-cli agent keystore dnssec export](tdns-cli_agent_keystore_dnssec_export.md)	 - Export a DNSSEC key pair from the keystore as BIND-style .private/.key files
* [tdns-cli agent keystore dnssec gen-ds](tdns-cli_agent_keystore_dnssec_gen-ds.md)	 - Generate DS records for a zone's KSK(s) from the keystore
* [tdns-cli agent keystore dnssec generate](tdns-cli_agent_keystore_dnssec_generate.md)	 - Generate a new DNSSEC key pair and add it to the keystore
* [tdns-cli agent keystore dnssec import](tdns-cli_agent_keystore_dnssec_import.md)	 - Add a new DNSSEC key pair to the keystore
* [tdns-cli agent keystore dnssec list](tdns-cli_agent_keystore_dnssec_list.md)	 - List all DNSSEC key pairs in the keystore
* [tdns-cli agent keystore dnssec policies](tdns-cli_agent_keystore_dnssec_policies.md)	 - List the DNSSEC policies the server loaded (including any in error)
* [tdns-cli agent keystore dnssec policy](tdns-cli_agent_keystore_dnssec_policy.md)	 - DNSSEC policy utilities
* [tdns-cli agent keystore dnssec policy-cleanup](tdns-cli_agent_keystore_dnssec_policy-cleanup.md)	 - Remove a zone's retired keys (and their RRSIGs) now, keeping active keys
* [tdns-cli agent keystore dnssec purge](tdns-cli_agent_keystore_dnssec_purge.md)	 - Delete keys in 'removed' state, keeping the 3 most recent per zone
* [tdns-cli agent keystore dnssec query-parent](tdns-cli_agent_keystore_dnssec_query-parent.md)	 - Query configured parent-agent for child DS (poll until match or timeout)
* [tdns-cli agent keystore dnssec rollover](tdns-cli_agent_keystore_dnssec_rollover.md)	 - Perform a manual DNSSEC key rollover (standby→active, active→retired)
* [tdns-cli agent keystore dnssec setstate](tdns-cli_agent_keystore_dnssec_setstate.md)	 - Set the state of and existing DNSSEC key pair in the TDNSD keystore

