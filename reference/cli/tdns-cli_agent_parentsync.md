## tdns-cli agent parentsync

Parent delegation sync commands

### Options

```
  -h, --help   help for parentsync
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

* [tdns-cli agent](tdns-cli_agent.md)	 - TDNS Agent commands
* [tdns-cli agent parentsync bootstrap](tdns-cli_agent_parentsync_bootstrap.md)	 - Trigger SIG(0) KEY bootstrap with parent for a zone
* [tdns-cli agent parentsync delta](tdns-cli_agent_parentsync_delta.md)	 - Compute delta between parent delegation data and child zone data
* [tdns-cli agent parentsync election](tdns-cli_agent_parentsync_election.md)	 - Trigger leader re-election for a zone
* [tdns-cli agent parentsync inquire](tdns-cli_agent_parentsync_inquire.md)	 - KeyState EDNS(0) inquiry commands
* [tdns-cli agent parentsync status](tdns-cli_agent_parentsync_status.md)	 - Show parent sync status for a zone
* [tdns-cli agent parentsync sync](tdns-cli_agent_parentsync_sync.md)	 - Sync delegation data in parent zone via DDNS UPDATE

