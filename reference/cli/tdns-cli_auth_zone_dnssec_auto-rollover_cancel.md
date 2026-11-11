## tdns-cli auth zone dnssec auto-rollover cancel

Cancel a pending manual KSK rollover request, or abort a KSK algorithm rollover

### Synopsis

Asks the daemon to clear manual_rollover_requested_at and
manual_rollover_earliest on the zone row. Has no effect on rollovers
that have already fired or on scheduled (lifetime-driven) rollovers.

With --ksk --alg-roll it instead ABORTS an in-flight KSK algorithm
rollover. That is only possible before the parent has confirmed the
new-algorithm DS: the new-algorithm KSK is removed and the zone returns
to idle. After confirmation an abort would be a reverse algorithm
rollover and is refused -- let the roll finish, then change policy
back.

Online-only: cancelling against a stopped daemon is meaningless (the
manual_rollover_* row isn't being read by anything).

```
tdns-cli auth zone dnssec auto-rollover cancel [flags]
```

### Options

```
      --alg-roll      Abort an in-flight KSK algorithm rollover (before the parent confirms the new-algorithm DS)
  -h, --help          help for cancel
  -z, --zone string   Zone
```

### Options inherited from parent commands

```
      --config string   config file (default is /etc/tdns/tdns-cli.yaml)
  -d, --debug           debug output
  -F, --force           force operation
  -H, --headers         show headers
      --ksk             Render only the KSK section (status / when); ignored by other subcommands
  -Z, --pzone string    parent zone name
  -v, --verbose         verbose output
      --version         print version and supported algorithms, then exit
      --zsk             Render only the ZSK section (status / when); ignored by other subcommands
```

### SEE ALSO

* [tdns-cli auth zone dnssec auto-rollover](tdns-cli_auth_zone_dnssec_auto-rollover.md)	 - Manage and inspect automated KSK rollover (scheduled + manual-ASAP)

