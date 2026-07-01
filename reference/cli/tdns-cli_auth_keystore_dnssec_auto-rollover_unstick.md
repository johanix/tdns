## tdns-cli auth keystore dnssec auto-rollover unstick

Skip the softfail-delay and probe the parent on the next tick

### Synopsis

Asks the daemon to clear next_push_at on the zone row so the
rollover engine fires a probe UPDATE on its very next tick instead of
waiting out the rest of the softfail-delay window. Operator override
for "I just fixed the parent and want to retry now."

Operationally optional: the engine polls the parent continuously
regardless of softfail-delay, so a parent fix is auto-detected within
confirm-poll-max even without 'unstick'. Use only to skip the wait.

Default mode talks to the daemon's API server. Use --offline to write
directly to the keystore file when the daemon is down (postmortem
use). The CLI checks the daemon sentinel via refuseIfDaemonAlive
and refuses to run if a live daemon is detected; --force overrides
the check for cases where the sentinel is stale.

Hardfail_count and last_softfail_* are preserved so status output
still shows the most recent failure context. The counter resets to 0
on the next successful confirmed observation.

Differs from 'reset' (which clears last_rollover_error for one keyid).

```
tdns-cli auth keystore dnssec auto-rollover unstick [flags]
```

### Options

```
      --force         With --offline: override the daemon-alive check
  -h, --help          help for unstick
      --offline       Write directly to keystore file (postmortem use; daemon is down)
  -z, --zone string   Zone
```

### Options inherited from parent commands

```
      --config string   config file (default is /etc/tdns/tdns-cli.yaml)
  -d, --debug           debug output
  -H, --headers         show headers
      --ksk             Render only the KSK section (status / when); ignored by other subcommands
  -Z, --pzone string    parent zone name
  -v, --verbose         verbose output
      --zsk             Render only the ZSK section (status / when); ignored by other subcommands
```

### SEE ALSO

* [tdns-cli auth keystore dnssec auto-rollover](tdns-cli_auth_keystore_dnssec_auto-rollover.md)	 - Manage and inspect automated KSK rollover (scheduled + manual-ASAP)

