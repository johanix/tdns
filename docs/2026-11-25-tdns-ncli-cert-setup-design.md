# tdns-ncli certificate setup: one writer per file

Date: 2026-11-25
Status: PROPOSAL, r3. All questions decided. Not implemented. Replaces the approach of tdns #1184
(`config add: client certificates by default`), which stays a draft for
reference and is closed when PR 2 opens (Q5). Builds on
2026-11-20-api-pinning-mtls-roles-design.md (the access file, the roles,
admin on the local socket only) and #1182 (the daemon's default API pair).

Revisions:

- r1, 2026-11-25: first cut. Johan agreed to rules 1 and 2 and to rule 3
  on 11-25, with one addition: switching an existing entry, for example
  from the API key to a client certificate, needs automation of its own.
  That is `config update` (section 5).
- r2, 2026-11-25: Johan's answers. Q1 yes: every access-file write goes
  through the daemon. Q3 yes: #1182's CLI pair-making goes. Q4 yes:
  `config update` with `--cert` and `--repin`. Q5: #1184 is closed when PR
  2 opens. Q2 stays open; section 10 now lists what turning on an access
  file changes, and corrects (b): a `config reload` is enough, no restart.
- r3, 2026-11-25: Q2 decided (b): with no `access-file:` the commands stop
  with the line to add (section 4).
- r3a, 2026-11-25: section 4 corrected. There is one entry per daemon, as on
  main (Johan's 11-23 ruling: no `unix://` entries). A stopped daemon gets
  the `config-file:`-only entry, and `config update --cert` completes it.
  The builder session caught the error.

## 1. Why #1184 is replaced

#1184 grew from about 1,070 to about 3,030 lines of code (plus 4,190 lines
of tests) in 44 commits. The CodeRabbit finding counts per round did not
fall: 14, 7, 5, 4, 6, 10. The rig and the external reviewer found it working
on the normal paths, and almost every new finding was another way two
events can interleave.

The cause is the shape of the design. In #1184, `config add` runs a
transaction across five things with different owners:

- the CLI config (the operator's);
- the daemon config;
- the access file;
- the daemon's API certificate pair;
- the running daemon's in-memory state, which may not match its files.

The daemon may also be running, stopped, starting, or not the daemon that
answers the socket, and two adds may run at once. Every pair of states that
can drift apart becomes a corner case, and rollback across five places
multiplies them. More rounds would find more of them.

## 2. Three rules

1. **One writer per file.** The daemon writes its own files: the access
   file and its API certificate pair. tdns-ncli writes only the CLI config
   and the operator's own client pair. Enrolling a certificate is one call
   to the daemon over the local socket.
2. **Certificate setup needs a running daemon.** For a stopped daemon,
   `config add` writes what needs no daemon and says what to run once it is
   up. tdns-ncli never makes the daemon's API certificate pair.
3. **`config add` writes new entries only.** It never changes an existing
   entry. Changing one is `config update` (section 5), one named entry at a
   time.

What follows from them:

- **No rollback.** Each step leaves a state that is valid on its own. The
  one state that can be left over is an enrolled pin with no CLI entry. It
  is the operator's own pin, harmless, shown by `client list`, and the next
  run reuses it.
- **No CLI-side locks on daemon files.** The daemon serializes its own
  writes. tdns-ncli takes one lock: the CLI config's.
- **No reasoning about which file the daemon runs.** After enrolling,
  tdns-ncli makes one real request over TCP with the certificate and the
  server pin. If it works, the entry works; if not, nothing is written.

## 3. The daemon: access changes over the socket

A new route, admin only, so the local socket only (TCP is at most
read-write, 2026-11-20 §3.4):

```
POST /access   {command, name, pin, role, comment}
  command: list | add | disable | enable | set-role | keyauth
```

For a write the daemon:

1. takes its own lock;
2. reads the access file, applies the change and validates the result
   (`ValidateAccessFile`, as `client add` does today);
3. writes it atomically, keeping `<name>.prev`, with the file's owner and
   mode (a new file: 0600);
4. loads it as its access policy, as a reload does;
5. answers with what is now in force: the clients, `keyauth`, the access
   file's path, and the SPKI pins of the certificate its TCP API serves.

`add` is idempotent. The same name with the same pin and role answers
"already there". The same name with another pin is refused ("disable it
first, or use another name"). A refused change writes nothing.

`list` returns the same answer without changing anything. It is also how
`config add` reads the server pins of a running daemon: from the
certificate the daemon serves, not from a file on disk.

**The existing `client` commands become callers of this route** (Q1, Johan,
2026-11-25: yes). `client
add|disable|enable|set-role|keyauth|list` keep their names and flags, so
the command in step 3 of the ownership design (2026-11-23 §5) is unchanged.
What changes is underneath: they no longer edit the file, take a lock or
reload. The code that does that moves from v2/cli/client_cmds.go into the
daemon, and the CLI's checks of the reload (`runsConfig`,
`verifyRunningDaemon`, `accessReloadVerdict` and their kin) go.

What this costs: the `client` commands need a running daemon. The access
file stays plain YAML, so a stopped daemon's file can still be edited by
hand and checked with `config check`. Lock-out is still impossible: the
socket does not depend on the access file (2026-11-20 §4).

## 4. `config add`

`config add <daemon.yaml>` runs as root on the daemon's host, as it does
today: it reads the daemon config, and the socket is root's.

**One entry per daemon**, as on main (Johan, 2026-11-23: no `unix://`
entries; root reaches the socket through the entry's `config-file:`).

**A running daemon** (the socket answers):

1. Make the operator's client pair if there is none (`ensureClientCert`,
   as `client init` does).
2. `add` the pin over the socket: name from `--name`, default the client
   name `client init` uses; role read-write. The answer carries the server
   pins.
3. Make one request over TCP with the client certificate and the server
   pins (`ping`).
4. Under the CLI config's lock, write the entry: base URL, server pins,
   `authmethod: certificate`, `config-file:` naming the daemon config. No
   API key.

If step 2 or 3 fails, nothing is written to the CLI config, and the output
says why, in the daemon's words. If step 4 fails, the pin stays enrolled
and the next run reuses it.

**A stopped daemon:** write the entry with `config-file:` only (no base URL),
which reaches the socket once the daemon runs. The output names `config
update <entry> --cert`, which fills in the base URL, pins and certificate
once the daemon is up. The daemon makes its API pair at its first start
(#1182), so the pair is never made by tdns-ncli.

**An entry for this daemon already exists:** it is left alone, and the
output names the `config update` command that would change it.

**A daemon config that names no access file** (Q2, Johan, 2026-11-25):
`config add`, `config update --cert` and `client add` stop with an error. It
gives:
- the exact `access-file:` line to add, with the suggested path;
- what turning the access file on changes: the API key drops to read-write
  on TCP, the TCP API needs TLS, and it takes TLS 1.3 only;
- the `config reload` that makes the daemon read it (no restart needed).

Then the operator runs the command again. No tool writes the daemon config.
`/access add` refuses the same case, so the daemon gives the same answer to
any caller.

## 5. `config update`

```
tdns-ncli config update <entry> --cert    # API key -> client certificate
tdns-ncli config update <entry> --repin   # take the daemon's current pins
```

Johan, 2026-11-25: switching an existing entry must be automated, not left
to hand edits. The access model is detailed for a reason, so tdns-ncli must
carry the operator through it.

Each run changes one named entry, in one way, and follows the steps of
section 4:

- **`--cert`:** steps 1 to 3 of `config add` for the entry's daemon, then
  rewrite the entry in place (adding the base URL to a `config-file:`-only
  entry): `authmethod: certificate`, the API key line
  removed, the server pins set from the daemon's answer. Every other line
  is kept (the YAML entry editor in v2/cli/apiservers_edit.go).
- **`--repin`:** `list` over the socket, a request over TCP with the new
  pins, then the entry's pins are replaced with the ones the daemon serves
  now. Old pins are dropped: after a rotation they name a key that is no
  longer in use.

The entry must name its daemon config (`config-file:`). An older entry
without that line needs `--daemon-config <file>`, and `config update` then
writes the line. It never guesses the daemon from the entry's address.

The same as for `config add`: the daemon must be running and local, and if
anything before the rewrite fails, the entry is left as it was.

## 6. Not handled, by design

These are outside the design. A review finding about them is answered by
reference to this section, not with code.

- Setting up a certificate for a stopped daemon.
- Files changed by hand, or by another tool, while a command runs.
- A daemon config that changes between the socket call and the TCP check
  (the TCP check fails, nothing is written, a rerun works).
- Daemons on another host. A remote operator uses `client init`, sends the
  pin, and the daemon's admin runs `client add` (2026-11-20 §3), as today.
- `config update` back from a certificate to the API key (later, if needed).
- Switching more than one entry per run.

**Review discipline.** Each PR states the rounds it took. If a round's
findings do not fall, the PR stops and Johan is asked before the next fix.

## 7. What changes in code already on main

- **#1182's CLI side:** `defaultApiCert`, `writeApiCert` and
  `unwriteApiCert` in v2/cli/cli_config_cmds.go go (rule 2; Q3, Johan,
  2026-11-25: yes). The daemon still makes its pair at start.
- **#1168's `client` commands:** they become callers of `/access`
  (section 3).

## 8. From #1184, kept

- `--daemon-config <file>` on the `client` commands and `config reload`, and
  running them without a CLI config (`cli.NoCliConfigNeeded`).
- The YAML entry editor's `config-file:` line (v2/cli/apiservers_edit.go).
- The fake daemon in cmdv2/ncli/daemon_config_test.go, for the tests.

Everything else in #1184 is not carried over: the cert setup plan
(`config_add_cert.go`), the locks on daemon files, rollback, the
re-planning under locks, the key verdicts and the conversion of known
entries inside `config add`.

## 9. PRs and size

| PR | What | Code, net | Tests |
|---|---|---|---|
| 1 | `/access` on the socket; `client` commands call it | about +250 | about 300 |
| 2 | `config add` per section 4; #1182's CLI pair code removed | about +200 | about 300 |
| 3 | `config update --cert`, `--repin` | about +250 | about 300 |

About 700 lines of code in all, against about 3,030 in #1184. PR 2 and PR 3
depend on PR 1. Each one is rig-tested on the lab's test VM, like #1184.

The ownership stack (#1186 to #1189) does not depend on any of this. #1187
adds `CheckAccessClientName` to `client add`. PR 1 moves that check to the
daemon, so whichever merges second adapts. The integration branch
`claude/integ-ncli-20261124` holds #1184 and is rebuilt without it when PR
2 opens.

## 10. Questions

Decided by Johan, 2026-11-25:

- **Q1. All access-file writes through the daemon:** yes. The `client`
  commands become callers of `/access` (section 3).
- **Q3. #1182's CLI pair-making leaves main:** yes (section 7). A daemon
  that has never started gets only its socket entry until it starts.
- **Q4. `config update` in this round: `--cert` and `--repin`:** yes.
  `--key` (back to the API key) later, if anyone needs it.
- **Q5. #1184:** closed when PR 2 opens.
- **Q2. A daemon config with no `access-file:`:** (b), stop with the line
  (section 4). The background follows.

Not decided: whether the sample configs carry the line uncommented. New
installs would then start with the key at read-write on TCP. They stay as
they are unless Johan says otherwise.

- **Q2 background.** tdns-ncli needs a change
  that only the daemon's access file can hold, and without an access file
  the daemon takes only the key. Turning an access file on changes three
  things for that daemon (code on main):
  - the API key drops from admin to read-write on TCP (v2/api_auth.go:143
    and :173);
  - the TCP API requires TLS; with `usetls: false` its TCP listeners stay
    off (v2/apirouters.go:538);
  - the TCP API takes TLS 1.3 only.

  The options:
  - (a) A default path, as the socket got on 11-23: unset means the
    default, and `none` means no access file. A missing file means key only,
    as today. The first `client add` creates the file, so the three changes
    above happen as a side effect of adding a client. That first add would
    have to say so, and refuse a daemon whose TCP API has no TLS.
  - (b) `config add` and `client add` stop with an error. It gives the
    exact line to add, what that line changes (the three points above) and
    the `config reload` that makes the daemon read it. No restart is needed;
    a reload can add an access file (v2/apirouters.go:239). Then run the
    command again.

  The sample configs carry the line commented out today. With (b), they
  could carry it uncommented, so new installs never meet the stop.
