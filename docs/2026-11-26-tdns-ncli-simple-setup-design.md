# tdns-ncli: fewer optional steps (follow-up to the cert-setup stack)

**Written 2026-11-26, r2; status 2026-11-27, r3.** r2 adds Johan's later
comments from that evening: the API key decision, the vocabulary, one-line
commands, no error twice, Change 4 and the table of optional knobs. Every
question is decided (below).

**Status (2026-11-27):** implemented, with the removal of API keys, in one
PR, #1210 (branch `claude/simple-setup`, open, not merged), after Johan's
go of 2026-11-27. tdns-mp's CLI and deployment scripts outside this repo need
companion changes (see "What breaks"); those are not made yet. The choices
the implementation had to make that this design left open are in "As
built" at the end. CodeRabbit's first round (on a7b7825e, 22 findings) is
answered: 3 were fixed already, 2 declined, and the other 17 fixed in the
commit after 15aadff3.
It follows the cert-setup stack (#1198, #1200, #1202) and is meant to come
right after that stack merges.

**Decided later on 11-26:** API key support will be dropped once the stack
has merged, because as it stands the setup is "very close to unusable". The
losses (bootstrap from a shared string, clients that only send headers, TLS
proxies, plaintext loopback) don't matter, and the migration cost is paid
once. With keys gone, Change 1 below gets simpler: the key's role, `keyauth`
and the TLS-only question disappear. Changes 2 and 3 stand as they are.

## Why

On a test host, the merged-to-be stack was usable, but not simple. Three things
got in the way:

1. **The access file is opt-in.** `config add` stops and asks the operator to
   add `access-file:` to the daemon config and reload. For tdns-imr the
   advised reload command does not even exist (`tdns-ncli imr config` has no
   `reload`).
2. **Errors play "20 questions".** Each refusal names one missing piece. The
   operator supplies it and gets the next refusal:
   `config update auth` → give `--cert` or `--repin` → no entry named "auth"
   → "tdns-auth" already uses a certificate.
3. **A daemon has two names.** The first tdns-auth's entry is `tdns-auth`,
   but its commands are `tdns-ncli auth …`. A second one is `auth2` in both
   places.

## Where the opt-in came from

The access file and its opt-in come from the 11-20 design
(`docs/2026-11-20-api-pinning-mtls-roles-design.md`, #1167/#1168):

- **It was a separate file** so that tdns-ncli could own it without touching
  the daemon config: "The tool may change one thing: the access file. It never
  touches the main daemon config."
- **It was opt-in** because of API keys: the design "keeps everything as it is
  until the operator opts in". An access file drops the key from admin to
  read-write on TCP, requires TLS, and allows TLS 1.3 only.

Since the stack, the daemon is the only writer of the access file (the
`/access` route on its socket). The first reason is gone. The second one
remains as long as API keys are admin on TCP.

## Change 1: the access file is always on

- **Default path:** `<config dir>/<config name>-access.yaml`, for example
  `/etc/tdns/tdns-auth-access.yaml`. `apiserver.access-file:` stays, but only
  to choose another path. The daemon never edits its own config.
- **The operator creates the file; the tools only manage what's in it**
  (Johan, 11-26). This works like the socket: an explicit `access-file:` is
  fine, and without one the default is used. Turning on remote access is one
  deliberate act, `touch <file>`, with no edit of the daemon config. Neither
  the daemon nor tdns-ncli ever creates the file. The `/access` route writes
  only into a file that exists.
- **The path is always spelt out.** Every message about it names the real
  file. The first `config add` or `client add` on a daemon without the file
  refuses with the complete command:

  ```
  Error: access file /etc/tdns/tdns-auth-access.yaml is missing, so
  tdns-auth takes no remote clients. Create it (empty is fine):
     touch /etc/tdns/tdns-auth-access.yaml
  then run this again:
     tdns-ncli config add /etc/tdns/tdns-auth.yaml
  ```

  No reload is needed: `/access` reads the file at each call, and the add
  loads it.
- **A missing file is a normal state, not an error.** It means socket only,
  no remote clients. The daemon logs it at INFO, so log sweeps for ERROR stay
  clean. `config status` shows it with the touch line.
- **An empty file is a valid empty policy.** `ParseAccessFile` already
  treats zero bytes that way (`v2/api_access.go:91`).
- **The daemon refuses an access file that others can write.** Anyone who
  can write the file can grant themselves access. Today `LoadAccessFile`
  (`v2/api_access.go:170`) checks neither owner nor mode. The new rule:
  owned by the daemon's user (root) and not writable by group or others.
  The refusal gives the `chown`/`chmod` line. `touch` under umask 022 makes
  0644, which passes: pins and roles are not secrets.
- **A file that exists but fails to load stays fail-closed,** as today: the
  TCP API answers 503 and the socket still works.
- **The API key is read-write on TCP, everywhere.** Admin is the local socket
  only, i.e. root on the daemon's host. `keyauth on|off` stays the switch for
  the key until keys are dropped.
- **The TCP API is TLS only, TLS 1.3.** `usetls: false` no longer starts a
  plaintext TCP listener.
- **The socket is on by default.** It already has a default path
  (`DefaultApiSocketDir`, `v2/api_socket.go:46`); the daemon config only
  overrides it.

What this removes from the stack:
- the stop in `config add` and `config update --cert`, and its advice
  (`noAccessFileAdvice`, `v2/api_access_route.go:436`), including the reload
  command per daemon type, which is wrong for tdns-imr;
- the "not there yet" state and its reload text (F2), and the start-up 503
  for a missing file (F4, `failedAtStart`);
- the "API key is admin again" path when an access file is removed.

## Change 2: every refusal ends with a complete command

**The rule:** a refusal ends with a command that works for this config as
printed. If it depends on which entry is meant, it gives one line per entry.
Checking every argument comes first, so the first refusal is the only one.

For that exchange, the first error would have been:

```
Error: config update needs an entry and --cert or --repin.
Your entries in /etc/tdns/tdns-ncli.yaml:
   auth   certificate  tdns-ncli config update auth --repin
   auth2  API key      tdns-ncli config update auth2 --cert
```

**A command stays on one line when it fits.** The 72-column budget includes
the indent. Break a command only when it does not fit, then only between
flags, with a trailing backslash. Today `noAccessFileAdvice`
(`v2/api_access_route.go:459`) always breaks the reload command, even though
`   tdns-ncli imr config reload --daemon-config /etc/tdns/tdns-imr.yaml` is 70
columns. The test above checks that a printed command is on one line whenever
it would fit.

**Say "certificate", not "key".** There are two ways to authenticate, an API
key and a certificate, so "key" must mean only the API key. A message that
speaks of a daemon's "key", or of pinning "the same key", signals the wrong
method, even though the pin really is a hash of the certificate's public key
(SPKI). The vocabulary rule:
- **API key:** the shared secret (`apikey:`, X-API-Key). Nothing else is
  called a key in API messages.
- **Certificate:** the daemon's or a client's certificate, named with its file
  where the tool knows it.
- **Certificate pin:** what an entry or the access file holds. "The daemon's
  certificate changed", never "a new key on the daemon".
- The docs explain once that a pin covers the certificate's public key, so a
  renewed certificate with the same key keeps its pin.

The messages to fix include `duplicatePins` (`v2/cli/cli_config_cmds.go:1268`,
"pin the same key… a key of its own"), the pin refusal (`v2/apiclient.go:247`,
"a new key on the daemon") and the daemon's log line when it writes its
certificate (`v2/api_cert.go:87`, "clients pin its key"). DNSSEC, TSIG and
SIG(0) keys are not affected. The same rule covers warnings. `config list`'s
duplicate-pin warning (`duplicatePins`, `v2/cli/cli_config_cmds.go:1241`),
seen on a test host on 11-26, where tdns-auth and tdns-imr both name
`/etc/tdns/certs/api.crt` under `apiserver:`, would read:

```
Warning: tdns-auth and tdns-imr use the same API certificate
(/etc/tdns/certs/api.crt): the CLI cannot tell them apart, so a
command meant for one is accepted by the other. To give tdns-imr
its own, remove certfile: and keyfile: under apiserver: in
/etc/tdns/tdns-imr.yaml and restart tdns-imr (at start it writes
/etc/tdns/certs/tdns-imr-api.crt). Then run:
   tdns-ncli config update imr --repin
```

**No error twice, and no repeated lead.** On the test host, a wrong flag printed
"Error: unknown flag: --daemon-config" twice: cobra printed it with the usage,
then our printer printed it again. The no-access-file stop opened with
"Error: No access file: …" and its next line began "No access file: …" again.
Each error says its verdict once.

A test enforces it: for each refusal in the `config` and `client` commands,
the printed command is parsed against the cobra tree, and it must exist with
those flags. That would have caught the imr `config reload`.

## Change 3: one name per daemon

**The rule:** an entry's name is its command word. Today
`RegisterRole("auth", "tdns-auth")` (`v2/cli/apiclient.go:136`) maps the
command `auth` to the entry `tdns-auth`. That is a leftover from before
instances, when entries were named after the program.

- Every entry has a name and a role. The first daemon of a role gets the
  role as its name (`auth`, `imr`, `agent`). Later ones get a name from the
  config file name, or `--name`, as now.
- The special case where a role-less row named `tdns-auth` is the canonical
  entry goes away (`chooseEntryName`, `checkInstanceEntries`), and so do the
  reserved names.
- Every command that takes an entry name takes that name. `config update
  auth` then just works.

## Change 4: every daemon's tree has the same config commands

`tdns-ncli imr config` has only `check`, `mwe` and `status`, though tdns-imr
serves `/config` with `reload` (`SetupSimpleAPIRouter`). Anything printed for
"a daemon" then fails for tdns-imr. **The rule:** every command a daemon's API
serves for operators has a command in that daemon's tree, under the same name
as in the other trees. A test compares each router's `/config` commands with
the tree's.

## The optional knobs, today and after

Johan's complaint is that there are too many optional steps. Here is every
knob an operator meets in the cert setup, and what happens to it once API keys
are dropped and Changes 1–4 are in:

| Knob | Today | After |
|---|---|---|
| `apiserver.apikey` | required in every daemon config (`validate:"required"`), even when unused | gone |
| `keyauth on/off` | turns the key off in the access file | gone |
| `authmethod:` on an entry | `apikey` or `certificate` | gone: always a certificate |
| `access-file:` | opt-in, by hand, then a reload | default path, set only to move it; remote access starts when the operator runs `touch <file>` |
| `socket:` | has a default path | unchanged; always on |
| `usetls:` | TCP API may be plaintext | gone: the TCP API is TLS 1.3 |
| `tlsauth:` on an entry | `pin` or `rootca` | gone: pins only (Q3) |
| `client:` block | where the CLI's pair is; has defaults | unchanged; override only |
| `config-file:` on an entry | optional; without it, `--daemon-config` is needed | written by `config add` for a local daemon; a remote one needs none |
| canonical row vs instance | a role-less `tdns-auth` row is special | gone (Change 3) |

## What breaks, and what to check first

- **Admin commands over TCP with the key** stop working. They need the
  socket, as with an access file today. Before implementing, list which
  callers do that: tdns-mp's CLI, the rigs and other deployment scripts.
- **Plaintext TCP API.** Deployment scripts outside this repo may have
  `usetls: false` and `http://` baseurls. tdns-mp's samples already use
  https.
- **Old entry names.** CLI configs with a `tdns-auth` or `tdns-imr` entry
  (see Q4).
- **Sample configs:** 31 files in tdns mention `apikey`. They need the
  `access-file:` and `socket:` lines dropped and the key's role explained.

## Size and shape

**One PR (Q6)** holds Changes 1–4 and the removal of API keys. It goes after
the check above, and alongside the migration of tdns-mp's CLI, other
deployment scripts and the sample configs.

Roughly +300 and -500 lines in total, most of the minus from the stack's
opt-in code.

## Questions for Johan

All decided on 2026-11-26, as below.

- **Q1, decided 11-26:** the access file is always read if it exists. If it
  does not exist, access is root only, through the socket.
- **Q4, decided 11-26:** no compatibility for old entry names ("KISS").
  `config check` fails on a `tdns-auth` or `tdns-imr` entry and prints the
  rename.
- **Q5, decided 11-26:** the rule covers the `config` and `client` commands
  first, where today's complexity and confusion are.
- **Q6, decided 11-26:** one PR, with Changes 1–4 and the key removal.
- **Q2, decided 11-26:** remove API keys in the same PR as the always-on
  access file.
- **Q3, decided 11-26:** drop `tlsauth: rootca`. Pins only.
- **Q7, decided 11-26:** the daemon may create its own certificate and key
  files (#1182, `EnsureDefaultApiCert`). In Johan's words, the restriction
  "is only about creating/changing its own *config*". So the rule is:
  - the daemon config is never created or changed by the daemon or by
    tdns-ncli;
  - the access file is config that the operator creates (`touch`), and the
    daemon then manages its contents through `/access`;
  - certificate and key files are the daemon's own, and it creates them as
    needed.

## As built (2026-11-27)

Choices the implementation made where this design was silent. Each can be
changed in the PR.

- **A daemon config with `apikey:` or `usetls:` still starts.** The daemon
  logs one WARNING per line ("no longer used ... Delete the line"), and
  `config check` warns the same. This lets old and new binaries share a rig
  config, and keeps ERROR sweeps clean.
- **An access file with `keyauth:` still loads.** The line is ignored (a
  WARNING says so), and the daemon's next write of the file drops it.
- **Every TCP request checks the access file** (a `stat`): one created,
  edited, chmodded or removed since the last load is loaded again, so it is
  in force at the next request, and removing it takes remote access away
  then. A missing file is logged at INFO once, not on every load.
- **`config add` and `config update --cert` reuse a certificate the access
  file has already**, under any name: they enrol it only when it is not
  there. A disabled one is refused with the `client enable` command.
- **The file check:** owner the daemon's user or root, and not writable by
  group or others. The refusal gives `chmod go-w <file>` or `chown <user>
  <file>`. The check is of the file read (one open file for both), so a
  file swapped in between cannot pass.
- **The client library sends https only** over TCP: an `http://` base URL,
  or a redirect to one, fails before anything is sent.
- **`socket: none` with an access file is allowed**: no admin anywhere is
  the operator's choice. (Before, an access file required the socket.)
- **The CLI config has a `config check` of its own** (`tdns-ncli config
  check`): Q4's "config check fails on an old entry" needed a command that
  checks the CLI config. It fails on an old name, plain `http://` (or any
  scheme but `https://` and `unix://`) and an https entry without pins, each
  with its fix; leftover key lines are notes.
- **`config update <entry> --rename <name>`** makes the rename a complete
  command, as Change 2 asks. It needs no daemon, and combines with `--cert`
  or `--repin`. A name that is a command of the CLI (`config`) is refused,
  as `config add` refuses it. A role's own entry renamed this way (`auth`)
  starts and restarts without `config-file:`, on the role's default config.
- **`--cert` works on an entry that has pins already**: it enrols the client
  certificate again ("already there") and takes the pins. It is the one
  command that makes an entry work; `--repin` takes new pins only.
- **An entry with an old name is never used.** A command that needs it
  refuses with the rename; `config add` refuses to add the role's entry while
  one is there.
- **`daemon start`, `stop` and `restart` need no API client.** Starting
  needs only the command, so an entry with no client (no baseurl and its
  daemon not running yet, or no client certificate) uses its daemon's local
  admin socket to see whether it runs. Not when the entry's TCP address is
  one its daemon config does not list: that may be another host's daemon.
- **An entry whose TCP address its daemon config does not list:** when
  the address is on this host (loopback, or one of its own addresses), it
  is a stale address of this host's daemon. The entry then uses the local
  admin socket (the daemon there must still say it runs the entry's
  `config-file:`), with a warning that gives `config update <entry>
  --cert`. An address on another host keeps the entry off this host's
  socket, as before. When its TCP path then refuses (no pins, no client
  certificate), or `ping` finds nothing at the address, the error says the
  address is not the daemon's, with the same fix.
- **An entry without `config-file:`** gets a fix command with the daemon
  config it most likely is: the role's default for a role's entry
  (`/etc/tdns/tdns-auth.yaml`), else `/etc/tdns/tdns-<name>.yaml`.
- **Two entries of one name:** the first counts, the later is ignored and
  `config list` says why.
- **The daemon's /config commands per type** are listed in the code
  (`ConfigOperatorCommands`), and a test checks that each tree has them;
  tdns-imr's tree got `config reload`.
- **No error twice:** the CLI roots silence cobra's own error print;
  `cobra.CheckErr` prints the one `Error:` line.
- **The rigs:** ixfr-interop and the debug rig reach their daemon over its
  local admin socket; oots writes a socket entry for this build's CLI and
  keeps a key entry for older builds, so runs that mix versions still work.
  tests/cli-access is left to its rig session: its cases are built around
  keys.

## What breaks (checked 2026-11-27)

- **tdns-mp:** pinned to tdns 405f40b6, so nothing breaks before its next
  re-pin. At that re-pin: mpcli's four `X-API-Key` entries in the sample,
  `mpcli configure` (it makes keys and pings with them through
  `tdns.NewClient`, which is gone), `tests/mp-policy-matrix`, and the five
  daemon samples' `apikey:` lines (harmless). No daemon calls another over
  the management API.
- **Deployment scripts outside this repo:** CLI entries with `X-API-Key`,
  and scripts that read a daemon's key from its config, break. `apiserver.apikey`
  lines in daemon configs become dead lines (a warning at start).
