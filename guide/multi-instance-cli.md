# Driving several instances of one daemon: tdns-ncli

> **`tdns-ncli` is a prototype.** It is shipped alongside `tdns-cli`, not in
> place of it, precisely because it is not yet tested enough to be the
> management tool. `tdns-cli` remains that. Treat what follows as something to
> try on a deployment where you can afford to, and keep driving production
> through `tdns-cli`.

One host can usefully run more than one instance of the same tdns daemon —
two `tdns-auth` processes serving different sets of zones, each with its own
config file, database, listen addresses and management API.

`tdns-cli` assumes one instance per daemon type. It reaches the authoritative
server through the `apiservers` entry named `auth`, so a second instance
can only be addressed by pointing the whole CLI at a different config file:

```bash
tdns-cli --config /etc/tdns-second/tdns-cli.yaml auth zone list
```

on every invocation. That works, but the flag is easy to forget, and
forgetting it is silent: the command runs against the *other* server and
reports success.

**`tdns-ncli`** makes the instance a command word instead:

```bash
tdns-ncli auth    zone list      # the first tdns-auth
tdns-ncli sectdns zone list      # a second tdns-auth
```

Everything else is the same tool. `tdns-ncli`'s `auth` command tree is
identical to `tdns-cli`'s, command for command.

## tdns-ncli and tdns-cli run side by side

**That is the point, not a transition step.** `tdns-ncli` is a prototype: it
carries the multi-instance behaviour so it can be exercised without putting
`tdns-cli` — the tool everything else depends on — behind a refactor. Until it
has the testing to be a replacement, both exist and `tdns-cli` is the one to
reach for.

`tdns-ncli` is installed alongside `tdns-cli`, not in place of it. Both are
built from the same library, but **each reads its own config file**:
`tdns-cli` reads `/etc/tdns/tdns-cli.yaml`, as it always has and unchanged,
and `tdns-ncli` reads `/etc/tdns/tdns-ncli.yaml`. Only `tdns-ncli` understands
the `role:` key described below, so it gets its own file rather than sharing
`tdns-cli`'s. When `tdns-ncli` replaces `tdns-cli`, both the binary name and
the config file name change.

If you use only one instance of each daemon, there is no reason to change
anything: keep using `tdns-cli`.

## Configuration

### Adding a daemon: `config add`

You do not have to write the `apiservers:` entries by hand. Point `tdns-ncli`
at the daemon's own config file, as root on the daemon's host, and it builds
one entry for that daemon:

```bash
tdns-ncli config add /etc/tdns/tdns-auth.yaml     # the first tdns-auth
tdns-ncli config add /etc/tdns/tdns-auth2.yaml    # a second one
```

For each file it:

- reads the `apiserver:` block (`addresses`, `socket` and `access-file`)
  and builds the base URL, always https; a wildcard listen address such as
  `0.0.0.0` becomes `127.0.0.1`, since that is where the CLI connects;
- works out which daemon it is for: `service.name` (`TDNS-AUTH`, `TDNS-AGENT`),
  or, for `tdns-imr`, an `imrengine:` block with no `service:` block, or
  failing both the file name. If it cannot tell it asks for `--role
  auth|agent|imr` rather than guessing. A `tdns-mp` daemon is refused
  (`service.name` decides over the file name here too);
- names the entry. **An entry's name is the command word that reaches
  it.** The first daemon of a type is named after the type, `auth`, `agent`
  or `imr` (`tdns-ncli auth ...`). Each further one becomes an instance,
  named after its file: `tdns-auth2.yaml` gives `auth2`, reached as
  `tdns-ncli auth2 ...`. `--name` chooses another; a name that is a role, an
  existing entry, or an existing command is refused. Every entry gets its
  `role:`;
- asks the daemon over its local admin socket whether it is running.

**A running daemon** takes TLS clients once its **access file** is there:
`<config dir>/<config name>-access.yaml`, or what `apiserver.access-file`
says. The daemon never creates it, and neither does tdns-ncli; without it
`config add` stops before it does anything, naming the file:

```
Error: access file /etc/tdns/tdns-auth-access.yaml is missing, so
tdns-auth takes no TLS clients. Create it (empty is fine):
   touch /etc/tdns/tdns-auth-access.yaml
then run this again:
   tdns-ncli config add /etc/tdns/tdns-auth.yaml
```

No reload is needed: the daemon reads the file when asked. Then the daemon
gets an entry that uses your client certificate:

1. your certificate is made if you have none, as `tdns-ncli client init`
   does;
2. the daemon adds its pin to its access file, as `--client-name` (default
   `user-host`), read-write;
3. one request over TCP, with the certificate and the pins of the
   certificate the daemon serves, checks that it works;
4. only then is the entry written:

```yaml
   - name:        auth
     role:        auth
     baseurl:     https://127.0.0.1:8989/api/v1
     pins:        [ "<the SPKI pin of the daemon's certificate>" ]
     config-file: /etc/tdns/tdns-auth.yaml
```

If the daemon refuses, or the request over TCP fails, nothing is written and
the output says why, with the command to run again. A pin the daemon added
before a failure stays (`client list` shows it); the next run reuses it.

**A stopped daemon** gets an entry with `config-file:` only. Run as root,
tdns-ncli reaches the daemon's local admin socket through it once the
daemon runs. The output names the command that completes the entry once the
daemon is up, and the `touch` for its access file if that is missing:

```bash
tdns-ncli config update auth --cert
```

A daemon with a socket and no TCP address gets the same `config-file:`-only
entry, running or not. `config add` never makes the daemon's API
certificate: the daemon makes it at its first start.

`config add` needs the daemon's local admin socket. A daemon config with
`socket: none`, or a socket it cannot open (not root), is refused.

**An entry for the daemon already there** (the same `config-file:`, or the
same address) is left alone, and the output names the `config update` that
would change it: `--cert` for an entry with no pins or no address yet,
`--repin` for one with pins, and `--rename` for one with an old name. Two
daemons on one address, or one daemon config with two addresses, are
refused.

It creates `/etc/tdns/tdns-ncli.yaml` (mode 0600) if it does not exist, so the
whole file can be built from the daemons' own configs. If it does exist, the
new entry is spliced into the existing `apiservers:` list in the style of the
entries already there; comments and everything else in the file are left
alone. `--dry-run` asks the daemon whether it runs, and shows the entry and
the steps it would take, without enrolling or writing anything.

Before it writes, it loads the file with the new entry the way the CLI
loads it, and refuses if the list would not be exactly the old one plus the
new entry. That happens when `apiservers:` is also defined in an `include:`
file or in `cli.localconfig`, which replaces the list in the main file;
`--file` names the file that holds the list. An `apiservers:` written inline
(`[ ... ]`) is not edited; the error prints the entry to add by hand. Two
adds at once take turns.

A second daemon of any of the three types becomes an instance: `auth`,
`agent` and `imr` all have instance trees.

### Changing an entry: `config update`

`config add` never changes an entry that is there. `config update` changes
one, named by its `name:`:

```bash
tdns-ncli config update auth2 --cert         # enrol your certificate, take the pins
tdns-ncli config update auth2 --repin        # after the daemon's certificate changed
tdns-ncli config update tdns-auth --rename auth   # an old name
```

Given no entry, or none of the three flags, it lists your entries with the
command for each, so the first refusal is the only one:

```
Error: config update needs an entry and --cert, --repin or
--rename.
Your entries in /etc/tdns/tdns-ncli.yaml:
   auth   pinned   tdns-ncli config update auth --repin
   auth2  no pins  tdns-ncli config update auth2 --cert
```

**`--cert`** enrols your client certificate with the daemon and takes its
address and pins: for an entry of the API key era, or a `config-file:`-only
entry once its daemon is up, or one whose certificate the daemon no longer
knows. It takes steps 1 to 3 of `config add` (your certificate, its pin added
by the daemon as `--client-name`, one request over TCP), then rewrites the
entry where it stands: the daemon's TCP address if the entry had none, and
the daemon's pins. It needs the daemon's access file, as `config add` does.

**`--repin`** takes the pins of the certificate the daemon serves now, for
example after its API certificate was renewed. One request over TCP with
the new pins and your certificate, and the entry's pins are replaced; the old
ones go. An entry that has the daemon's pins already is left as it is.
tdns-ncli names this command when the daemon's certificate does not match.

**`--rename`** gives the entry a new name, which is its command word. An
entry with an old name (`tdns-auth`, `tdns-imr`, `tdns-agent`: the program's
name, which entries had before their name was their command word) is not
used at all until it is renamed to its role (`auth`, `imr`, `agent`). It
needs no daemon, and goes with `--cert` or `--repin` as well.

Every edit drops the entry's lines of the API key era (`apikey:`,
`authmethod:`, `tlsauth:`, `rootca:`). `--cert` and `--repin` run as root on
the daemon's host, with the daemon running: they ask it over its local admin
socket. The daemon is the entry's `config-file:`; an older entry without one
needs `--daemon-config <file>`, and the line is written. The daemon is never
guessed from the entry's address. If anything before the write fails, the
entry is left as it was. Every other line of the file, comments included,
stays as it is, and the file is checked to load with only that entry changed
before it is written. `--dry-run` asks the daemon what it serves and shows
the entry as it would become.

### Checking: `config check`

`tdns-ncli config check` checks every entry without asking any daemon, and
gives the command that fixes each one that cannot be used:

```console
$ tdns-ncli config check
CLI config /etc/tdns/tdns-ncli.yaml: 1 problem.

tdns-auth: the old name of the auth entry; an entry's name is
now its command word. Rename it:
   tdns-ncli config update tdns-auth --rename auth --cert
```

It fails on an old name, on plain `http://` (the management API is TLS only)
and on an https entry without pins, and notes lines of the API key era and
two daemons with one certificate.

### Listing: `config list`

```console
$ tdns-ncli config list --check
CLI config: /etc/tdns/tdns-ncli.yaml

NAME   COMMAND  KIND              API                             DAEMON CONFIG              STATUS  CHECK
auth   auth     auth              https://127.0.0.1:8989/api/v1   /etc/tdns/tdns-auth.yaml   ok      ok, up 3d4h, v1.2.3
auth2  auth2    instance of auth  https://127.0.0.1:8990/api/v1   /etc/tdns/tdns-auth2.yaml  ok      ok, up 3d4h, v1.2.3
```

One row per entry: the command word that reaches it, what kind of entry it is,
the API it talks to, the daemon config it refers to (the compiled-in default,
marked `(default)`, for a role's entry with no `config-file:`), and whether
`tdns-ncli` can use it. An entry that is ignored says why, with the same
reasons the start-up warnings give. `--check` pings every API and exits
non-zero if any does not answer.

(This is the CLI's own config. `tdns-ncli auth config check` is the other
`config`: it checks a *daemon's* config.)

### The file format

An extra instance is one more `apiservers:` entry, whose name is not its
role's:

```yaml
apiservers:
   - name:              auth
     role:              auth
     baseurl:           https://127.0.0.1:8989/api/v1
     pins:              [ "<the first server's certificate pin>" ]
     config-file:       /etc/tdns/tdns-auth.yaml

   - name:              sectdns
     role:              auth
     baseurl:           https://127.0.0.1:8990/api/v1
     pins:              [ "<the second server's certificate pin>" ]
     config-file:       /etc/tdns/sec-tdns-auth.yaml
```

| key | meaning |
|---|---|
| `name` | the command word **and** the API-client name. `name: sectdns` gives you `tdns-ncli sectdns ...` |
| `role` | which daemon's command tree to build: `auth`, `agent` or `imr`. |
| `config-file` | the daemon's own config: root reaches its local admin socket through it, and `config check` reads it (see below) |
| `pins` | the SPKI pins of the daemon's API certificate, by which the CLI verifies it over TCP |

An entry named after its role (`auth`, `role: auth`, or no `role:`) is that
role's entry, reached through its built-in command tree. Any other name with
a `role:` is an extra instance. There is no compatibility with the names of
before (`tdns-auth`): `config check` fails on them and prints the rename.

There is no limit of two. Any number of entries may carry `role: auth`, each
getting its own command word, and likewise `role: agent` for a second
`tdns-agent` (see "Agent instances" below). `tdns-imr` instances are not
supported yet.

### Both configs can live in /etc/tdns

Because each instance names its own daemon config file, a second instance no
longer needs a parallel `/etc` tree:

```
/etc/tdns/tdns-auth.yaml         # instance 1
/etc/tdns/sec-tdns-auth.yaml     # instance 2
/etc/tdns/tdns-ncli.yaml         # one CLI config describing both
```

The two daemons must still differ in everything that cannot be shared:
`db.file`, `log.file`, `listeners.addresses` (ports!), `apiserver.addresses`
and the API certificate, `dynamiczones.configfile` and `.zonedirectory`, and any
`include:` targets. A copied config that misses one of those fails at start-up
— except for one case worth knowing about, below.

### One sharp edge: listeners.udp-sockets

If **both** instances set `listeners.udp-sockets` greater than 1 on a platform
with a load-balancing reuseport option (Linux, FreeBSD, and NetBSD with the
out-of-tree `SO_REUSEPORT_LB` patch), and both listen on the same address, the
kernel will form **one load-balance group across both daemons** and split
incoming queries between them. There is no error: roughly half the queries
reach the wrong server.

With the default `udp-sockets: 1` the bind is a plain one and an address
collision fails loudly, which is what you want. Only raise it on an instance
whose listen addresses are its own.

## What each command talks to

Every command resolves its target from the command word it was reached
through. `tdns-ncli sectdns zone list` asks the `sectdns` server; the
first tdns-auth is not contacted.

`--debug` prints the resolution, which is the quickest way to confirm a new
entry is wired the way you meant:

```console
$ tdns-ncli --debug sectdns zone list
InitApiClients: setting up API clients for: auth sectdns
Using API client for "sectdns":
BaseUrl: https://127.0.0.1:8990/api/v1
```

### config check

`config check` reads the config file named by that instance's `config-file:`
key:

```console
$ tdns-ncli auth config check
Checking auth config: /etc/tdns/tdns-auth.yaml

$ tdns-ncli sectdns config check
Checking sectdns config: /etc/tdns/sec-tdns-auth.yaml
```

Without `config-file:` the check falls back to the compiled-in default
(`/etc/tdns/tdns-auth.yaml`) — which for a second instance is the wrong file.
Set it.

## imr instances

A second `tdns-imr` (a resolver, not an authoritative server) is wired with
`role: imr`:

```yaml
   - name:              imr2
     role:              imr
     baseurl:           https://127.0.0.1:8081/api/v1
     pins:              [ "<the second resolver's certificate pin>" ]
     config-file:       /etc/tdns/tdns-imr2.yaml
```

A resolver offers the CLI less than an authoritative server does, so an imr
instance has only what talks to the daemon's management API:

```
tdns-ncli imr2 ping | daemon | config (check, mwe, reload, status)
tdns-ncli imr2 query <name> <type>
tdns-ncli imr2 flush (common | all) <domain>
tdns-ncli imr2 forward (list | probe | status)
tdns-ncli imr2 stub (list | probe | status)
tdns-ncli imr2 stats (auth-transports | client-transports | transport-stats)
```

and not the commands that only describe the process they run in, which for
`tdns-ncli` is never the resolver: `show` and `set` (they are for
`tdns-imr --cli`), `stats large-ksk`, `dsync-query` (it starts a resolver of
its own inside the CLI), and `zone` (placeholders). `tdns-ncli imr ...` has them
as before; they report on the CLI process and say so.

`imr2 config check` reads `imr2`'s own `config-file:` by default. `imr2 flush`,
`query` and the `stats` commands go to `imr2`'s daemon: they used to pass the
literal role `imr`, so a second resolver's cache would have been flushed by
asking the first.

## What an instance tree does not include

Two subtrees are deliberately absent from an instance:

- **`report`** and **`notify`**. Neither talks to a management API — they are
  wire-protocol tools that build a report about a zone or send a NOTIFY
  message to an address you give them. There is no "which instance" for them
  to be scoped to, so they stay on the first daemon's tree only.

Everything else `tdns-cli auth` offers is available on an instance, including
`zone`, `keystore`, `truststore`, `config`, `daemon`, `db`, `debug`, `catalog`,
`ddns`, `del`, `dsync-api`, `imr`, `ping` and `stop`.

## Agent instances

A second `tdns-agent` is wired the same way, with `role: agent`:

```yaml
   - name:              agent2
     role:              agent
     baseurl:           https://127.0.0.1:8988/api/v1
     pins:              [ "<the second agent's certificate pin>" ]
     config-file:       /etc/tdns/tdns-agent2.yaml
```

`tdns-ncli agent2 ...` then offers exactly what `tdns-ncli agent ...` does:
`zone` (including `dsync` and `parentsync`), `config`, `daemon`, `db`, `debug`,
`imr`, `keystore`, `truststore` and `ping`. Nothing is left out: every subtree
of the agent's tree talks to the agent's management API.

Two things differ from an auth instance, both because an agent instance is an
agent. `config` has no `transport-signal` (the agent does not synthesize one),
and `config check` checks the file as a tdns-agent config. The first is decided
when the command tree is built, from the tree's kind, not from the name you
chose.

The rest of this guide (the config-file layout, the reserved names, running
two daemons side by side) applies unchanged.

## Choosing instance names

The name becomes a top-level command word, so it must not collide with an
existing one. `tdns-ncli` refuses a collision at start-up rather than
shadowing the built-in command, and says so:

```console
$ tdns-ncli auth zone list
tdns-ncli: apiservers entry "imr": name collides with a built-in role -- entry ignored (choose another name)
```

(for an entry named `imr` with `role: auth`).

The refused entry loses its subcommand; the rest of the CLI is unaffected.
The same happens for an entry naming an unknown `role:`, or one with no
`name`.

Reserved for an instance: `auth`, `agent`, `imr`, `scanner` (each is its
role's entry's name), the old names `tdns-auth`, `tdns-agent`, `tdns-imr`,
and the top-level commands `cert`, `client`, `config`, `util`, `version`,
`show-cmds`, `completion` and `help`.

Nor may an entry take the name of any other entry. Two entries of one name
would be one API client, the later silently replacing the earlier, so a
command meant for one daemon would reach the other: the first one counts,
and the later one is ignored, saying why.

## Verifying the daemon, and being known by a certificate

**tdns-ncli verifies the daemon on every https entry, by its pins and
nothing else.** `config add` pins the certificate the running daemon serves,
as the daemon itself reports it, so there is nothing to do:

```yaml
   - name:        auth
     baseurl:     https://127.0.0.1:8989/api/v1
     pins:        [ "<the SPKI pin of the daemon's certificate>" ]
```

A pin is the SPKI SHA-256 of the daemon's certificate, so it covers the
certificate's public key: a renewed certificate with the same key keeps its
pin. No CA and no name check, and a list, so a new certificate can be added
before the daemon changes to it. An https entry without pins is refused,
with the `config update --cert` that gives it some, and so is a plain
`http://` entry: the management API is TLS 1.3 only. There are no API keys.

**Your own certificate** is made once:

```bash
tdns-ncli client init
```

It writes a self-signed certificate and its key (mode 0600) to
`~/.config/tdns/certs/` (for root, `/etc/tdns/certs/tdns-ncli-client.crt`
and `.key`) and prints its pin and the line that enrolls it on a daemon
(`config add` does both for a daemon on the same host). Every TCP connection
presents it; a top-level `client:` block (`cert:`, `key:`) names other files.

**On the daemon's host**, as root, `tdns-ncli <daemon> client ...` has the
daemon change its access file:

```bash
tdns-ncli auth client add anna --pin <pin> --role read-write
tdns-ncli auth client list            # what the daemon runs, and its server pins
tdns-ncli auth client disable anna    # revoked, entry kept
tdns-ncli auth client set-role anna read-only
```

The daemon writes the file, so the commands need it running: each one goes
to its local admin socket, found through its daemon config (`--daemon-config
<file>`, else the role's entry's `config-file:`). The daemon checks every
change with its own validator (a file it would refuse is not written),
writes it atomically with the previous file kept as `.prev`, and puts it in
force at once (`--dry-run` shows the result and changes nothing;
`--no-reload` is ignored). With `--daemon-config` they need no CLI config.
The daemon never creates the file: without it the commands stop with the
`touch` that creates it, and the same command to run again. A stopped
daemon's file can still be edited by hand and checked with `config check`.
Roles and the rules behind them: `guide/config-tdns-auth.md`, "Network clients
and roles".

## Running two tdns-auth daemons

The CLI side is only half of it; the daemons themselves need distinct
identities. Two things are worth knowing:

- **There is no pidfile.** On NetBSD, `rc.subr` identifies a daemon by
  matching `$procname` against the running command, so two instances of one
  binary are indistinguishable to it and either script's `stop` matches both.
  Run the second instance through a differently-named symlink to the same
  binary, with `command` and `procname` both pointing at the symlink. Make the
  symlink in `start_precmd` so a package upgrade cannot leave it dangling.

- **The API certificate is per-instance.** Each daemon must serve a
  certificate of its own: the CLI tells daemons apart by their pins, so one
  certificate for both removes the only thing stopping a misdirected command
  from being accepted. Leaving `certfile:` and `keyfile:` out gives each
  daemon its own default pair; `config list` warns about two daemons with one
  pin.

## Migrating

1. Install `tdns-ncli` alongside `tdns-cli` (`make -C cmdv2/ncli install`).
2. Create each daemon's access file (`touch
   /etc/tdns/tdns-auth-access.yaml`), then build tdns-ncli's config from the
   daemons' own, as root on their host: `tdns-ncli config add
   /etc/tdns/tdns-auth.yaml`, then once for each further daemon or instance.
   `/etc/tdns/tdns-cli.yaml` is not touched; an existing one is moved over
   with `tdns-ncli --config /etc/tdns/tdns-cli.yaml config check`, which
   prints a command for each entry to change.
3. Check it with `tdns-ncli config list --check`, or one daemon with
   `tdns-ncli --debug <name> ping`.
4. Use whichever binary you prefer. `tdns-cli` is unchanged, and every
   existing command line keeps working under both names.

There is no cut-over date and no behaviour change to `tdns-cli`.
