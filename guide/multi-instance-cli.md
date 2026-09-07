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
server through the `apiservers` entry named `tdns-auth`, so a second instance
can only be addressed by pointing the whole CLI at a different config file:

```bash
tdns-cli --config /etc/tdns-second/tdns-cli.yaml auth zone list
```

on every invocation. That works, but the flag is easy to forget, and
forgetting it is silent: the command runs against the *other* server and
reports success.

**`tdns-ncli`** makes the instance a command word instead:

```bash
tdns-ncli auth    zone list      # the canonical tdns-auth
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
built from the same library, both read the same `/etc/tdns/tdns-cli.yaml`, and
`tdns-cli` behaves exactly as it always has — it ignores the `role:` key
described below, so one config file serves both.

If you use only one instance of each daemon, there is no reason to change
anything: keep using `tdns-cli`.

## Configuration

An extra instance is one more `apiservers:` entry carrying a `role:` key:

```yaml
apiservers:
   - name:              tdns-auth
     baseurl:           https://127.0.0.1:8989/api/v1
     apikey:            <the canonical server's api key>
     authmethod:        X-API-Key

   - name:              sectdns
     role:              auth
     baseurl:           https://127.0.0.1:8990/api/v1
     apikey:            <the second server's api key>
     authmethod:        X-API-Key
     config-file:       /etc/tdns/sec-tdns-auth.yaml
```

| key | meaning |
|---|---|
| `name` | the command word **and** the API-client name. `name: sectdns` gives you `tdns-ncli sectdns ...` |
| `role` | which daemon's command tree to build. Currently only `auth`. |
| `config-file` | the instance's own daemon config, used by `config check` (see below) |

`role:` is what marks an entry as an extra instance. An entry without it is a
canonical target, reached through its built-in command tree exactly as before —
which is why existing config files need no edit.

There is no limit of two. Any number of entries may carry `role: auth`, each
getting its own command word.

### Both configs can live in /etc/tdns

Because each instance names its own daemon config file, a second instance no
longer needs a parallel `/etc` tree:

```
/etc/tdns/tdns-auth.yaml         # instance 1
/etc/tdns/sec-tdns-auth.yaml     # instance 2
/etc/tdns/tdns-cli.yaml          # one CLI config describing both
```

The two daemons must still differ in everything that cannot be shared:
`db.file`, `log.file`, `listeners.addresses` (ports!), `apiserver.addresses`
and `apiserver.apikey`, `dynamiczones.configfile` and `.zonedirectory`, and any
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
canonical `tdns-auth` is not contacted.

`--debug` prints the resolution, which is the quickest way to confirm a new
entry is wired the way you meant:

```console
$ tdns-ncli --debug sectdns zone list
InitApiClients: setting up API clients for: tdns-auth sectdns
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

## What an instance tree does not include

Two subtrees are deliberately absent from an instance:

- **`report`** and **`notify`**. Neither talks to a management API — they are
  wire-protocol tools that build a report about a zone or send a NOTIFY
  message to an address you give them. There is no "which instance" for them
  to be scoped to, so they stay on the canonical tree only.

Everything else `tdns-cli auth` offers is available on an instance, including
`zone`, `keystore`, `truststore`, `config`, `daemon`, `db`, `debug`, `catalog`,
`ddns`, `del`, `dsync-api`, `imr`, `ping` and `stop`.

## Choosing instance names

The name becomes a top-level command word, so it must not collide with an
existing one. `tdns-ncli` refuses a collision at start-up rather than
shadowing the built-in command, and says so:

```console
$ tdns-ncli auth zone list
tdns-ncli: apiservers entry "auth": name collides with a built-in role -- entry ignored (choose another name)
```

The refused entry loses its subcommand; the rest of the CLI is unaffected.
The same happens for an entry naming an unknown `role:`, or one with no
`name`.

Reserved: `auth`, `agent`, `imr`, `scanner`, and the top-level commands
`cert`, `util`, `version`, `show-cmds`, `completion` and `help`.

## Running two tdns-auth daemons

The CLI side is only half of it; the daemons themselves need distinct
identities. Two things are worth knowing:

- **There is no pidfile.** On NetBSD, `rc.subr` identifies a daemon by
  matching `$procname` against the running command, so two instances of one
  binary are indistinguishable to it and either script's `stop` matches both.
  Run the second instance through a differently-named symlink to the same
  binary, with `command` and `procname` both pointing at the symlink. Make the
  symlink in `start_precmd` so a package upgrade cannot leave it dangling.

- **The API key is per-instance.** `apiserver.apikey` in each daemon's config
  must match the `apikey` of the corresponding `apiservers` entry. Using one
  key for both removes the only thing stopping a misdirected command from
  being accepted.

## Migrating

1. Install `tdns-ncli` alongside `tdns-cli` (`make -C cmdv2/ncli install`).
2. Add the `role:` entry for the second instance to `/etc/tdns/tdns-cli.yaml`.
   `tdns-cli` ignores it.
3. Check the wiring with `tdns-ncli --debug <name> ping`.
4. Use whichever binary you prefer. `tdns-cli` is unchanged, and every
   existing command line keeps working under both names.

There is no cut-over date and no behaviour change to `tdns-cli`.
