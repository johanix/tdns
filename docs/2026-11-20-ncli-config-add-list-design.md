# tdns-ncli: `config add`, `config list`, and its own config file

**Date:** 2026-11-20
**Status:** implemented on `feature/ncli-config-add-list` (PR 1 of 3). PR 2
(agent instance trees) and PR 3 (imr instance trees) are separate; see the end.

Builds on `docs/2026-09-07-cli-multi-instance-design.md`.

## Problem

Addressing a second `tdns-auth` from `tdns-ncli` meant hand-writing an
`apiservers:` entry (`name`, `role: auth`, `baseurl`, `apikey`, `authmethod`,
`config-file`) whose every value is already in the daemon's own config, in
`apiserver:` and in the file's path. Copying them is the error source the
multi-instance work exists to remove: a wrong port or a mistyped key gives a
command that reaches nothing, or the wrong daemon.

## Decisions

Made by the maintainer when this was evaluated, 2026-11-20:

1. **tdns-ncli reads its own config, `/etc/tdns/tdns-ncli.yaml`**, not
   `tdns-cli.yaml`. Only tdns-ncli understands `role:`. (The shared `ApiDetails`
   does carry the field and `tdns-cli` ignores unknown keys, so a shared file
   would have worked; a separate one is the cleaner cut for the day tdns-ncli
   replaces tdns-cli, when the binary name and the config name both change.)
2. **`config add <daemon-config.yaml>` and `config list [--check]`.** No
   `config remove` for now.
3. Three PRs: this one, then agent instances, then imr instances.
4. tdns-mp daemons are out of scope: they have their own CLI.

## `config add`

`tdns-ncli config add /etc/tdns/tdns-auth2.yaml` reads the daemon config and
adds one `apiservers:` entry.

**What it reads.** `apiserver.addresses` (first one), `apiserver.apikey`,
`apiserver.usetls`, through viper plus `include:` expansion, so an
`apiserver:` block in an included file is found. `usetls` defaults to true when
absent, exactly as the daemon applies it (`v2/parseconfig.go`). A wildcard
listen address (`0.0.0.0`, `::`, no host) becomes loopback: it is where the
daemon listens, not where the CLI connects. `authmethod` is written `X-API-Key`,
spelled exactly, since the client matches it case-sensitively.

**Which daemon.** Nothing in a daemon config states its type; the binary
decides. Evidence, strongest first: `service.name` (`TDNS-AUTH`, `TDNS-AGENT`,
trailing digits ignored, whole words only); no `service:` block but an
`imrengine:` block (tdns-imr); the file name. Undecidable gives an error asking
for `--role`, never a guess: a daemon filed under the wrong role gets the wrong
command tree pointed at it. `TDNS-MPAGENT` and its relatives are refused.

**Canonical or instance.** If the CLI config has no entry named for the role's
built-in client (`tdns-auth`, `tdns-agent`, `tdns-imr`) the new entry is that
canonical entry, reached as `auth`, `agent`, `imr`. Otherwise it is an instance
with `role:` set, named after the file (`tdns-auth2.yaml` is `auth2`;
`tdns-auth.yaml` in another directory is `auth` taken, so `auth2`). `--name`
overrides and is refused when it collides with a role, an entry, a command or a
reserved word. An instance of a role with no instance tree is refused; today
that is every role but `auth`.

**Idempotence and clashes.** An entry with the same `config-file:` and the same
API address means "already known", and nothing changes. The same file with a
different address (the daemon was reconfigured), or a different file naming an
address another entry already uses (two daemons cannot listen on one address),
is an error that says which entry.

**Editing the file.** As text, not through viper's `WriteConfig` (which writes
the *merged* config, folding includes and `cli.localconfig` into the main file
and dropping comments) and not through a YAML library round trip (which
normalises the layout of every line). The entry is spliced at the end of the
existing `apiservers:` list in the style of the entries there: indent, dash
gap, value column, blank-line separation, plain or column-0 dashes. A missing
`apiservers:` key is appended; a file that does not exist is created, mode
0600, with a short header. An inline `apiservers: [...]` is not edited: the error
prints the entry to add by hand. The write is atomic (temp file in the same
directory, rename), keeps the mode, and follows a symlink so the link stays a
link. Values that are not plain YAML scalars are single-quoted.

**Checking its own work.** After writing, the CLI config is loaded the way the
CLI loads it (`ReadApiServers`: main file, includes, then `cli.localconfig`).
If the effective list is not exactly the old list plus the new entry, the file
is restored (or removed, if it was created) and the error says why. The case
this exists for is `apiservers:` also defined in an include or in
`cli.localconfig`: lists are replaced, not merged, so an entry added to the
main file would be invisible. `--file` names the file that holds the list.

**Output.** The entry is printed with the API key masked. The key is the one
secret in it and has no place in terminal scrollback.

## `config list [--check]`

One row per entry: name, command word, kind (built-in role or instance of a
role), API URL, daemon config (the compiled-in default, marked `(default)`, for
a canonical entry with no `config-file:`), and status. Status uses the same
function WireInstanceTrees uses (`checkInstanceEntries`), so what the list says
is what the wiring does; an ignored entry says why. The list judges the entries
against the CLI as it was before instances were wired (`builtinRoles()` and a
stand-in root), since by the time `list` runs the instance trees are on the
real root and would look like collisions with themselves.

`--check` pings every API concurrently (default 5 s each) and exits non-zero if
any fails. It sets up its own clients, so it works on a config that
`initConfig` would refuse, and it does not exit the process on an unreadable
`rootca` file the way `NewClient` does.

`config` is a root-level command with an annotation; the root's
`PersistentPreRun` skips config and API loading for it (`IsCliConfigCmd`),
because these commands read and edit that file themselves and `config add` is
how it comes to exist. It is attached in `init()`, before instance wiring, so an
instance named `config` is refused.

## A hole found on the way

`WireInstanceTrees` compared an instance's name against role names (`auth`) and
against earlier instances, but not against API *client* names (`tdns-auth`).
`name: tdns-auth, role: auth` passed every check. `InitApiClients` keys
`tdns.Globals.ApiClients` by entry name, so it and the canonical `tdns-auth`
entry were one client, the later replacing the earlier: a command meant for one
daemon reached the other, with no message. Instance names are now also checked
against the built-in roles' clients and every canonical entry.
`TestInstanceNameMayNotShareAnApiClient` fails without the check.

## Plumbing

- `tdns.DefaultNcliCfgFile` (`/etc/tdns/tdns-ncli.yaml`).
- `cli.DefaultCliConfigFile`, a variable initialised to `tdns.DefaultCliCfgFile`
  so tdns-cli is unchanged; tdns-ncli's `init()` sets it. Read by
  `ConfigPathFromArgs`, the three fallbacks in `ksk_rollover_cli.go`, and the
  ncli root.
- `cli.ReadApiServers` (the strict form of `EarlyApiServers`, which now wraps
  it) returns the effective list with errors.
- A missing tdns-ncli config now says how to create it instead of a bare open
  error.

## Not done here

- **Agent instances** (PR 2) and **imr instances** (PR 3): `knownInstanceRoles`
  has only `auth`. `config add` already works for the first agent or imr (the
  canonical entry) and picks up a second one as soon as the role has a tree.
- `config remove`, and `config list` comparing an entry to its daemon config
  (drift), were not asked for.
- Ownership of an edited file is not preserved on rename; the CLI config is the
  invoking operator's own file.
