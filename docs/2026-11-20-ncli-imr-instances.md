# tdns-ncli: instances of tdns-imr

**Date:** 2026-11-20
**Status:** implemented on `feature/ncli-imr-instances` (PR 3 of 3). PR 1 is
`config add` / `config list`; PR 2 is agent instances.

Builds on `docs/2026-09-07-cli-multi-instance-design.md` and
`docs/2026-11-20-ncli-config-add-list-design.md`.

## What it is

An `apiservers:` entry with `role: imr` now becomes a command tree
(`cli.NewImrTree`), so a second resolver is reached as `tdns-ncli imr2 ...`.
Unlike the auth and agent trees it is not the full canonical tree: a standalone
resolver offers the CLI less, and several `imr` commands only describe the
process they run in.

On the tree (everything that talks to the daemon's API): `ping`, `daemon`,
`config` (`check`, `mwe`, `status`), `query`, `flush` (`common`, `all`),
`forward`, `stub`, and `stats` with `auth-transports`, `client-transports` and
`transport-stats`.

Deliberately off it: `show` and `set` (read and change the state of the process
they run in; they exist for `tdns-imr --cli`), `stats large-ksk` (in-process
metrics), `dsync-query` (starts a resolver inside the CLI and queries with it,
so no daemon is involved) and `zone` (placeholders that print a line).

## Two decisions

**Copy the commands, do not rebuild them.** The auth and agent trees came from
turning package-level command values into factories. The imr ones are shared
with the tdns-imr daemon's own shell (`tdns-imr --cli` runs the same
`*cobra.Command` values in-process) and are wrapped at `init()` time
(`dispatchRemote`, `guardInProcess`); reworking them would put the daemon's
shell at risk for a CLI feature. So `query`, `flush` and `stats` are copied from
the canonical commands (`cloneCmdTree`, `cloneCmdOnly`), leaving one definition
of each: a flag added later appears on instances too. The copy takes every
exported field of `cobra.Command` and shares the flags, and
`TestCloneCopiesEveryCobraField` sets every field to a marker and requires the
copy to carry it, so a cobra upgrade that adds one fails there.

**An allowlist for `stats`.** `imrInstanceStats` names the three API-backed
subcommands. A denylist of `large-ksk` would put a future in-process stats
command on instances until someone noticed.

## The hardcoded role

Every API-backed imr command passed the literal role `imr`: `query`, `flush`,
the three `stats` commands, `config status` and `config check`. With one
resolver that is invisible. With two, `tdns-ncli imr2 flush all example.com.`
flushes the first resolver's cache and reports success. They now ask the
command tree (`imrRoleFor(cmd)`, which falls back to `imr` outside a tagged
tree, i.e. in the tdns-imr shell) or take the role the factory was given
(`NewImrConfigCmdFor(role)`). `imr config check` also reads the entry's
`config-file:` before the compiled-in default, so `imr2 config check` checks
`imr2`'s config; for the canonical entry that only matters if it has a
`config-file:`.

`imr2 config mwe` writes `imr2`'s `config-file:` (or `<file>.mwe` beside it),
not the canonical `tdns-imr.yaml`, and refuses without a `config-file:` or
`--dir`. The canonical resolver keeps writing `<dir>/tdns-imr.yaml` whatever
its entry says (CodeRabbit round 1: tdns-cli runs the same command). The
printed entry's `config-file:` is the file the printed start command uses, and
the printed check is `tdns-ncli imr2 config check`.

## Starting an instance's daemon

`<instance> daemon start` and `restart` started the entry's `command:` with
only the CLI's own flags, so the daemon read its compiled-in default config:
the canonical daemon's file. They now pass `--config <config-file:>` when the
entry has one and no `--config` was given (`daemonStartFlags`); an explicit
`--config` still decides, as before. This lives in the shared `NewDaemonCmd`,
so it covers auth instances as well, and a canonical entry with a
`config-file:` (CodeRabbit round 1).

## Guarding it

- `TestImrInstanceCommandsReachTheirOwnDaemon` runs each API-backed command
  through an instance and through the canonical tree against two live TLS test
  servers, and requires the right server to see exactly one request and the
  other none. With the old literal restored at one site it fails with
  "instance server saw [], canonical server saw [imr-flush]".
- `TestNoHardcodedImrRoleInApiCalls` parses the package and rejects the literal
  `"imr"` as the role argument of `SendImrMgmtCmd`, `SendImrFlush`,
  `GetApiClient` and `fetchImrStatus`.
- `TestInstanceTreeMatchesCanonicalImrTree` (cmdv2/ncli): the canonical imr
  tree (41 commands) must equal the instance tree (29) plus the deliberately
  absent paths (12), in both directions, and each absent entry must still be
  real. A new canonical command is a decision: add it to `NewImrTree` or to the
  list with a reason.

## Not done

- `show`, `set` and `dsync-query` have no remote equivalent. Giving them one
  would mean new API endpoints, which is a daemon change, not a CLI one.
- The role is registered in an `init()` in `imr_tree.go`, not in the map
  literal in `instances.go`, so the per-role pull requests do not all edit the
  same lines. The guide's `role:` table row and the comment above that map name
  the roles one PR at a time; after all three merge they should read `auth`,
  `agent`, `imr`.
