# tdns-cli role-mapping fallout

**Date:** 2026-07-20
**Status:** open — deferred cleanup, no work started
**Found while:** implementing `tdns-cli agent config check|mwe` (PR #311)

## Background

`tdns-cli` groups commands per daemon role (`auth`, `agent`, `imr`, `scanner`).
Many command trees are built by role-parameterized factories
(`NewConfigCmd(role)`, `NewDaemonCmd(role)`, `NewKeystoreCmd(role)`, …) and
attached per role in `cmdv2/cli/shared_cmds.go`; others self-wire in
`v2/cli/*.go` `init()`s.

Adding the agent variants of `config check`/`config mwe` surfaced a class of
bug: **a command is attached to a role whose daemon cannot serve it.** The
command exists, `--help` documents it, and it fails only when run — sometimes
silently.

PR #311 fixed the `config check` instances and, separately, every case where
help text merely *named* the wrong daemon (commit "Stop CLI help text naming
the wrong daemon"). Everything below is what remains.

The audit covered the active tree only: repo root, `v2/*`, `cmdv2/*`. Legacy
`cmd/`, `tdns/`, `music/`, `obe/` were ignored per the standing rule that only
the active tree is maintained.

---

## A. Broken at runtime

### A1. `agent parentsync` — the API bridge is missing (RESURRECT, do not delete)

**This functionality is needed in tdns for the agent.** It is *not* a tdns-mp
concern, despite the `/agent` endpoint comment in `apirouters.go` pointing at
tdns-mp. It must be restored, not removed.

Affected: `agent parentsync status | bootstrap | inquire update | election`
(`v2/cli/parentsync_cmds.go:28,53,81,108,151`).

Current state — the two halves exist and the bridge between them does not:

- **CLI half exists.** The commands build an `AgentMgmtPost` with
  `Command: "parentsync-status"` / `-bootstrap` / `-inquire` / `-election`
  and POST it to `/agent`.
- **Engine half exists.** `v2/parentsync_bootstrap.go` provides
  `ParentSyncAfterKeyPublication`, `QueryParentKeyState`,
  `QueryParentKeyStateDetailed`, `UpdateParentState`, `BootstrapWithParent`,
  `ZoneHasParentSyncAgent`.
- **Bridge missing.** There is no `HandleFunc("/agent", …)` anywhere in `v2/`
  or `cmdv2/`, and no handler for any of the four `parentsync-*` command
  strings outside `v2/cli/`. Verified by grep and by live test.

Two independent defects, both must be fixed:

1. **The request struct is not serializable.** `AgentMgmtPost`
   (`v2/structs.go:967`) carries `Response chan *AgentMgmtResponse` — an
   in-process channel — yet is used as an HTTP POST body. It fails in the
   client before any network I/O:

   ```
   $ tdns-cli agent parentsync status --zone example.com
   api.RequestNG: Error from json.NewEncoder: json: unsupported type: chan *tdns.AgentMgmtResponse
   ```

   `AgentMgmtPost` is doing double duty as both an in-process message and a
   wire type. The fix pattern already exists next door: `ImrMgmtPost`
   (`v2/structs.go:996`) has an explicit comment that it *"deliberately does
   NOT reuse AgentMgmtPost, whose agent/RR fields are unrelated ... and whose
   overloading here would be a future footgun."* Either split out a wire-only
   request type, or tag the channel `json:"-"`.

2. **The route and handler must be (re)introduced** for `AppTypeAgent` in
   `SetupAPIRouter`, dispatching the four `parentsync-*` commands to the
   engine functions above. Worth reconsidering the endpoint name: `/agent` on
   a daemon that *is* an agent is uninformative, and the name currently
   carries a comment reserving it for tdns-mp. Something like
   `/parentsync` would not collide.

Also blocked on this: `agent zone addrr` / `delrr`
(`v2/cli/agent_zone_cmds.go:314,388`) POST to the same `/agent`. They are
currently defused — the attachment is commented out at
`agent_zone_cmds.go:437` — so they are dead code today, but re-enabling them
before the bridge exists would reintroduce the same failure.

### A2. `tdns-cli imr {query,stats,show,flush,set,zone}` — daemon-only commands attached to the CLI

`ImrQueryCmd`, `ImrStatsCmd`, `ImrShowCmd`, `ImrFlushCmd`, `ImrSetCmd` and
`ImrZoneCmd` are the **tdns-imr daemon's own in-process REPL commands**, wired
onto the daemon's `rootCmd` at `cmdv2/imr/shared_cmds.go:12-25`, where
`Conf.Internal.RecursorCh` / `RRsetCache` are populated.

`v2/cli/imr_cmds.go:528` re-attaches those same `*cobra.Command` values under
tdns-cli's `ImrCmd`, where `Conf.Internal.*` is always nil:

```
$ tdns-cli imr query example.com A
Querying example.com for A records (verbose mode: false)
No active channel to RecursorEngine. Terminating.
```

Affected leaves: `imr query`; `imr stats`, `stats auth-transports`,
`stats auth-servers`; `imr show config`, `show options`; `imr flush common`,
`flush all`; `imr set linewidth`, `set server transport`.
(`imr stats transport-stats` is the exception — it goes over `/imr` and works.)

**The fix already exists in-tree.** `addImrLeafCmds(parent, role)`
(`v2/cli/agent_imr_cmds.go:270-279`) builds API-based equivalents that POST to
`/imr`, and is called for `agent` and `auth` but never for `imr`. So
`tdns-cli agent imr query` works while `tdns-cli imr query` does not. Call it
for `imr` and stop re-attaching the daemon REPL commands.

Note `/imr` *is* registered for `AppTypeImr` (`apirouters.go:72-74`), so the
server side needs nothing.

### A3. `imr zone list` / `imr zone check` are stubs

`imr zone list` only prints `Listing records for zone: %s`
(`v2/cli/imr_cmds.go:179`); `imr zone check` prints `[NYI]`
(`imr_cmds.go:205`). Implement or remove.

### A4. `<role> daemon reload` silently pretends to succeed

`daemon reload` (`v2/cli/daemon_cmds.go:84`) sends command `"reload"` to
`/command`, but `APIcommand` (`v2/apihandler_funcs.go:276-308`) only handles
`status`, `stop` and `api`. The request falls to `default:` and the CLI prints
an empty success line:

```
$ tdns-cli agent daemon reload
Reload:  Message:
```

Nothing reloaded, no error shown. Affects every role. `config reload` already
does the real work, so the likely resolution is to delete `daemon reload`
rather than implement it — but that is a user-visible interface change.

---

## B. Commands offered where they make no sense

### B1. `agent keystore dnssec *`

Offered on a daemon that never signs: `SetupZoneSigning` returns early for
`AppTypeAgent`, and no `ResignerEngine` / `KeyStateWorker` is started. The
`/keystore` endpoint is registered for the agent and the handler has no
app-type gate, so the commands "work" — they just manage keys nothing will
ever use. Consider gating the `dnssec` subtree to auth, or documenting why an
agent keystore holds DNSSEC keys. (`agent keystore sig0|tsig` are legitimate.)

---

## C. Coverage gaps — the daemon serves it, the CLI does not offer it

| Endpoint | Registered for | Missing CLI |
|---|---|---|
| `/imr` | imr (`apirouters.go:72-74`) | see A2 — `addImrLeafCmds(ImrCmd, "imr")` |
| `/config` | imr (`apirouters.go:66`) | `imr config reload` / `reload-zones` / `status`. `NewImrConfigCmd` wires only `check`+`mwe`, and its comment justifies this with "tdns-imr has no zone/tsig/keystore state" — true, but `APIconfig` serves reload/status regardless of app type. |
| `/debug` | imr (`apirouters.go:67`) | no `imr debug`; `NewDebugCmd` is wired for auth and agent only |
| `/catalog` | agent (`apirouters.go:96`, unconditional) | `CatalogCmd` is auth-only (`cmdv2/cli/root.go:93`) |
| `/delegation` | agent (`apirouters.go:103`) | agent reaches it only via `parentsync delta|sync`; the fuller `DelCmd` (`del status|sync|export`) is auth-only |

---

## D. Adjacent findings (not CLI, found in the same pass)

### D1. `GET /config/paths` is auth-only, probably by accident

`apirouters.go:117` registers it inside the `if Globals.App.Type ==
AppTypeAuth` block, alongside the `/rollover/*` routes. It is generic
config-path discovery with nothing rollover-specific about it. Because of
this, `agent config check` cannot ask the daemon which config file it loaded
and falls back to the compiled-in default.

This also caused a real bug, fixed in PR #311: `/config/paths` was doubling as
the liveness probe, so its 404 was read as "daemon is down" and disabled *all*
running-config correlation for non-auth roles. Liveness is now an API ping and
path discovery is gated on `roleHasConfigPaths(role)`.

Moving the registration into the auth-or-agent block would let the agent do
path discovery; `roleHasConfigPaths` is then the single line to update.

### D2. The unknown-config-key warning has false positives

`parseconfig.go:346` warns:

```
unknown config keys ignored (possible misspellings)
keys=[keybootstrap delegationsync common server resolver delegationbackends validator]
```

The detector uses mapstructure's unused-key set, so it flags every block read
directly through viper rather than decoded into `Config`. Of those seven,
**five are live**: `delegationsync` (26 viper reads), `common`, `server`,
`validator` (3 each), and `delegationbackends`
(`viper.UnmarshalKey`, `v2/delegation_backend.go:63`).

The noise has a real cost: a genuinely dead `multi-provider:` block sat in the
shipped agent sample config unnoticed, because it looked exactly like the five
false positives. Suggested: an allowlist of known viper-direct top-level keys,
so the warning only fires on actual unknowns.

Related: adding a `deprecatedConfigKeys` entry (`parseconfig.go:209`) for
`multi-provider` would give operators real advice ("moved to tdns-mp; use
tdns-mpagent") instead of "possible misspellings".

### D3. `resolver:` and `keybootstrap:` look dead everywhere

Both are still present as top-level blocks in
`cmdv2/agent/tdns-agent.sample.yaml` (lines 59 and 118) and in
`tdns-mp/cmd/mpagent/tdns-mpagent.sample.yaml`, but no reader was found in
either repo. The `KeyBootstrap` that does exist is a *zone-level*
`updatepolicy` field (`v2/structs.go:362`), unrelated to the top-level
`keybootstrap:` block.

Deliberately **not** removed: "no reader found" is weaker evidence than the
`multi-provider` case (which was positively confirmed to live in tdns-mp).
Confirm before deleting.

---

## Suggested sequencing

1. **A1 (`agent parentsync`)** — restores needed agent functionality. Wire
   struct + route + handler. Independent of everything else.
2. **A2/A3 (`imr` subtree)** — largest user-visible cleanup; the fix is mostly
   deletion plus one existing call, so it is cheaper than it looks.
3. **D1** — one line server-side, plus one line in `roleHasConfigPaths`.
4. **A4, B1, C** — interface changes; batch them so the CLI surface changes
   once rather than repeatedly.
5. **D2** — quality-of-life, but it is what let this class of rot hide.

## Root cause, for whoever does the cleanup

There is no declaration anywhere of *which roles a command is valid for*. A
factory takes a `role string` and the caller decides where to attach it;
nothing checks that the daemon behind that role serves the endpoint. Both A1
and A2 are instances of that. A small per-role capability table — consulted at
attach time, or asserted in a test that walks the command tree against the
routes `SetupAPIRouter` registers per app type — would turn this whole class of
bug into a compile-or-test-time failure instead of a runtime surprise.
