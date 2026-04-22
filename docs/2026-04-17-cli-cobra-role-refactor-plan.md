# CLI Cobra cleanup: explicit role, shared run functions, and removal of GetCommandContext

## Scope

- `**tdns/v2/cli**` — shared Cobra command library used by `tdns-cli`, auth tooling, and others.
- `**tdns-mp/v2/cli**` — multi-provider CLI (`mpcli`) built on the same patterns.

Out of scope for this document: other repos under the workspace (`tdns-nm`, `traffic`, legacy `tdns/tdns/cli`, etc.) unless they import these packages and need a follow-up build fix.

## Background

Cobra does not allow attaching the same `*cobra.Command` instance under multiple parents. The codebase previously inferred “which API server am I talking to?” by scanning `**os.Args**` via `**GetCommandContext(cmdName)**`, then passed that string to `**GetApiClient(parent, …)**`, which maps it to a key in `**tdns.Globals.ApiClients**` (see `getClientKeyFromParent` in `tdns/v2/cli/ping.go`).

That inference breaks or becomes ambiguous when subcommand names repeat under different trees or when argv layout changes.

## Goals (acceptance criteria)

1. Any API-bound CLI action can be registered under **multiple** Cobra parents **without** `GetCommandContext` / argv scanning.
2. `**role`** (the same string set understood by `getClientKeyFromParent`: e.g. `agent`, `combiner`, `signer`, `auth`, `scanner`, `imr`, …) is passed **explicitly** from the registration site into `**run…(role, cmd, args)`** or into `**new…Cmd(role)**`.
3. `**GetApiClient(role, die)**` remains the single mapping from role → configured HTTP client (`tdns.Globals.ApiClients`). No duplicate mp-local client registry in this phase.
4. `**GetCommandContext**`: no remaining call sites in `tdns/v2/cli` or `tdns-mp/v2/cli`; the function is removed (or briefly left as a deprecated no-op if a staged rollout is needed).
5. Each actionable command is either:
  - a **thin shell** whose `Run` / `RunE` only forwards to a named `**run…`** with `**role**` (and `cmd` / `args` as needed), or
  - a **parameterized factory** `new…Cmd(role)` when **all** Cobra metadata (`Use`, `Short`, `Long`, flags) are **identical** for every attachment point.
6. **Dead code removal**: delete `**tdns/v2/cli/deadcode_hsync_cmds.go`** and `**tdns/v2/cli/deadcode_hsync_debug_cmds.go**` as part of the work (they are not migration targets). After deletion, fix any broken `init` wiring and ensure dependents still build.

## Design rules (hybrid, non-dogmatic)


| Situation                                                                          | Prefer                                                                                                                                                                                                      |
| ---------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Same `Use` / `Short` / `Long` / flags for every clone; only parent in tree differs | `**newXCmd(role) *cobra.Command**` returning a new pointer each time, `**Run**` pointing at shared `**runX(role, cmd, args)**` (same idea as `newDumpServersCmd` / `runDumpServers` in `imr_dump_cmds.go`). |
| Help text, flags, or `Args` differ per role / parent                               | **Separate `var …Cmd`** (or a factory with **extra parameters** beyond `role` if it stays readable).                                                                                                        |
| All cases                                                                          | **One named `run…`** (or shared helper) per behavior; **no** large anonymous `Run` bodies duplicated across clones.                                                                                         |


**Note:** The second return value of `GetCommandContext` (`chain`) is unused everywhere it was audited (always discarded with `_`). The replacement design does not need to preserve it.

**Watch item — non-mechanical rewrite sites:** Most `GetCommandContext` callers pass the leaf verb (`"ping"`, `"keys"`, `"zone"`), so the rewrite is a straight “delete the argv scan, pass the role from the Cobra node above.” A minority pass a **middle-word marker** (variable `prefix` in `SendAgentMgmtCmd` — values like `"parentsync"`, `"peer"`, `"imr"`, `"debug"`; `cmdName` in combiner helpers). For those the rewrite is **not** mechanical: you must determine the **role** each caller *intended*, which is not the marker string. **Do not treat those markers as `getClientKeyFromParent` / `GetApiClient` roles** — they only locate a word in `os.Args`. The new **role** is whatever identifies the configured API client; HTTP paths (e.g. `/agent`) stay as they are today. Validate awkward argv (repeated words, wrappers). See Phase 2 row on `SendAgentMgmtCmd` for the concrete plan.

## Phase 0 — Housekeeping

1. Delete `**deadcode_hsync_cmds.go**` and `**deadcode_hsync_debug_cmds.go**`.
2. `**go build ./...**` (or project-standard targets) for binaries that embed `tdns/v2/cli` and `tdns-mp/v2/cli`.
3. Fix any `init`-time wiring that referenced removed commands.

## Phase 1 — Contract: role + API client (`tdns/v2/cli`)

1. Treat the first parameter of `**GetApiClient**` as `**role**` (rename / document; optional type alias such as `type CliAPIRole string` with constants aligned to `getClientKeyFromParent`).
2. Enumerate supported roles: `auth`, `server`, `agent`, `combiner`, `signer`, `scanner`, `imr`, `msa`, `auditor`, `kdc`, `krs` (current switch in `ping.go`). Note which subset `**tdns-mp**` uses in practice.
3. Grep for `**GetCommandContext**`; for each site, record the inferred parent → that becomes the **explicit `role`** supplied by the Cobra node that owns the command.

## Phase 2 — High-churn shared commands first (`tdns/v2/cli`)

These are the worst for argv inference and prove the pattern.


| Item                                                                            | Direction                                                                                                                                                                                               |
| ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `**PingCmd**` (attached under `AuthCmd`, `AgentCmd`, `ScannerCmd`, `ImrCmd`, …) | Stop using a single shared pointer. Use `**newPingCmd(role)**` or per-tree `**var …PingCmd**` with `**Run: func(…) { runPing(role, cmd, args) }**`. `**runPing**` calls `**GetApiClient(role, true)**`. |
| **Zone / agent zone (`RunZoneList`, …)**                                        | Finish migration: remove `**GetCommandContext("zone")`** from helpers; pass `**role**` from each shell into `**runZone…(role, …)**`.                                                                    |
| `**runKeysCommand**` (`jose_keys_cmds.go`)                                      | Replace `**GetCommandContext("keys")**` with `**role**` passed from `**keysGenerateCmd` / `keysShowCmd**` (agent vs combiner trees capture different roles).                                            |
| `**SendAgentMgmtCmd**` (`parentsync_cmds.go` in `tdns/v2/cli`; `agent_cmds.go` in `tdns-mp/v2/cli`) | **Non-mechanical rewrite.** The same helper name and pattern exist in **both** packages (two independent definitions, not one shared function). Plan for **two signature changes** and **two call-site sweeps** (`tdns/v2/cli` vs `tdns-mp/v2/cli`). The current `prefix` parameter is a middle-word argv marker (`"parentsync"`, `"peer"`, `"imr"`, `"debug"`), not a role and not a leaf verb. Change the signature from `SendAgentMgmtCmd(req, prefix string)` to `SendAgentMgmtCmd(req, role string)` (or accept `*tdns.ApiClient` directly). Then audit **every** call site (≈15 across `tdns/v2/cli` and `tdns-mp/v2/cli`) and assign the correct role explicitly: parentsync callers → `"agent"`; `tdns-mp` callers passing `"peer"` → whichever role that command is actually attached under; etc. Do **not** global-replace `prefix` with a single role. Track call sites as a checklist; build after each batch. |


## Phase 3 — Systematic sweep (`tdns/v2/cli`)

Process file groups in an order that keeps the tree building (helpers before many leaves):

1. `**daemon_cmds.go**`, `**config_cmds.go**`, `**catalog_cmds.go**`, `**transaction_cmds.go**`, `**truststore_cmds.go**`, `**keystore_cmds.go**`: each action → `**run…(role, cmd, args)**` with role fixed per attachment.
2. `**distrib_cmds.go**`: replace `**GetCommandContext("distrib")**` / `**"peer"**` with explicit `**role**` per agent vs combiner command; consolidate shared bodies in `**runDistrib…**` helpers.
3. `**agent_zone_cmds.go**`, `**zone_cmds.go**`, `**zone_dsync_cmds.go**`: complete `**role**` threading; use factories only where metadata is truly identical across clones.
4. Remaining files from the CLI inventory (e.g. `**imr_cmds**`, `**ddns_cmds**`, `**debug_cmds**`, `**notify_cmds**`, …): same rule — **no argv-based parent detection**; shared helpers take `**role`** or an `*tdns.ApiClient` obtained via `**GetApiClient(role, …)**`.

`**imr_dump_cmds.go`:** Already uses `**Run: runDumpServers`** / `**runDumpKeys**` with `**newDump*Cmd()**` for duplicate tree positions. No `**GetCommandContext**` there today; optional later `**role = "imr"**` only if IMR dump ever needs the same client path as HTTP APIs (unlikely).

## Phase 4 — `tdns-mp/v2/cli`

Same hybrid rules; smaller surface.

- `**router_cmds.go**`, `**peer_cmds.go**`, `**gossip_cmds.go**`: behavior already uses `**run*(role, …)**`; ensure **every** `GetApiClient` / helper path uses that `**role`** and **remove** all `**tdnscli.GetCommandContext`** usage.
- `**agent_cmds.go`** *(see Phase 2 for `SendAgentMgmtCmd`)*, `**agent_zone_cmds.go**`, `**combiner_cmds.go**`, `**combiner_edits_cmds.go**`, `**signer_cmds.go**`, `**hsync_cmds.go**`, `**agent_debug_cmds.go**`: replace `**GetCommandContext("zone")**`, `**"local"**`, `**"peer"**`, `**"debug"**`, variable `**prefix**` in hsync, etc., with **closure-captured `role`** (or `*tdns.ApiClient` from `**GetApiClient(role, true)**` once at the shell).
- `**executeCombinerRequest**` (`combiner_cmds.go`): stop using `**GetCommandContext(cmdName)**`; use `**GetApiClient("combiner", true)**` (or pass `**api**` from the caller) so behavior does not depend on argv position.

## Phase 5 — Remove `GetCommandContext`

1. Repository grep: **zero** references in `**tdns/v2/cli`** and `**tdns-mp/v2/cli**`.
2. Delete the function from `**ping.go**` (or keep one release as deprecated if needed).

## Phase 6 — Verification

1. **Build:** primary targets (`tdns/cmdv2`, `tdns-mp` entrypoints) per project Makefile conventions.
2. **Manual smoke matrix (minimal):**
  - `**ping`** under **auth** and **agent** (and any other attached parent).
  - **Zone list** (or equivalent) under **auth** vs **agent**.
  - **Combiner** zone / data paths.
  - **Signer** zone `**mplist`**.
  - **mp** router / peer / gossip on **agent**, **combiner**, **signer**.
3. Optional: CI or pre-commit **grep** for `**GetCommandContext`** or `**os.Args**` in `cli` packages to prevent regression.

## Optional follow-up (separate effort)

If `**tdns.Globals.ApiClients**` coupling becomes painful, extract a small shared module (e.g. `**apiclient**`) used by both `**tdns**` and `**tdns-mp**`, still with **one** registry — not a second copy of `**GetApiClient`** logic inside mp only.

## References

- `tdns/v2/cli/ping.go` — `**GetApiClient**`, `**getClientKeyFromParent**`, `**GetCommandContext**` (to be removed).
- `tdns/v2/cli/imr_dump_cmds.go` — factory pattern for duplicate Cobra nodes with shared `**Run**` (`newDumpServersCmd`, `runDumpServers`).

---

## Implementation status (branch `cli-cobra-role-refactor`)

Feature branch committed in both repos. Baseline: ~60 `GetCommandContext` call sites across `tdns/v2/cli` + `tdns-mp/v2/cli`. Current: ~26 live call sites remain (plus 4 in `deadcode_*_cmds.go` that carry `//go:build ignore` and don't compile).

**Done (builds green in both repos):**

- `PingCmd` → `NewPingCmd(role)` factory. All 8 attachment sites updated (auth, agent, imr, scanner in tdns; root "server" default in tdns-cli; signer, combiner, agent in mpcli). Flags moved into the factory; the stale `daemon_cmds.go` flag setup was deleted.
- `KeysCmd` → `NewKeysCmd(role)` factory. Role threaded through `runKeysCommand`; 3 attachment sites updated (agent in tdns-cli; combiner + agent in mpcli).
- `catalog_cmds.go` — 13 sites hardcoded to `"server"` (only attached under rootCmd in cliv2).
- `distrib_cmds.go` — 6 sites removed. Helpers already took a `component` string that is the role; `runDistribOp` / `runAgentDiscover` hardcoded to `"agent"` (single-parent).
- `transaction_cmds.go` — 3 sites removed. Helpers use the `component` parameter; combiner-only commands hardcoded to `"combiner"`.
- `parentsync_cmds.go` — 2 direct `GetCommandContext("parentsync")` sites hardcoded to `"agent"` (parentsync is agent-only today). **The `SendAgentMgmtCmd(prefix)` site is deliberately untouched** — that's the non-mechanical rewrite tracked below.
- `agent_zone_cmds.go` in both repos — 7 + 9 sites hardcoded to `"agent"` (AgentZoneCmd is agent-only in both tdns-cli and mpcli).
- `combiner_edits_cmds.go` — 2 sites hardcoded to `"combiner"`.
- `signer_cmds.go` — 1 site hardcoded to `"signer"`.

**Not done — multi-parent commands that still need factory treatment:**

Each of these `*Cmd` pointers is attached under 2+ Cobra parents (tdns-cli `root` / `AgentCmd` / `AuthCmd`, plus mpcli `SignerCmd` / `CombinerCmd` / `AgentCmd` in various combinations). Mechanical hardcoding is **unsafe** because the correct role genuinely differs per attachment. Each needs a `NewXxxCmd(role)` factory (and, where the subcommands are also shared package vars, those need to be created inside the factory too):

- `tdns/v2/cli/zone_cmds.go` (5 sites) — `ZoneCmd` attached under `AuthCmd` (role `"auth"`) and `mpcli.SignerCmd` (role `"signer"`).
- `tdns/v2/cli/daemon_cmds.go` (6 sites) — `DaemonCmd` attached under root, `AgentCmd` (tdns-cli), and `SignerCmd` / `CombinerCmd` / `AgentCmd` (mpcli). Sub-commands (`DaemonRestartCmd`, etc.) are shared package vars.
- `tdns/v2/cli/config_cmds.go` (3 sites) — `ConfigCmd` attached under root + `AgentCmd` (tdns-cli), and three trees in mpcli.
- `tdns/v2/cli/keystore_cmds.go` (3 sites) — `KeystoreCmd` attached under `AuthCmd` + `AgentCmd` (tdns-cli) and `SignerCmd` + `AgentCmd` (mpcli). Plus nested subcommand tree (`truststoreSig0Cmd` / children) is shared package vars — whole tree needs to move into the factory.
- `tdns/v2/cli/truststore_cmds.go` (1 site) — same shape as keystore (`Sig0TrustMgmt` helper, nested `truststoreSig0Cmd` subtree).
- `tdns-mp/v2/cli/agent_debug_cmds.go` (1 site, `DebugAgentQueueStatusCmd`) — attached via `DebugAgentCmd` under `tdnscli.DebugCmd`, which is multi-parent. Hits `/agent/debug`, so role might always be `"agent"` — **needs confirmation** before hardcoding.

**Not done — non-mechanical (watch-item) rewrites:**

- `tdns/v2/cli/parentsync_cmds.go` `SendAgentMgmtCmd(prefix string)` — the one marker-string site in tdns. All current callers pass `"parentsync"`; intended role is `"agent"`. Change signature to `SendAgentMgmtCmd(req, role string)` and audit callers.
- `tdns-mp/v2/cli/agent_cmds.go` — 4 sites including a **second, independent** `SendAgentMgmtCmd` definition in this package (not the tdns one). Callers pass `"local"`, `"peer"`, or a variable `prefix`. Each caller needs per-site role analysis.
- `tdns-mp/v2/cli/hsync_cmds.go` — 1 site, `prefix` variable into tdns-mp's local `SendAgentMgmtCmd`.
- `tdns-mp/v2/cli/combiner_cmds.go` `executeCombinerRequest(cmdName)` — same pattern (argv marker, not role). Plan doc suggests `GetApiClient("combiner", true)` or threading the client in.

**Phase 5 (remove `GetCommandContext`) cannot land until all of the above are done.** The function itself is still defined and referenced from the remaining 26 live call sites.

