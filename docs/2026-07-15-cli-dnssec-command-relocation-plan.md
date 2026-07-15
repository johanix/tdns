# PR-CLI — Relocate DNSSEC rollover/policy commands to `zone dnssec`

**Status:** implementation-ready; all decisions settled (§3f, §4).
**Sequence:** lands **first**, before PR-F4 and the transactional-policy-reload
project. Mostly a CLI-verb relocation; the **one** wire change is the
`set-policy` → `policy-set` command rename (both ends). The bulk of the work is
the **doc sweep**. Hard move, **no compatibility aliases** (decided).

## 0. Target tree

Decided (full scope): consolidate **all** of the zone's DNSSEC verbs under a new
`zone dnssec` group, and rename `set-policy` → `policy-set` so the three policy
verbs read consistently.

```
auth zone dnssec policy-set ...         (renamed from `zone set-policy`)
auth zone dnssec policy-change ...      (moved from keystore + promoted out of auto-rollover)
auth zone dnssec policy-reset ...       (RESERVED — lands with the policy project, not here)
auth zone dnssec auto-rollover ...      (moved from keystore)
auth zone dnssec sign ...               (moved from `zone sign`)
auth zone dnssec resign ...             (moved from `zone resign`)
auth zone dnssec nsec ...               (moved from `zone nsec`)
```

Rationale (Johan): `keystore` is about key *material*; signing/policy/rollover
are zone *DNSSEC operations* and belong under `zone dnssec`. The three policy
verbs (`policy-set`/`policy-change`/`policy-reset`) sit together and read
consistently.

**The rename is full — CLI verb *and* wire command** (Johan: keeping the verb
`policy-set` but the wire command `set-policy` would be too confusing). So the
mgmt-API command string changes `set-policy` → `policy-set` on **both** the CLI
sender (`zone_cmds.go:341`) and the server handler (`apihandler_zone.go:102`).
Version-skew note: an old `tdns-cli` against a new `tdns-auth` (or vice versa)
will not resolve the command — acceptable under the same "own tooling, deploy
cli+server together" posture as the hard move, but flag it in the PR.

---

## 1. Current structure (code-accurate)

- **auto-rollover subtree:** `newAutoRolloverCmd(role)`
  (`v2/cli/ksk_rollover_cli.go:1734`), subcommands: `when`, `asap`, `cancel`,
  `policy-change`, `status`, `reset`, `unstick`, `validate`
  (`ksk_rollover_cli.go:1755-1764`).
- **policy-change:** `newAutoRolloverPolicyChangeCmd()`
  (`ksk_rollover_cli.go:1772`). Sends `ZonePost{Command:"change-policy"}`. Has
  its **own** `-z/--zone` + `-p/--policy` flags (`:1820-1821`) and does **not**
  read the auto-rollover parent's persistent `--ksk/--zsk` flags → **clean to
  promote to a sibling**. (Note: it isn't even listed in the auto-rollover
  parent's `Long` help, `:1738-1746` — it's an odd fit there today.)
- **Attach point (source):** `newKeystoreDnssecCmd(role)`
  (`v2/cli/keystore_cmds.go:570`, `Use: "dnssec"`); its `AddCommand` at
  `keystore_cmds.go:797` includes `newAutoRolloverCmd(role)`.
- **Role binding:** `NewKeystoreCmd("auth")` **and** `NewKeystoreCmd("agent")`
  (`cmdv2/cli/shared_cmds.go:37,39`) → auto-rollover currently exists under
  **both** `auth keystore dnssec` and `agent keystore dnssec`.
- **Destination trees:**
  - auth: `NewZoneCmd("auth")` (`v2/cli/auth_cmds.go:20`); tree built in
    `v2/cli/zone_cmds.go`, `AddCommand` at `zone_cmds.go:216`. **There is no
    `zone dnssec` group yet** — `zone` has flat verbs (`set-policy` `:104`,
    `sign`, `resign`, `nsec`, …). PR-CLI must **create** `zone dnssec`.
  - agent: a **separate** `AgentZoneCmd` (`v2/cli/agent_zone_cmds.go:21`,
    attached `:429`) with agent-specific verbs — does not share `NewZoneCmd`.

---

## 2. Reference docs are auto-generated

The CLI reference (`reference/cli/tdns-cli_*.md`) is generated from the live
cobra tree by `tdns-cli gen-docs --dir reference/cli` (`cmdv2/cli/gendocs.go`,
`doc.GenMarkdownTree`). So after the code move, regenerating rewrites the pages —
**but `GenMarkdownTree` does not delete stale files**, so the old
`*_keystore_dnssec_auto-rollover*` pages must be `git rm`'d by hand.

---

## 3. Code changes

a. **Create the group.** New `newZoneDnssecCmd(role)` returning a
   `Use: "dnssec"` command; wire it into `NewZoneCmd`'s `AddCommand`
   (`v2/cli/zone_cmds.go:216`).

b. **Detach from keystore.** Remove `newAutoRolloverCmd(role)` from the
   `AddCommand` list at `v2/cli/keystore_cmds.go:797`.

c. **Promote policy-change.** Remove `newAutoRolloverPolicyChangeCmd()` from the
   auto-rollover parent's `AddCommand` (`ksk_rollover_cli.go:1759`).

d. **Move the existing zone DNSSEC verbs into the group.** In `NewZoneCmd`
   (`zone_cmds.go:216`), remove `sign`, `resign`, `nsec`, and `setPolicy` from
   the top-level `AddCommand`, and instead add them to `newZoneDnssecCmd`
   alongside `newAutoRolloverCmd(role)` and `newAutoRolloverPolicyChangeCmd()`.
   (These are locals built earlier in `NewZoneCmd`; the cleanest refactor is to
   have `newZoneDnssecCmd` take them, or inline their construction there.)

e. **Rename `set-policy` → `policy-set` (CLI verb + wire command).** Four sites,
   all of the `set-policy` string in code:
   - `zone_cmds.go:104` — cobra `Use: "set-policy"` → `"policy-set"` (CLI verb)
   - `zone_cmds.go:341` — `Command: "set-policy"` → `"policy-set"` (wire send)
   - `apihandler_zone.go:102` — `case "set-policy":` → `case "policy-set":`
     (server dispatch)
   - `api_structs.go:211` — update the doc comment referencing `"set-policy"`
   Coordinate with the transactional-policy project: that work extracts the
   `set-policy` handler's transactional core (`apihandler_zone.go` ~`:363`), so
   land this rename first (or note the new command name there).

f. **Fix in-code help text.** Sweep `ksk_rollover_cli.go` (and any zone help)
   for strings that name an absolute path. Relative subcommand references (e.g.
   the `auto-rollover asap -z <zone> --zsk` hint in policy-change's `Long`
   `:1785`, the `auto-rollover unstick` hint at `:1264`) still resolve under the
   new parent and can stay; only `keystore dnssec …` / `zone set-policy` strings
   need changing. `grep -n "keystore dnssec\|set-policy" v2/cli` to confirm.

g. **Agent role — DECIDED: drop.** Agents never sign (`SetupZoneSigning` no-ops
   for `AppTypeAgent`; the resigner isn't meaningful there), so
   `auto-rollover`/`policy-change` under `agent keystore dnssec` are vestigial.
   Move them to `auth zone dnssec` **only**; do **not** add a `zone dnssec` group
   to `AgentZoneCmd`. (`sign`/`resign`/`set-policy` are auth-`NewZoneCmd`-only
   already, so nothing to drop there.)

---

## 4. Scope of `zone dnssec` — DECIDED: full

Consolidate all zone DNSSEC verbs under `zone dnssec` (per §0): `policy-set`
(renamed), `policy-change` (moved), `auto-rollover` (moved), `sign`, `resign`,
and — recommended, please confirm — `nsec`. `policy-reset` is reserved for the
policy project. This is larger doc churn than a minimal move but gives the
coherent end-state, with all three `policy-*` verbs together.

*(The minimal alternative — `zone dnssec = { auto-rollover, policy-change }`,
leaving `sign`/`resign`/`set-policy`/`nsec` top-level — was considered and
rejected in favour of the full consolidation above.)*

---

## 5. Doc sweep (the main work)

### Reference guide — regenerate + prune

1. Build `tdns-cli`, run `tdns-cli gen-docs --dir reference/cli`.
2. `git rm` stale pages (GenMarkdownTree does not delete):
   - `tdns-cli_auth_keystore_dnssec_auto-rollover*.md` (parent +
     `asap/cancel/policy-change/reset/status/unstick/validate/when`),
   - `tdns-cli_agent_keystore_dnssec_auto-rollover*.md` (dropped from agent, §3g),
   - `tdns-cli_auth_zone_set-policy.md`, `tdns-cli_auth_zone_sign.md`,
     `tdns-cli_auth_zone_resign.md`, `tdns-cli_auth_zone_nsec*.md` (verbs moved
     under the new group).
3. `git add` new pages: `reference/cli/tdns-cli_auth_zone_dnssec*.md`.
4. Check `reference/cli/README.md` for a hand-maintained command index.

### tdns guide — hand-edit

Path changes across the guide:

- `keystore dnssec auto-rollover` → `zone dnssec auto-rollover`
- `auto-rollover policy-change` → `zone dnssec policy-change` (note the
  **promotion** — it is `zone dnssec policy-change`, **not** `zone dnssec
  auto-rollover policy-change`)
- `zone set-policy` → `zone dnssec policy-set` (verb moved **and** renamed)
- `zone sign` → `zone dnssec sign`; `zone resign` → `zone dnssec resign`;
  `zone nsec` → `zone dnssec nsec`

Known hits (re-grep to be exhaustive — the rename/move widens the sweep):

- `guide/key-rollover.md` — the heavy user: ~`:211, :219, :229, :241, :826,
  :828, :1022, :1028, :1035` (auto-rollover/policy-change).
- `guide/pq-dnssec.md:409`
- `guide/README.md:60`
- also grep the whole `guide/` tree for `zone set-policy`, `zone sign`,
  `zone resign`, `zone nsec` (esp. `guide/app-tdns-cli.md`,
  `guide/app-tdns-auth.md`, `guide/special-features.md`,
  `guide/configuration.md`, `guide/pq-dnssec.md`).

### Historical design docs — leave alone

`docs/2026-06-16-*`, `docs/2026-06-17-*`, `docs/2026-04-28-*`,
`docs/2026-04-29-*`, `docs/2026-06-21-*` reference the old paths but are
point-in-time records — **do not rewrite** them.

### Verification gate

```
grep -rn "keystore dnssec auto-rollover\|auto-rollover policy-change\|zone set-policy\|zone sign\|zone resign\|zone nsec" guide reference
```
must return **zero** hits after the sweep (historical `docs/` excluded).

---

## 6. Verification

- Build; `tdns-cli auth zone dnssec --help` lists `policy-set`, `policy-change`,
  `auto-rollover`, `sign`, `resign`, `nsec`; `tdns-cli auth keystore dnssec
  --help` no longer lists auto-rollover/policy-change; top-level `tdns-cli auth
  zone --help` no longer lists `set-policy`/`sign`/`resign`/`nsec`.
- Smoke: `tdns-cli auth zone dnssec policy-change -z <zone> -p <policy>` still
  issues the `change-policy` call; `tdns-cli auth zone dnssec policy-set -z
  <zone> -p <policy>` issues the **renamed** `policy-set` wire command and the
  server applies it (verify the policy actually changes, since both ends moved).
- Agent (§3g): `tdns-cli agent keystore dnssec --help` no longer shows
  auto-rollover, and no `agent` variant remains anywhere.
- Regenerate reference; confirm the grep gate is clean and no stale pages remain.

---

## 7. Risk / PR slicing

Single small PR (**PR-CLI**). Two intended breaking changes: the command-surface
relocation (hard move, no aliases) and the `set-policy` → `policy-set` wire
rename (cli↔server must be deployed together). Both accepted — our own tooling,
all call sites owned. Lands first so PR-F4 and the policy project build on the
settled command layout (and `policy-reset` drops straight into `zone dnssec`).
