# tdns-ncli: instances of tdns-agent

**Date:** 2026-11-20
**Status:** implemented on `feature/ncli-agent-instances` (PR 2 of 3). PR 1 is
`config add` / `config list`; PR 3 is imr instances.

Builds on `docs/2026-09-07-cli-multi-instance-design.md` (auth instances) and
`docs/2026-11-20-ncli-config-add-list-design.md`.

## What it is

`apiservers:` entries with `role: agent` now become a command tree, the way
`role: auth` ones always did:

```yaml
   - name: agent2
     role: agent
     baseurl: https://127.0.0.1:8988/api/v1
     ...
```

`tdns-ncli agent2 zone dsync publish` drives the second agent;
`tdns-ncli agent ...` is untouched. The tree is `cli.NewAgentTree`, registered
in `knownInstanceRoles`.

## What had to change

The recipe is the one the auth work established: every subcommand comes from a
role-parameterised factory, the tree root carries the target, and no command
carries a literal role.

- **`NewAgentZoneCmd(role)`.** The agent's `zone` group was a package-level
  value, `AgentZoneCmd`, with its eleven subcommands as package-level values
  too. A cobra command has one parent, so a second tree needs its own copy of
  each, which means a factory. Seven of them asked for `GetApiClient("agent")`
  whatever tree they sat in; they now call `GetApiClientForCmd(cmd)`, which
  reads the target off the tree. `ResolveAlgorithm` and `CreateUpdate`, which
  took the literal, take `role`. The canonical tree is `NewAgentZoneCmd("agent")`
  from `init()`, so tdns-cli's behaviour is unchanged. The two blocks of
  disabled `addrr`/`delrr` code are left as they were. #1170 (merged into
  main first, 2026-11-21) added `add`, `delete`, `modify` and `list-dynamic` to
  the old package-level group; with main merged in, `NewAgentZoneCmd` adds
  them with `newZoneDynamicCmds(role)`, so an instance's `zone add` adds to
  that instance (`TestAgentZoneDynamicCmds` checks both trees).
- **The hidden legacy `agent parentsync`** is now `newLegacyAgentParentSync`, so
  an instance tree keeps it too (hidden, as on the canonical tree).
- **`NewConfigCmdFor(role, flavour)`.** `config` omits `transport-signal` for an
  agent, decided with `role != "agent"` when the tree is built. For an instance
  `role` is its own name (`agent2`), so an agent instance would have been given
  an auth-only command. The flavour cannot be looked up from the CLI config
  here: commands are built before that config is loaded. So the tree factory,
  which knows what it is building, passes it. `NewConfigCmd(role)` is
  `NewConfigCmdFor(role, role)`, unchanged for every existing caller.

## Guarding it

- `TestInstanceTreeMatchesCanonicalAgentTree` (cmdv2/ncli) is the auth parity
  test generalised: the canonical agent tree and an instance tree must have the
  same commands (128 and 128 today), so a command wired only into a binary's
  `shared_cmds.go` and not into `NewAgentTree` fails the build. Nothing is
  deliberately absent for the agent.
- `TestNoHardcodedAuthRoleRemains` now also rejects `GetApiClient("agent")`.
  It still allows `"scanner"` and `"imr"` literals, which have no instance
  factory yet.
- `TestAgentInstanceZoneCommandsReachTheirOwnClient` resolves the seven
  commands that used to hardcode the role through a second instance and
  requires the second instance's client, and the canonical tree's still the
  canonical client.
- `TestAgentInstanceConfigHasNoTransportSignal` fails with the old
  `role != "agent"` test restored.

## Not done

- `config mwe` is still "not implemented" for any instance, agent or auth.
- imr instances are PR 3.
- Merging with PR 1: both change the `knownInstanceRoles` block in
  `v2/cli/instances.go` (PR 1 its comment, this one its map). Whichever merges
  second takes both. After the merge `tdns-ncli config add` accepts a second
  agent, since it asks `knownInstanceRoles`.
