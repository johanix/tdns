# Big Bang Fallout: Known Issues in mpagent

Date: 2026-03-28
Status: Active tracking

Issues discovered during lab testing of the mpagent binary
after the big-bang agent extraction to tdns-mp.

## 1. Leader Elections Not Implemented

**Severity:** HIGH — affects delegation sync, SIG(0) key
management, provider group coordination.

The entire leader election block in `start_agent.go` is
replaced with a TODO. No `LeaderElectionManager` is
created, no OnFirstLoad election callbacks are attached
to zones, and the `OnLeaderElected` handler (which
generates SIG(0) keys and publishes them to the combiner
and remote agents) does not run.

**What doesn't work:**
- Per-zone and per-group leader elections
- SIG(0) key generation for delegation sync
- KEY publication to combiner
- `parentSyncAfterKeyPublication` (DSYNC bootstrap)

**Root cause:** The leader election setup code in tdns
uses several unexported symbols (`broadcastElectToZone`,
`configuredPeers`, `providerGroupMgr`,
`importSig0KeyFromPeer`, `parseKeygenAlgorithm`,
`parentSyncAfterKeyPublication`). All of these are now
in the copied files in tdns-mp — the symbols ARE
available locally. The TODO block can be replaced with
the actual implementation.

**Fix:** Implement the leader election block in
`start_agent.go` using the local types and functions.
All the pieces are present in tdns-mp; they just need
to be wired together.

## 2. Agent API Route Coverage

**Severity:** LOW — main endpoints work, edge cases may
not.

The tdns `SetupAPIRouter` registers agent routes only
for `AppTypeAgent`, not `AppTypeMPAgent`. We added
`SetupMPAgentRoutes` which registers `/agent`,
`/agent/distrib`, `/agent/transaction`, `/agent/debug`.

**Potential gaps:**
- Any route registered in tdns for agents that we missed
- Routes registered conditionally based on AppType in
  other parts of tdns

**Status:** Main CLI commands (peer list, zone edits,
gossip, resync, etc.) all work. No known broken endpoint
yet, but systematic audit not done.

## 3. Config Reload (SIGHUP) Callback Duplication

**Severity:** MEDIUM — may cause duplicate MP analysis on
zone refresh after a config reload.

`ParseZones` in tdns registers `MPPreRefresh` and
`MPPostRefresh` callbacks on zones with `OptMultiProvider`
during the first load. These are the TDNS versions of
the callbacks (in tdns/v2/hsync_utils.go).

On SIGHUP reload, `ParseZones` runs again. It only
registers callbacks when `zdp.FirstZoneLoad` is true,
so existing zones should not get duplicate callbacks.
But new zones added during reload WILL get the tdns
callbacks, not the tdns-mp versions.

**What this means:**
- Existing zones: OK (tdns callbacks registered once
  at initial load, work via tdns code path)
- New zones added via SIGHUP: get tdns callbacks which
  call `zd.HsyncChanged()` etc. (tdns receiver methods).
  These work because the methods exist on `*tdns.ZoneData`.
  However, they use `tdns.Conf.Internal.MPTransport`
  (nil for mpagent) for certain operations.

**Fix:** Either register tdns-mp callbacks for new zones
in a post-reload hook, or accept the limitation (new
zones require a full restart of mpagent).

## 4. Residual tdns.Conf.Internal.* References

**Severity:** MEDIUM — causes nil dereferences for code
paths not yet fully converted.

Some tdns-mp code still reads from `tdns.Conf.Internal.*`
instead of `conf.InternalMp.*`. These references work
for fields that are dual-written (DistributionCache,
CombinerState, TransportManager) but fail for fields
that are NOT dual-written (MPTransport, AgentRegistry,
MsgQs, ZoneDataRepo).

**Known fixed instances:**
- `RequestAndWaitForKeyInventory` — fixed (takes tm param)
- `RequestAndWaitForEdits` — fixed (takes tm + msgQs + zdr)
- `RequestAndWaitForConfig/Audit` — fixed (takes msgQs)
- `applyEditsToSDE` — fixed (takes zdr param)
- `apihandler_agent.go` refresh-keys — fixed

**Possibly remaining:**
- Any code path in the copied files that wasn't exercised
  during testing. A systematic grep for
  `tdns.Conf.Internal.` in tdns-mp/v2/ would find them.

**Fix:** Grep and fix remaining references.

## 5. parentSyncAfterKeyPublication Unavailable

**Severity:** LOW (blocked by issue 1 anyway)

The function `parentSyncAfterKeyPublication` is an
unexported method on `*tdns.Config`. It's called in the
`OnLeaderElected` handler after KEY publication to
trigger DSYNC bootstrap with the parent (KeyState
inquiry + DDNS UPDATE).

Since leader elections aren't implemented yet (issue 1),
this function is never called. When issue 1 is fixed,
this function needs to be reimplemented locally in
tdns-mp as a method on `*tdnsmp.Config`.

**Fix:** Implement alongside issue 1. The function calls
several other unexported tdns functions that are now
available locally in the copied parentsync_leader.go.
