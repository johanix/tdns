# Plan: Refresh Delegation Sync (DDNS) and KeyState
# EDNS(0) Implementation

## Context

The tdns codebase has a working but aging implementation
of automatic delegation synchronization via DDNS
(draft-ietf-dnsop-delegation-mgmt-via-ddns-01) and a
half-implemented KeyState EDNS(0) option
(draft-berra-dnsop-keystate-02). Both predate recent
architectural improvements (OnFirstLoad callbacks,
structured logging, transport refactoring). This plan
modernizes both subsystems to align with current codebase
patterns.

## Current State Assessment

### A. Delegation Sync — What Works
- **Child side**: Detects delegation changes (NS/glue),
  discovers DSYNC targets, sends SIG(0)-signed UPDATEs
  or NOTIFYs
- **Parent side**: Publishes DSYNC RRs, accepts child
  UPDATEs, validates SIG(0) signatures, key
  bootstrapping
- **Key files**: `delegation_sync.go`,
  `childsync_utils.go`, `delegation_utils.go`,
  `dsync_lookup.go`, `ops_dsync.go`, `zone_utils.go`

### B. Delegation Sync — Issues Found

1. **DeferredUpdate still used for agent transport
   setup** (`agent_setup.go:97,192`):
   `SetupApiTransport` and `SetupDnsTransport` use the
   legacy `DeferredUpdate` mechanism with
   `ZoneIsReady()` precondition. Should be converted to
   `OnFirstLoad` callbacks.

2. **DSYNC publication bypasses OnFirstLoad**:
   `SetupZoneSync` is called BEFORE `OnFirstLoad`
   callbacks in `refreshengine.go:99-111`. This means
   DSYNC publication happens during zone load but
   outside the callback framework. It works, but the
   timing is fragile — if PublishDsyncRRs fails, there's
   no retry.

3. **`dump.P()` debug calls left in production code**:
   `delegation_sync.go:529` (`dump.P(dsynctarget)`) and
   `zone_updater.go:835` (`dump.P(dss)`) — should be
   removed or replaced with structured logging.

4. **Swedish comments in code**: `keybootstrapper.go`,
   `keystate.go` contain Swedish comments
   (`"Standardvarde"`, `"Hamta aktuell nyckelstatus"`,
   `"Kunde inte hamta"`, etc.). Should be translated to
   English.

5. **Stale `log.Printf` in keystate code**:
   `edns0_keystate.go:107` uses `log.Printf` instead of
   structured logging.

6. **`viper.GetXxx()` direct access throughout**:
   `delegation_sync.go`, `ops_dsync.go`,
   `keybootstrapper.go`, `keystate.go` all read config
   directly from viper. This couples zone-level logic
   to global config. Should eventually use zone-specific
   config (but full migration is architectural — see A8
   below).

7. **`SetupZoneSync` uses `viper.GetString` for DSYNC
   target**: `zone_utils.go:1051` reads
   `delegationsync.parent.update.target` from global
   viper instead of zone-specific config.

8. **`Globals.Zonename` used in
   `keybootstrapper.go:187`**: Hard reference to a
   single zone name, breaks multi-zone scenarios.

9. **`Globals.ImrEngine` used in
   `keybootstrapper.go:286`**: Should be injected, not
   global.

10. **`ZoneUpdateChangesDelegationData` (old version)**:
    Exists alongside
    `ZoneUpdateChangesDelegationDataNG`. The old version
    at line 693 appears to be dead code — only `NG` is
    called.

### C. KeyState EDNS(0) — What Works
- **Codec**: `edns0_keystate.go` — Create/Parse/Extract/
  Attach functions are complete and follow the pattern
  of other EDNS0 options
- **Key states defined**: All values from
  draft-berra-dnsop-keystate-02 sections 5.1 and 5.2
- **ProcessKeyState**: `keystate.go` handles
  INQUIRY_KEY, REQUEST_AUTO_BOOTSTRAP, INQUIRY_POLICY
- **Key bootstrapper**: `keybootstrapper.go` —
  verification loop, multi-attempt verification,
  exponential backoff

### D. KeyState EDNS(0) — Issues Found

1. **NOT integrated into query responder**: The
   `MsgOptions.KeyState` field is populated during
   EDNS0 extraction (`edns0.go:73-76`), but **nobody
   checks it**. The query responder
   (`queryresponder.go`) never calls `ProcessKeyState`
   or `HandleKeyStateOption`. This means: child sends
   KeyState inquiry -> parent ignores it.

2. **Wire format mismatch with draft-02**: The draft
   defines 4 fields: KEY-ID (16 bits), KEY-STATE
   (8 bits), KEY-DATA (8 bits), EXTRA-TEXT (variable).
   The implementation has only 3 fields: KeyID
   (16 bits), KeyState (8 bits), ExtraText (variable).
   **KEY-DATA is missing.** The code packs/unpacks
   3 bytes minimum, but the draft requires 4.

3. **Stale keystate values**: The implementation defines
   codes 0-12 plus 255. The draft-02 removed codes 3
   (INQUIRY_POLICY), 11 (POLICY_MANUAL_REQUIRED), and
   12 (POLICY_AUTO_BOOTSTRAP) — bootstrap policy
   discovery is now via SVCB "bootstrap" SvcParamKey.
   Code still has all of them and `ProcessKeyState`
   still handles `KeyStateInquiryPolicy`.

4. **`keyStateToString` is private and unused**:
   `edns0_keystate.go:71` — should be exported and used
   in logging.

5. **UPDATE Receiver SIG(0) signing not implemented**:
   The draft requires that responses to queries
   containing a KeyState OPT be signed by the UPDATE
   Receiver's SIG(0) key. The
   `SyncZoneDelegationViaNotify` and query response
   paths don't do this.

6. **No SVCB "bootstrap" SvcParamKey support**: The
   draft-01 delegation-mgmt spec defines an SVCB record
   at the DSYNC target advertising bootstrap methods.
   No code publishes or parses this.

7. **`ProcessKeyState` auto-bootstrap is stubbed**:
   Lines 48-53 of `keystate.go` — the actual
   `startAutoBootstrap()` call is commented out.

### E. DeferredUpdate vs OnFirstLoad

| DeferredUpdate | OnFirstLoad |
|---|---|
| Used by: `agent_setup.go` (2 callers for transport record publication) | Used by: `parseconfig.go` (signing callbacks), `main_initfuncs.go` (combiner) |
| Mechanism: poll precondition every 10s | Mechanism: fire once after first zone load |
| No retry limit, no timeout | One-shot, cleared after execution |
| Zone may not exist yet when submitted | Zone guaranteed to exist when callback fires |

**Conclusion**: DeferredUpdate callers in
`agent_setup.go` should be migrated to OnFirstLoad
callbacks. `SetupApiTransport` and `SetupDnsTransport`
both use `ZoneIsReady` as precondition — this is exactly
what OnFirstLoad provides.

The `DeferredUpdaterEngine` itself should be **kept** for
now — it's a general mechanism and removing it is a
separate cleanup task.

## Implementation Plan

### Step 1: Fix KeyState EDNS(0) wire format (align with
draft-02)

**Files**: `edns0/edns0_keystate.go`

- Add `KeyData uint8` field to `KeyStateOption` struct
- Update `CreateKeyStateOption` to pack 4 bytes minimum
  (KeyID:2 + KeyState:1 + KeyData:1 + ExtraText:var)
- Update `ParseKeyStateOption` to require 4 bytes
  minimum and unpack KeyData
- Export `KeyStateToString()` (rename from
  `keyStateToString`)
- Remove stale codes 3 (INQUIRY_POLICY),
  11 (POLICY_MANUAL_REQUIRED),
  12 (POLICY_AUTO_BOOTSTRAP)
- Fix `log.Printf` -> use structured logging

### Step 2: Update KeyState callers for new wire format

**Files**: `keystate.go`, `keybootstrapper.go`

- Update all `KeyStateOption{}` constructions to include
  `KeyData: 0` (or meaningful value)
- Remove `KeyStateInquiryPolicy` handler from
  `ProcessKeyState`
- Remove policy-related response codes
  (`KeyStatePolicyManualRequired`,
  `KeyStatePolicyAutoBootstrap`)
- Translate all Swedish comments to English
- Replace `Globals.Zonename` with proper per-zone
  iteration
- Replace `Globals.ImrEngine` with injected reference
  (or accept as parameter)

### Step 3: Wire KeyState into query responder

**Files**: `queryresponder.go` or `do53.go` (whichever
is the right hook point)

- After extracting `MsgOptions` and determining the
  zone, check `msgoptions.KeyState != nil`
- If present AND this is a parent zone with
  `OptDelSyncParent`: call
  `kdb.HandleKeyStateOption(opt, zonename)`
- Attach response KeyState option to the reply message
- This completes the child->parent->child KeyState
  inquiry loop

### Step 4: Migrate to OnFirstLoad (agent transport +
SetupZoneSync)

**Files**: `agent_setup.go`, `parseconfig.go`,
`refreshengine.go`, `zone_utils.go`

**4a. Agent transport setup:**
- Convert `SetupApiTransport` from DeferredUpdate to an
  OnFirstLoad callback on the agent identity zone
- Convert `SetupDnsTransport` similarly
- Registration: in `SetupAgent`, append to
  `zd.OnFirstLoad` for the agent identity zone
- Remove `createDeferredUpdate` helper if no longer used

**4b. SetupZoneSync -> OnFirstLoad:**
- Remove `SetupZoneSync` call from
  `refreshengine.go:99`
- Register `SetupZoneSync` as OnFirstLoad callback in
  `parseconfig.go` for zones with `OptDelSyncParent`
  or `OptDelSyncChild`
- This means DSYNC publication and child
  delegation-sync-setup happen after signing callbacks,
  which is correct (child needs signed KEY RRs before
  bootstrapping with parent)

### Step 5: Clean up delegation sync code

**Files**: `delegation_sync.go`, `zone_updater.go`,
`ops_dsync.go`, `zone_utils.go`

- Remove `dump.P()` calls (2 sites)
- Remove dead `ZoneUpdateChangesDelegationData` function
  (the old version, ~145 lines)
- Remove stale commented-out DeferredUpdate code in
  `zone_utils.go:1034-1041`
- Translate any remaining Swedish comments
- Replace `zd.Logger.Printf` in `ops_dsync.go` with
  structured logging (slog)

### Step 6: Add SVCB bootstrap capability advertisement

**Files**: `ops_dsync.go` (or new code in `ops_svcb.go`)

- When publishing DSYNC RRs for a parent zone, also
  publish an SVCB record at the DSYNC target
- SVCB should advertise supported bootstrap methods via
  the "bootstrap" SvcParamKey
- Value derived from config (e.g.,
  `delegationsync.parent.bootstrap.methods`)
- Format: `updater.parent.example. IN SVCB 0 .
  bootstrap="at-apex,unsigned,manual"`

### Step 7: Sign KeyState responses with UPDATE
Receiver's SIG(0) key

**Files**: `queryresponder.go` or `do53.go`, possibly
`sign.go`

- When responding to a query that contained a KeyState
  OPT and we are the UPDATE Receiver (parent zone)
- Sign the response with the UPDATE Receiver's SIG(0)
  key (the key published at the DSYNC target name)
- This requires looking up the active SIG(0) key for
  the DSYNC target in the keystore

## Architectural Decisions (Resolved)

**A1**: Move `SetupZoneSync` into `OnFirstLoad` —
consistent ordering with other callbacks. DSYNC
publication happens after signing setup. Requires
removing the `SetupZoneSync` call from
`refreshengine.go:99` and registering it as an
OnFirstLoad callback in `parseconfig.go` for zones with
`OptDelSyncParent` or `OptDelSyncChild`.

**A2**: **Keep DeferredUpdaterEngine** — it's general
infrastructure. Don't remove even after Step 4.

**A3**: **Implement Steps 6 and 7 now** — complete
implementation aligned with the drafts.

**A4**: **Make keybootstrapper event-driven** — remove
the 10-second ticker polling. Instead, trigger key state
checks when: (a) delegation sync happens, (b) new key is
bootstrapped, (c) explicit CLI/API request. Add a new
Step 8 for this.

### Step 8: Make keybootstrapper event-driven

**Files**: `keybootstrapper.go`

- Remove the 10-second `time.Ticker` that polls all
  SIG(0) keys
- Replace with event-driven triggers:
  - **On key bootstrap**: `kbCmdBootstrap` already
    triggers verification — keep this
  - **On delegation sync**: After successful
    `SyncZoneDelegation`, send a
    `kbCmdUpdateKeyState` to the bootstrapper for the
    relevant zone
  - **On explicit request**: CLI `dsync-query` or API
    `/delegation` commands can trigger a key state
    check
- Keep the `verifications` sync.Map for tracking
  in-progress verifications
- The periodic retry logic for failed verifications
  should use a per-key timer rather than a global ticker

## Verification

1. **Build**:
   `cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make`
2. **Agent startup**: Verify agent starts, loads zones
   with `delegation-sync-child`, sets up SIG(0) keys
3. **Parent startup**: Verify parent starts, loads zones
   with `delegation-sync-parent`, publishes DSYNC RRs
4. **KeyState inquiry**: Send a query with KeyState
   EDNS0 option to parent, verify response contains
   KeyState
5. **Delegation sync**: Change NS in child zone, verify
   UPDATE sent to parent
6. **Transport records**: Verify agent transport records
   (URI, SVCB, TLSA, KEY) are published via OnFirstLoad

## Linear Issues

Create a Linear project "Delegation Sync Refresh" with
issues for each step.
