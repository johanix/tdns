# Open Items: Projects, Issues, and Bugs

Compiled 2026-03-20 from audit of all planning documents in
tdns/docs/ and the MEMORY.md tracking file. Each item verified
against current codebase.

## High Priority

### 1. Signer Serial Confusion
- **Source**: MEMORY.md ("Other Active Work")
- **Status**: Partially addressed
- **Description**: Signer conflates incoming serial (from
  combiner NOTIFY) with outgoing serial. Outgoing serial
  persistence was added (db_outgoing_serial.go), but the
  signer still has no separate tracking of the serial
  received from the combiner vs the serial it advertises.
- **Impact**: Can cause missed NOTIFYs or stale zone data
  if serials get out of sync.

### 2. No-Signing-Without-Authorization Enforcement
- **Source**: This session's work (2026-03-20)
- **Status**: Fix applied, needs broad testing
- **Description**: Empty signers list in HSYNCPARAM now
  means "no signing authorized" instead of the previous
  "sign by default". Also: identity checks added to
  delegation-sync-child dynamic option, allow-combine
  gated on HSYNC3 identity, mp-not-listed-error warning.
- **Risk**: Zones that previously relied on the default
  signing behavior will stop being signed. Verify all
  test zones have explicit signers= in HSYNCPARAM.

## Medium Priority

### 3. Complete Operations Migration (API/CLI paths)
- **Source**: 2026-03-15-migrate-remaining-legacy-records.md
- **Status**: Partially done (1 of 5 API paths migrated)
- **Description**: Of the 5 ZoneUpdate constructions in
  apihandler_agent.go, only the addrr/delrr path (line
  1823) populates zu.Operations. The other 4 paths
  (inject-sync at line 1237, send-to-combiner at line
  1429, test-policy at line 1520, inject-fake-sync at
  line 1729) still only populate RRs and RRsets.
- **Also remaining**: Legacy combiner fallback path
  (combiner_chunk.go lines 352-458) cannot be removed
  until all senders populate Operations.
- **Impact**: The legacy RRsets path works but loses the
  explicit operation semantics (add vs delete vs replace).

### 4. Agent Zone Data Persistence (Phase 4)
- **Source**: 2026-02-17-transport-unification-and-
  message-symmetry.md
- **Status**: Not implemented (by design)
- **Description**: Agents do not persist synced zone data
  to disk. On restart they re-bootstrap via three RFI
  calls (EDITS from combiner, KEYSTATE from signer,
  SYNC from peers). Only the combiner persists via
  CombinerContributions table.
- **Impact**: Slow restarts in large deployments; brief
  data loss window during restart until RFI completes.

### 5. Resync on Agent Startup
- **Source**: MEMORY.md ("Deferred Future Work")
- **Status**: Deferred
- **Description**: Automatically run pull+push resync for
  each configured zone when the agent starts. Currently
  requires manual CLI command. The RFI hydration
  (EDITS + KEYSTATE + peer discovery) partially covers
  this but is not a full bidirectional resync.

### 6. SYNC Handler Unification (Phase 6)
- **Source**: 2026-02-17-transport-unification-and-
  message-symmetry.md (line 278)
- **Status**: Deferred
- **Description**: Single HandleSync with callbacks for
  both agent and combiner processing. Currently separate.
- **Why deferred**: SYNC is the core data path; abstraction
  must not add latency. Low urgency.

## Low Priority

### 7. Inline SYNC Confirmation (Phase 7)

- **Source**: 2026-02-17-transport-unification-and-
  message-symmetry.md (line 309)
- **Status**: Partial -- infrastructure in place, but
  duplicate DistributionID detection and explicit NOTIFY
  fallback are missing.
- **Impact**: Optimization, not a correctness issue.

### 8. DNS-79: GetZoneAgentData Bug
- **Source**: Linear issue DNS-79
- **Status**: Open
- **Description**: Investigate discrepancy between
  GetZoneAgentData and getAllAgentsForZone (returns 0
  remote agents unexpectedly).

### 9. DNS-80: Agent CLI Commands for ClassANY
- **Source**: Linear issue DNS-80
- **Status**: Open
- **Description**: Needed for CSYNC management where
  single-record RRsets require ClassANY operations.

### 10. DNS-81: Audit Command
- **Source**: Linear issue DNS-81
- **Status**: Open
- **Description**: CLI command to compare local vs combiner
  vs remote agent state for a zone.

### 11. CLI Purge Tools
- **Source**: MEMORY.md ("Other Active Work")
- **Status**: Open
- **Description**: CLI commands to purge old stale data
  from agent/combiner databases.

## Docs Needing Status Updates

The following design documents have items marked as pending
or planning that are actually implemented. The docs should
be updated to reflect completion:

- **2026-03-09-parentsync-key-publication.md**: Phase 3c
  (SIG(0) private key distribution) is marked "Planning"
  but is fully implemented: onLeaderElected callback,
  RFI CONFIG with sig0key subtype, importSig0KeyFromPeer,
  GetSig0KeyRaw in keystore.

- **2026-03-15-migrate-remaining-legacy-records.md**:
  Agent-to-agent SYNC path uses Operations. Combiner
  processes Operations first. But 4 of 5 API/CLI local
  update paths still only populate RRs/RRsets. Legacy
  the legacy fallback path remains as dead code.

- **MEMORY.md**: "KEYSTATE as sole DNSKEY source" is
  listed as "IN PROGRESS" but is implemented for agents
  (the only role that needed it). Non-agents correctly
  fall back to zone transfer data by design.
