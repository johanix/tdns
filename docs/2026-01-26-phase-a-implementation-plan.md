# Phase A: Infrastructure Generalization - Implementation Plan

## Document Version
- **Date**: 2025-01-26
- **Status**: Ready to Execute
- **Duration**: 1-2 weeks
- **Risk**: Low (extraction of already-generic code)

## Overview

Phase A extracts remaining generic utilities from tdns-nm/tnm to tdns/v2 for shared use by KDC, KRS, and future agent implementations. Most infrastructure was already generalized during the recent crypto refactoring; this phase completes the extraction.

## What's Already Done (Recent Refactoring)

✅ **Backend abstraction** - Complete crypto abstraction layer (`v2/crypto/`)
✅ **CHUNK RR type** - Unified in `v2/core/rr_chunk.go`
✅ **NOTIFY RR type** - Unified in `v2/core/rr_notify.go`
✅ **Transport parsing** - Extracted to `v2/core/transport.go`
✅ **Feature flags** - `use_crypto_v2` migration architecture
✅ **Confirmation framework** - EDNS(0) CHUNK option structure

## What Phase A Will Extract

### Total Scope: ~230 lines of code extraction

---

## Task 1: CHUNK Format Utilities

**Source**: `tdns-nm/tnm/chunk_format.go`
**Destination**: `tdns/v2/core/chunk_utilities.go` (new file)

**Functions to Move** (~100 lines):
```go
CreateCHUNKManifest(metadata map[string]interface{}, payload []byte, chunkCount uint16) (*ManifestData, error)
ExtractManifestData(chunk *dns.RR) (*ManifestData, error)
CalculateCHUNKHMAC(chunk *CHUNK, key []byte) []byte
VerifyCHUNKHMAC(chunk *CHUNK, key []byte) (bool, error)
```

**Why Generic**:
- No KDC/KRS-specific logic
- Work with any manifest metadata
- HMAC applies to any chunk, not just key distributions
- Agents will need identical functionality

**Changes Required**:
- Import paths update in tnm files
- No behavioral changes
- Keep tnm/chunk_format.go for distribution-specific metadata helpers

**Testing**:
- Existing KDC/KRS tests should pass unchanged
- Add unit tests in v2/core/ for extracted functions

---

## Task 2: NOTIFY Pattern Helpers

**Source**: `tdns-nm/tnm/kdc/notify.go`
**Destination**: `tdns/v2/core/notify_helpers.go` (new file)

**Functions to Extract** (~50 lines):
```go
ExtractCorrelationIDFromQNAME(qname string, zone string) (string, error)
BuildNotifyQNAME(correlationID string, zone string) string
```

**Generalization**:
- "Distribution ID" becomes "Correlation ID" (generic term)
- Zone parameter stays (applies to any NOTIFY-based coordination)
- Agents use same pattern for sync operations

**Keep in tnm/kdc/notify.go**:
- `SendNotifyWithDistributionID()` - KDC-specific wrapper
- DNS client setup - KDC-specific configuration

**Changes Required**:
- Update KDC/KRS code to use generic helpers
- Correlation ID can be distribution ID, sync ID, or any operation ID

**Testing**:
- KDC NOTIFY sending should work unchanged
- KRS NOTIFY receiving should work unchanged
- Add tests for generic correlation ID handling

---

## Task 3: Confirmation Accumulation Framework

**Source**: `tdns-nm/tnm/krs/confirm.go`
**Destination**: `tdns/v2/core/confirmation.go` (new file)

**Interfaces to Define** (~80 lines):
```go
// Generic confirmation entry (implemented by KeyStatusEntry, ComponentStatusEntry, SyncStatusEntry, etc.)
type ConfirmationEntry interface {
    GetId() string          // Unique identifier (key ID, component ID, sync ID)
    GetStatus() string      // "success" or "failed"
    GetDetails() string     // Error message or details
}

// Generic confirmation accumulator
type ConfirmationAccumulator struct {
    entries     map[string]ConfirmationEntry
    startTime   time.Time
    completedTime *time.Time
}

func NewConfirmationAccumulator() *ConfirmationAccumulator
func (ca *ConfirmationAccumulator) AddSuccess(entry ConfirmationEntry)
func (ca *ConfirmationAccumulator) AddFailure(entry ConfirmationEntry)
func (ca *ConfirmationAccumulator) GetSuccesses() []ConfirmationEntry
func (ca *ConfirmationAccumulator) GetFailures() []ConfirmationEntry
func (ca *ConfirmationAccumulator) IsComplete() bool
```

**Keep in tnm/krs/confirm.go**:
- `KeyStatusEntry` struct - KRS-specific
- `ComponentStatusEntry` struct - KRS-specific
- `SendConfirmationToKDC()` - KRS-specific sending logic
- Both implement `ConfirmationEntry` interface

**Agents Will Add**:
- `SyncStatusEntry` struct - Agent-specific
- `SendConfirmationToAgent()` - Agent-to-agent confirmation

**Changes Required**:
- KRS confirmation code uses generic accumulator
- KRS-specific types implement ConfirmationEntry interface
- No change to EDNS(0) CHUNK option structure

**Testing**:
- KRS confirmation accumulation should work unchanged
- Add unit tests for generic accumulator logic

---

## Implementation Order

### Week 1: Extraction
1. **Day 1-2**: Extract CHUNK utilities
   - Create `v2/core/chunk_utilities.go`
   - Move functions from tnm/chunk_format.go
   - Update imports in KDC/KRS code
   - Run existing tests

2. **Day 3-4**: Extract NOTIFY helpers
   - Create `v2/core/notify_helpers.go`
   - Generalize correlation ID handling
   - Update KDC/KRS to use generic helpers
   - Run existing tests

3. **Day 5**: Extract confirmation framework
   - Create `v2/core/confirmation.go`
   - Define interfaces
   - Update KRS to implement interfaces
   - Run existing tests

### Week 2: Testing and Documentation
1. **Day 1-2**: Comprehensive testing
   - Unit tests for all extracted functions
   - Integration tests (KDC→KRS flow)
   - Verify backward compatibility

2. **Day 3-4**: Documentation
   - Add godoc comments to new files
   - Update architecture docs
   - Document agent usage patterns

3. **Day 5**: Code review and merge
   - Final review
   - Merge to main branch
   - Tag as "phase-a-complete"

---

## Success Criteria

✅ **All existing tests pass** - No behavioral changes to KDC/KRS
✅ **~230 lines extracted** - Code moved to tdns/v2/core
✅ **Clean abstractions** - Interfaces defined for agents to implement
✅ **Documentation complete** - Godoc and architecture docs updated
✅ **Ready for Project 2** - Agents can use shared infrastructure

---

## Risk Assessment

**LOW RISK**:
- Extracting already-generic code (zero business logic changes)
- No new functionality, just reorganization
- Comprehensive test coverage exists
- Can rollback easily if issues arise

**Mitigation**:
- Run full test suite after each extraction
- Keep commit history clean (one task per commit)
- Review each extraction before moving to next

---

## Files Created

```
tdns/v2/core/
├── chunk_utilities.go         (NEW - ~100 lines)
├── notify_helpers.go          (NEW - ~50 lines)
└── confirmation.go            (NEW - ~80 lines)
```

## Files Modified

```
tdns-nm/tnm/
├── chunk_format.go            (Keep distribution-specific helpers)
├── kdc/notify.go              (Use generic helpers)
└── krs/confirm.go             (Implement ConfirmationEntry interface)
```

---

## Next Steps After Phase A

**Immediate**: Ready to start Project 2 (DNS Mode)
- Agents use CHUNK utilities from v2/core
- Agents use NOTIFY helpers from v2/core
- Agents implement ConfirmationEntry for sync confirmations

**Parallel**: Can proceed with Project 1 (JWE/JWS) independently
- Backend implementations work independently
- No conflicts with Phase A changes
- Both projects leverage shared infrastructure

---

## Questions Before Starting

None - architecture is clear and implementation is straightforward extraction.

Ready to execute Phase A.
