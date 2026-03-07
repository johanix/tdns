# Generalize CHUNK Communications Framework - Migration Plan

## Date: 2026-01-27
## Status: 🚧 **IN PROGRESS**

---

## Overview

This document describes the migration plan to extract the CHUNK-based distribution framework from tdns-nm (KDC/KRS-specific) into tdns (generic DNS infrastructure), making it reusable for HSYNC and other future projects.

**Goals:**
1. Create generic operations framework in tdns repo
2. Move distribution tracking infrastructure from tdns-nm to tdns
3. Migrate manifest format from custom JSON to standard JWT
4. Enable HSYNC to reuse the framework for agent-to-agent communication

---

## Motivation

### Current Architecture (Problems)

```
tdns (generic DNS)
  ↓ (depends on)
tdns-nm (KDC/KRS operations)
  ↓ (contains)
Operations infrastructure (DistributionEntry, JWS(JWE), manifests)
```

**Problems:**
- HSYNC needs operations infrastructure, but it's locked in tdns-nm
- Distribution tracking is KDC/KRS-specific but pattern is generic
- Custom JSON manifest format (not standards-compliant)
- Code duplication when HSYNC implements similar infrastructure

### Target Architecture (Solutions)

```
tdns (generic DNS + operations framework)
  ├─ crypto/ (backends: hpke, jose)
  ├─ distrib/ (NEW - generic framework)
  │   ├─ types.go (OperationEntry, DistributionMetadata)
  │   ├─ transport.go (JWS(JWE()) helpers)
  │   ├─ manifest.go (CHUNK manifest - JWT format)
  │   ├─ tracker.go (Distribution lifecycle)
  │   ├─ confirmation.go (Confirmation protocol)
  │   └─ persistence.go (DB schema)
  │
  ├─ HSYNC (uses distributions framework)
  │   └─ operations/ (sync_start, sync_chunk, sync_complete)
  │
tdns-nm (KDC/KRS - uses distributions framework)
  └─ kdc/
      └─ operations/ (roll_key, ping, delete_key)
```

**Benefits:**
1. **Reusability**: HSYNC and other projects can use same infrastructure
2. **Clean dependencies**: tdns-nm depends on tdns (correct direction)
3. **Separation of concerns**: Generic vs domain-specific
4. **Standards compliance**: JWT manifests (not custom JSON)

---

## Key Design Decisions

### 1. Package Location

**Decision**: `github.com/johanix/tdns/v2/distrib/`

**Rationale:**
- Part of tdns (generic DNS infrastructure)
- Optional import (only used by apps that need it)
- Single Go module (no multi-module complexity)
- Apps like tdns-auth/tdns-imr don't import it (no forced dependencies)

### 2. Distribution Pattern is Generic

The **distribution pattern** applies to any reliable delivery over DNS:

1. **Sender** creates distribution record (pending state)
2. **Sender** sends CHUNK records via DNS
3. **Sender** sends NOTIFY to receiver
4. **Receiver** fetches CHUNKs
5. **Receiver** processes payload
6. **Receiver** sends confirmation NOTIFY
7. **Sender** marks distribution confirmed

**Use cases:**
- **KDC → KRS** (key distribution)
- **Agent A → Agent B** (zone sync)
- **Future**: Any reliable delivery over DNS

### 3. What's Generic vs Domain-Specific

**Generic (tdns/distrib):**
- ✅ Distribution record model
- ✅ Distribution states (pending, confirmed, failed, expired)
- ✅ Confirmation tracking
- ✅ Database schema for distributions
- ✅ CHUNK manifest format (JWT)
- ✅ JWS(JWE()) transport functions
- ✅ NOTIFY protocol
- ✅ Operation entry format

**Domain-Specific (tdns-nm, HSYNC):**
- Operation types (roll_key vs sync_chunk)
- Payload content (DNSSEC keys vs zone data)
- Business logic (retire key on confirm vs update zone serial)
- Triggers (key rotation schedule vs zone update detection)

### 4. Database Schema

Both KDC and HSYNC need similar distribution tracking:

```sql
-- Generic schema (common fields)
CREATE TABLE distribution_records (
    id TEXT PRIMARY KEY,
    distribution_id TEXT NOT NULL,
    sender_id TEXT NOT NULL,      -- KDC ID or Agent ID
    receiver_id TEXT NOT NULL,    -- Node ID or Agent ID
    operation TEXT NOT NULL,      -- roll_key, sync_chunk, etc.
    content_type TEXT NOT NULL,   -- key_operations, sync_operations, etc.
    encrypted_key BLOB,           -- JWE payload
    status TEXT NOT NULL,         -- pending, confirmed, failed
    created_at INTEGER NOT NULL,
    confirmed_at INTEGER,
    expires_at INTEGER,

    -- Domain-specific fields (nullable, used by specific implementations)
    zone_name TEXT,               -- For KDC key operations
    key_id TEXT,                  -- For KDC key operations
    sequence INTEGER,             -- For HSYNC chunk tracking
    total INTEGER                 -- For HSYNC chunk tracking
);
```

**Approach**: Shared schema with extension fields (common + optional domain-specific).

### 5. Manifest Format Migration

**Current (Custom JSON):**
```json
{
  "chunk_count": 1,
  "chunk_size": 25000,
  "metadata": {
    "distribution_id": "148075a9",
    "timestamp": 1769509199,
    "crypto": "jose",
    ...
  }
}
```

**Target (JWT/JWS):**
```json
// JWS Header:
{
  "alg": "ES256",
  "typ": "JWT"
}

// JWS Payload (Claims):
{
  "iss": "kdc",                        // Standard: issuer
  "sub": "gbg.iis.se.",                // Standard: subject (receiver)
  "iat": 1769509199,                   // Standard: issued at
  "exp": 1769509499,                   // Standard: expiration

  // Custom claims (namespace: tdns:)
  "tdns:distribution_id": "148075a9",
  "tdns:chunk_count": 1,
  "tdns:chunk_size": 25000,
  "tdns:content_type": "key_operations",
  "tdns:crypto": "jose",
  "tdns:zone_count": 1,
  "tdns:key_count": 1
}

// Signed: JWS(header + payload)
```

**Benefits:**
- Standards compliance (JWT/JWS)
- Interoperability with other implementations
- Consistency (manifest and payload both use JOSE)
- Built-in signature verification

---

## Migration Phases

### Phase 1: Create Package Structure ✅
**Goal**: Establish empty package structure in tdns repo

**Location**: `github.com/johanix/tdns/v2/distrib/`

**Files**:
```
distrib/
├── doc.go                    # Package documentation
├── types.go                  # Core types (stub)
├── transport.go              # JWS(JWE) helpers (stub)
├── manifest.go               # Manifest operations (stub)
├── tracker.go                # Distribution tracking (stub)
├── confirmation.go           # Confirmation protocol (stub)
├── persistence.go            # DB schema (stub)
└── manifest_test.go          # Tests (stub)
```

**Tasks**:
- [x] Create directory structure
- [x] Write package documentation in doc.go
- [x] Create stub files with package declaration
- [x] Commit: "distributions: create package structure"

**Verification**: `go build ./distributions` succeeds

---

### Phase 2: Move Core Types and Interfaces
**Goal**: Define generic types and interfaces in tdns/distrib

**Source files (tdns-nm)**:
- `tnm/distribution.go` (DistributionEntry)
- `tnm/kdc/structs.go` (DistributionRecord - extract generic parts)

**Destination**: `tdns/v2/distrib/types.go`

**What to move**:
- `OperationEntry` struct (generic operation format)
- `DistributionMetadata` struct (manifest metadata)
- `ManifestData` struct (CHUNK manifest data)
- `DistributionState` constants (pending, confirmed, failed)
- `DistributionRecord` struct (generic distribution record)
- `DistributionTracker` interface (lifecycle management)
- `DistributionStore` interface (persistence)

**Files to create**:
- `distrib/types.go` - Core types and structs
- `distrib/tracker.go` - DistributionTracker interface
- `distrib/persistence.go` - DistributionStore interface + SQL schema

**Tasks**:
- [ ] Create types.go with OperationEntry, DistributionMetadata, ManifestData
- [ ] Create tracker.go with DistributionTracker interface
- [ ] Create persistence.go with DistributionStore interface and SQL schema
- [ ] Update tdns-nm to import from tdns/distrib (aliases for now)
- [ ] Commit: "distributions: add core types and interfaces"

**Verification**: tdns-nm still compiles with new imports

---

### Phase 3: Move Transport Functions
**Goal**: Move JWS(JWE()) encoding/decoding functions to tdns/distrib

**Source**: `tnm/hpke_transport_v2.go`

**Destination**: `tdns/v2/distrib/transport.go`

**Functions to move**:
- `EncryptSignAndEncodeV2()` → `EncryptSignAndEncode()`
- `EncryptAndEncodeV2()` → `EncryptAndEncode()`
- `DecodeDecryptAndVerifyV2()` → `DecodeDecryptAndVerify()`
- `DecodeAndDecryptV2()` → `DecodeAndDecrypt()`
- Helper functions: `splitJWS()`, `base64Decode()`

**Tasks**:
- [ ] Copy functions from tnm/hpke_transport_v2.go to distrib/transport.go
- [ ] Update function names (remove V2 suffix)
- [ ] Update imports in tdns-nm to use distrib.EncryptSignAndEncode
- [ ] Keep old functions in tnm as wrappers (temporary, for compatibility)
- [ ] Run tests
- [ ] Commit: "distributions: add transport functions"

**Verification**:
- tdns-nm compiles
- Existing transport tests pass
- Can send ping operation successfully

---

### Phase 4: Move Manifest Operations
**Goal**: Move CHUNK manifest creation/parsing to tdns/distrib

**Source**:
- `tnm/chunk.go` (CreateCHUNKManifest, ParseCHUNKManifest)
- `tnm/kdc/chunks_v2.go` (manifest building logic)

**Destination**: `tdns/v2/distrib/manifest.go`

**Functions to move**:
- `CreateCHUNKManifest()` → `CreateManifest()`
- `ParseCHUNKManifest()` → `ParseManifest()`
- `EstimateManifestSize()`
- `ShouldIncludePayloadInline()`
- `SplitIntoCHUNKs()`

**Tasks**:
- [ ] Move manifest functions to distrib/manifest.go
- [ ] Update imports in tdns-nm
- [ ] Update tnm/kdc/chunks_v2.go to use distrib.CreateManifest
- [ ] Keep wrappers in tnm for compatibility
- [ ] Run tests
- [ ] Commit: "distributions: add manifest operations"

**Verification**:
- Can create manifest
- Can parse manifest
- Can split large payloads into chunks

---

### Phase 5: Refactor tdns-nm to Use distributions Package
**Goal**: Update tdns-nm (KDC/KRS) to use tdns/distrib instead of local implementations

**Files to update**:
- `tnm/kdc/chunks_v2.go` (use distributions for manifest, transport)
- `tnm/krs/chunk.go` (use distributions for parsing, decryption)
- `tnm/distribution.go` (type aliases, temporary)

**Changes**:
1. **KDC Distribution Creation**: Use `distrib.CreateManifest()`
2. **KDC Payload Building**: Use `distrib.EncryptSignAndEncode()`
3. **KRS Distribution Processing**: Use `distrib.ParseManifest()`
4. **KRS Payload Decryption**: Use `distrib.DecodeDecryptAndVerify()`
5. **Type Aliases**: Create temporary aliases in tnm/distribution.go

**Tasks**:
- [ ] Update all imports in tdns-nm to use distrib package
- [ ] Replace local types with distrib.OperationEntry, etc.
- [ ] Replace local functions with distrib.CreateManifest, etc.
- [ ] Run full test suite
- [ ] Test end-to-end: KDC create distribution → KRS receive → confirm
- [ ] Remove old implementations from tnm (keep type aliases temporarily)
- [ ] Commit: "tdns-nm: migrate to distrib package"

**Verification**:
- All tdns-nm tests pass
- Can create distributions (ping, roll_key, update_components)
- Can process distributions
- Can confirm distributions
- KDC and KRS work end-to-end

---

### Phase 6: JWT Manifest Migration
**Goal**: Replace custom JSON manifest with standard JWT (JWS) format

**Why JWT?**
- Standards compliance (RFC 7519)
- Interoperability with other implementations
- Built-in signature verification
- Consistent with JWS(JWE()) payload format

**Implementation**:

**New file**: `distrib/manifest_jwt.go`

**Key types**:
```go
type ManifestClaims struct {
    // Standard JWT claims
    Issuer     string `json:"iss"`           // Sender ID
    Subject    string `json:"sub"`           // Receiver ID
    IssuedAt   int64  `json:"iat"`           // Unix timestamp
    Expiration int64  `json:"exp,omitempty"` // Unix timestamp

    // Custom claims (tdns namespace)
    DistributionID  string `json:"tdns:distribution_id"`
    ChunkCount      int    `json:"tdns:chunk_count"`
    ChunkSize       int    `json:"tdns:chunk_size"`
    ContentType     string `json:"tdns:content_type"`
    Crypto          string `json:"tdns:crypto"`
    // ... other fields
}
```

**Functions**:
- `CreateJWTManifest()` - Creates signed JWT manifest
- `ParseJWTManifest()` - Parses and verifies JWT manifest
- `ConvertMetadataToClaims()` - Helper for migration

**Core package update**:
```go
// core/chunk.go
const (
    FormatJSON   CHUNKFormat = 1
    FormatBASE64 CHUNKFormat = 2
    FormatJWT    CHUNKFormat = 3  // NEW
)
```

**KDC feature flag**:
```go
// tnm/config.go
type KdcConf struct {
    // ... existing fields ...
    UseJWTManifest bool `yaml:"use_jwt_manifest"` // NEW
}
```

**Backward Compatibility**:
1. KDC can create both JSON and JWT manifests (controlled by flag)
2. KRS can parse both formats (auto-detects based on Format field)
3. Default: JSON manifest (existing behavior)
4. Gradual rollout: Enable JWT on KDC, KRS handles both

**Tasks**:
- [ ] Implement JWT manifest creation/parsing in distrib/manifest_jwt.go
- [ ] Add FormatJWT constant to core/chunk.go
- [ ] Add use_jwt_manifest config flag to KDC
- [ ] Update KDC to create JWT manifests (when enabled)
- [ ] Update KRS to parse JWT manifests (auto-detect)
- [ ] Write tests for JWT format
- [ ] Test end-to-end with JWT manifests
- [ ] Document JWT claim structure
- [ ] Commit: "distributions: add JWT manifest format"

**Verification**:
- KDC can create JWT manifests
- KRS can parse JWT manifests
- Signature verification works
- Inline payload works with JWT
- Backward compatibility: JSON manifests still work
- End-to-end: KDC (JWT) → KRS (parse JWT) → confirm

---

### Phase 7: Testing and Documentation
**Goal**: Comprehensive testing and documentation

**Unit Tests**:
- `distrib/transport_test.go` - Test all transport functions
- `distrib/manifest_test.go` - Test manifest operations (JSON)
- `distrib/manifest_jwt_test.go` - Test JWT functionality
- `distrib/types_test.go` - Test type conversions

**Integration Tests**:
- End-to-end KDC → KRS with JWT
- Mixed environment (JSON + JWT)
- Error cases (bad signatures, expired manifests, etc.)

**Documentation**:
- `distrib/README.md` - Package overview and usage
- `distrib/MIGRATION.md` - Migration guide (JSON → JWT)
- `distrib/ARCHITECTURE.md` - Design decisions and patterns
- Update main tdns README with distrib package info

**Performance Testing**:
- Benchmark: JWT vs JSON manifest
- Benchmark: JWS(JWE()) vs JWE only
- Size overhead analysis

**Tasks**:
- [ ] Write unit tests for all functions
- [ ] Write integration tests (end-to-end)
- [ ] Write documentation (README, architecture docs)
- [ ] Write migration guide
- [ ] Run performance benchmarks
- [ ] Update changelog
- [ ] Commit: "distributions: add tests and documentation"

**Verification**:
- All tests pass
- Code coverage > 80%
- Documentation complete
- Migration guide clear

---

## Summary Timeline

| Phase | Goal | Duration | Status |
|-------|------|----------|--------|
| 1 | Create package structure | 1 hour | ✅ Complete |
| 2 | Move types and interfaces | 2 hours | 🚧 In Progress |
| 3 | Move transport functions | 2 hours | ⏳ Pending |
| 4 | Move manifest operations | 2 hours | ⏳ Pending |
| 5 | Refactor tdns-nm | 4 hours | ⏳ Pending |
| 6 | JWT manifest migration | 6 hours | ⏳ Pending |
| 7 | Testing and documentation | 4 hours | ⏳ Pending |
| **Total** | | **21 hours** | |

---

## Rollback Plan

Each phase is independently committable and testable:
- **Phase 1-2**: Easy rollback (no functional changes)
- **Phase 3-4**: Medium rollback (keep wrappers in tnm)
- **Phase 5**: Hard rollback (but comprehensive tests before)
- **Phase 6**: Easy rollback (feature flag controls JWT usage)

---

## Success Criteria

✅ All tdns-nm tests pass
✅ KDC can create JWT manifests
✅ KRS can parse JWT manifests
✅ Backward compatibility maintained (JSON manifests still work)
✅ Code in tdns/distrib is generic (no KDC-specific logic)
✅ Documentation complete
✅ Ready for HSYNC to use distrib package

---

## Future Work (Post-Migration)

### Phase 8: HSYNC Integration
- Define HSYNC-specific operations (sync_start, sync_chunk, sync_complete)
- Implement DistributionTracker for HSYNC agents
- Use distrib package for agent-to-agent communication

### Phase 9: Deprecate JSON Manifest
- Set default to JWT manifest
- Remove custom JSON format support
- Simplify codebase

### Phase 10: Multi-Recipient Optimization
- Implement true multi-recipient JWE (not N single-recipient JWEs)
- Reduce distribution size for multi-node deployments

---

## Related Documentation

- Phase 4B+4C: JWS(JWE(JOSE)) Integration Summary (`/Users/johani/src/git/tdns-project/tdns/docs/phase4bc-jose-integration-summary.md`)
- Phase 4D: JWS(JWE(HPKE)) Integration Summary (`/Users/johani/src/git/tdns-project/tdns-nm/docs/phase4d-hpke-signing-integration-summary.md`)
- HPKE Backend Implementation: `github.com/johanix/tdns/v2/crypto/hpke/backend.go`
- JOSE Backend Implementation: `github.com/johanix/tdns/v2/crypto/jose/backend.go`

---

**Document Status**: Phase 1 Complete, Phase 2 In Progress
**Last Updated**: 2026-01-27
**Author**: Claude Sonnet 4.5
