# Adding JOSE Support to TDNS CHUNK Distribution System

**Date:** 2026-01-21
**Status:** Implementation Plan
**Goal:** Add JOSE (JSON Object Signing and Encryption) support alongside existing HPKE implementation

## Executive Summary

This document outlines the plan to add JOSE cryptographic backend support to the TDNS CHUNK-based key distribution system. The primary driver is enabling future C-language implementation of KRS, where JOSE has better library support than HPKE.

**Key Requirements:**
- Maintain working system at every step
- Keep existing HPKE implementation unchanged
- Support both HPKE and JOSE simultaneously
- Enable per-node backend selection
- Backward compatible at all stages

**Strategy:** Parallel implementation with feature flags, allowing gradual migration without disrupting existing deployments.

---

## Table of Contents

1. [Motivation](#motivation)
2. [Architecture Overview](#architecture-overview)
3. [Implementation Strategy](#implementation-strategy)
4. [Detailed Phase Plan](#detailed-phase-plan)
5. [Testing Strategy](#testing-strategy)
6. [Migration Path](#migration-path)
7. [Rollback Procedures](#rollback-procedures)

---

## Motivation

### Primary Driver: C Implementation Requirements

Future implementation of KRS in C for integration with authoritative DNS servers (BIND9, NSD, Knot DNS) requires robust crypto library support:

**HPKE in C:**
- Requires OpenSSL 3.2+ (very recent, limited deployment)
- Few mature standalone libraries
- Limited documentation and examples
- Small community

**JOSE in C:**
- Well-established libraries (cjose, libjwt)
- Mature ecosystem with extensive documentation
- Broader developer familiarity
- Better integration prospects with DNS server projects

### Secondary Benefits

- **Ecosystem familiarity:** JOSE (JWE/JWK) widely understood in web/API contexts
- **Debugging tools:** Standard tools like jwt.io available
- **Future flexibility:** Easier to find developers and maintainers
- **Standards maturity:** RFCs 7515-7517 (2015) vs RFC 9180 (2022)

### Non-Goals

- **Not replacing HPKE:** Both backends will coexist indefinitely
- **Not changing CHUNK RRtype:** Existing wire format works for both
- **Not breaking existing deployments:** Backward compatibility mandatory

---

## Architecture Overview

### Current Architecture (HPKE-only)

```
┌─────────────────────────────────────────────────────────────┐
│ KDC (Key Distribution Center)                               │
├─────────────────────────────────────────────────────────────┤
│ Distribution Creation:                                       │
│   1. Get DNSSEC key (plaintext)                             │
│   2. Encrypt with HPKE using node's public key              │
│   3. Create manifest (JSON metadata)                        │
│   4. Combine → CHUNK records                                │
│   5. Publish via DNS                                        │
└─────────────────────────────────────────────────────────────┘
                            ↓ DNS NOTIFY
                            ↓ CHUNK query/response
┌─────────────────────────────────────────────────────────────┐
│ KRS (Key Receiver Service)                                  │
├─────────────────────────────────────────────────────────────┤
│ Distribution Processing:                                     │
│   1. Receive NOTIFY                                         │
│   2. Query CHUNK records                                    │
│   3. Reassemble chunks                                      │
│   4. Parse manifest                                         │
│   5. Decrypt with HPKE using private key                    │
│   6. Install DNSSEC keys                                    │
└─────────────────────────────────────────────────────────────┘
```

**Key Observation:** Steps 2 and 5 are the only crypto-specific operations. Everything else (DNS transport, chunking, manifest handling) is crypto-agnostic.

### Target Architecture (HPKE + JOSE)

```
┌─────────────────────────────────────────────────────────────┐
│ Crypto Abstraction Layer                                    │
├─────────────────────────────────────────────────────────────┤
│ Interface: CryptoBackend                                    │
│   - GenerateKeypair()                                       │
│   - Encrypt(recipientPubKey, plaintext) → ciphertext       │
│   - Decrypt(privateKey, ciphertext) → plaintext            │
│   - SerializeKey() / ParseKey()                             │
├─────────────────────────────────────────────────────────────┤
│ Implementations:                                             │
│   - HPKE Backend (wraps tdns/v2/hpke)                      │
│   - JOSE Backend (uses go-jose library)                    │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ KDC                                                         │
├─────────────────────────────────────────────────────────────┤
│ Distribution Creation:                                       │
│   1. Get DNSSEC key                                         │
│   2. Select backend based on node's supported_crypto       │
│   3. backend.Encrypt(key) → ciphertext                     │
│   4. Create manifest with "crypto" field                   │
│   5. CHUNK records (unchanged wire format)                  │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ KRS                                                         │
├─────────────────────────────────────────────────────────────┤
│ Distribution Processing:                                     │
│   1-4. [Same as before]                                     │
│   5. Read manifest "crypto" field                          │
│   6. Load appropriate backend                               │
│   7. backend.Decrypt(ciphertext) → plaintext               │
│   8. Install keys                                           │
└─────────────────────────────────────────────────────────────┘
```

### Enrollment Flow Extension

**Current enrollment request:**
```json
{
  "krs_hpke_pubkey": "base64...",
  "krs_sig0_pubkey": "base64...",
  "auth_token": "token..."
}
```

**New enrollment request (backward compatible):**
```json
{
  "krs_hpke_pubkey": "base64...",    // or krs_jose_pubkey (JWK)
  "krs_sig0_pubkey": "base64...",
  "auth_token": "token...",
  "supported_crypto": ["jose"]        // NEW: advertise capabilities
}
```

**KDC behavior:**
- If `supported_crypto` absent → defaults to `["hpke"]` (backward compatibility)
- Stores supported crypto methods in nodes table
- Uses this information when creating distributions

---

## Implementation Strategy

### Parallel Implementation Principle

**Never break the existing system.** Implement new functionality alongside old code, controlled by feature flags.

```
Phase 1: Build abstraction layer (new code, no integration)
Phase 2: Integrate into KDC (parallel v2 functions, feature flag OFF)
Phase 3: Integrate into KRS (parallel v2 functions, feature flag OFF)
Phase 4: Testing and gradual activation (feature flag ON for test nodes)
```

### Feature Flag Strategy

**Configuration in KDC:**
```yaml
kdc:
  use_crypto_v2: false  # Default: use old path
  # When true: use new abstracted crypto path
```

**Configuration in KRS:**
```yaml
krs:
  use_crypto_v2: false  # Default: use old path
```

**Migration stages:**
1. **Development:** v2=false everywhere, v2 code exists but unused
2. **Testing:** v2=true for specific test nodes only
3. **Gradual rollout:** v2=true for more nodes
4. **Complete:** v2=true everywhere, v1 code deprecated
5. **Cleanup:** Remove v1 code (optional, low priority)

### File Organization

**New files (additions only):**
```
tdns/v2/crypto/
├── backend.go           # Interface definition
├── types.go             # Common types
├── registry.go          # Backend registration
├── selection.go         # Backend selection logic
├── hpke/
│   ├── backend.go       # Wrapper around tdns/v2/hpke
│   └── backend_test.go
└── jose/
    ├── backend.go       # JOSE implementation
    └── backend_test.go

tdns-nm/tnm/kdc/
├── encrypt_v2.go        # Abstracted encryption
├── chunks_v2.go         # Abstracted chunk creation
└── distribution_v2.go   # Abstracted distribution logic

tdns-nm/tnm/krs/
├── decrypt_v2.go        # Abstracted decryption
└── chunk_v2.go          # Abstracted chunk processing
```

**Unchanged files (until optional cleanup):**
```
tdns/v2/hpke/*           # All HPKE code stays as-is
tdns/v2/core/rr_chunk.go # CHUNK RRtype unchanged
tdns-nm/tnm/kdc/encrypt.go
tdns-nm/tnm/kdc/chunks.go
tdns-nm/tnm/krs/decrypt.go
tdns-nm/tnm/krs/chunk.go
```

---

## Detailed Phase Plan

### Phase 1: Foundation (Sessions 1-3)

#### Session 1: Crypto Abstraction Interface + HPKE Wrapper

**Goal:** Define clean interface, wrap existing HPKE code

**Deliverables:**
- `tdns/v2/crypto/backend.go` - Interface definition
- `tdns/v2/crypto/types.go` - Common types
- `tdns/v2/crypto/hpke/backend.go` - HPKE wrapper
- `tdns/v2/crypto/hpke/backend_test.go` - Tests

**Interface definition:**
```go
package crypto

// Backend defines the interface for cryptographic operations
type Backend interface {
    // Name returns the backend identifier ("hpke", "jose")
    Name() string

    // GenerateKeypair generates a new key pair
    GenerateKeypair() (PrivateKey, PublicKey, error)

    // ParsePublicKey deserializes a public key
    ParsePublicKey(data []byte) (PublicKey, error)

    // ParsePrivateKey deserializes a private key
    ParsePrivateKey(data []byte) (PrivateKey, error)

    // SerializePublicKey serializes a public key
    SerializePublicKey(key PublicKey) ([]byte, error)

    // SerializePrivateKey serializes a private key
    SerializePrivateKey(key PrivateKey) ([]byte, error)

    // Encrypt encrypts plaintext for recipient
    Encrypt(recipientPubKey PublicKey, plaintext []byte) ([]byte, error)

    // Decrypt decrypts ciphertext using private key
    Decrypt(privateKey PrivateKey, ciphertext []byte) ([]byte, error)
}

// PrivateKey represents a private key (backend-specific)
type PrivateKey interface {
    Backend() string
}

// PublicKey represents a public key (backend-specific)
type PublicKey interface {
    Backend() string
}
```

**HPKE wrapper implementation:**
```go
package hpke

import (
    "github.com/johanix/tdns/v2/crypto"
    "github.com/johanix/tdns/v2/hpke"
)

type hpkeBackend struct{}

func NewBackend() crypto.Backend {
    return &hpkeBackend{}
}

func (b *hpkeBackend) Name() string {
    return "hpke"
}

func (b *hpkeBackend) GenerateKeypair() (crypto.PrivateKey, crypto.PublicKey, error) {
    priv, pub := hpke.GenerateKeypair()
    return &privateKey{data: priv}, &publicKey{data: pub}, nil
}

// ... wrapper implementations for all interface methods
```

**Testing:**
```bash
cd tdns/v2/crypto/hpke
go test -v
# Should pass all tests, proving wrapper works identically to direct HPKE
```

**Validation criteria:**
- [ ] Tests pass
- [ ] Interface compiles
- [ ] Existing system still works (no integration yet)

---

#### Session 2: JOSE Backend Implementation

**Goal:** Implement JOSE backend using go-jose library

**Dependencies:**
```bash
go get github.com/go-jose/go-jose/v3
```

**Deliverables:**
- `tdns/v2/crypto/jose/backend.go`
- `tdns/v2/crypto/jose/backend_test.go`

**JOSE backend implementation:**
```go
package jose

import (
    "github.com/go-jose/go-jose/v3"
    "github.com/johanix/tdns/v2/crypto"
)

type joseBackend struct{}

func NewBackend() crypto.Backend {
    return &joseBackend{}
}

func (b *joseBackend) Name() string {
    return "jose"
}

func (b *joseBackend) Encrypt(recipientPubKey crypto.PublicKey, plaintext []byte) ([]byte, error) {
    pubKey := recipientPubKey.(*publicKey)

    // Create encrypter with ECDH-ES+A256GCM
    encrypter, err := jose.NewEncrypter(
        jose.A256GCM,
        jose.Recipient{
            Algorithm: jose.ECDH_ES,
            Key:       pubKey.jwk,
        },
        nil,
    )
    if err != nil {
        return nil, err
    }

    // Encrypt
    jwe, err := encrypter.Encrypt(plaintext)
    if err != nil {
        return nil, err
    }

    // Return compact serialization
    return []byte(jwe.CompactSerialize())
}

// ... other methods
```

**Algorithm selection:**
- **Key Agreement:** ECDH-ES (Ephemeral-Static Elliptic Curve Diffie-Hellman)
- **Content Encryption:** A256GCM (AES-256 in Galois/Counter Mode)
- **Curve:** P-256 (NIST P-256, widely supported)

**Testing:**
```bash
cd tdns/v2/crypto/jose
go test -v
# Tests should verify:
# - Key generation works
# - Encryption produces valid JWE
# - Decryption recovers plaintext
# - Round-trip preserves data
```

**Validation criteria:**
- [ ] Tests pass
- [ ] JWE compact serialization is valid
- [ ] Compatible with standard JOSE libraries
- [ ] Existing system still works

---

#### Session 3: Backend Registry & Selection

**Goal:** Provide mechanism to register and retrieve backends

**Deliverables:**
- `tdns/v2/crypto/registry.go`
- `tdns/v2/crypto/selection.go`
- `tdns/v2/crypto/crypto_test.go`

**Registry implementation:**
```go
package crypto

import (
    "fmt"
    "sync"
)

var (
    backends = make(map[string]Backend)
    mu       sync.RWMutex
)

// RegisterBackend registers a crypto backend
func RegisterBackend(backend Backend) {
    mu.Lock()
    defer mu.Unlock()
    backends[backend.Name()] = backend
}

// GetBackend retrieves a backend by name
func GetBackend(name string) (Backend, error) {
    mu.RLock()
    defer mu.RUnlock()

    backend, exists := backends[name]
    if !exists {
        return nil, fmt.Errorf("unknown crypto backend: %s", name)
    }
    return backend, nil
}

// ListBackends returns all registered backend names
func ListBackends() []string {
    mu.RLock()
    defer mu.RUnlock()

    names := make([]string, 0, len(backends))
    for name := range backends {
        names = append(names, name)
    }
    return names
}
```

**Auto-registration in init():**
```go
// In tdns/v2/crypto/hpke/backend.go
func init() {
    crypto.RegisterBackend(NewBackend())
}

// In tdns/v2/crypto/jose/backend.go
func init() {
    crypto.RegisterBackend(NewBackend())
}
```

**Testing:**
```bash
cd tdns/v2/crypto
go test -v
# Tests should verify:
# - Both backends auto-register
# - GetBackend("hpke") works
# - GetBackend("jose") works
# - GetBackend("unknown") returns error
```

**Validation criteria:**
- [ ] Tests pass
- [ ] Both backends retrievable
- [ ] Existing system still works

---

### Phase 2: KDC Integration (Sessions 4-6)

#### Session 4: KDC Crypto Router (Shadow Implementation)

**Goal:** Create parallel encryption functions using abstraction layer

**Deliverables:**
- `tdns-nm/tnm/kdc/encrypt_v2.go`
- `tdns-nm/tnm/kdc/chunks_v2.go`

**Key function signatures:**

```go
// encrypt_v2.go

// EncryptKeyForNodeV2 encrypts using abstracted crypto backend
func (kdc *KdcDB) EncryptKeyForNodeV2(
    key *DNSSECKey,
    node *Node,
    backend crypto.Backend,
    kdcConf *tnm.KdcConf,
    distributionID ...string,
) (encryptedKey []byte, ephemeralPubKey []byte, distID string, err error) {
    // Parse node's public key using backend
    nodePubKey, err := backend.ParsePublicKey(node.LongTermPubKey)
    if err != nil {
        return nil, nil, "", fmt.Errorf("failed to parse node public key: %v", err)
    }

    // Encrypt using backend
    ciphertext, err := backend.Encrypt(nodePubKey, key.PrivateKey)
    if err != nil {
        return nil, nil, "", fmt.Errorf("failed to encrypt key: %v", err)
    }

    // ... rest of logic (distribution record creation, etc.)

    return ciphertext, nil, distID, nil
}
```

```go
// chunks_v2.go

// prepareChunksForNodeV2 uses backend-selected encryption
func (kdc *KdcDB) prepareChunksForNodeV2(
    nodeID, distributionID string,
    conf *tnm.KdcConf,
) (*preparedChunks, error) {
    // Get node to determine backend
    node, err := kdc.GetNode(nodeID)
    if err != nil {
        return nil, err
    }

    // Select backend based on node's supported crypto
    backendName := selectBackendForNode(node)
    backend, err := crypto.GetBackend(backendName)
    if err != nil {
        return nil, err
    }

    log.Printf("KDC: Using %s backend for node %s", backendName, nodeID)

    // ... encryption using backend.Encrypt()

    // Create manifest with crypto field
    metadata := tnm.CreateManifestMetadata(contentType, distributionID, nodeID, extraFields)
    metadata["crypto"] = backendName  // NEW: indicate backend in manifest

    // ... rest of chunk preparation
}

func selectBackendForNode(node *Node) string {
    // For now, use first supported backend
    // Later: could have policy (prefer JOSE, fallback to HPKE, etc.)
    if len(node.SupportedCrypto) > 0 {
        return node.SupportedCrypto[0]
    }
    return "hpke" // Default
}
```

**Feature flag integration:**
```go
// In existing functions, check flag:
func (kdc *KdcDB) prepareChunksForNode(...) {
    if conf.UseCryptoV2 {
        return kdc.prepareChunksForNodeV2(...)
    }
    // ... existing implementation
}
```

**Testing:**
```bash
cd tdns-nm/tnm/kdc
go test -v -run TestEncryptKeyForNodeV2
go test -v -run TestPrepareChunksV2
```

**Validation criteria:**
- [ ] V2 functions compile and pass tests
- [ ] Feature flag OFF → old path works
- [ ] Feature flag ON → v2 path works with HPKE (same output as v1)
- [ ] No behavior changes in production

---

#### Session 5: Manifest Format Extension

**Goal:** Add crypto field to manifest (backward compatible)

**Deliverables:**
- Update `tdns-nm/tnm/manifest.go`
- Update `tdns-nm/tnm/manifest_test.go`

**Manifest struct update:**
```go
// In tdns-nm/tnm/types.go or manifest.go

type ManifestData struct {
    ChunkCount uint16                 `json:"chunk_count"`
    ChunkSize  uint16                 `json:"chunk_size,omitempty"`
    Crypto     string                 `json:"crypto,omitempty"`  // NEW FIELD
    Metadata   map[string]interface{} `json:"metadata,omitempty"`
    Payload    []byte                 `json:"payload,omitempty"`
}
```

**Backward compatibility:**
- If `Crypto` field is missing (old manifests) → defaults to "hpke"
- If `Crypto` field present → use specified backend

**Helper functions:**
```go
// GetCrypto returns the crypto backend from manifest, defaulting to HPKE
func (m *ManifestData) GetCrypto() string {
    if m.Crypto == "" {
        return "hpke"
    }
    return m.Crypto
}

// SetCrypto sets the crypto backend in manifest
func (m *ManifestData) SetCrypto(backend string) {
    m.Crypto = backend
}
```

**Testing:**
```bash
# Test backward compatibility
go test -v -run TestManifestBackwardCompat
# - Parse old manifest (no crypto field) → defaults to "hpke"
# - Parse new manifest (with crypto field) → reads correctly

# Test forward compatibility
go test -v -run TestManifestForwardCompat
# - Old code (ignores crypto field) can still parse new manifests
```

**Validation criteria:**
- [ ] Old manifests parse correctly (default to hpke)
- [ ] New manifests include crypto field
- [ ] Old KRS can parse new manifests (ignores unknown field)

---

#### Session 6: KDC Backend Selection & Database Schema

**Goal:** Store supported_crypto per node, use in distribution creation

**Deliverables:**
- Update `tdns-nm/tnm/kdc/db.go`
- Add `tdns-nm/tnm/kdc/db_migrations.go` migration
- Update `tdns-nm/tnm/kdc/structs.go`

**Database migration:**
```sql
-- Migration: Add supported_crypto column to nodes table
ALTER TABLE nodes ADD COLUMN supported_crypto TEXT DEFAULT '["hpke"]';

-- For existing rows, set default
UPDATE nodes SET supported_crypto = '["hpke"]' WHERE supported_crypto IS NULL;
```

**Struct update:**
```go
// In tdns-nm/tnm/kdc/structs.go

type Node struct {
    ID              string    `json:"id"`
    LongTermPubKey  []byte    `json:"long_term_pub_key"`
    LongTermSigKey  []byte    `json:"long_term_sig_key"`
    SupportedCrypto []string  `json:"supported_crypto"` // NEW FIELD
    CreatedAt       time.Time `json:"created_at"`
    UpdatedAt       time.Time `json:"updated_at"`
}
```

**Database functions:**
```go
// In tdns-nm/tnm/kdc/db.go

func (kdc *KdcDB) AddNode(node *Node) error {
    supportedCryptoJSON, _ := json.Marshal(node.SupportedCrypto)

    _, err := kdc.DB.Exec(
        `INSERT INTO nodes (id, long_term_pub_key, long_term_sig_key,
                           supported_crypto, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
        node.ID, node.LongTermPubKey, node.LongTermSigKey,
        supportedCryptoJSON, node.CreatedAt, node.UpdatedAt,
    )
    return err
}

func (kdc *KdcDB) GetNode(nodeID string) (*Node, error) {
    var node Node
    var supportedCryptoJSON string

    err := kdc.DB.QueryRow(
        `SELECT id, long_term_pub_key, long_term_sig_key, supported_crypto,
                created_at, updated_at
         FROM nodes WHERE id = ?`,
        nodeID,
    ).Scan(&node.ID, &node.LongTermPubKey, &node.LongTermSigKey,
           &supportedCryptoJSON, &node.CreatedAt, &node.UpdatedAt)

    if err != nil {
        return nil, err
    }

    // Parse JSON array
    if supportedCryptoJSON != "" {
        json.Unmarshal([]byte(supportedCryptoJSON), &node.SupportedCrypto)
    }

    // Default to HPKE if empty
    if len(node.SupportedCrypto) == 0 {
        node.SupportedCrypto = []string{"hpke"}
    }

    return &node, nil
}
```

**Testing:**
```bash
cd tdns-nm/tnm/kdc
go test -v -run TestNodeSupportedCrypto
# - Create node with supported_crypto: ["jose"]
# - Retrieve node, verify field is correct
# - Create node without field, verify defaults to ["hpke"]
```

**Validation criteria:**
- [ ] Migration succeeds on test database
- [ ] Existing nodes default to ["hpke"]
- [ ] New nodes can specify ["jose"] or ["hpke", "jose"]
- [ ] Distribution creation uses correct backend

---

### Phase 3: KRS Integration (Sessions 7-9)

#### Session 7: KRS Crypto Router (Shadow Implementation)

**Goal:** Create parallel decryption functions using abstraction layer

**Deliverables:**
- `tdns-nm/tnm/krs/decrypt_v2.go`
- `tdns-nm/tnm/krs/chunk_v2.go`

**Key function signatures:**

```go
// decrypt_v2.go

// DecryptAndStoreKeyV2 decrypts using abstracted crypto backend
func DecryptAndStoreKeyV2(
    krsDB *KrsDB,
    backend crypto.Backend,
    encryptedKey []byte,
    longTermPrivKey []byte,
    distributionID, zoneID string,
) error {
    // Parse private key using backend
    privKey, err := backend.ParsePrivateKey(longTermPrivKey)
    if err != nil {
        return fmt.Errorf("failed to parse private key: %v", err)
    }

    // Decrypt using backend
    plaintext, err := backend.Decrypt(privKey, encryptedKey)
    if err != nil {
        return fmt.Errorf("failed to decrypt key: %v", err)
    }

    // ... rest of key storage logic

    return nil
}
```

```go
// chunk_v2.go

// ProcessDistributionV2 processes distribution with backend selection
func ProcessDistributionV2(
    krsDB *KrsDB,
    conf *tnm.KrsConf,
    distributionID string,
    processTextResult *string,
) error {
    // ... fetch and reassemble chunks (same as before)

    // Extract manifest
    manifestData, err := ExtractManifestFromCHUNK(manifestChunk)
    if err != nil {
        return fmt.Errorf("failed to extract manifest: %v", err)
    }

    // Get crypto backend from manifest
    backendName := manifestData.GetCrypto()
    backend, err := crypto.GetBackend(backendName)
    if err != nil {
        return fmt.Errorf("unsupported crypto backend %s: %v", backendName, err)
    }

    log.Printf("KRS: Using %s backend for distribution %s", backendName, distributionID)

    // ... decrypt using backend.Decrypt()

    // Process based on content type
    switch contentType {
    case "key_operations", "node_operations":
        return processOperationsV2(krsDB, conf, backend, reassembled, contentType)
    // ...
    }
}
```

**Feature flag integration:**
```go
// In existing functions:
func ProcessDistribution(...) error {
    if conf.UseCryptoV2 {
        return ProcessDistributionV2(...)
    }
    // ... existing implementation
}
```

**Testing:**
```bash
cd tdns-nm/tnm/krs
go test -v -run TestProcessDistributionV2
# Test with both HPKE and JOSE encrypted distributions
```

**Validation criteria:**
- [ ] V2 functions compile and pass tests
- [ ] Can process HPKE distributions
- [ ] Can process JOSE distributions
- [ ] Feature flag OFF → old path works

---

#### Session 8: KRS Enrollment with Crypto Capabilities

**Goal:** Advertise supported crypto in enrollment request

**Deliverables:**
- Update `tdns-nm/tnm/krs/bootstrap.go`
- Update `tdns-nm/tnm/kdc/bootstrap.go`

**Enrollment request structure update:**

```go
// In tdns-nm/tnm/types.go

type EnrollmentRequest struct {
    KRSPubKey       []byte   `json:"krs_pubkey"`
    KRSSigKey       []byte   `json:"krs_sig_key"`
    AuthToken       string   `json:"auth_token"`
    SupportedCrypto []string `json:"supported_crypto,omitempty"` // NEW FIELD
}
```

**KRS enrollment request creation:**
```go
// In tdns-nm/tnm/krs/bootstrap.go

func CreateEnrollmentRequest(
    krsPubKey []byte,
    krsSigKey []byte,
    authToken string,
    supportedCrypto []string, // NEW PARAMETER
) (*EnrollmentRequest, error) {
    return &EnrollmentRequest{
        KRSPubKey:       krsPubKey,
        KRSSigKey:       krsSigKey,
        AuthToken:       authToken,
        SupportedCrypto: supportedCrypto, // NEW FIELD
    }, nil
}
```

**Configuration in KRS:**
```yaml
# krs.yaml
krs:
  supported_crypto:
    - "hpke"
    # Future C implementation:
    # - "jose"
```

**KDC enrollment processing:**
```go
// In tdns-nm/tnm/kdc/bootstrap.go

func (kdc *KdcDB) ProcessEnrollmentRequest(req *EnrollmentRequest) error {
    // ... validate auth token, etc.

    // Parse supported_crypto, default to ["hpke"] if missing
    supportedCrypto := req.SupportedCrypto
    if len(supportedCrypto) == 0 {
        supportedCrypto = []string{"hpke"} // Backward compatibility
    }

    // Create node with supported crypto
    node := &Node{
        ID:              extractNodeID(req),
        LongTermPubKey:  req.KRSPubKey,
        LongTermSigKey:  req.KRSSigKey,
        SupportedCrypto: supportedCrypto, // Store capabilities
        CreatedAt:       time.Now(),
        UpdatedAt:       time.Now(),
    }

    return kdc.AddNode(node)
}
```

**Testing:**
```bash
# Test enrollment with supported_crypto
go test -v -run TestEnrollmentWithCrypto

# Test backward compatibility
go test -v -run TestEnrollmentBackwardCompat
# - Old KRS (no supported_crypto field) → defaults to ["hpke"]
```

**Validation criteria:**
- [ ] Enrollment request includes supported_crypto
- [ ] KDC stores capabilities correctly
- [ ] Backward compatible with old KRS
- [ ] Database reflects correct crypto support per node

---

#### Session 9: End-to-End V2 Path Activation

**Goal:** Enable and test complete v2 path with both backends

**Test scenarios:**

**Scenario 1: HPKE-only node (existing behavior)**
```bash
# 1. Enroll node with HPKE support
curl -X POST http://kdc:8080/api/enroll \
  -d '{"supported_crypto": ["hpke"], ...}'

# 2. Create distribution for zone
curl -X POST http://kdc:8080/api/distributions/create \
  -d '{"zone": "example.com", "node_id": "ns1.example.com"}'

# 3. KRS processes distribution
# Expected: Uses HPKE backend, manifest has "crypto": "hpke"

# 4. Verify key installed
dig @ns1.example.com example.com DNSKEY
```

**Scenario 2: JOSE-only node (new functionality)**
```bash
# 1. Enroll node with JOSE support
curl -X POST http://kdc:8080/api/enroll \
  -d '{"supported_crypto": ["jose"], ...}'

# 2. Create distribution
curl -X POST http://kdc:8080/api/distributions/create \
  -d '{"zone": "example.com", "node_id": "ns2.example.com"}'

# 3. KRS processes distribution
# Expected: Uses JOSE backend, manifest has "crypto": "jose"

# 4. Verify key installed
dig @ns2.example.com example.com DNSKEY
```

**Scenario 3: Mixed deployment**
```bash
# 1. KDC manages both ns1 (HPKE) and ns2 (JOSE)

# 2. Create distribution for zone on both nodes
curl -X POST http://kdc:8080/api/distributions/create \
  -d '{"zone": "example.com", "nodes": ["ns1.example.com", "ns2.example.com"]}'

# 3. KDC creates two distributions:
#    - ns1: HPKE-encrypted
#    - ns2: JOSE-encrypted

# 4. Both KRS instances process their distributions
# Expected: Both install same key, different encryption paths

# 5. Verify both have identical DNSKEY
dig @ns1.example.com example.com DNSKEY
dig @ns2.example.com example.com DNSKEY
# Should be identical
```

**Feature flag activation:**
```yaml
# kdc.yaml
kdc:
  use_crypto_v2: true  # ENABLE V2 PATH

# krs.yaml (on each KRS)
krs:
  use_crypto_v2: true  # ENABLE V2 PATH
```

**Validation criteria:**
- [ ] HPKE-only nodes work correctly
- [ ] JOSE-only nodes work correctly
- [ ] Mixed deployment works correctly
- [ ] Can toggle feature flag without breaking system
- [ ] Both backends produce working DNSSEC keys

---

### Phase 4: Production Readiness (Sessions 10-11)

#### Session 10: Migration Guide & Documentation

**Goal:** Document how to migrate existing deployments

**Deliverables:**

**1. Migration guide: `tdns-nm/docs/CRYPTO-MIGRATION.md`**

Topics:
- Overview of changes
- Upgrade path for existing deployments
- How to enable v2 path
- How to test before full activation
- Rollback procedures
- Troubleshooting

**2. Configuration documentation updates**

Add to existing config docs:
```yaml
# KDC configuration
kdc:
  use_crypto_v2: false  # Set true to use abstracted crypto
  # When false: legacy HPKE-only path
  # When true: backend selected per node

# KRS configuration
krs:
  use_crypto_v2: false  # Set true to use abstracted crypto
  supported_crypto:     # Advertised during enrollment
    - "hpke"
  # Future: Add "jose" for C implementations
```

**3. Operator guide: `tdns-nm/docs/CRYPTO-BACKENDS.md`**

Topics:
- What are crypto backends?
- HPKE vs JOSE comparison
- When to use which backend
- Performance considerations
- Security properties of each

**4. Example configurations**

```yaml
# Example 1: All HPKE (existing deployments)
kdc:
  use_crypto_v2: true
  # All nodes have supported_crypto: ["hpke"]

# Example 2: Gradual JOSE rollout
kdc:
  use_crypto_v2: true
  nodes:
    - id: ns1.example.com
      supported_crypto: ["hpke"]  # Existing node
    - id: ns2.example.com
      supported_crypto: ["jose"]  # New node

# Example 3: Dual support (future)
krs:
  supported_crypto:
    - "hpke"
    - "jose"
  # KDC will prefer first in list
```

**Validation criteria:**
- [ ] Documentation is clear and complete
- [ ] Migration steps are tested
- [ ] Examples work as documented

---

#### Session 11: Testing, Cleanup & Final Validation

**Goal:** Comprehensive testing and optional v1 code deprecation

**Testing checklist:**

**Unit tests:**
- [ ] All crypto backends pass identical test suite
- [ ] Manifest backward/forward compatibility
- [ ] Enrollment request parsing (with and without supported_crypto)

**Integration tests:**
- [ ] KDC creates distributions with correct backend
- [ ] KRS processes distributions with correct backend
- [ ] Mixed deployments work

**End-to-end tests:**
- [ ] Full enrollment → distribution → key installation flow
- [ ] Both HPKE and JOSE paths
- [ ] Feature flag toggling

**Performance tests:**
- [ ] Benchmark HPKE vs JOSE encryption/decryption
- [ ] Measure impact on distribution creation time
- [ ] Measure impact on distribution processing time

**Optional cleanup (low priority):**

If v2 path is stable and v1 is no longer needed:

1. Add deprecation warnings to v1 functions:
```go
// Deprecated: Use EncryptKeyForNodeV2 instead
func (kdc *KdcDB) EncryptKeyForNode(...) {
    log.Println("WARNING: Using deprecated v1 encryption path")
    // ... existing implementation
}
```

2. Update internal calls to use v2 functions
3. Eventually remove v1 code (breaking change, requires major version bump)

**Note:** Cleanup is optional and can be deferred indefinitely. Having both paths is acceptable.

**Validation criteria:**
- [ ] All tests pass
- [ ] Performance acceptable
- [ ] Documentation complete
- [ ] System stable with v2 enabled

---

## Testing Strategy

### Test Pyramid

```
                    ┌─────────────────┐
                    │   E2E Tests     │  ← Full system tests
                    │  (Sessions 9-11)│
                    └─────────────────┘
                  ┌───────────────────────┐
                  │  Integration Tests    │  ← Component interaction
                  │    (Sessions 4-8)     │
                  └───────────────────────┘
            ┌─────────────────────────────────┐
            │        Unit Tests               │  ← Individual functions
            │      (Sessions 1-3)             │
            └─────────────────────────────────┘
```

### Test Coverage Requirements

**Unit tests (Sessions 1-3):**
- Crypto backend interface compliance
- Encrypt/decrypt round-trip
- Key serialization/deserialization
- Backend registration and retrieval

**Integration tests (Sessions 4-8):**
- KDC distribution creation with backend selection
- Manifest format compatibility
- Database schema migrations
- KRS distribution processing with backend detection
- Enrollment flow with crypto capabilities

**End-to-end tests (Sessions 9-11):**
- Full enrollment → distribution → key installation
- Mixed deployments (multiple backends)
- Feature flag behavior
- Rollback procedures

### Continuous Testing During Development

**After each session:**
1. Run unit tests: `go test -v ./...`
2. Run integration tests: `go test -v -tags=integration ./...`
3. Manual validation: Test in development environment
4. Confirm old path still works: Toggle feature flag OFF

**Before each session:**
1. Verify previous session's work still passes tests
2. Ensure no regressions in existing functionality

---

## Migration Path

### For Existing HPKE Deployments

**Phase 1: Upgrade to v2-capable code (no behavior change)**
```
1. Deploy updated KDC with v2 code (use_crypto_v2: false)
2. Deploy updated KRS with v2 code (use_crypto_v2: false)
3. Verify system still works
4. Database migration runs automatically (adds supported_crypto column)
5. Existing nodes get supported_crypto: ["hpke"] by default
```

**Phase 2: Enable v2 path (uses abstraction layer)**
```
1. Enable on one test KRS first: use_crypto_v2: true
2. Test distribution processing
3. If successful, enable on KDC: use_crypto_v2: true
4. Enable on remaining KRS instances
5. Monitor for issues
```

**Phase 3: Deploy new nodes with JOSE (optional)**
```
1. Enroll new KRS with supported_crypto: ["jose"]
2. KDC will automatically use JOSE backend for this node
3. Existing HPKE nodes continue working unchanged
```

### For New Deployments

**Start with v2 from day one:**
```
1. Deploy KDC and KRS with use_crypto_v2: true
2. Choose backend per node:
   - Go-based KRS: Can use HPKE or JOSE
   - C-based KRS (future): Use JOSE
3. No migration needed
```

---

## Rollback Procedures

### Immediate Rollback (if v2 path has issues)

**Step 1: Disable feature flag**
```yaml
# kdc.yaml
kdc:
  use_crypto_v2: false  # Revert to v1 path

# krs.yaml
krs:
  use_crypto_v2: false  # Revert to v1 path
```

**Step 2: Restart services**
```bash
systemctl restart tdns-kdc
systemctl restart tdns-krs
```

**Step 3: Verify system working**
```bash
# Test distribution creation and processing
# Should use v1 (HPKE-only) path
```

**No data loss:** supported_crypto column remains in database but is unused by v1 path.

### Partial Rollback (specific node having issues)

**Option 1: Keep node on v1 path**
```yaml
# kdc.yaml - can mix v1 and v2
kdc:
  use_crypto_v2: true
  nodes:
    - id: ns1.example.com
      force_v1: true  # Force this node to v1 path
```

**Option 2: Change node's backend**
```bash
# Update node's supported_crypto in database
UPDATE nodes SET supported_crypto = '["hpke"]' WHERE id = 'ns2.example.com';
```

### Full Rollback (revert code)

**If v2 code itself needs to be removed:**
```bash
# Git revert to pre-v2 commit
git revert <commit-range>

# Or use previous release
git checkout v1.0.0
```

**Database compatibility:** supported_crypto column is ignored by old code, no schema rollback needed.

---

## Risk Assessment

### Low Risk Items
- Crypto abstraction layer (new code, no integration)
- JOSE backend implementation (isolated)
- Manifest format extension (backward compatible)
- Feature flags (can be toggled)

### Medium Risk Items
- Database migration (needs testing on real data)
- KDC backend selection (affects distribution creation)
- Enrollment flow changes (affects onboarding)

### High Risk Items
- First production activation of v2 path (test thoroughly)
- Mixed deployments (HPKE + JOSE) (complex state)

### Mitigation Strategies
1. **Parallel implementation:** v1 always available as fallback
2. **Feature flags:** Gradual rollout, easy rollback
3. **Testing:** Comprehensive test suite at each phase
4. **Documentation:** Clear procedures for operators
5. **Monitoring:** Log backend usage, track errors per backend

---

## Success Criteria

### Technical Success
- [ ] Both HPKE and JOSE backends functional
- [ ] Crypto abstraction layer clean and well-tested
- [ ] Backward compatibility maintained
- [ ] Forward path for C implementation clear
- [ ] Performance acceptable (< 10% overhead from abstraction)

### Operational Success
- [ ] Existing deployments unaffected
- [ ] Migration path documented and tested
- [ ] Rollback procedures validated
- [ ] Mixed deployments work reliably

### Project Success
- [ ] Code merged to main branch
- [ ] Documentation complete
- [ ] Team confident in new system
- [ ] Ready for C implementation phase

---

## Timeline Summary

| Phase | Sessions | Calendar Time | Key Deliverables |
|-------|----------|---------------|------------------|
| Phase 1: Foundation | 1-3 | 1 week | Crypto abstraction layer, both backends |
| Phase 2: KDC Integration | 4-6 | 1-2 weeks | KDC uses abstraction, manifest updates |
| Phase 3: KRS Integration | 7-9 | 1-2 weeks | KRS uses abstraction, enrollment updates |
| Phase 4: Production | 10-11 | 1 week | Documentation, testing, validation |
| **Total** | **11 sessions** | **4-5 weeks** | **Production-ready dual-backend system** |

**Assumptions:**
- 2-3 sessions per week
- Each session ~2-3 hours of developer work
- ~2 hours of operator testing/validation per session

---

## Next Steps

1. **Immediate:** Begin Session 1 (Crypto Abstraction Interface + HPKE Wrapper)
2. **After Session 1:** Review interface design, run tests, confirm approach
3. **Session 2:** Implement JOSE backend
4. **Continue:** Follow phase plan sequentially

---

## References

**Related Documents:**
- `tdns/docs/hpke-design.md` - Current HPKE implementation
- `tdns/docs/kdc-krs-workflow.md` - KDC/KRS architecture
- `tdns-nm/docs/hpke-jose-migration.md` - Original migration discussion

**External Standards:**
- RFC 9180: Hybrid Public Key Encryption (HPKE)
- RFC 7516: JSON Web Encryption (JWE)
- RFC 7517: JSON Web Key (JWK)
- RFC 7518: JSON Web Algorithms (JWA)

**Libraries:**
- `github.com/go-jose/go-jose/v3` - JOSE implementation for Go
- `tdns/v2/hpke` - Existing HPKE implementation

---

**Document Status:** Active Implementation Plan
**Last Updated:** 2026-01-21
**Next Review:** After Phase 1 completion