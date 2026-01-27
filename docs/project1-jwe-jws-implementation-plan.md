# Project 1: JWE/JWS Redesign - Implementation Plan

## Document Version
- **Date**: 2026-01-26
- **Status**: Ready to Execute
- **Duration**: 4-6 weeks
- **Risk**: LOW (backend abstraction contains changes)

## Overview

Project 1 replaces custom JSON encryption wrapper with standard JWE/JWS format for V2 crypto (both JOSE and HPKE backends). This provides:
- Standard RFC 7515/7516 format for external interoperability
- Multi-recipient support (single encryption, N recipients)
- Authenticated and signed distributions
- Path to eventual V1 migration

---

## Current State Analysis

### What's Already Done ✅
- ✅ Backend abstraction interface (`v2/crypto/backend.go`)
- ✅ Backend registry system (`v2/crypto/registry.go`)
- ✅ HPKE backend implementation (X25519)
- ✅ JOSE backend implementation (P-256)
- ✅ Feature flag architecture (`use_crypto_v2`)
- ✅ Cross-backend testing framework
- ✅ Phase A generalization (CHUNK, NOTIFY, confirmation)

### Current Format (V2)
```
Backend.Encrypt(pubKey, plaintext) → raw ciphertext
  - HPKE: <encapsulated_key (32 bytes)><encrypted_data>
  - JOSE: JWE compact serialization (5 base64url parts)
```

### Target Format (Project 1)
```
Backend.Encrypt(pubKey, plaintext) → JWS(JWE(plaintext))
  - Outer: JWS with KDC signature
  - Inner: JWE with recipient encryption
  - Multi-recipient: Single JWE with multiple encrypted_keys
```

---

## Architecture Decisions

### Decision 1: Implementation Approach

**Chosen: Option A - JWE/JWS Internal to Backend**

**Rationale**:
- ✅ Zero changes to KDC/KRS caller code
- ✅ Backend abstraction works perfectly
- ✅ Multi-recipient becomes backend optimization detail
- ✅ Clean separation of concerns

**Implementation**:
```go
// KDC code UNCHANGED:
ciphertext, _ := backend.Encrypt(nodePublicKey, plaintext)

// Backend internally returns JWS(JWE(...)) instead of raw ciphertext
```

### Decision 2: Signing Keys

**KDC Signing**:
- KDC signs with existing `kdc_jose_priv_key` (P-256) or `kdc_hpke_priv_key` (X25519)
- Public keys distributed to nodes during enrollment (already in enrollment blob)
- Nodes verify JWS signature before decryption

**Node Signing** (for future node→KDC messages):
- Nodes sign with `LongTermPrivKey` (already exists)
- KDC verifies with stored `node.LongTermPubKey`
- Enables bidirectional authenticated communication

### Decision 3: Multi-Recipient Strategy

**For V2 JOSE**:
- Use JWE JSON Serialization (supports multiple recipients)
- Single ciphertext, multiple `encrypted_key` entries
- Each recipient gets unique encrypted key

**For V2 HPKE**:
- Our interpretation: multiple HPKE encryptions in JWE recipients array
- Each recipient: separate HPKE encryption with ephemeral key
- Format: JWE JSON Serialization with HPKE-specific fields

**For V1 (unchanged)**:
- Single-recipient only
- Direct HPKE with custom JSON wrapper
- No changes during Project 1

### Decision 4: Protected Headers

**Required Fields** (in JWE protected header):
```json
{
  "alg": "ECDH-ES+A256KW",           // JWE key algorithm
  "enc": "A256GCM",                   // JWE content encryption
  "typ": "tdns-distribution",         // TDNS custom type
  "distribution_id": "uuid",          // Distribution identifier
  "content_type": "key_operations",   // Content type
  "timestamp": "2025-01-26T...",      // Creation time (replay protection)
  "crypto_backend": "jose",           // Backend used
  "distribution_ttl": "5m",           // TTL for replay protection
  "sender": "kdc.example.com.",       // Sender identity
  "recipients_count": 3               // Number of recipients
}
```

---

## Implementation Phases

### Phase 1: Backend Interface Extensions (Week 1)

**Goal**: Add multi-recipient support to Backend interface without breaking existing code

**Tasks**:

1. **Extend Backend interface** (`v2/crypto/backend.go`):
   ```go
   type Backend interface {
       // Existing methods (keep unchanged)
       Name() string
       GenerateKeypair() (PrivateKey, PublicKey, error)
       ParsePublicKey([]byte) (PublicKey, error)
       ParsePrivateKey([]byte) (PrivateKey, error)
       SerializePublicKey(PublicKey) ([]byte, error)
       SerializePrivateKey(PrivateKey) ([]byte, error)
       Encrypt(pubKey PublicKey, plaintext []byte) ([]byte, error)
       Decrypt(privKey PrivateKey, ciphertext []byte) ([]byte, error)
       GetEphemeralKey(ciphertext []byte) []byte

       // NEW: Multi-recipient methods
       EncryptMultiRecipient(recipients []PublicKey, plaintext []byte, metadata map[string]interface{}) ([]byte, error)
       DecryptMultiRecipient(privKey PrivateKey, ciphertext []byte) ([]byte, error)

       // NEW: Signing methods
       Sign(privKey PrivateKey, data []byte) ([]byte, error)
       Verify(pubKey PublicKey, data []byte, signature []byte) (bool, error)
   }
   ```

2. **Add default implementations**:
   - For backends that don't implement multi-recipient yet, fall back to single-recipient loop
   - Add signing/verification stubs

3. **Update tests**:
   - Add multi-recipient test cases
   - Test signature verification

**Deliverable**: Extended interface, backward compatible

---

### Phase 2: JOSE Backend JWS(JWE) Implementation (Week 2-3)

**Goal**: Implement RFC-compliant JWS(JWE(JOSE)) with multi-recipient support

**Tasks**:

1. **Implement JWE Multi-Recipient** (`v2/crypto/jose/backend.go`):
   ```go
   func (b *JoseBackend) EncryptMultiRecipient(recipients []PublicKey, plaintext []byte, metadata map[string]interface{}) ([]byte, error) {
       // 1. Generate content encryption key (CEK)
       // 2. Encrypt plaintext with CEK (AES-256-GCM)
       // 3. For each recipient:
       //    - Derive shared secret via ECDH-ES
       //    - Encrypt CEK with recipient's public key
       //    - Add to recipients array
       // 4. Build JWE JSON Serialization
       // 5. Return JWE structure
   }
   ```

2. **Implement JWS Signing**:
   ```go
   func (b *JoseBackend) Sign(privKey PrivateKey, data []byte) ([]byte, error) {
       // 1. Create JWS protected header (ES256)
       // 2. Sign data with P-256 ECDSA
       // 3. Build JWS Compact Serialization: <header>.<payload>.<signature>
       // 4. Return JWS
   }
   ```

3. **Wrap JWE in JWS**:
   ```go
   func (b *JoseBackend) EncryptAndSign(recipients []PublicKey, plaintext []byte, signingKey PrivateKey, metadata map[string]interface{}) ([]byte, error) {
       // 1. Create JWE (multi-recipient)
       jwe := b.EncryptMultiRecipient(recipients, plaintext, metadata)
       // 2. Sign JWE structure
       jws := b.Sign(signingKey, jwe)
       // 3. Return JWS(JWE(...))
       return jws, nil
   }
   ```

4. **Implement Decryption**:
   ```go
   func (b *JoseBackend) DecryptMultiRecipient(privKey PrivateKey, ciphertext []byte) ([]byte, error) {
       // 1. Parse JWS outer layer
       // 2. Verify JWS signature (if verification key provided)
       // 3. Extract JWE from JWS payload
       // 4. Find recipient entry matching our key
       // 5. Decrypt CEK with our private key
       // 6. Decrypt ciphertext with CEK
       // 7. Return plaintext
   }
   ```

5. **Protected Headers**:
   - Add all required fields to JWE protected header
   - Include metadata passed from caller
   - Ensure RFC compliance

6. **Testing**:
   - Single-recipient JWE
   - Multi-recipient JWE (2, 3, 5 recipients)
   - JWS signature verification
   - Round-trip encrypt/decrypt
   - Cross-recipient decryption

**Deliverable**: RFC-compliant JWS(JWE(JOSE)) implementation

---

### Phase 3: HPKE Backend JWS(JWE) Implementation (Week 4)

**Goal**: Implement JWS(JWE(HPKE)) with our interpretation (not RFC-dependent)

**Tasks**:

1. **Design HPKE-in-JWE Format**:
   ```json
   {
     "protected": "<base64url(protected_headers)>",
     "ciphertext": "<base64url(ciphertext)>",
     "iv": "<base64url(iv)>",
     "tag": "<base64url(auth_tag)>",
     "recipients": [
       {
         "header": {
           "kid": "node1_keyid",
           "epk_hpke": "<base64url(ephemeral_pubkey_32bytes)>"
         },
         "encrypted_key": "<base64url(hpke_encapsulated_key)>"
       }
     ]
   }
   ```

2. **Implement Multi-Recipient HPKE**:
   ```go
   func (b *HpkeBackend) EncryptMultiRecipient(recipients []PublicKey, plaintext []byte, metadata map[string]interface{}) ([]byte, error) {
       // 1. Generate random CEK (32 bytes)
       // 2. Encrypt plaintext with CEK (AES-256-GCM)
       // 3. For each recipient:
       //    - HPKE encrypt the CEK with recipient's public key
       //    - Store encapsulated key + ephemeral key
       // 4. Build JWE JSON structure with HPKE recipients
       // 5. Return JWE
   }
   ```

3. **Wrap in JWS** (same pattern as JOSE):
   ```go
   func (b *HpkeBackend) Sign(privKey PrivateKey, data []byte) ([]byte, error) {
       // Use Ed25519 or similar for X25519 key signing
       // Or: Use a separate signing keypair
   }
   ```

4. **Implement Decryption**:
   - Parse JWS outer layer
   - Verify signature
   - Extract JWE
   - Find matching recipient entry
   - HPKE decrypt CEK
   - Decrypt ciphertext with CEK
   - Return plaintext

5. **Testing**:
   - Single and multi-recipient
   - JWS signature with HPKE
   - Round-trip tests
   - Compatibility with JOSE format (same JWS structure)

**Deliverable**: JWS(JWE(HPKE)) implementation

---

### Phase 4: Integration and Metadata (Week 5)

**Goal**: Integrate with KDC/KRS and add protected headers

**Tasks**:

1. **Update Manifest Metadata**:
   - Protected headers now live in JWE, not in CHUNK manifest
   - Manifest metadata becomes supplementary
   - Add `jwe_format` indicator to manifest

2. **KDC Integration**:
   - KDC loads signing key during initialization
   - Pass signing key to backend during encryption
   - No other changes needed (backend handles JWE/JWS internally)

3. **KRS Integration**:
   - KRS loads KDC public key during enrollment
   - Pass verification key to backend during decryption
   - Backend verifies signature before decryption

4. **Backward Compatibility**:
   - V1 code path unchanged
   - V2 with feature flag disabled: use current format
   - V2 with feature flag enabled: use JWS(JWE) format
   - Add format detection in DecryptMultiRecipient

5. **Protected Headers Enrichment**:
   - Extract metadata from CHUNK manifest
   - Include in JWE protected header
   - Validate timestamp (replay protection)
   - Validate distribution_ttl

**Deliverable**: Integrated JWE/JWS in KDC/KRS

---

### Phase 5: Testing and Validation (Week 6)

**Goal**: Comprehensive testing of all scenarios

**Test Cases**:

1. **Unit Tests**:
   - JWE creation and parsing
   - JWS signing and verification
   - Multi-recipient encryption/decryption
   - Protected headers validation

2. **Backend Tests**:
   - JOSE backend: RFC compliance
   - HPKE backend: our interpretation
   - Cross-backend incompatibility (should fail cleanly)

3. **Integration Tests**:
   - KDC→KRS distribution (single recipient)
   - KDC→multiple KRS (multi-recipient)
   - Signature verification by KRS
   - Replay protection (timestamp validation)
   - Distribution TTL enforcement

4. **Migration Tests**:
   - V1 still works (unchanged)
   - V2 with old format still decryptable (during transition)
   - V2 with new format works
   - Format detection works correctly

5. **Performance Tests**:
   - Multi-recipient vs N single-recipient
   - Signature verification overhead
   - Large payload handling

**Deliverable**: Fully tested JWE/JWS implementation

---

## Implementation Strategy

### Option A: Internal to Backend (CHOSEN)

**Pros**:
- Zero KDC/KRS code changes
- Clean abstraction
- Backend responsibility
- Easy rollback

**Cons**:
- Backend must manage signing keys
- Slightly more complex backend code

### Signing Key Management

**KDC Side**:
```go
// During KDC initialization:
kdcJoseKeys, _ := kdc.GetKdcJoseKeypair(conf.KdcJosePrivKey)
backend.SetSigningKey(kdcJoseKeys.PrivateKey)

// During encryption (unchanged caller code):
ciphertext, _ := backend.Encrypt(nodePublicKey, plaintext)
// Backend internally uses signing key to create JWS
```

**KRS Side**:
```go
// During KRS initialization (enrollment):
kdcJosePubKey := conf.KdcJosePubKey
backend.SetVerificationKey(kdcJosePubKey)

// During decryption (unchanged caller code):
plaintext, _ := backend.Decrypt(nodePrivateKey, ciphertext)
// Backend internally verifies JWS signature
```

---

## Risk Mitigation

### Risk 1: Format Incompatibility

**Risk**: Old and new formats incompatible
**Mitigation**:
- Feature flag controls format
- Format detection in DecryptMultiRecipient
- Gradual rollout per node

### Risk 2: Performance Regression

**Risk**: Multi-recipient adds overhead
**Mitigation**:
- Benchmark before/after
- Single-recipient path remains fast
- Multi-recipient only used when beneficial

### Risk 3: Signature Verification Failures

**Risk**: Key distribution issues cause verification failures
**Mitigation**:
- Enrollment blob includes KDC public keys
- Fallback to no verification if key not available
- Clear error messages for debugging

---

## Timeline

| Week | Phase | Deliverable |
|------|-------|-------------|
| 1 | Backend Interface Extensions | Extended interface, backward compatible |
| 2-3 | JOSE JWS(JWE) Implementation | RFC-compliant JOSE backend |
| 4 | HPKE JWS(JWE) Implementation | HPKE backend with JWE/JWS |
| 5 | Integration and Metadata | KDC/KRS integration complete |
| 6 | Testing and Validation | All tests passing, ready for rollout |

**Total**: 6 weeks (can be compressed to 4-5 weeks with focused effort)

---

## Success Criteria

- ✅ JOSE backend produces RFC-compliant JWS(JWE) format
- ✅ HPKE backend produces JWS(JWE(HPKE)) format (our interpretation)
- ✅ Multi-recipient support works (2+ recipients)
- ✅ Signature verification works
- ✅ Protected headers include all required metadata
- ✅ V1 code path unchanged and functional
- ✅ V2 backward compatible with feature flag
- ✅ All existing tests pass
- ✅ New JWE/JWS tests pass
- ✅ Performance acceptable (multi-recipient break-even at 3+ nodes)

---

## Next Steps

1. **Start Phase 1**: Extend Backend interface
2. **Review and approve** interface design before implementation
3. **Implement incrementally**: One phase at a time, test thoroughly
4. **Document as we go**: Update godoc, examples, migration guide

---

## Open Questions

1. **HPKE Signing Algorithm**: Use Ed25519 or separate signing keypair?
   - **Recommendation**: Use separate P-256 signing key for consistency with JOSE

2. **Multi-Recipient Threshold**: When to use multi-recipient vs N single-recipient?
   - **Recommendation**: Always use multi-recipient for 2+ nodes (simpler, future-proof)

3. **Format Indicator**: How to detect JWE/JWS vs old format?
   - **Recommendation**: Check for JWS structure (3 base64url parts separated by dots)

4. **V1 Migration Timeline**: When to migrate V1 to JWE(HPKE)?
   - **Recommendation**: After Project 1 complete and stable (out of scope for now)

---

**Document Status**: Ready for implementation
**Next Action**: Extend Backend interface (Phase 1, Week 1)
