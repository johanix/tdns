# JOSE JWE/JWS Redesign for Encrypted Distributions

## Document Version
- **Date**: 2026-01-25
- **Status**: Design Phase (Pre-Implementation)
- **Author**: Architecture Review
- **Project**: TDNS-NM Crypto V2 Enhancement

## Executive Summary

This document proposes replacing the custom JSON encryption wrapper with standard JOSE JWE/JWS format for encrypted distributions in TDNS. This provides:

1. **Standard format** - Leverages mature RFC 7515 (JWS) and RFC 7516 (JWE) implementations
2. **Multi-recipient support** - Single distribution encrypted for multiple nodes simultaneously
3. **Language interoperability** - Better C/C++ support for future ports
4. **Phased transition** - Keeps V1 (HPKE-only) unchanged, evolves V2 (crypto abstraction)

## Current Architecture

### V1 (Original - HPKE only, unchanged)
```
base64(custom_json_wrapper(HPKE_encrypted_payload))
```

### V2 (Crypto V2 - current)
```
base64(custom_json_wrapper(encrypted_payload))
  where encrypted_payload = HPKE or JWE (raw)
```

### Problems with Current V2

1. **Custom JSON wrapper** - Non-standard, requires custom parsers in every language
2. **Single-recipient only** - Each distribution encrypted for one node
3. **No built-in authentication** - Metadata not integrity-protected
4. **Language barriers** - C/C++ interop limited due to custom format

## Proposed Architecture

### V2 Enhanced (Crypto V2 with JWE/JWS)

```
JWS(JWE(plaintext))
  - JWE uses JSON Serialization format (multi-recipient capable)
  - JWS signs the entire JWE structure
  - Protected headers contain all metadata
```

### Serialization Format

**Outer format**: JWS Compact Serialization (3 parts)
```
<JWS_HEADER>.<JWE_COMPACT>.<SIGNATURE>
```

**JWE inner**: JWE JSON Serialization
```json
{
  "protected": "<base64url(protected_headers)>",
  "ciphertext": "<base64url(ciphertext)>",
  "iv": "<base64url(iv)>",
  "tag": "<base64url(auth_tag)>",
  "recipients": [
    {
      "header": {...recipient1_headers...},
      "encrypted_key": "<base64url(encrypted_key_1)>"
    },
    {
      "header": {...recipient2_headers...},
      "encrypted_key": "<base64url(encrypted_key_2)>"
    }
  ]
}
```

**Full flow for KDC distributing key to 3 nodes**:
1. Generate plaintext (DNSSEC key material, operations, etc.)
2. Encrypt once with AES-256-GCM → single ciphertext
3. Create 3 recipients in JWE (one per node public key)
4. Sign JWE structure with KDC private key → JWS
5. Send single distribution message to all 3 nodes
6. Each node verifies JWS signature (cheap)
7. Each node decrypts with their unique encrypted_key (ECDH)

## Key Design Decisions

### 1. JWS(JWE(plaintext)) Order

**Chosen: JWS OUTER, JWE INNER**

**Rationale**:
- Signature verification is inexpensive (cryptographic hash)
- Decryption is expensive (symmetric + ECDH)
- Verify sender authenticity BEFORE processing potentially large payload
- Detect tampering/forgery without decryption overhead

### 2. Metadata Location

**Chosen: Protected Headers (both JWE and JWS)**

Protected headers are:
- Included in JWS signature (authenticated)
- Included in JWE authenticated tag (integrity-protected)
- Cannot be modified without invalidating both signatures

**Protected headers contain**:
```json
{
  "alg": "ECDH-ES+A256KW",        // JWE key algorithm
  "enc": "A256GCM",                 // JWE content encryption
  "typ": "tdns-distribution",       // TDNS custom type
  "distribution_id": "uuid",        // Distribution identifier
  "content_type": "key_operations", // Content type (operations, key_distribution, etc.)
  "timestamp": "2025-01-25T...",    // Creation time
  "crypto_backend": "jose",         // Backend used (jose, hpke)
  "distribution_ttl": "5m",         // TTL for replay protection
  "retire_time": "168h",            // Key retirement timing (if applicable)
  "sender": "kdc.example.com.",     // Sender identity
  "recipients_count": 3             // Number of recipients in distribution
}
```

### 3. HPKE Transition Strategy

**Three code paths with different evolution**:

**V1 (Direct HPKE) Evolution**:
- **Now**: Custom JSON + HPKE (unchanged, must remain functional)
- **Later**: JWE(HPKE) - standard JWE format, no JWS layer
- **Scope**: Single-recipient only, DNSSEC provides integrity
- **Timeline**: Independent of Project 1, lower priority

**V2 with JOSE**:
- **Phase 1 (Project 1)**: JWS(JWE(JOSE)) format
- Standard RFC 7515 (JWS) and RFC 7516 (JWE)
- Multi-recipient support via JWE JSON Serialization
- Full signing chain for authenticated distribution

**V2 with HPKE**:
- **Phase 1 (Now)**: HPKE continues using custom wrapper
- **Phase 2 (Project 1 completion)**: JWS(JWE(HPKE)) with our interpretation
- Multi-recipient support for HPKE
- **Note**: Not waiting for IETF RFC `draft-ietf-jose-hpke` - this is our interpretation for internal TDNS use
- **Future**: If/when IETF RFC emerges, consider alignment (out of scope now)

**Code Pattern After Project 1**:
```go
if backend == "jose" {
    // Standard JWS(JWE) with RFC-compliant JOSE
    return encryptWithJWEJWS(plaintext, nodePublicKeys, kdcPrivateKey)
} else if backend == "hpke" {
    // Our interpretation of JWS(JWE(HPKE))
    return encryptWithJWEJWS_HPKE(plaintext, nodePublicKeys, kdcPrivateKey)
}
```

**Future Option** (out of scope):
- Once V2's JWS(JWE(HPKE)) is stable and tested
- Could potentially retire V1 entirely
- V2's JWS(JWE(HPKE)) would supersede V1's JWE(HPKE)
- Decision deferred based on operational experience

### 4. Serialization Format

**Chosen: JWE JSON Serialization (not compact)**

**Rationale for JSON**:
- Supports multi-recipient (multiple encrypted_keys)
- Compact form (5 base64url parts) only supports single recipient
- Standard format from RFC 7516

**Encoding**: Entire JWE JSON structure is base64url-encoded in JWS payload

### 5. Key Distribution and Signing

**KDC Perspective**:
- KDC signs with `kdc_jose_priv_key` (P-256) or `kdc_hpke_priv_key` (X25519)
- KDC encrypts for node with node's `LongTermPubKey`
- KDC public keys distributed to nodes during enrollment
- Nodes verify JWS signature with KDC's public key

**Node (Edge) Perspective**:
- Node can sign with its own `LongTermPrivKey`
- KDC verifies node signatures with stored `node.LongTermPubKey`
- Enables bidirectional authenticated communication

## Multi-Recipient Example

**Scenario**: KDC distributes new ZSK to 3 edge nodes

**Traditional (current)**:
```
Distribution 1: base64(JOSE_encrypt(zsk, node1_pubkey)) → node1
Distribution 2: base64(JOSE_encrypt(zsk, node2_pubkey)) → node2
Distribution 3: base64(JOSE_encrypt(zsk, node3_pubkey)) → node3
```
= 3 separate messages, 3 encryptions

**With Multi-Recipient JWE**:
```
Distribution: JWS(JWE(zsk, [node1_pubkey, node2_pubkey, node3_pubkey]))
  with recipients: [
    { encrypted_key_for_node1 },
    { encrypted_key_for_node2 },
    { encrypted_key_for_node3 }
  ]
```
= 1 message, 1 encryption, 3 recipients

**Benefits**:
- Network efficiency (1/3 bandwidth for this distribution)
- KDC efficiency (1 encryption instead of 3)
- Atomic multi-node deployment (all get same key at same time)

## Backward Compatibility Strategy

### V1 (Original) Evolution
- **Now**: Keep existing code path completely untouched during Project 1
- **Later (independent)**: Migrate V1 to JWE(HPKE) - standard format, no JWS
- **Purpose**: Eliminate custom JSON, single-recipient only
- **Future option**: Once V2 stable, consider retiring V1 entirely

### V2 Transition Path (Project 1)
1. **Phase 1 (Initial JWE/JWS)**:
   - V2 with JOSE → JWS(JWE(JOSE)) (RFC-compliant)
   - V2 with HPKE → custom wrapper (unchanged initially)
   - Feature flag controls V1 vs V2

2. **Phase 2 (Project 1 completion)**:
   - Migrate V2 HPKE to JWS(JWE(HPKE)) with our interpretation
   - Unify all V2 under JWE/JWS envelope
   - Multi-recipient support for both JOSE and HPKE
   - **Not dependent on IETF RFC** - internal TDNS implementation

3. **Phase 3 (Future, out of scope)**:
   - If IETF RFC for HPKE-in-JOSE emerges, consider alignment
   - Potentially deprecate V1 if V2 proves stable
   - Remove legacy custom JSON wrapper entirely

### Migration Window
- V1 and V2 coexist during transition
- No forced migration - operators choose when to enable `use_crypto_v2`
- Once V2 mature and tested, deprecate V1
- Old custom wrapper can be removed in future major version

## Signing and Verification Flow

### KDC → Node (Distribution)

```
KDC:
  1. plaintext = serialize(key_material or operations)
  2. jwe_object = encrypt_jwe(
       plaintext,
       recipients=[node1_pubkey, node2_pubkey, ...],
       protected_headers={distribution_id, crypto_backend, ...}
     )
  3. jws = sign_jws(
       payload=base64url(jwe_object),
       private_key=kdc_jose_privkey,
       headers={alg: "ES256", kid: "kdc_keyid", ...}
     )
  4. send(jws) to nodes

Node:
  1. jws_parsed = parse_jws(received_message)
  2. verify_jws_signature(jws_parsed, kdc_jose_pubkey)  // Cheap
  3. jwe_object = decode(jws_parsed.payload)
  4. plaintext = decrypt_jwe(jwe_object, node_privkey)  // Expensive
  5. process(plaintext)
```

### Node → KDC (Enrollment or Update)

```
Node:
  1. plaintext = serialize(enrollment_request or update)
  2. jwe_object = encrypt_jwe(
       plaintext,
       recipients=[kdc_pubkey],  // Single recipient for node→KDC
       protected_headers={...}
     )
  3. jws = sign_jws(
       payload=base64url(jwe_object),
       private_key=node_privkey,
       headers={alg: "ES256", kid: "node_keyid", ...}
     )
  4. send(jws) to KDC

KDC:
  1. jws_parsed = parse_jws(received_message)
  2. verify_jws_signature(jws_parsed, node_pubkey)  // Cheap
  3. jwe_object = decode(jws_parsed.payload)
  4. plaintext = decrypt_jwe(jwe_object, kdc_privkey)  // Expensive
  5. process(plaintext, node_id)
```

## Trade-offs and Considerations

### Advantages
✅ **Standardization** - RFC 7515, 7516 (mature, widely supported)
✅ **Multi-recipient** - Single distribution for multiple nodes
✅ **Authentication** - Signed and encrypted, metadata protected
✅ **Language support** - Leverages standard library implementations
✅ **Interoperability** - C/C++, Python, JavaScript, Go, Rust, etc.
✅ **Future-proof** - Path to HPKE standardization in JOSE
✅ **Performance** - Multi-recipient reduces encryption overhead

### Disadvantages/Considerations
⚠️ **Message size** - JSON Serialization more verbose than compact form
⚠️ **Processing complexity** - Slightly more complex than custom wrapper
⚠️ **HPKE interim** - Stays with custom wrapper during transition
⚠️ **Library dependencies** - Requires JOSE library (already using for JOSE backend)

### Performance Analysis
- **Single recipient**: ~5-10% larger message than compact form (acceptable for gained multi-recipient)
- **Multi-recipient break-even**: At ~3 recipients, more efficient than 3 separate distributions
- **Verification cost**: Signature verification negligible vs. decryption

## Implementation Phases

### Phase 1: Design and Library Integration (Current)
- ✅ Finalize JWE/JWS design (this document)
- ✅ Verify library support for JWE JSON Serialization
- ✅ Prototype multi-recipient JOSE encryption

### Phase 2: Core Implementation
- [ ] Implement JWE/JWS envelope functions in tnm package
- [ ] Update EncryptAndEncodeV2 for JOSE to use JWE/JWS
- [ ] Update DecodeAndDecryptV2 for JOSE to parse JWE/JWS
- [ ] Keep HPKE on custom wrapper (unchanged)
- [ ] Add multi-recipient recipient list parameter

### Phase 3: Integration
- [ ] Update KDC distribution creation to support multi-recipient
- [ ] Update KRS CHUNK handler to parse JWE/JWS
- [ ] Update enrollment blob generation
- [ ] Update bootstrap blob generation

### Phase 4: Testing
- [ ] Unit tests for JWE/JWS encoding/decoding
- [ ] Multi-recipient decryption tests
- [ ] Signature verification tests
- [ ] Backward compatibility tests (V1 unchanged)
- [ ] Integration tests (KDC → multiple KRS nodes)

### Phase 5: Documentation and Rollout
- [ ] Update API documentation
- [ ] Create migration guide
- [ ] Add examples for custom header usage

## Open Questions for Implementation

1. **JWE Key Algorithm**: Use ECDH-ES+A256KW (standard) or ECDH-ES (direct)?
   - Current: ECDH-ES+A256KW (more standard, slightly more overhead)

2. **Protected vs Unprotected Headers**: All in protected (our choice) or split?
   - Current: All in protected (authenticated + integrity)

3. **Custom Header Namespace**: Use standard "x_" prefix or TDNS-specific?
   - Recommendation: Use "tdns_" prefix for clarity

4. **Key ID (kid) Header**: Include in JWS headers for key identification?
   - Recommendation: Yes, include KDC and node key IDs

5. **Content Type**: Standard "application/jose+json" or custom?
   - Recommendation: Standard JOSE type with "typ: tdns-distribution"

## References

- RFC 7515: JSON Web Signature (JWS)
- RFC 7516: JSON Web Encryption (JWE)
- RFC 7518: JSON Web Algorithms (JWA)
- RFC 9180: Hybrid Public Key Encryption
- draft-ietf-jose-hpke: HPKE in JOSE (informational only; our implementation is independent)

## Appendix: Example JWE/JWS Structure

### Complete Example Message

```
eyJhbGciOiJFUzI1NiIsImtpZCI6ImtkY19hMWIyYzNkNCIsInR5cCI6Impvc2Urand
zIn0.
eyJwcm90ZWN0ZWQiOiJleUpzYjI5MGQybHVaeUk2SWpRM01qSTBPREExTVRndWFBQiI
sImNpcGhlcnRleHQiOiJuQkhtUDh3REZaVHNEaTRXa3AxM0IiLCJpdiI6IjlVMDAxLXQ
xTVEtUllERDhxIiwidGFnIjoiZTQyZWY0ZTM4ODJhNjdiNiIsInJlY2lwaWVudHMiOlt
dfQ.
<base64url(signature)>
```

### Decoded Protected Headers

```json
{
  "alg": "ECDH-ES+A256KW",
  "enc": "A256GCM",
  "typ": "tdns-distribution",
  "distribution_id": "d5a7e8b4-1234-5678-abcd-ef1234567890",
  "content_type": "key_operations",
  "timestamp": "2025-01-25T10:30:45Z",
  "crypto_backend": "jose",
  "distribution_ttl": "5m",
  "sender": "kdc.example.com.",
  "recipients_count": 3
}
```

### Decoded JWE JSON (inner structure)

```json
{
  "protected": "eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJ0eXAiOiJ0ZG5zLWRpc3RyaWJ1dGlvbiIsImRpc3RyaWJ1dGlvbl9pZCI6ImQ1YTdlOGI0LTEyMzQtNTY3OC1hYmNkLWVmMTIzNDU2Nzg5MCIsImNvbnRlbnRfdHlwZSI6ImtleV9vcGVyYXRpb25zIiwidGltZXN0YW1wIjoiMjAyNS0wMS0yNVQxMDozMDo0NVoiLCJjcnlwdG9fYmFja2VuZCI6Impvc2UiLCJkaXN0cmlidXRpb25fdHRsIjoiNW0iLCJzZW5kZXIiOiJrZGMuZXhhbXBsZS5jb20uIiwicmVjaXBpZW50c19jb3VudCI6M30",
  "ciphertext": "nBHmP8wDFZTsDi4Wkp13B",
  "iv": "9U001-tMQ-RYDD8q",
  "tag": "e42ef4e3882a67b6",
  "recipients": [
    {
      "header": {
        "kid": "node1_keyid",
        "epk": {...ephemeral_public_key_for_node1...}
      },
      "encrypted_key": "encrypted_cek_for_node1"
    },
    {
      "header": {
        "kid": "node2_keyid",
        "epk": {...ephemeral_public_key_for_node2...}
      },
      "encrypted_key": "encrypted_cek_for_node2"
    },
    {
      "header": {
        "kid": "node3_keyid",
        "epk": {...ephemeral_public_key_for_node3...}
      },
      "encrypted_key": "encrypted_cek_for_node3"
    }
  ]
}
```

---

**Document Status**: Ready for implementation planning
**Next Step**: Discuss Project 2 before finalizing implementation plan
