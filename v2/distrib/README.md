# distrib - CHUNK-based Distribution Framework

Package `distrib` provides a generic CHUNK-based distribution framework for reliable delivery over DNS.

## Overview

This package implements the core infrastructure for distributing encrypted payloads via DNS CHUNK records, including:

- Distribution lifecycle management (pending, confirmed, failed, expired)
- JWS(JWE()) transport encoding/decoding
- CHUNK manifest creation and parsing (JSON and JWT formats)
- Confirmation protocol handling
- Persistence interfaces for distribution tracking

## Distribution Pattern

The distribution pattern applies to any reliable delivery over DNS:

1. Sender creates distribution record (pending state)
2. Sender encrypts and prepares CHUNK records
3. Sender sends NOTIFY to receiver
4. Receiver queries CHUNK manifest
5. Receiver fetches additional chunks (if not inline)
6. Receiver decrypts and processes payload
7. Receiver sends confirmation NOTIFY
8. Sender marks distribution confirmed

## Manifest Formats

### JSON Format (FormatJSON = 1)

The original manifest format using JSON with nested metadata:

```json
{
  "chunk_count": 1,
  "chunk_size": 25000,
  "metadata": {
    "content": "key_operations",
    "distribution_id": "abc123",
    "receiver_id": "node.example.com.",
    "timestamp": 1234567890,
    "crypto": "jose"
  },
  "payload": "base64-encoded-data"  // Only if inline
}
```

JSON manifests use HMAC-SHA256 for integrity protection.

### JWT Format (FormatJWT = 2)

The newer JWT format uses flattened claims and built-in signatures:

```json
{
  "iss": "kdc",
  "sub": "distribution",
  "iat": 1234567890,
  "distribution_id": "abc123",
  "receiver_id": "node.example.com.",
  "content": "key_operations",
  "crypto": "jose",
  "chunk_count": 0,
  "chunk_size": 0,
  "chunk_hash": "sha256:...",
  "payload": "base64-encoded-data"  // Only if inline
}
```

JWT manifests are signed (JWS), providing cryptographic authenticity.

## Inline Payload Optimization

When the payload is small enough to fit within DNS message size limits:
- Payload is included directly in the manifest
- `chunk_count` is set to 0
- Only one DNS query is needed

Thresholds:
- Max payload size for inline: 500 bytes
- Max total manifest size: 1200 bytes

## Usage

### Creating a JSON Manifest

```go
import "github.com/johanix/tdns/v2/distrib"

// Create metadata
metadata := distrib.CreateManifestMetadata(
    "key_operations",
    distributionID,
    receiverID,
    map[string]interface{}{
        "crypto": "jose",
        "key_count": 5,
    },
)

// Create manifest data
manifestData := &distrib.ManifestData{
    ChunkCount: 0,  // Inline payload
    Metadata:   metadata,
    Payload:    encryptedPayload,
}

// Create CHUNK record
chunk, err := distrib.CreateCHUNKManifest(manifestData, core.FormatJSON)

// Calculate HMAC
err = distrib.CalculateCHUNKHMAC(chunk, hmacKey)
```

### Creating a JWT Manifest

```go
import "github.com/johanix/tdns/v2/distrib"

claims := &distrib.JWTManifestClaims{
    Issuer:         "kdc",
    DistributionID: distributionID,
    ReceiverID:     receiverID,
    Content:        "key_operations",
    Crypto:         "jose",
    ChunkCount:     0,
    Payload:        base64.StdEncoding.EncodeToString(encryptedPayload),
}

chunk, err := distrib.CreateJWTManifest(claims, signingKey, backend)
```

### Extracting Manifest Data

```go
// Auto-detect format
if distrib.IsJWTManifest(chunk) {
    jwtData, err := distrib.ExtractJWTManifestData(chunk, verificationKey, backend)
    // Use jwtData.Claims for flattened claims
    // Use jwtData.Payload for decoded inline payload
} else if distrib.IsJSONManifest(chunk) {
    manifestData, err := distrib.ExtractManifestData(chunk)
    // Use manifestData.Metadata for nested metadata
    // Use manifestData.Payload for inline payload
}
```

### Transport Encoding (JWS(JWE()))

```go
// Encrypt and encode for transport
encoded, err := distrib.EncryptSignAndEncode(
    backend,
    recipientPubKey,
    plaintext,
    signingKey,
    metadata,
)

// Decode and decrypt with signature verification
plaintext, err := distrib.DecodeDecryptAndVerify(
    backend,
    privateKey,
    verificationKey,
    encoded,
)
```

## Package Organization

- `types.go` - Core types (OperationEntry, DistributionMetadata, etc.)
- `transport.go` - JWS(JWE()) encoding/decoding functions
- `manifest.go` - CHUNK manifest operations (JSON format)
- `manifest_jwt.go` - JWT manifest format (standards-compliant)
- `confirmation.go` - Confirmation protocol helpers

## Backward Compatibility

The package maintains full backward compatibility:

1. JSON format with HMAC remains the default for unsigned distributions
2. JWT format is used when signing keys are available
3. Receivers auto-detect the format and handle both
4. V1 crypto path (direct HPKE) continues to work unchanged

## Use Cases

- **KDC → KRS**: Key distribution with encrypted DNSSEC keys
- **Agent A → Agent B**: Zone sync via HSYNC
- **Future**: Any reliable delivery over DNS
