# CHUNK Implementation Review

Date: 2026-02-26

Review of the CHUNK RRtype RDATA design, EDNS(0) option implementation,
and JOSE security layer integration.

## Files Reviewed

- `core/rr_chunk.go` — CHUNK RDATA struct, Pack/Unpack, String/Parse
- `core/chunk_utilities.go` — ManifestData, CreateCHUNKManifest, HMAC calculation
- `edns0/edns0_chunk.go` — ChunkOption struct, CreateChunkOption, ParseChunkOption
- `agent/transport/dns.go` — sendNotifyWithPayload, sendPing, EDNS(0) payload handling
- `agent/transport/chunk_notify_handler.go` — extractChunkPayload, receiver side
- `agent/transport/crypto.go` — SecureWrapper.WrapOutgoing (JWE+JWS)

---

## Issue 1: Sequence and Total — partially redundant

### CHUNK RDATA fields (rr_chunk.go:67-75)

```
Format     uint8   — JSON=1, JWT=2
HMACLen    uint16  — 0 for data chunks
HMAC       []byte  — HMAC-SHA256 (manifest only)
Sequence   uint16  — 0=manifest, 1..N=data
Total      uint16  — total chunk count
DataLength uint16  — payload length
Data       []byte  — JSON manifest or chunk payload
```

### Manifest JSON (chunk_utilities.go:20-25)

```go
type ManifestData struct {
    ChunkCount uint16  `json:"chunk_count"`
    ChunkSize  uint16  `json:"chunk_size,omitempty"`
    Metadata   map[string]interface{} `json:"metadata,omitempty"`
    Payload    []byte  `json:"payload,omitempty"`
}
```

At chunk_utilities.go:54: `Total: manifestData.ChunkCount` — they are always equal.

### Analysis

- **Sequence**: Needed. It is the sole ordering mechanism for data chunks.
  The presentation (slide p6) shows chunk numbers prepended to qnames
  (`1.{receiver}.{dist}.{sender}`), but the actual code in
  `buildChunkQueryQname()` (dns.go:189-192) does NOT include the sequence
  number in the qname. So RDATA `Sequence` is the only way to order chunks.

- **Total in data chunks**: Redundant with `chunk_count` in the manifest
  JSON. The receiver always fetches the manifest first (Sequence=0) and
  knows the total from there. Repeating Total in each data chunk costs
  2 bytes per chunk and allows sanity checking but adds no information.

- **Total in manifest RDATA**: Redundant with `chunk_count` in the manifest
  JSON Data field. Same value, stored twice.

### Decision needed

Either:
- (a) Accept the redundancy (it's cheap, allows sanity checks), or
- (b) Remove Total from data chunks (set to 0), rely on manifest for count, or
- (c) Remove `chunk_count` from ManifestData JSON (derive from RDATA Total)

### Presentation vs code mismatch

The presentation shows fragmented query names like:
```
Chunk 1:  1.{receiverID}.{distID}.{senderID}
Chunk 2:  2.{receiverID}.{distID}.{senderID}
```

But the code doesn't prepend chunk numbers to query names. Either:
- The code needs updating to match the design, or
- The presentation should be updated to match the code

This matters because if chunk numbers were in qnames, the RDATA Sequence
field truly would be redundant for the query mode (but still needed for
multi-record RRset responses).

---

## Issue 2: HMAC vs JWS — two separate integrity mechanisms

### HMAC (chunk_utilities.go:124-148)

- Symmetric HMAC-SHA256 over `Format (1 byte) + Data field`
- Only on manifests (Sequence=0)
- Key: caller-provided 32-byte symmetric key
- Stored in CHUNK RDATA fields HMACLen + HMAC
- Used when Format=FormatJSON (1)

### JWS on manifest (distrib/manifest_jwt.go)

- Asymmetric ECDSA P-256 (ES256)
- The entire Data field IS a JWS compact serialization (header.payload.signature)
- When Format=FormatJWT (2), HMACLen=0 and HMAC=nil
- JWS covers JWTManifestClaims JSON

### JWS(JWE) on transport payload (agent/transport/crypto.go:227-263)

- Application JSON → JWE encrypt (ECDH-ES + A256GCM) → JWS sign (ES256)
- JWS covers the JWE ciphertext (not the plaintext)
- Result: `base64(JWS(JWE(plaintext)))`
- Stored in EDNS(0) option Data or CHUNK query answer Data
- Receiver can verify sender identity before decrypting

### Summary table

| Mechanism | Location | Algorithm | Covers | When |
|-----------|----------|-----------|--------|------|
| HMAC | RDATA HMACLen+HMAC | HMAC-SHA256 (symmetric) | Format byte + Data | FormatJSON manifest |
| JWS manifest | RDATA Data field | ES256 (asymmetric) | JWTManifestClaims JSON | FormatJWT manifest |
| JWS(JWE) transport | EDNS(0) or CHUNK Data | ECDH-ES+A256GCM / ES256 | JWE blob | Agent transport |

These three are mutually exclusive per message.

### Issue: HMAC doesn't cover Sequence or Total

The HMAC at chunk_utilities.go:133-136 covers only `Format + Data`.
An attacker could tamper with Sequence or Total without invalidating
the HMAC. For a manifest (Sequence=0), this is low risk since the
receiver checks Sequence==0. But it should be documented explicitly,
and the question is whether HMAC should also cover Sequence and Total.

---

## Issue 3: EDNS(0) option vs CHUNK RDATA — inconsistent framing

### The designed EDNS(0) format (edns0_chunk.go:30-36)

```go
type ChunkOption struct {
    Format     uint8   // Same as CHUNK RDATA
    HMACLen    uint16  // Same as CHUNK RDATA
    HMAC       []byte  // Same as CHUNK RDATA
    DataLength uint16  // Same as CHUNK RDATA
    Data       []byte  // Same as CHUNK RDATA
}
```

This is CHUNK RDATA minus Sequence and Total (since EDNS(0) can't fragment).
Has proper Pack() and ParseChunkOption() methods.

### What the transport actually does (dns.go:763-766)

```go
opt.Option = append(opt.Option, &dns.EDNS0_LOCAL{
    Code: edns0.EDNS0_CHUNK_OPTION_CODE,
    Data: finalPayload,  // Raw JSON or base64(JWS(JWE))
})
```

And the receiver (chunk_notify_handler.go:137-138):

```go
if localOpt.Code == edns0.EDNS0_CHUNK_OPTION_CODE {
    return localOpt.Data, nil  // Raw bytes, no ParseChunkOption()
}
```

### The problem

The main agent-to-agent transport puts **raw payload bytes** directly
in the EDNS(0) option — no Format, no HMACLen, no HMAC, no DataLength
framing. It completely bypasses the `ChunkOption` structure.

The `CreateChunkOption`/`ParseChunkOption` functions are only used by
the KDC/KRS code paths (enrollment confirmations, key status reports).

This means:
1. The EDNS(0) option content is NOT the same as CHUNK RDATA minus
   Sequence/Total. It's just raw payload with no framing at all.
2. The receiver has no Format byte to distinguish JSON from JWT — it
   relies on both sides having the same SecureWrapper configuration.
3. There's no HMAC protection on the EDNS(0) path (HMAC is only
   calculated for CHUNK RR manifests).

### Decision needed

Either:
- (a) Make the transport use `CreateChunkOption()` so EDNS(0) payloads
  have proper framing (Format + HMAC + Data), matching the design, or
- (b) Accept that EDNS(0) inline mode carries raw payload and document
  this as intentional (the JOSE layer provides its own framing/integrity), or
- (c) Unify: the EDNS(0) option should carry exactly the same bytes as
  would appear in a single-chunk CHUNK RDATA (including Sequence=0, Total=1)

---

## Issue 4: DataLength field is redundant

In the wire format, DataLength (uint16) is explicitly encoded before
Data. But since CHUNK RDATA is always the complete RDATA of the record,
the DNS message framing already provides the total RDATA length. Given
the variable-length HMAC field before it, DataLength does help the parser
know where Data ends without relying on the DNS RDLENGTH. So it's a
reasonable belt-and-suspenders choice, but worth noting.

For the EDNS(0) option, the EDNS option length field serves the same
purpose, making DataLength even more redundant there.

---

## Issue 5: Two EDNS(0) option codes

The code uses two option codes:
- `EDNS0_CHUNK_OPTION_CODE` (65004) — carries payload data
- `EDNS0_CHUNK_QUERY_ENDPOINT_CODE` (65005) — carries query endpoint (host:port)

The presentation mentions only the payload option. The query hint option
is mentioned on slide p10 as "Query hint option — Endpoint for CHUNK queries"
but the distinction between two separate option codes is not explicit.

---

## Recommended Actions

1. **Decide on Sequence/Total redundancy** — keep or simplify
2. **Decide on qname chunk numbering** — implement it or remove from presentation
3. **Fix EDNS(0) framing inconsistency** — either use ChunkOption properly
   or document that raw payload is intentional for the transport path
4. **Consider extending HMAC coverage** to include Sequence and Total
5. **Document the three integrity mechanisms** clearly in the design docs
   (HMAC vs JWS-manifest vs JWS(JWE)-transport)
