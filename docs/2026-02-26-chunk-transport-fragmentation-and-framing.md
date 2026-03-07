# CHUNK Transport: Fragmentation + ChunkOption Framing

Date: 2026-02-26
Linear issues: DNS-120 (EDNS(0) framing), DNS-121 (Sequence/Total), DNS-122 (HMAC coverage)

Two related tasks:
- **Part A**: Consistent use of `ChunkOption` for EDNS(0) payloads (no more raw bytes)
- **Part B**: CHUNK fragmentation + reassembly in agent transport (migrate from KDC-only)

Part A is a prerequisite for Part B — once EDNS(0) payloads carry a Format byte,
the receiver can distinguish inline-small from manifest-only NOTIFYs.

---

## Part A: Migrate EDNS(0) to ChunkOption framing

### Problem

The EDNS(0) `ChunkOption` struct (`edns0/edns0_chunk.go:30-36`) defines a proper
wire format: `Format(uint8) + HMACLen(uint16) + HMAC(variable) + DataLength(uint16) + Data(variable)`.
Functions `CreateChunkOption()` (line 81) and `ParseChunkOption()` (line 192) implement
Pack/Unpack. But the agent transport bypasses them entirely — it puts raw payload
bytes directly into `EDNS0_LOCAL.Data`.

### Goal

Every EDNS(0) option with code `EDNS0_CHUNK_OPTION_CODE` (65004) must use
`CreateChunkOption()` on the sender side and `ParseChunkOption()` on the receiver side.
This gives us:
- A Format byte so the receiver knows JSON vs JWT without guessing
- Room for HMAC if we ever want it on the inline path
- Consistent framing across all code paths

### Writer sites to update (5 total)

All in `tdns/v2/agent/transport/`:

| # | File | Function | Lines | Current code |
|---|------|----------|-------|-------------|
| W1 | `dns.go` | `sendNotifyWithPayload` | 763-766 | `EDNS0_LOCAL{Code: ..., Data: finalPayload}` |
| W2 | `dns.go` | `Ping` (edns0 mode) | 475-478 | Same pattern |
| W3 | `dns.go` | `Confirm` | 705-709 | Same pattern |
| W4 | `handlers.go` | `sendChunkResponse` | 537-542 | `EDNS0_LOCAL{Code: 65004, Data: payload}` |
| W5 | `chunk_notify_handler.go` | `sendConfirmResponse` | 294-297 | `EDNS0_LOCAL{Code: ..., Data: payloadBytes}` |

**Change for each**: Replace `&dns.EDNS0_LOCAL{Code: edns0.EDNS0_CHUNK_OPTION_CODE, Data: payload}`
with `edns0.CreateChunkOption(payloadFormat, nil, payload)`.

The `payloadFormat` is already available at each site:
- W1: `payloadFormat` variable exists (set to `core.FormatJSON` or `core.FormatJWT` after encryption)
- W2: Same — `payloadFormat` is computed in the Ping function
- W3: Confirm payloads are always JSON → `core.FormatJSON`
- W4: The `sendChunkResponse` function receives `payload []byte` — add a `format uint8` parameter, callers pass `core.FormatJSON`
- W5: Confirm response is always JSON → `core.FormatJSON`

Note W4 also uses a hardcoded `65004` instead of the constant — fix that too.

### Reader sites to update (5 total)

| # | File | Function | Lines | Current code |
|---|------|----------|-------|-------------|
| R1 | `chunk_notify_handler.go` | `extractChunkPayload` | 135-140 | `return localOpt.Data` (raw bytes) |
| R2 | `handler.go` | `extractChunkPayload` | 141-145 | Same pattern |
| R3 | `dns.go` | `extractPingConfirmFromResponse` | 538-549 | `json.Unmarshal(local.Data, &confirm)` |
| R4 | `dns.go` | `extractKeystateConfirmFromResponse` | 620-630 | Same pattern |
| R5 | `dns.go` | `extractConfirmFromResponse` | 867-873 | Same pattern |

**Change for each**: Replace direct `localOpt.Data` access with:
```go
chunkOpt, err := edns0.ParseChunkOption(localOpt)
if err != nil {
    return ..., fmt.Errorf("invalid CHUNK option: %w", err)
}
// Use chunkOpt.Data (the actual payload) and chunkOpt.Format
```

For R1 and R2: return `chunkOpt.Data` and `chunkOpt.Format` — update the function
signatures to return `([]byte, uint8, error)` so callers have the Format byte.

For R3-R5: call `ParseChunkOption` first, then `json.Unmarshal(chunkOpt.Data, ...)`.

### Return type change for extractChunkPayload

Both `extractChunkPayload` functions (R1, R2) currently return `([]byte, error)`.
Change to `([]byte, uint8, error)` where `uint8` is the format. Update all callers
to accept and (for now) ignore the format byte. This is needed for Part B where
the receiver checks format to decide if payload is a manifest.

### Existing helper

`edns0.ExtractChunkOption(opt *dns.OPT) (*ChunkOption, bool)` at `edns0_chunk.go:314-333`
already wraps `ParseChunkOption` with iteration over OPT options. Consider using this
where we currently iterate manually (R3-R5 all have a manual loop).

### Build verification

```bash
cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make
```

All changes are in `tdns/v2/agent/transport/` (3 files) + possibly signature changes
that propagate to callers in `tdns/v2/`. No cross-repo impact.

---

## Part B: CHUNK fragmentation + reassembly in agent transport

### Problem

The agent transport currently stores and fetches a single opaque blob per qname
(query mode) or sends it inline (edns0 mode). There is no fragmentation: if the
payload exceeds ~64 KB (DNS message limit), it fails. The KDC/KRS already has
working fragmentation with sequence-numbered qnames, but the agent transport
does not.

### Available building blocks

Already implemented in `tdns/v2/distrib/manifest.go`:
- `SplitIntoCHUNKs(data, chunkSize, format) []*core.CHUNK` (line 179)
- `ReassembleCHUNKs(chunks []*core.CHUNK) ([]byte, error)` (line 237)
- `PrepareDistributionChunks(payload, contentType, distID, receiverID, hmacKey, chunkSize, extraMetadata) ([]*core.CHUNK, error)` (line 300)

Already implemented in `tdns/v2/core/chunk_utilities.go`:
- `CreateCHUNKManifest(manifestData, format) (*core.CHUNK, error)` (line 38)
- `ExtractManifestData(chunk *core.CHUNK) (*ManifestData, error)` (line 76)
- `CalculateCHUNKHMAC` / `VerifyCHUNKHMAC` (lines 124, 167)

KDC reference patterns:
- Sequence-numbered qnames: `fmt.Sprintf("%d.%s", sequence, baseQname)` (KRS `chunk.go:70`)
- Chunk ID parsing from first label: `strconv.ParseUint(labels[0], 10, 16)` (KDC `dns_handler.go:181`)
- Fetch loop: `for i := 1; i <= manifestData.ChunkCount; i++` (KRS `chunk.go:466-473`)
- Chunk array indexed by ID: `prepared.chunks[chunkID]` (KDC `chunks.go:425`)

### Step B1: Upgrade ChunkPayloadStore to support chunk arrays

**File**: `tdns/v2/chunk_store.go`

Current interface:
```go
type ChunkPayloadStore interface {
    Get(qname string) (payload []byte, format uint8, ok bool)
    Set(qname string, payload []byte, format uint8)
}
```

New interface:
```go
type ChunkPayloadStore interface {
    // Get returns a single stored payload (for inline/edns0 small payloads)
    Get(qname string) (payload []byte, format uint8, ok bool)
    // Set stores a single payload blob
    Set(qname string, payload []byte, format uint8)

    // GetChunk returns a specific chunk by sequence number (0=manifest, 1..N=data)
    GetChunk(qname string, sequence uint16) (chunk *core.CHUNK, ok bool)
    // SetChunks stores a complete chunk set (manifest at index 0, data chunks follow)
    SetChunks(qname string, chunks []*core.CHUNK)
}
```

Update `MemChunkPayloadStore` to add a second map:
```go
type MemChunkPayloadStore struct {
    mu      sync.RWMutex
    entries map[string]*chunkPayloadEntry     // single-blob entries (backward compat)
    chunks  map[string]*chunkArrayEntry       // chunk array entries (fragmented)
    ttl     time.Duration
}

type chunkArrayEntry struct {
    chunks  []*core.CHUNK  // index 0 = manifest, 1..N = data chunks
    expires time.Time
}
```

`GetChunk(qname, seq)` looks up `chunks[qname]` then returns `entry.chunks[seq]`.
`SetChunks(qname, chunks)` stores the array with TTL.

### Step B2: Sender-side fragmentation (query mode)

**File**: `tdns/v2/agent/transport/dns.go`

Current flow in `sendNotifyWithPayload` (line 744-748):
```go
useQueryMode := t.chunkMode == "query" && t.chunkSet != nil
if useQueryMode {
    chunkQueryQname := buildChunkQueryQname(peer.ID, distributionID, t.ControlZone)
    t.chunkSet(chunkQueryQname, finalPayload, payloadFormat)
}
```

New flow — add a size threshold (e.g. 60000 bytes):
```go
useQueryMode := t.chunkMode == "query" && t.chunkSet != nil
if useQueryMode {
    baseQname := buildChunkQueryQname(peer.ID, distributionID, t.ControlZone)
    if len(finalPayload) <= chunkInlineThreshold {
        // Small payload: store as single blob (current behavior)
        t.chunkSet(baseQname, finalPayload, payloadFormat)
    } else {
        // Large payload: fragment into CHUNK array
        allChunks, err := distrib.PrepareDistributionChunks(
            finalPayload, req.MessageType, distributionID,
            peer.ID, nil, 0, nil)
        if err != nil { return ..., err }
        t.chunkSetChunks(baseQname, allChunks)
    }
}
```

Add `chunkSetChunks func(qname string, chunks []*core.CHUNK)` to `DNSTransport` struct
alongside the existing `chunkSet`. Wire it up from `ChunkPayloadStore.SetChunks` in
`hsync_transport.go:199-202`.

For edns0 mode: if payload exceeds ~60000 bytes, fall back to query mode
automatically (store chunks, send NOTIFY without inline payload). This requires
the receiver to handle both modes regardless of its config, which is already the
case — `fetchChunkViaQuery` is called whenever EDNS(0) has no payload.

### Step B3: Add sequence number to buildChunkQueryQname

**File**: `tdns/v2/agent/transport/dns.go` (line 189-193)

Current:
```go
func buildChunkQueryQname(receiverID, distID, senderID string) string {
    r := strings.TrimSuffix(dns.Fqdn(receiverID), ".")
    s := strings.TrimSuffix(dns.Fqdn(senderID), ".")
    return dns.Fqdn(r + "." + distID + "." + s)
}
```

Add a sibling function (keep the original for the base qname):
```go
func buildChunkQueryQnameWithSeq(sequence uint16, receiverID, distID, senderID string) string {
    base := buildChunkQueryQname(receiverID, distID, senderID)
    return dns.Fqdn(fmt.Sprintf("%d.%s", sequence, strings.TrimSuffix(base, ".")))
}
```

Format: `<sequence>.<receiver>.<distid>.<sender>.`

This matches the KDC pattern at `krs/chunk.go:70`.

### Step B4: Upgrade CHUNK query handler for chunk arrays

**File**: `tdns/v2/chunk_query_handler.go`

Current handler (line 36-83) serves a single CHUNK RR with `Sequence=0, Total=1`.

New logic:
1. Parse the first label of qname as a potential chunk sequence number
2. If it's a number → look up `store.GetChunk(baseQname, sequence)`
3. If it's not a number → look up `store.Get(qname)` (current single-blob path)

```go
func chunkQueryHandler(ctx context.Context, req *DnsQueryRequest, store ChunkPayloadStore) error {
    qname := dns.Fqdn(req.Qname)

    // Try to parse first label as chunk sequence number
    labels := dns.SplitDomainName(qname)
    if len(labels) >= 4 {
        if seq, err := strconv.ParseUint(labels[0], 10, 16); err == nil {
            // Numbered chunk query: strip sequence label to get base qname
            baseQname := dns.Fqdn(strings.Join(labels[1:], "."))
            chunk, ok := store.GetChunk(baseQname, uint16(seq))
            if ok {
                // Serve the specific chunk
                return serveChunkRR(req, qname, chunk)
            }
            // Fall through to single-blob lookup
        }
    }

    // Single-blob lookup (current path)
    payload, format, ok := store.Get(qname)
    if !ok {
        return ErrNotHandled
    }
    chunk := &core.CHUNK{
        Format: format, Sequence: 0, Total: 1,
        DataLength: uint16(len(payload)), Data: payload,
    }
    return serveChunkRR(req, qname, chunk)
}
```

Extract the RR-building + response-writing into a `serveChunkRR` helper.

### Step B5: Receiver-side manifest-first fetch loop

**File**: `tdns/v2/agent/transport/chunk_notify_handler.go`

Current `fetchChunkViaQuery` (line 168-200) does a single CHUNK query and
returns the payload. Replace with a two-phase fetch:

**Phase 1**: Fetch manifest (sequence 0)
```go
manifestQname := buildChunkQueryQnameWithSeq(0, h.LocalID, distributionID, senderID)
manifestChunk, err := fetchSingleChunk(ctx, queryTarget, manifestQname)
```

**Phase 2**: Check if payload is inline or fragmented
```go
manifestData, err := core.ExtractManifestData(manifestChunk)
if manifestData.ChunkCount == 0 {
    // Inline payload — return manifest's Payload field
    return manifestData.Payload, nil
}
```

**Phase 3**: Fetch data chunks 1..N
```go
var dataChunks []*core.CHUNK
for i := uint16(1); i <= manifestData.ChunkCount; i++ {
    chunkQname := buildChunkQueryQnameWithSeq(i, h.LocalID, distributionID, senderID)
    chunk, err := fetchSingleChunk(ctx, queryTarget, chunkQname)
    if err != nil {
        return nil, fmt.Errorf("failed to fetch chunk %d/%d: %w", i, manifestData.ChunkCount, err)
    }
    dataChunks = append(dataChunks, chunk)
}
return distrib.ReassembleCHUNKs(dataChunks)
```

This mirrors the KRS pattern at `krs/chunk.go:462-473`.

Also need a `fetchSingleChunk` helper that returns `*core.CHUNK` instead of
just `[]byte` — either modify `FetchChunkViaQuery` or add a new
`FetchChunkRR(ctx, serverAddr, qname) (*core.CHUNK, error)` to `DNSTransport`.

### Step B6: Backward compatibility for the transition

During the transition, the receiver must handle both:
- **Old format**: Single CHUNK RR with `Sequence=0, Total=1` (current)
- **New format**: Manifest CHUNK RR with `Sequence=0, Total=N` + data chunks

Detection is easy: if `Total == 1` and `Sequence == 0`, it's a single blob.
If `Total > 1` or the Data field parses as a `ManifestData` with `ChunkCount > 0`,
it's a manifest needing multi-chunk fetch.

However, per the "no backwards compatibility" rule — since there is no installed
base, we can skip this and just implement the new format from day one. The
manifest-first approach works fine for single payloads too (just set
`ChunkCount=0` with inline payload). **Decision: go straight to manifest format.**

### Step B7: Update DNSTransport.FetchChunkViaQuery

**File**: `tdns/v2/agent/transport/dns.go` (line 1109-1144)

Current function returns `([]byte, uint8, error)` — it extracts `chunk.Data`
and `chunk.Format` from the first CHUNK RR in the answer.

Add a new `FetchChunkRR` that returns the full `*core.CHUNK`:
```go
func (t *DNSTransport) FetchChunkRR(ctx context.Context, serverAddr, qname string) (*core.CHUNK, error) {
    // Same DNS query logic as FetchChunkViaQuery
    // But return the CHUNK struct instead of just Data
}
```

Keep `FetchChunkViaQuery` as a convenience wrapper for callers that just want bytes.

### Implementation order

```
B1 → B2 → B3 → B4 → B5 → B7
```

All steps can be tested incrementally. B1 is pure data structure, B2-B3 are
sender-side, B4 is the query handler, B5+B7 are receiver-side.

---

## Combined execution order

**Do Part A first** (half day), then Part B (2-3 days):

```
A: ChunkOption framing
  A.1  Update writer sites W1-W5 to use CreateChunkOption()
  A.2  Update reader sites R1-R5 to use ParseChunkOption()
  A.3  Change extractChunkPayload return type to include format
  A.4  Build + verify

B: Fragmentation
  B.1  Upgrade ChunkPayloadStore interface + MemChunkPayloadStore
  B.2  Sender-side: fragment large payloads into chunk arrays
  B.3  Add buildChunkQueryQnameWithSeq()
  B.4  Upgrade chunk query handler for sequence-numbered qnames
  B.5  Receiver-side: manifest-first fetch loop
  B.7  Add FetchChunkRR to DNSTransport
  B.6  Build + verify
```

### Files touched

| File | Part A | Part B |
|------|--------|--------|
| `agent/transport/dns.go` | W1,W2,W3,R3,R4,R5 | B2,B3,B7 |
| `agent/transport/handlers.go` | W4 | — |
| `agent/transport/chunk_notify_handler.go` | W5,R1 | B5 |
| `agent/transport/handler.go` | R2 | — |
| `chunk_store.go` | — | B1 |
| `chunk_query_handler.go` | — | B4 |
| `hsync_transport.go` | — | B2 (wiring) |

### Decision items to confirm before starting

1. **Chunk size default**: 60000 bytes (matches `distrib/manifest.go` default)?
   KDC uses smaller chunks for UDP. Agent transport uses TCP, so 60000 is fine.

2. **Inline threshold**: Store as single blob when payload ≤ 60000 bytes,
   fragment when larger? Or always use manifest format? (Recommend: always
   manifest for consistency, with `ChunkCount=0` and inline `Payload` for small.)

3. **HMAC on manifests**: Skip for now (HMAC key management is not part of
   the agent transport)? Or wire up HMAC using a configured key?
   (Recommend: skip, the JWS(JWE) layer handles integrity.)

4. **edns0 mode large payloads**: Auto-fallback to query mode when payload
   exceeds ~60 KB? Or error out? (Recommend: auto-fallback.)
