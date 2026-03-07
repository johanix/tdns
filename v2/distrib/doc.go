// Package distrib provides a generic CHUNK-based distribution framework
// for reliable delivery over DNS.
//
// This package implements the core infrastructure for distributing encrypted
// payloads via DNS CHUNK records, including:
//
//   - Distribution lifecycle management (pending, confirmed, failed, expired)
//   - JWS(JWE()) transport encoding/decoding
//   - CHUNK manifest creation and parsing (JSON and JWT formats)
//   - Confirmation protocol handling
//   - Persistence interfaces for distribution tracking
//
// # Distribution Pattern
//
// The distribution pattern applies to any reliable delivery over DNS:
//
//  1. Sender creates distribution record (pending state)
//  2. Sender sends CHUNK records via DNS
//  3. Sender sends NOTIFY to receiver
//  4. Receiver fetches CHUNKs
//  5. Receiver processes payload
//  6. Receiver sends confirmation NOTIFY
//  7. Sender marks distribution confirmed
//
// # Use Cases
//
//   - KDC → KRS (key distribution)
//   - Agent A → Agent B (zone sync via HSYNC)
//   - Future: Any reliable delivery over DNS
//
// # Package Organization
//
//   - types.go: Core types (OperationEntry, DistributionMetadata, etc.)
//   - transport.go: JWS(JWE()) encoding/decoding functions
//   - manifest.go: CHUNK manifest operations (JSON format)
//   - manifest_jwt.go: JWT manifest format (standards-compliant)
//   - tracker.go: DistributionTracker interface
//   - confirmation.go: Confirmation protocol helpers
//   - persistence.go: DistributionStore interface and SQL schema
package distrib
