# Future KRS-Auth Integration via KeyProvider Interface

## Overview

This document describes the design for integrating KDC-distributed keys with `tdns-auth` (the authoritative nameserver) after the KDC/KRS codebase is migrated to a separate repository. The key requirement is that **distributed keys must never be stored on disk** for security reasons.

## Problem Statement

After migration:
- KDC/KRS will be in a separate repository (`tdns-kms`)
- TDNS will have no knowledge of KDC/KRS
- `tdns-auth` needs access to keys distributed from KDC for on-the-fly signing
- **Security requirement**: Distributed keys must never be persisted to disk
- KRS is a test/debugging tool, not the final destination for keys

## Solution: KeyProvider Interface

TDNS will expose a `KeyProvider` interface that allows external components to provide DNSSEC keys dynamically, without requiring TDNS to know about KDC/KRS.

### Key Principles

1. **No disk storage**: Keys provided via KeyProvider are never written to the database
2. **In-memory only**: Distributed keys are decrypted and cached in memory
3. **Clean separation**: TDNS remains unaware of KDC/KRS implementation details
4. **Hybrid support**: System can use both local DB keys and distributed keys

## KeyProvider Interface Design

### Interface Definition

```go
// In tdns/tdns/keystore.go

// KeyProvider is an interface for external key sources
// Keys provided via this interface are never persisted to disk
type KeyProvider interface {
    // GetKeys returns DNSSEC keys for a zone in a specific state
    // Returns keys that are available in-memory only (never persisted)
    // Returns nil, nil if no keys found (not an error)
    GetKeys(zoneName, state string) (*DnssecKeys, error)
    
    // WatchKeys returns a channel that notifies when keys for a zone change
    // This allows tdns-auth to invalidate caches when new keys arrive
    // Returns nil if watching is not supported
    WatchKeys(zoneName string) (<-chan KeyChangeEvent, error)
    
    // GetKeyInfo returns metadata about available keys (for debugging/listing)
    // Does not include private key material
    GetKeyInfo(zoneName string) ([]KeyInfo, error)
}

type KeyChangeEvent struct {
    ZoneName string
    Action   string // "added", "removed", "updated"
    KeyID    uint16
}

type KeyInfo struct {
    ZoneName  string
    KeyID     uint16
    KeyType   string // "KSK", "ZSK"
    Algorithm uint8
    State     string
    // No private key material in metadata
}

// RegisterKeyProvider registers an external key provider
// If a provider is registered, GetDnssecKeys() will query it first
func (kdb *KeyDB) RegisterKeyProvider(provider KeyProvider) error
```

### Modified GetDnssecKeys() Behavior

```go
func (kdb *KeyDB) GetDnssecKeys(zonename, state string) (*DnssecKeys, error) {
    // 1. If KeyProvider is registered, query it first
    if kdb.keyProvider != nil {
        keys, err := kdb.keyProvider.GetKeys(zonename, state)
        if err == nil && keys != nil && (len(keys.KSKs) > 0 || len(keys.ZSKs) > 0) {
            // Keys found from provider (in-memory, never persisted)
            return keys, nil
        }
        // If provider returns no keys, fall through to database
    }
    
    // 2. Fall back to database (for locally managed keys)
    // ... existing database query logic ...
}
```

## Key Receiver Component Design

### Location

The key receiver component will be in the `tdns-kms` repository, likely as part of the KRS package or a separate `keyreceiver` package.

### Responsibilities

1. **Receive keys from KDC**: Listen for NOTIFY messages and fetch JSONMANIFEST/JSONCHUNK records
2. **Decrypt keys**: Use HPKE to decrypt keys received from KDC
3. **Cache in memory**: Store decrypted keys in memory (never write to disk)
4. **Implement KeyProvider**: Provide keys to TDNS via the KeyProvider interface
5. **Notify on changes**: Emit KeyChangeEvent when keys are added/removed/updated

### Implementation Sketch

```go
// In tdns-kms/krs/keyprovider.go (new)

package krs

import (
    "sync"
    "github.com/johanix/tdns/tdns"  // TDNS as library
)

type KdcKeyProvider struct {
    // In-memory cache of decrypted keys
    // Structure: [zoneName][state] -> *DnssecKeys
    keyCache map[string]map[string]*tdns.DnssecKeys
    
    // Channels for watching key changes
    watchers map[string][]chan tdns.KeyChangeEvent
    
    // KRS database (for metadata only, not private keys)
    krsDB *KrsDB
    
    mutex sync.RWMutex
}

// GetKeys implements KeyProvider interface
func (kp *KdcKeyProvider) GetKeys(zoneName, state string) (*tdns.DnssecKeys, error) {
    kp.mutex.RLock()
    defer kp.mutex.RUnlock()
    
    if zoneKeys, ok := kp.keyCache[zoneName]; ok {
        if keys, ok := zoneKeys[state]; ok {
            return keys, nil
        }
    }
    return nil, nil // No keys found (not an error)
}

// WatchKeys implements KeyProvider interface
func (kp *KdcKeyProvider) WatchKeys(zoneName string) (<-chan tdns.KeyChangeEvent, error) {
    kp.mutex.Lock()
    defer kp.mutex.Unlock()
    
    ch := make(chan tdns.KeyChangeEvent, 10)
    if kp.watchers[zoneName] == nil {
        kp.watchers[zoneName] = []chan tdns.KeyChangeEvent{}
    }
    kp.watchers[zoneName] = append(kp.watchers[zoneName], ch)
    return ch, nil
}

// GetKeyInfo implements KeyProvider interface
func (kp *KdcKeyProvider) GetKeyInfo(zoneName string) ([]tdns.KeyInfo, error) {
    kp.mutex.RLock()
    defer kp.mutex.RUnlock()
    
    var infos []tdns.KeyInfo
    if zoneKeys, ok := kp.keyCache[zoneName]; ok {
        for state, keys := range zoneKeys {
            for _, ksk := range keys.KSKs {
                infos = append(infos, tdns.KeyInfo{
                    ZoneName:  zoneName,
                    KeyID:     ksk.KeyId,
                    KeyType:   "KSK",
                    Algorithm: ksk.Algorithm,
                    State:     state,
                })
            }
            for _, zsk := range keys.ZSKs {
                infos = append(infos, tdns.KeyInfo{
                    ZoneName:  zoneName,
                    KeyID:     zsk.KeyId,
                    KeyType:   "ZSK",
                    Algorithm: zsk.Algorithm,
                    State:     state,
                })
            }
        }
    }
    return infos, nil
}

// OnKeyReceived is called when KRS receives a key from KDC
func (kp *KdcKeyProvider) OnKeyReceived(receivedKey *ReceivedKey) error {
    // Decrypt key in memory (using HPKE with node's private key)
    decryptedKey, err := kp.decryptKey(receivedKey)
    if err != nil {
        return fmt.Errorf("failed to decrypt key: %v", err)
    }
    
    // Convert to DnssecKeys format
    dnssecKeys, err := kp.convertToDnssecKeys(decryptedKey, receivedKey)
    if err != nil {
        return fmt.Errorf("failed to convert key: %v", err)
    }
    
    // Store in memory cache (never write to disk)
    kp.mutex.Lock()
    if kp.keyCache[receivedKey.ZoneName] == nil {
        kp.keyCache[receivedKey.ZoneName] = make(map[string]*tdns.DnssecKeys)
    }
    kp.keyCache[receivedKey.ZoneName][receivedKey.State] = dnssecKeys
    kp.mutex.Unlock()
    
    // Notify watchers
    kp.notifyWatchers(receivedKey.ZoneName, "added", receivedKey.KeyID)
    
    return nil
}

// StartReceiving starts the key receiver (listens for KDC distributions)
func (kp *KdcKeyProvider) StartReceiving(ctx context.Context) error {
    // Implementation would:
    // 1. Listen for NOTIFY messages from KDC
    // 2. Query JSONMANIFEST/JSONCHUNK records
    // 3. Reassemble and decrypt keys
    // 4. Call OnKeyReceived() for each key
    // ... (similar to current KRS implementation)
}
```

## Integration in tdns-auth

### Option 1: Embedded Key Receiver (Recommended)

The key receiver component is embedded in `tdns-auth` and registered at startup:

```go
// In tdns-kms/cmd/tdns-auth/main.go (or similar)

package main

import (
    "context"
    "github.com/johanix/tdns/tdns"        // TDNS as library
    "github.com/johanix/tdns-kms/krs"     // KRS code from new repo
)

func main() {
    // 1. Load configuration
    config := tdns.LoadConfig(...)
    
    // 2. Initialize TDNS as library
    app, err := tdns.New(config)
    if err != nil {
        log.Fatal(err)
    }
    
    // 3. Initialize key receiver component (from tdns-kms)
    krsDB, err := krs.NewKrsDB(krsConf.Database.DSN)
    if err != nil {
        log.Fatal(err)
    }
    
    keyProvider := krs.NewKdcKeyProvider(krsDB, krsConf)
    
    // 4. Register key provider with TDNS
    app.GetKeyDB().RegisterKeyProvider(keyProvider)
    
    // 5. Start key receiver (listens for KDC distributions)
    go keyProvider.StartReceiving(ctx)
    
    // 6. Start TDNS
    ctx := context.Background()
    app.Start(ctx)
}
```

### Option 2: Separate Process (Alternative)

The key receiver runs as a separate process and communicates with `tdns-auth` via a different mechanism (e.g., shared memory, Unix socket). This is more complex but provides better isolation.

## Key Flow

### Distribution Flow

```
KDC → (HPKE encrypted) → Key Receiver → (decrypt in memory) → KeyProvider cache
                                                                    ↓
                                                              tdns-auth queries
                                                                    ↓
                                                              On-the-fly signing
```

### Key Access Flow

```
tdns-auth needs keys for signing
    ↓
GetDnssecKeys(zoneName, "active")
    ↓
Check KeyProvider (if registered)
    ↓
    ├─→ Keys found → Return from memory cache
    └─→ No keys → Fall back to database (local keys)
```

## Security Considerations

### Key Storage

- **Distributed keys**: Never written to disk, only in-memory cache
- **Local keys**: Can still be stored in database (for manually managed zones)
- **Key decryption**: Happens in memory, decrypted keys never persisted

### Key Lifetime

- Keys remain in memory cache until:
  - Replaced by newer keys from KDC
  - Node receives key revocation notification
  - Process restarts (keys must be re-fetched from KDC)

### Cache Invalidation

- When new keys arrive, old keys are replaced in cache
- `WatchKeys()` allows `tdns-auth` to invalidate its internal caches
- No stale keys in memory

## Benefits

1. **Security**: Distributed keys never touch disk
2. **Clean separation**: TDNS doesn't know about KDC/KRS
3. **Flexible**: Supports multiple key sources (local DB + distributed)
4. **Efficient**: Keys cached in memory for fast access
5. **Cache invalidation**: WatchKeys() allows cache updates when keys change
6. **Backward compatible**: Existing local key management continues to work

## Open Questions

1. **Key lifetime**: How long should decrypted keys stay in memory? (until revoked/replaced)
2. **Multiple providers**: Should TDNS support multiple KeyProviders?
3. **Key priority**: If both DB and KeyProvider have keys, which takes precedence?
   - **Proposed**: KeyProvider takes precedence (distributed keys override local)
4. **State management**: How does KeyProvider handle key state transitions?
   - **Proposed**: KeyProvider manages its own state, TDNS just queries for specific states
5. **Key revocation**: How are revoked keys removed from cache?
   - **Proposed**: KDC sends revocation notification, KeyProvider removes from cache
6. **Process restart**: What happens when `tdns-auth` restarts?
   - **Proposed**: KeyProvider must re-fetch keys from KDC (keys not persisted)
7. **Performance**: Is in-memory cache fast enough for high query rates?
   - **Proposed**: Yes, in-memory map lookups are very fast

## Migration Path

### Phase 1: Add KeyProvider Interface to TDNS

1. Define `KeyProvider` interface in `tdns/keystore.go`
2. Add `RegisterKeyProvider()` method to `KeyDB`
3. Modify `GetDnssecKeys()` to check KeyProvider first
4. Add `WatchKeys()` support for cache invalidation
5. Test with a mock KeyProvider implementation

### Phase 2: Implement KeyProvider in tdns-kms

1. Create `KdcKeyProvider` struct in `tdns-kms/krs/`
2. Implement all KeyProvider interface methods
3. Integrate with existing KRS key receiving logic
4. Add in-memory caching
5. Add key change notification mechanism

### Phase 3: Integrate with tdns-auth

1. Update `tdns-auth` initialization to create and register KeyProvider
2. Ensure key receiver starts and listens for KDC distributions
3. Test end-to-end: KDC → Key Receiver → tdns-auth signing
4. Verify keys never touch disk

### Phase 4: Documentation and Testing

1. Document KeyProvider interface usage
2. Add integration tests
3. Performance testing with high query rates
4. Security audit of in-memory key handling

## Dependencies

### TDNS (after migration)

- No dependencies on KDC/KRS
- Exposes KeyProvider interface
- Supports registration of external key providers

### tdns-kms (new repo)

- Depends on `github.com/johanix/tdns` (TDNS as library)
- Implements KeyProvider interface
- Uses existing KRS key receiving logic

## Success Criteria

1. ✅ Distributed keys never written to disk
2. ✅ `tdns-auth` can sign responses using distributed keys
3. ✅ TDNS has no knowledge of KDC/KRS
4. ✅ KeyProvider interface is clean and extensible
5. ✅ System supports both local and distributed keys
6. ✅ Cache invalidation works correctly
7. ✅ Performance is acceptable for production use

---

**Document Version**: 1.0  
**Last Updated**: 2025-12-25  
**Status**: Design Phase  
**Related Documents**: `MIGRATION_PLAN.md`

