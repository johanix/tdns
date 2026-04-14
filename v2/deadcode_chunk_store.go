/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Chunk payload store for query-mode CHUNK: agent stores payload by qname,
 * combiner fetches via CHUNK query. Used when chunk_mode is "query".
 */

package tdns

import (
	"sync"
	"time"

	"github.com/johanix/tdns/v2/core"
)

// ChunkPayloadStore stores payloads keyed by NOTIFY qname for query-mode CHUNK.
// Agent: Set before sending NOTIFY; CHUNK query handler Get() returns payload.
// Entries expire after TTL to avoid unbounded growth.
// Format is stored alongside payload (FormatJSON=1, FormatJWT=2).
type ChunkPayloadStore interface {
	Get(qname string) (payload []byte, format uint8, ok bool)
	Set(qname string, payload []byte, format uint8)
	GetChunk(qname string, sequence uint16) (chunk *core.CHUNK, ok bool)
	SetChunks(qname string, chunks []*core.CHUNK)
}

type chunkPayloadEntry struct {
	payload []byte
	format  uint8
	expires time.Time
}

type chunkArrayEntry struct {
	chunks  []*core.CHUNK
	expires time.Time
}

const chunkStoreMaxEntries = 10000

// MemChunkPayloadStore is an in-memory store with TTL.
type MemChunkPayloadStore struct {
	mu          sync.RWMutex
	entries     map[string]*chunkPayloadEntry
	chunkArrays map[string]*chunkArrayEntry
	ttl         time.Duration
}

// NewMemChunkPayloadStore creates a store with the given TTL (e.g. 5*time.Minute).
func NewMemChunkPayloadStore(ttl time.Duration) *MemChunkPayloadStore {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &MemChunkPayloadStore{
		entries:     make(map[string]*chunkPayloadEntry),
		chunkArrays: make(map[string]*chunkArrayEntry),
		ttl:         ttl,
	}
}

func (s *MemChunkPayloadStore) Get(qname string) ([]byte, uint8, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[qname]
	if !ok || e == nil {
		return nil, 0, false
	}
	if time.Now().After(e.expires) {
		delete(s.entries, qname)
		return nil, 0, false
	}
	// Return a copy so caller cannot mutate
	out := make([]byte, len(e.payload))
	copy(out, e.payload)
	return out, e.format, true
}

func (s *MemChunkPayloadStore) Set(qname string, payload []byte, format uint8) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Evict oldest entry if at capacity (and this is a new key)
	if _, exists := s.entries[qname]; !exists && len(s.entries) >= chunkStoreMaxEntries {
		s.evictOldestEntry()
	}

	s.entries[qname] = &chunkPayloadEntry{
		payload: append([]byte(nil), payload...),
		format:  format,
		expires: time.Now().Add(s.ttl),
	}
}

// evictOldestEntry removes the entry with the earliest expiration time.
// Must be called with mu held.
func (s *MemChunkPayloadStore) evictOldestEntry() {
	var oldestKey string
	var oldestTime time.Time
	first := true
	for k, e := range s.entries {
		if first || e.expires.Before(oldestTime) {
			oldestKey = k
			oldestTime = e.expires
			first = false
		}
	}
	if !first {
		delete(s.entries, oldestKey)
	}
}

// SetChunks stores a chunk array (manifest + data chunks) under the given qname.
// The chunks are deep-copied to prevent mutation by the caller.
func (s *MemChunkPayloadStore) SetChunks(qname string, chunks []*core.CHUNK) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Evict oldest chunk array if at capacity (and this is a new key)
	if _, exists := s.chunkArrays[qname]; !exists && len(s.chunkArrays) >= chunkStoreMaxEntries {
		s.evictOldestChunkArray()
	}

	// Deep copy all chunks
	copied := make([]*core.CHUNK, len(chunks))
	for i, c := range chunks {
		cp := *c
		cp.Data = append([]byte(nil), c.Data...)
		if c.HMAC != nil {
			cp.HMAC = append([]byte(nil), c.HMAC...)
		}
		copied[i] = &cp
	}

	s.chunkArrays[qname] = &chunkArrayEntry{
		chunks:  copied,
		expires: time.Now().Add(s.ttl),
	}
}

// GetChunk returns a specific chunk by sequence number from a stored chunk array.
// Sequence 0 = manifest, 1..N = data chunks. The index into the array equals the sequence number.
func (s *MemChunkPayloadStore) GetChunk(qname string, sequence uint16) (*core.CHUNK, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.chunkArrays[qname]
	if !ok || e == nil {
		return nil, false
	}
	if time.Now().After(e.expires) {
		delete(s.chunkArrays, qname)
		return nil, false
	}
	if int(sequence) >= len(e.chunks) {
		return nil, false
	}

	// Return a copy
	c := e.chunks[sequence]
	cp := *c
	cp.Data = append([]byte(nil), c.Data...)
	if c.HMAC != nil {
		cp.HMAC = append([]byte(nil), c.HMAC...)
	}
	return &cp, true
}

// evictOldestChunkArray removes the chunk array with the earliest expiration time.
// Must be called with mu held.
func (s *MemChunkPayloadStore) evictOldestChunkArray() {
	var oldestKey string
	var oldestTime time.Time
	first := true
	for k, e := range s.chunkArrays {
		if first || e.expires.Before(oldestTime) {
			oldestKey = k
			oldestTime = e.expires
			first = false
		}
	}
	if !first {
		delete(s.chunkArrays, oldestKey)
	}
}
