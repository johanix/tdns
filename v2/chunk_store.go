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
)

// ChunkPayloadStore stores payloads keyed by NOTIFY qname for query-mode CHUNK.
// Agent: Set before sending NOTIFY; CHUNK query handler Get() returns payload.
// Entries expire after TTL to avoid unbounded growth.
// Format is stored alongside payload (FormatJSON=1, FormatJWT=2).
type ChunkPayloadStore interface {
	Get(qname string) (payload []byte, format uint8, ok bool)
	Set(qname string, payload []byte, format uint8)
}

type chunkPayloadEntry struct {
	payload []byte
	format  uint8
	expires time.Time
}

// MemChunkPayloadStore is an in-memory store with TTL.
type MemChunkPayloadStore struct {
	mu      sync.RWMutex
	entries map[string]*chunkPayloadEntry
	ttl     time.Duration
}

// NewMemChunkPayloadStore creates a store with the given TTL (e.g. 5*time.Minute).
func NewMemChunkPayloadStore(ttl time.Duration) *MemChunkPayloadStore {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &MemChunkPayloadStore{
		entries: make(map[string]*chunkPayloadEntry),
		ttl:     ttl,
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
	s.entries[qname] = &chunkPayloadEntry{
		payload: append([]byte(nil), payload...),
		format:  format,
		expires: time.Now().Add(s.ttl),
	}
}
