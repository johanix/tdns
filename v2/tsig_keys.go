/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"encoding/base64"
	"fmt"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// TsigKeyStore is the auth-server TSIG secret store, keyed by key NAME (the NSD
// `key:` model — one secret per name). It is the single secret source for
// signing outbound and verifying inbound replication messages. Loaded from the
// keys: config block at startup (LoadTsigKeys) and, later, upserted by the
// dynamic-zone API. It replaces Globals.TsigKeys on the auth replication path;
// Globals.TsigKeys remains only for the CLI/reporter client path.
type TsigKeyStore struct {
	mu   sync.RWMutex
	keys map[string]TsigDetails // name -> {Name, Algorithm, Secret}
}

func NewTsigKeyStore() *TsigKeyStore {
	return &TsigKeyStore{keys: make(map[string]TsigDetails)}
}

// Get returns the key for name. NOKEY, the empty string, and unknown names all
// return (zero, false). Nil-receiver safe.
func (s *TsigKeyStore) Get(name string) (TsigDetails, bool) {
	if s == nil || name == "" || name == NOKEY {
		return TsigDetails{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.keys[dns.CanonicalName(name)]
	return d, ok
}

// Has reports whether a (non-NOKEY) key name is defined.
func (s *TsigKeyStore) Has(name string) bool {
	_, ok := s.Get(name)
	return ok
}

// Add upserts a key by name (used by the dynamic-zone API).
func (s *TsigKeyStore) Add(d TsigDetails) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[dns.CanonicalName(d.Name)] = d // canonical (lowercase FQDN) key, matches the wire name
}

// Names returns the set of defined key names (used to re-point the catalog
// config-check off Globals.TsigKeys).
func (s *TsigKeyStore) Names() map[string]bool {
	out := map[string]bool{}
	if s == nil {
		return out
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for n := range s.keys {
		out[n] = true
	}
	return out
}

// LoadTsigKeys (re)builds conf.Internal.TsigKeyStore from the keys: block. NOKEY
// is reserved — a keys.tsig[] entry named NOKEY (any case) is an error, because
// the sentinel must stay unambiguous — and every entry must be complete. Bad
// entries are skipped (resilient-config rule: a single bad key does not abort
// startup; zones referencing the skipped name are quarantined at parse), and the
// first error is returned for loud logging. A missing keys: block is not an error.
func (conf *Config) LoadTsigKeys() error {
	store := NewTsigKeyStore()
	var firstErr error
	for _, t := range conf.Keys.Tsig {
		if strings.EqualFold(t.Name, NOKEY) || strings.EqualFold(t.Name, BLOCKED) {
			if firstErr == nil {
				firstErr = fmt.Errorf("keys.tsig: %q is a reserved sentinel (NOKEY/BLOCKED) and cannot be a key name", t.Name)
			}
			continue
		}
		if t.Name == "" || t.Algorithm == "" || t.Secret == "" {
			if firstErr == nil {
				firstErr = fmt.Errorf("keys.tsig: entry %q is incomplete (name, algorithm and secret are all required)", t.Name)
			}
			continue
		}
		store.Add(t)
	}
	conf.Internal.TsigKeyStore = store
	return firstErr
}

// tsigKeyDefined reports whether a primary/notify/ACL key name is acceptable:
// NOKEY (no TSIG) or a name defined in the keys: store.
func (conf *Config) tsigKeyDefined(name string) bool {
	return name == NOKEY || conf.Internal.TsigKeyStore.Has(name)
}

// knownTsigAlgo reports whether algo names a supported HMAC TSIG algorithm
// (canonical compare, so "hmac-sha256" and "hmac-sha256." both match).
func knownTsigAlgo(algo string) bool {
	switch dns.CanonicalName(algo) {
	case dns.HmacSHA1, dns.HmacSHA224, dns.HmacSHA256, dns.HmacSHA384, dns.HmacSHA512:
		return true
	}
	return false
}

// validateTsigKeySpec checks an inline (API-supplied) TSIG key before it enters
// the store: a complete, non-reserved name, a supported algorithm, and a base64
// secret. Used by the dynamic-zone add/modify path and the dynamic-config reload.
func validateTsigKeySpec(name, algo, secret string) error {
	if name == "" || secret == "" {
		return fmt.Errorf("tsig key requires both a name and a secret")
	}
	if strings.EqualFold(name, NOKEY) || strings.EqualFold(name, BLOCKED) {
		return fmt.Errorf("tsig key name %q is a reserved sentinel (NOKEY/BLOCKED)", name)
	}
	if !knownTsigAlgo(algo) {
		return fmt.Errorf("tsig algorithm %q for key %q is not a supported HMAC algorithm", algo, name)
	}
	if _, err := base64.StdEncoding.DecodeString(secret); err != nil {
		return fmt.Errorf("tsig secret for key %q is not valid base64: %w", name, err)
	}
	return nil
}
