/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Backend registry for crypto abstraction layer
 */

package crypto

import (
	"fmt"
	"sort"
	"sync"
)

var (
	backends = make(map[string]Backend)
	mu       sync.RWMutex
)

// RegisterBackend registers a crypto backend
// This is typically called from init() functions in backend packages
func RegisterBackend(backend Backend) {
	mu.Lock()
	defer mu.Unlock()

	name := backend.Name()
	if _, exists := backends[name]; exists {
		panic(fmt.Sprintf("crypto backend %q already registered", name))
	}

	backends[name] = backend
}

// GetBackend retrieves a backend by name
// Returns ErrUnsupportedBackend if the backend is not registered
func GetBackend(name string) (Backend, error) {
	mu.RLock()
	defer mu.RUnlock()

	backend, exists := backends[name]
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedBackend, name)
	}

	return backend, nil
}

// ListBackends returns all registered backend names in sorted order
func ListBackends() []string {
	mu.RLock()
	defer mu.RUnlock()

	names := make([]string, 0, len(backends))
	for name := range backends {
		names = append(names, name)
	}

	sort.Strings(names)
	return names
}

// IsBackendRegistered checks if a backend is registered
func IsBackendRegistered(name string) bool {
	mu.RLock()
	defer mu.RUnlock()

	_, exists := backends[name]
	return exists
}
