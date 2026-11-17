/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package core

import "testing"

// UpdateIf stores what its callback returns only when the callback says so,
// and never creates a key.
func TestConcurrentMapUpdateIf(t *testing.T) {
	m := NewCmap[int]()
	called := false
	if m.UpdateIf("absent", func(v int) (int, bool) { called = true; return v + 1, true }) || called || m.Has("absent") {
		t.Errorf("absent key: stored %v, callback called %v", m.Has("absent"), called)
	}
	m.Set("k", 1)
	if m.UpdateIf("k", func(v int) (int, bool) { return v + 1, false }) {
		t.Error("callback declined, UpdateIf reported a store")
	}
	if v, _ := m.Get("k"); v != 1 {
		t.Errorf("callback declined, value %d, want 1", v)
	}
	if !m.UpdateIf("k", func(v int) (int, bool) { return v + 1, true }) {
		t.Error("callback accepted, UpdateIf reported no store")
	}
	if v, _ := m.Get("k"); v != 2 {
		t.Errorf("callback accepted, value %d, want 2", v)
	}
}
