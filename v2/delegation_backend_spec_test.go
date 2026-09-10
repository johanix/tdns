/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

// withDelegationBackends installs a delegationbackends list in viper for the
// test, the way the config file would.
func withDelegationBackends(t *testing.T, backends ...map[string]any) {
	t.Helper()
	prev := viper.Get("delegationbackends")
	t.Cleanup(func() { viper.Set("delegationbackends", prev) })
	viper.Set("delegationbackends", backends)
}

func TestResolveDelegationBackendSpec(t *testing.T) {
	confs := []DelegationBackendConf{
		{Name: "frag", Type: "zonefile", Directory: "/tmp/frag"},
		{Name: "reg", Store: "external-db"},
		{Name: "both", Type: "db", Store: "sqlite"},
		{Name: "dir-push", Store: "direct", Writer: "ddns"},
		{Name: "defaults"},
		{Name: "hands-off", Writer: "manual"},
		{Name: "push", Type: "upstream", DDNS: DdnsWriterConf{Key: "agent-to-primary"}},
		{Name: "push-unsigned", Type: "upstream"},
		{Name: "push-lab", Writer: "ddns", DDNS: DdnsWriterConf{AllowInsecure: true}},
		{Name: "nodir", Writer: "zonefile"},
		{Name: "odd", Writer: "carrier-pigeon"},
		{Name: "oldtype", Type: "carrier-pigeon"},
	}
	for _, tc := range []struct {
		name          string
		store, writer string
		err           string
	}{
		{name: "db", store: "sqlite", writer: "none"},
		{name: "direct", store: "direct", writer: "none"},
		{name: "frag", store: "sqlite", writer: "zonefile"},
		{name: "defaults", store: "sqlite", writer: "none"},
		{name: "hands-off", store: "sqlite", writer: "none"},
		{name: "push", store: "sqlite", writer: "ddns"},
		{name: "push-lab", store: "sqlite", writer: "ddns"},
		{name: "push-unsigned", err: "ddns.key"},
		{name: "reg", err: "is not compiled into"},
		{name: "both", err: "cannot be combined"},
		{name: "dir-push", err: "accepts only writer none"},
		{name: "nodir", err: "directory is required"},
		{name: "odd", err: "unknown writer"},
		{name: "oldtype", err: "unknown type"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := resolveDelegationBackendSpec(tc.name, confs)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("want an error containing %q, got %v", tc.err, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if spec.Store != tc.store || spec.Writer != tc.writer {
				t.Fatalf("resolved to (%s, %s), want (%s, %s)", spec.Store, spec.Writer, tc.store, tc.writer)
			}
		})
	}

	if _, err := resolveDelegationBackendSpec("nosuch", confs); !errors.Is(err, errDelegationBackendUnknown) {
		t.Fatalf("an undefined name must resolve to errDelegationBackendUnknown, got %v", err)
	}
}

type fakeDelegationStore struct{ name string }

func (f *fakeDelegationStore) ApplyChildUpdate(string, UpdateRequest) error { return nil }
func (f *fakeDelegationStore) GetDelegationData(string, string) (map[string]map[uint16][]dns.RR, error) {
	return map[string]map[uint16][]dns.RR{}, nil
}
func (f *fakeDelegationStore) ListChildren(string) ([]string, error) { return nil, nil }
func (f *fakeDelegationStore) Name() string                          { return f.name }

var registerFakeStoreOnce sync.Once

// A store registered from outside package tdns -- the external-db module's
// situation -- is resolvable by its config name and is what the composed
// backend is built around.
func TestRegisteredStoreIsResolvedAndBuilt(t *testing.T) {
	registerFakeStoreOnce.Do(func() {
		RegisterDelegationStore("fake-store", func(spec DelegationBackendSpec, _ *KeyDB, _ *ZoneData) (DelegationStore, error) {
			return &fakeDelegationStore{name: "fake:" + spec.Name}, nil
		})
	})
	withDelegationBackends(t, map[string]any{"name": "handoff", "store": "fake-store"})

	b, err := LookupDelegationBackend("handoff", nil, nil)
	if err != nil {
		t.Fatalf("LookupDelegationBackend: %v", err)
	}
	if b.Name() != "handoff" {
		t.Errorf("backend name = %q, want the operator's word", b.Name())
	}
	c, ok := b.(*composedDelegationBackend)
	if !ok {
		t.Fatalf("got %T, want the composed backend", b)
	}
	if c.store.Name() != "fake:handoff" || c.writer != nil {
		t.Fatalf("composed as (%s, %v)", c.store.Name(), c.writer)
	}
	for _, n := range RegisteredDelegationStores() {
		if n == "fake-store" {
			return
		}
	}
	t.Fatal("fake-store is not listed among the registered stores")
}

// type: zonefile composes the sqlite store with the zonefile writer, and
// behaves as the zonefile backend did. The notify-command key is hyphenated,
// which the viper decoder only maps with the mapstructure tag.
func TestLookupComposesTheZonefileTypeName(t *testing.T) {
	dir := t.TempDir()
	withDelegationBackends(t, map[string]any{
		"name": "frag", "type": "zonefile", "directory": dir, "notify-command": "true",
	})
	kdb := newTestKeyDB(t)

	b, err := LookupDelegationBackend("frag", kdb, nil)
	if err != nil {
		t.Fatalf("LookupDelegationBackend: %v", err)
	}
	c := b.(*composedDelegationBackend)
	if c.store.Name() != DelegationStoreSqlite {
		t.Errorf("store = %s, want sqlite", c.store.Name())
	}
	w, ok := c.writer.(*zonefileWriter)
	if !ok {
		t.Fatalf("writer = %T, want the zonefile writer", c.writer)
	}
	if w.notifyCommand != "true" {
		t.Errorf("notify-command did not decode: %q", w.notifyCommand)
	}

	if err := b.ApplyChildUpdate("example.", childUpdate(t, "child.example. 3600 IN NS ns.child.example.")); err != nil {
		t.Fatalf("ApplyChildUpdate: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "child.example.zone")); err != nil {
		t.Fatalf("the fragment was not written: %v", err)
	}
}

// A backend named by the operator whose type is direct is judged as direct by
// the combination rules, not as "some name that is not direct".
func TestValidationJudgesANamedDirectBackendAsDirect(t *testing.T) {
	withDelegationBackends(t, map[string]any{"name": "mine", "type": "direct"})

	err := validateDelegationBackendCombination(
		&ZoneConf{Name: "example.", Type: "secondary", DelegationBackend: "mine"},
		map[ZoneOption]bool{})
	if err == nil {
		t.Fatal("a named direct backend on a secondary was accepted")
	}
	if msg := delegationBackendContract(
		&ZoneConf{Name: "example.", DelegationBackend: "mine"},
		map[ZoneOption]bool{OptAllowChildUpdates: true}); msg != "" {
		t.Fatalf("a direct backend has no hand-off contract to state, got %q", msg)
	}
}

func TestValidationReportsAContradictoryDefinition(t *testing.T) {
	withDelegationBackends(t, map[string]any{"name": "both", "type": "db", "store": "sqlite"})

	err := validateDelegationBackendCombination(
		&ZoneConf{Name: "example.", Type: "primary", DelegationBackend: "both"},
		map[ZoneOption]bool{})
	if err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("want the contradiction reported, got %v", err)
	}
}
