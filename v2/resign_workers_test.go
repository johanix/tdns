/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
)

// The worker count goes config file -> viper -> runtime-config snapshot -> the
// engine as it starts -> the pool. These pin each step, and what the value
// means: absent is 3, nothing below 1 is a width, and nothing above
// maxResignWorkers is, so that a typo cannot start thousands of goroutines
// against the one keystore handle.

func TestTheResignerWorkersDefaultToThree(t *testing.T) {
	if defaultResignWorkers != 3 {
		t.Fatalf("the default is %d; the ruling and the docs say 3", defaultResignWorkers)
	}
	n, note := resignWorkersFor(0)
	if n != 3 || note != "" {
		t.Errorf("unset resolves to %d (%q), want 3 and no complaint: absent is not an error", n, note)
	}

	prev := ConfLive()
	t.Cleanup(func() { liveConfig.Store(prev) })
	liveConfig.Store(&RuntimeConfig{}) // nothing configured
	if st := readResignerSettings(); st.workers != 3 || st.workersNote != "" {
		t.Errorf("an engine started on an empty snapshot runs %d workers (%q), want 3", st.workers, st.workersNote)
	}
}

func TestResignWorkersForBoundsTheValue(t *testing.T) {
	cases := []struct {
		configured int
		want       int
		complaint  string // a word the note must carry; "" means no note
	}{
		{0, 3, ""},
		{1, 1, ""},
		{2, 2, ""},
		{3, 3, ""},
		{16, 16, ""},
		{maxResignWorkers, maxResignWorkers, ""},
		{maxResignWorkers + 1, maxResignWorkers, "at most"},
		{1000, maxResignWorkers, "at most"},
		{300000, maxResignWorkers, "at most"},
		{-1, 3, "at least 1"},
		{-100, 3, "at least 1"},
	}
	for _, tc := range cases {
		n, note := resignWorkersFor(tc.configured)
		if n != tc.want {
			t.Errorf("workers: %d -> %d, want %d", tc.configured, n, tc.want)
		}
		switch {
		case tc.complaint == "" && note != "":
			t.Errorf("workers: %d is fine and was complained about: %q", tc.configured, note)
		case tc.complaint != "" && !strings.Contains(note, tc.complaint):
			t.Errorf("workers: %d -> note %q, want one that says %q", tc.configured, note, tc.complaint)
		}
		if n < 1 || n > maxResignWorkers {
			t.Errorf("workers: %d resolved to %d, outside 1..%d", tc.configured, n, maxResignWorkers)
		}
	}
}

func TestRuntimeConfigCarriesTheResignerWorkers(t *testing.T) {
	viper.Set("resignerengine.workers", 7)
	t.Cleanup(func() { viper.Set("resignerengine.workers", 0) })

	if rc := (&Config{}).buildRuntimeConfig(); rc.ResignerWorkers != 7 {
		t.Errorf("snapshot resignerengine.workers = %d, want 7", rc.ResignerWorkers)
	}
}

// What the engine is started with is what the snapshot says, resolved: this is
// the step between the config and the pool that ResignerEngine takes, and the
// interval beside it is untouched.
func TestTheResignerIsStartedWithTheConfiguredWorkers(t *testing.T) {
	prev := ConfLive()
	t.Cleanup(func() { liveConfig.Store(prev) })

	for _, tc := range []struct {
		configured, workers, interval int
		note                          bool
	}{
		{5, 5, 300, false},
		{1, 1, 60, false},
		{0, defaultResignWorkers, 3600, false},
		{100000, maxResignWorkers, 60, true},
		{-4, defaultResignWorkers, 60, true},
	} {
		liveConfig.Store(&RuntimeConfig{ResignerWorkers: tc.configured, ResignerInterval: tc.interval})
		st := readResignerSettings()
		if st.workers != tc.workers || (st.workersNote != "") != tc.note {
			t.Errorf("configured %d: started with %d workers (note %q), want %d (note: %v)",
				tc.configured, st.workers, st.workersNote, tc.workers, tc.note)
		}
		if st.interval != tc.interval {
			t.Errorf("the interval became %d, want %d", st.interval, tc.interval)
		}
	}

	liveConfig.Store(&RuntimeConfig{ResignerInterval: 5})
	if st := readResignerSettings(); st.interval != 60 {
		t.Errorf("interval 5 became %d; the floor of 60 must still hold", st.interval)
	}
}
