package tdns

import (
	"testing"

	"github.com/spf13/viper"
)

// The poll settings go config file -> viper -> runtime-config snapshot ->
// ScannerEngine's tick. A reload replaces the snapshot, which is how polling is
// switched without a restart, and without the engine reading viper while the
// reload writes it.

func TestRuntimeConfigCarriesThePollSettings(t *testing.T) {
	viper.Set("scanner.poll.enabled", true)
	viper.Set("scanner.poll.bootstrap", true)
	viper.Set("scanner.poll.concurrency", 3)
	t.Cleanup(func() {
		viper.Set("scanner.poll.enabled", false)
		viper.Set("scanner.poll.bootstrap", false)
		viper.Set("scanner.poll.concurrency", 0)
	})

	rc := (&Config{}).buildRuntimeConfig()

	if !rc.ScannerPollEnabled || !rc.ScannerPollBootstrap || rc.ScannerPollConcurrency != 3 {
		t.Errorf("snapshot enabled=%v bootstrap=%v concurrency=%d; want true, true, 3",
			rc.ScannerPollEnabled, rc.ScannerPollBootstrap, rc.ScannerPollConcurrency)
	}
}

func TestPollSettingsFollowThePublishedSnapshot(t *testing.T) {
	prev := ConfLive()
	t.Cleanup(func() { liveConfig.Store(prev) })

	liveConfig.Store(&RuntimeConfig{})
	if got := readScannerPollConf(); got.Enabled || got.Bootstrap || got.Concurrency != defaultPollConcurrency {
		t.Errorf("empty snapshot: %+v; want polling off with the default concurrency", got)
	}

	liveConfig.Store(&RuntimeConfig{ScannerPollEnabled: true, ScannerPollBootstrap: true, ScannerPollConcurrency: 7})
	if got := readScannerPollConf(); !got.Enabled || !got.Bootstrap || got.Concurrency != 7 {
		t.Errorf("published snapshot: %+v; want enabled, bootstrap, concurrency 7", got)
	}
}
