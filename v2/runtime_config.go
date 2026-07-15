/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"sync/atomic"

	"github.com/spf13/viper"
)

// RuntimeConfig is an immutable snapshot of config that is read at RUNTIME and
// can change on reload. It is never mutated after publish: a reload builds a
// fresh one and atomically swaps the pointer (copy-on-write). This lets the hot
// reader paths (RefreshEngine, signer) read reloadable config lock-free instead
// of racing config reload on shared maps ("fatal error: concurrent map read and
// map write"). Same model as the zone snapshot. Only the ONE writer (reload) is
// guarded; the many reads are free.
//
// See docs/2026-07-15-runtime-config-snapshot-plan.md.
type RuntimeConfig struct {
	// Reloadable maps read outside the parse/API paths. Copied from the
	// parse-scratch conf fields at publish time so the snapshot is independent
	// and immutable.
	DnssecPolicies map[string]DnssecPolicy
	MultiSigner    map[string]MultiSignerConf

	// Scalars read at runtime (phase 1: the racy/hot set). Stored raw as viper
	// returned them; readers keep their existing gate/clamp logic.
	MaxRefresh       int  // service.maxrefresh
	MinRefresh       int  // service.minrefresh
	ResignerInterval int  // resignerengine.interval
	PeriodicResign   bool // service.resign
	ServiceDebug     bool // service.debug
}

// liveConfig holds the current published snapshot. Seeded with an empty snapshot
// so ConfLive() never returns nil for a reader that runs before the first
// publish (it gets safe zero-value defaults: empty maps, 0 scalars → the
// readers' existing clamps/fallbacks apply).
var liveConfig atomic.Pointer[RuntimeConfig]

func init() { liveConfig.Store(&RuntimeConfig{}) }

// ConfLive returns the current runtime-config snapshot. Never nil, lock-free.
func ConfLive() *RuntimeConfig { return liveConfig.Load() }

// buildRuntimeConfig snapshots the just-parsed config into a fresh immutable
// RuntimeConfig. Copies the maps (small) so the snapshot does not alias the
// parse-scratch conf fields. MUST be called single-threaded — the caller holds
// confMu — after ParseConfig / reloadDnssecFromFile have finalized the config.
func (conf *Config) buildRuntimeConfig() *RuntimeConfig {
	pols := make(map[string]DnssecPolicy, len(conf.Internal.DnssecPolicies))
	for k, v := range conf.Internal.DnssecPolicies {
		pols[k] = v
	}
	ms := make(map[string]MultiSignerConf, len(conf.MultiSigner))
	for k, v := range conf.MultiSigner {
		ms[k] = v
	}
	return &RuntimeConfig{
		DnssecPolicies:   pols,
		MultiSigner:      ms,
		MaxRefresh:       viper.GetInt("service.maxrefresh"),
		MinRefresh:       viper.GetInt("service.minrefresh"),
		ResignerInterval: viper.GetInt("resignerengine.interval"),
		PeriodicResign:   viper.GetBool("service.resign"),
		ServiceDebug:     viper.GetBool("service.debug"),
	}
}

// publishRuntimeConfig builds a fresh snapshot and atomically publishes it. Call
// as the last step of startup and of every reload path, while holding confMu.
func (conf *Config) publishRuntimeConfig() {
	liveConfig.Store(conf.buildRuntimeConfig())
}
