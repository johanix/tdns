/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"maps"
	"slices"
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
	ProbeTimeout     int  // service.probetimeout (seconds)
	TransferTimeout  int  // service.transfertimeout (seconds)
	ResignerInterval int  // resignerengine.interval
	ResignerWorkers  int  // resignerengine.workers; read once, when the resigner starts
	ServiceDebug     bool // service.debug

	// The scanner's poll settings, read by ScannerEngine on every tick
	// (scanner_poll.go).
	ScannerPollEnabled     bool // scanner.poll.enabled
	ScannerPollBootstrap   bool // scanner.poll.bootstrap
	ScannerPollConcurrency int  // scanner.poll.concurrency

	// JournalOff is journal.active: false, the delta-persistence kill-switch.
	// Stored INVERTED, so the zero value -- the seed snapshot a reader gets
	// before the first publish -- means ON, which is what an absent
	// journal.active means (see JournalConf.Active).
	//
	// It lives here, not behind confMu, because it is read by the publish path
	// under zd.mu, and a reload takes zd.mu per zone while holding confMu's
	// write lock: a confMu read there is the zd.mu -> confMu / confMu -> zd.mu
	// inversion that deadlocks the daemon (#1001).
	//
	// Built from conf.Journal, which therefore has to hold only an accepted
	// value: reloadConfig puts the running one back when it refuses a reload.
	JournalOff bool

	// TransportSignal is the transport signal's configuration as last
	// accepted, for the readers that run outside the parse/API paths or
	// race a reload (transportSignalConfig).
	TransportSignal transportSignalConf

	// src is the Config the snapshot was built from.
	src *Config
}

// transportSignalConf is the part of the config the transport signal's
// readers use: the signal pass, the preview and release API, and config
// status.
type transportSignalConf struct {
	Transport         TransportConf
	Identities        []string
	ListenerAddresses []string
}

// clone is a copy that shares no map or slice with t.
func (t transportSignalConf) clone() transportSignalConf {
	c := t
	c.Transport.Ports = maps.Clone(t.Transport.Ports)
	c.Transport.Targets = maps.Clone(t.Transport.Targets)
	c.Identities = slices.Clone(t.Identities)
	c.ListenerAddresses = slices.Clone(t.ListenerAddresses)
	return c
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
		ProbeTimeout:     viper.GetInt("service.probetimeout"),
		TransferTimeout:  viper.GetInt("service.transfertimeout"),
		ResignerInterval: viper.GetInt("resignerengine.interval"),
		ResignerWorkers:  viper.GetInt("resignerengine.workers"),
		ServiceDebug:     viper.GetBool("service.debug"),

		ScannerPollEnabled:     viper.GetBool("scanner.poll.enabled"),
		ScannerPollBootstrap:   viper.GetBool("scanner.poll.bootstrap"),
		ScannerPollConcurrency: viper.GetInt("scanner.poll.concurrency"),

		JournalOff: conf.Journal.Active != nil && !*conf.Journal.Active,

		TransportSignal: transportSignalConf{
			Transport:         conf.Service.Transport,
			Identities:        conf.Service.Identities,
			ListenerAddresses: conf.Listeners.Addresses,
		}.clone(),
		src: conf,
	}
}

// transportSignalConfig is the Config the transport signal's readers use:
// the pass at a zone's first load (runTransportSignalPass), the preview and
// release API, and config status. It holds service.transport,
// service.identities and listeners.addresses as last accepted, from the
// published runtime-config snapshot, and nothing else.
//
// Not conf itself: a reload decodes those fields into conf in place, under
// confMu, clearing service.transport first, and puts the running values back
// only once it has refused the file. A reader of conf in between sees a
// cleared or a refused value (CodeRabbit on #1118). Nor conf read under
// confMu.RLock: the pass runs on the refresh engine's goroutine, which drains
// RefreshZoneCh, and a zone reload holds confMu while it queues every zone's
// refresh there (ParseZones), so a pass waiting for the lock could leave
// both stuck. The snapshot is built under confMu by the writer, at startup
// before any engine starts and after every reload that is accepted, never
// after one that is refused, and read here without a lock.
//
// A conf the snapshot was not built from, a test's, is read as it is.
func (conf *Config) transportSignalConfig() *Config {
	rc := ConfLive()
	if rc.src != conf {
		return conf
	}
	t := rc.TransportSignal.clone()
	c := &Config{}
	c.Service.Transport = t.Transport
	c.Service.Identities = t.Identities
	c.Listeners.Addresses = t.ListenerAddresses
	return c
}

// publishRuntimeConfig builds a fresh snapshot and atomically publishes it. Call
// as the last step of startup and of every reload path, while holding confMu.
func (conf *Config) publishRuntimeConfig() {
	liveConfig.Store(conf.buildRuntimeConfig())
}
