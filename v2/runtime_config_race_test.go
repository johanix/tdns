/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

// TestRuntimeConfigSnapshotNoRace is the regression guard for the
// "fatal error: concurrent map read and map write" crashes found load-testing
// the config-reload path. Runtime readers must go through the immutable
// RuntimeConfig snapshot (ConfLive()), never the parse-scratch conf maps or the
// global viper — those are rewritten on every reload.
//
// Under `-race`: the writer goroutine simulates a reload storm (rewrite viper,
// rebuild the plain DnssecPolicies map, republish the snapshot) while readers
// hammer ConfLive() reads and the signer hot path (NeedsResigning). If any
// reader is reverted to read viper or the plain map, the detector trips.
func TestRuntimeConfigSnapshotNoRace(t *testing.T) {
	conf := &Config{}
	conf.Internal.DnssecPolicies = map[string]DnssecPolicy{"default": {}}
	conf.MultiSigner = map[string]MultiSignerConf{}
	conf.publishRuntimeConfig()

	rrsig := &dns.RRSIG{Expiration: uint32(time.Now().Add(time.Hour).Unix())}
	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Writer: reload storm — rewrite the global viper, rebuild the parse-scratch
	// map, republish. All single-threaded within this goroutine (as a real
	// reload is, under confMu).
	wg.Add(1)
	go func() {
		defer wg.Done()
		const cfg = "resignerengine:\n    interval: 300\nservice:\n    maxrefresh: 3600\n    minrefresh: 60\n"
		for {
			select {
			case <-stop:
				return
			default:
				viper.SetConfigType("yaml")
				_ = viper.ReadConfig(strings.NewReader(cfg))
				conf.Internal.DnssecPolicies = map[string]DnssecPolicy{"default": {}}
				conf.publishRuntimeConfig()
			}
		}
	}()

	// Readers: snapshot reads + the signer hot path.
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 5000; j++ {
				rt := ConfLive()
				_ = rt.DnssecPolicies["default"]
				_ = rt.MultiSigner
				_ = rt.MaxRefresh
				_ = rt.MinRefresh
				_ = NeedsResigning(rrsig, 3600)
			}
		}()
	}

	time.Sleep(40 * time.Millisecond)
	close(stop)
	wg.Wait()
}
