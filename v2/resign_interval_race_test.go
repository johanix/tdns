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

// TestNeedsResigningNoViperRace is a regression guard for the
// "fatal error: concurrent map read and map write" crash seen under a
// config-reload storm: NeedsResigning runs in the signing hot path (per RRset,
// in the ResignerEngine goroutine) and must NOT read the process-global viper,
// whose map is not thread-safe while a config reload rewrites it via
// viper.ReadConfig. The interval is cached in an atomic (SetResignerIntervalSec)
// instead.
//
// Run under `-race`: the writer goroutine rewrites the global viper in a loop
// (as ParseConfig does on every reload) while readers hammer NeedsResigning. If
// anyone reintroduces a viper read into NeedsResigning, the race detector trips.
func TestNeedsResigningNoViperRace(t *testing.T) {
	SetResignerIntervalSec(300)
	rrsig := &dns.RRSIG{Expiration: uint32(time.Now().Add(time.Hour).Unix())}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Writer: simulate config reload rewriting the global viper map.
	wg.Add(1)
	go func() {
		defer wg.Done()
		const cfg = "resignerengine:\n    interval: 300\n"
		for {
			select {
			case <-stop:
				return
			default:
				viper.SetConfigType("yaml")
				_ = viper.ReadConfig(strings.NewReader(cfg))
				SetResignerIntervalSec(viper.GetInt("resignerengine.interval"))
			}
		}
	}()

	// Readers: the signing hot path.
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 5000; j++ {
				_ = NeedsResigning(rrsig, 3600)
			}
		}()
	}

	time.Sleep(40 * time.Millisecond)
	close(stop)
	wg.Wait()
}
