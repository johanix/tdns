/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"fmt"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
)

// faketimeBannerInterval is how often a resolver on the test clock says so.
const faketimeBannerInterval = time.Hour

// startDataClock makes the resolver's data time the test clock that
// imrengine.testing asks for (faketime), and warns that it is in use, at start
// and every hour after, until ctx ends. Without faketime it does nothing, and
// data time is real time. A retried start keeps the clock it started.
// docs/2026-09-28-imr-deckard-test-clock-and-switches.md §3.3.
func startDataClock(ctx context.Context, t ImrTestingConf) error {
	if err := t.Validate(); err != nil {
		return err
	}
	if !t.FaketimeOn() {
		return nil
	}
	path := t.FaketimePath()
	if path == "" {
		return fmt.Errorf("faketime: no timestamp file: set faketime-file or $FAKETIME_TIMESTAMP_FILE")
	}
	if c := cache.DataClock(); c != nil && c.Path() == path {
		return nil
	}
	c, err := cache.NewFileClock(path)
	if err != nil {
		return fmt.Errorf("faketime: %w", err)
	}
	cache.SetDataClock(c)

	warn := func() {
		lgImr.Warn("imrengine.testing.faketime: data time is a TEST CLOCK; a test-harness setting, not for production",
			"file", path, "data_time", c.Now().Format(time.RFC3339))
	}
	warn()
	go func() {
		tick := time.NewTicker(faketimeBannerInterval)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				warn()
			}
		}
	}()
	return nil
}

// dataClockStatus describes the test clock in use for the status report, or
// is empty on real time.
func dataClockStatus() string {
	c := cache.DataClock()
	if c == nil {
		return ""
	}
	return fmt.Sprintf("faketime %s: %s", c.Path(), c.Now().Format(time.RFC3339))
}
