/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"strings"
	"testing"

	cache "github.com/johanix/tdns/v2/cache"
)

// A resolver asked for the test clock without a file does not start
// (TestFaketimeActivationDataClock in the resolver's tests has the rest).
func TestFaketimeActivation(t *testing.T) {
	t.Cleanup(func() { cache.SetDataClock(nil) })
	t.Setenv("FAKETIME_TIMESTAMP_FILE", "")
	ctx := context.Background()

	conf := &Config{}
	conf.Imr.Testing.Faketime = true
	if err := conf.InitImrEngine(ctx, true); err == nil || !strings.Contains(err.Error(), "faketime") {
		t.Errorf("InitImrEngine with faketime and no file: %v; want a faketime error", err)
	}
}
