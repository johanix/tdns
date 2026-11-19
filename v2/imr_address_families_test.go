/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"strings"
	"testing"
)

// An unknown address family stops the resolver from starting, before it has
// built anything.
func TestAnUnknownAddressFamilyStopsTheStart(t *testing.T) {
	conf := &Config{}
	conf.Imr.OutboundAddressFamilies = []string{"ipv4", "ipv5"}
	err := conf.InitImrEngine(context.Background())
	if err == nil || !strings.Contains(err.Error(), "imrengine.outbound-address-families") {
		t.Fatalf("InitImrEngine: %v, want an error naming imrengine.outbound-address-families", err)
	}
	if conf.Internal.ImrEngine != nil {
		t.Error("the resolver was built")
	}
}
