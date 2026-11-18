/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"testing"
)

func TestAllowLoopbackNameserversOptionParses(t *testing.T) {
	conf := &Config{}
	conf.Imr.OptionsStrs = []string{"allow-loopback-nameservers"}
	conf.parseImrOptions()
	if conf.Imr.Options[ImrOptAllowLoopbackNameservers] != "true" {
		t.Fatalf("options %v, want allow-loopback-nameservers set", conf.Imr.Options)
	}
}
