/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"testing"

	"github.com/miekg/dns"
)

// The forward half of this test is imr's TestQminForwardAndOwnZoneSendTheFullNameForwardHalf.
func TestQminForwardAndOwnZoneSendTheFullName(t *testing.T) {
	rig := newOwnZoneRig(t)
	if rig.imr.Options == nil {
		rig.imr.Options = map[ImrOption]string{}
	}
	rig.imr.Options[ImrOptQnameMinimisation] = "true"
	resp, err := rig.imr.ImrQuery(context.Background(), "www."+ownParent, dns.TypeA, dns.ClassINET, nil)
	if err != nil || resp.RRset == nil || rdataOf(resp.RRset.RRs[0]) != "192.0.2.2" {
		t.Fatalf("own zone: %+v err %v", resp, err)
	}
	requireUpstreamNotAsked(t, rig.upLog, ownParent)
}
