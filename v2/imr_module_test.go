/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"testing"

	"github.com/miekg/dns"
)

// The methods that answered on a nil *Imr before the resolver moved into its
// own module still do: conf.Internal.ImrEngine is nil under
// imrengine.active: false, and config reload calls RefreshDnssecPolicy on it.
// Promoted from the embedded *imrcore.Imr, each would dereference the nil
// outer *Imr. A wrapper around a nil module Imr answers the same.
func TestImrNilSafeMethods(t *testing.T) {
	for name, imr := range map[string]*Imr{"nil": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			imr.RefreshDnssecPolicy(map[uint8]bool{dns.ED25519: true}, DNSKEYTransportForceUDP)
			if st := imr.StatusReport(); st != nil {
				t.Errorf("StatusReport = %+v, want nil", st)
			}
			if res, err := imr.ReloadZones(nil, nil); err != nil || res.Changed() {
				t.Errorf("ReloadZones = %+v, %v; want nothing changed, no error", res, err)
			}
			imr.RefreshRoot(context.Background(), "")
			if present, _, count := imr.RootNSStatus(); present || count != 0 {
				t.Errorf("RootNSStatus = %v, %d; want absent, 0", present, count)
			}
			if l := imr.ForwardZoneList(); l != nil {
				t.Errorf("ForwardZoneList = %v, want nil", l)
			}
			if l := imr.StubZoneList(); l != nil {
				t.Errorf("StubZoneList = %v, want nil", l)
			}
			if l := imr.StubZoneStatus(); l != nil {
				t.Errorf("StubZoneStatus = %v, want nil", l)
			}
			if rr := imr.TransportSignalRRType(); rr != dns.TypeSVCB {
				t.Errorf("TransportSignalRRType = %d, want SVCB", rr)
			}
			if imr.TransportSignalCached("example.") {
				t.Error("TransportSignalCached = true, want false")
			}
		})
	}
}
