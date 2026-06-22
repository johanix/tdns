package tdns

import (
	"testing"

	"github.com/miekg/dns"
)

// P-3: the proxy NOTIFY action. emitProxyNotifies applies the D4 act-mapping —
// NOTIFY(CSYNC) when CSYNC or NS/glue changed, NOTIFY(CDS) when CDS or DNSKEY
// changed — and emits to the resolved target(s) without publish/sign. (The
// DSYNC-discovery half of ProxyNotifyParent needs the network and is exercised
// on the testbed.)

func drainNotifyTypes(q chan NotifyRequest) []uint16 {
	var got []uint16
	for {
		select {
		case r := <-q:
			got = append(got, r.RRtype)
		default:
			return got
		}
	}
}

func TestEmitProxyNotifiesActMapping(t *testing.T) {
	targets := []string{"192.0.2.53:53"}
	cases := []struct {
		name     string
		analysis ProxyDelegationAnalysis
		want     []uint16 // order: CSYNC before CDS
	}{
		{"cds-only", ProxyDelegationAnalysis{CdsChanged: true}, []uint16{dns.TypeCDS}},
		{"csync-only", ProxyDelegationAnalysis{CsyncChanged: true}, []uint16{dns.TypeCSYNC}},
		{"dnskey-drives-cds", ProxyDelegationAnalysis{DnskeyChanged: true}, []uint16{dns.TypeCDS}},
		{"nsglue-drives-csync", ProxyDelegationAnalysis{NsOrGlueChanged: true}, []uint16{dns.TypeCSYNC}},
		{"both", ProxyDelegationAnalysis{CdsChanged: true, CsyncChanged: true}, []uint16{dns.TypeCSYNC, dns.TypeCDS}},
		{"all-four", ProxyDelegationAnalysis{CdsChanged: true, CsyncChanged: true, NsOrGlueChanged: true, DnskeyChanged: true}, []uint16{dns.TypeCSYNC, dns.TypeCDS}},
		{"none", ProxyDelegationAnalysis{}, nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			zd := &ZoneData{ZoneName: "child.example."}
			q := make(chan NotifyRequest, 4)
			a := tc.analysis
			sent := zd.emitProxyNotifies(q, &a, targets)

			got := drainNotifyTypes(q)
			if len(got) != len(tc.want) {
				t.Fatalf("emitted %v NOTIFY types, want %v", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("NOTIFY[%d] = %d, want %d (full %v vs %v)", i, got[i], tc.want[i], got, tc.want)
				}
			}
			// The returned label list must match the emitted count.
			if len(sent) != len(tc.want) {
				t.Fatalf("returned %v labels, want %d", sent, len(tc.want))
			}
			// Each emitted NOTIFY must carry the target through unchanged.
			for _, r := range got {
				_ = r // type checked above; targets verified below via a fresh send
			}
		})
	}
}

// The emitted NOTIFY carries the resolved targets and the zone, unchanged.
func TestEmitProxyNotifiesTargetPassthrough(t *testing.T) {
	zd := &ZoneData{ZoneName: "child.example."}
	q := make(chan NotifyRequest, 2)
	targets := []string{"192.0.2.53:53", "[2001:db8::53]:53"}

	zd.emitProxyNotifies(q, &ProxyDelegationAnalysis{CsyncChanged: true}, targets)
	select {
	case r := <-q:
		if r.RRtype != dns.TypeCSYNC {
			t.Fatalf("rrtype = %d, want CSYNC", r.RRtype)
		}
		if r.ZoneName != "child.example." || r.ZoneData != zd {
			t.Fatalf("zone not passed through: name=%q zd=%p", r.ZoneName, r.ZoneData)
		}
		if len(r.Targets) != 2 || r.Targets[0] != targets[0] || r.Targets[1] != targets[1] {
			t.Fatalf("targets not passed through: %v", r.Targets)
		}
	default:
		t.Fatal("expected a NOTIFY(CSYNC)")
	}
}
