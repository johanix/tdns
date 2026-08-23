package tdns

import (
	"strings"
	"testing"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// A transfer that did not deliver an apex SOA must produce an error, not a
// panic. dns.Transfer.In already rejects an AXFR stream that ends without its
// closing SOA, so these states need a peer that is misbehaving in some other
// way -- which is exactly when a nameserver has to stay up rather than take
// the process down with a nil dereference or an index out of range.
func TestTransferredApexSOARejectsIncompleteTransfers(t *testing.T) {
	const zone = "example."

	withOwner := func(od *OwnerData) *ZoneData {
		zd := &ZoneData{ZoneName: zone, Data: core.NewCmap[OwnerData]()}
		if od != nil {
			zd.Data.Set(zone, *od)
		}
		return zd
	}

	apexNoSOA := &OwnerData{Name: zone, RRtypes: NewRRTypeStore()}
	apexNoSOA.RRtypes.Set(dns.TypeNS, core.RRset{RRs: []dns.RR{
		&dns.NS{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeNS}, Ns: "ns1." + zone},
	}})

	// An SOA RRset whose first record is not an SOA cannot come off the wire,
	// but it is what the type assertion guards, and an unasserted type
	// assertion is a panic like any other.
	apexWrongType := &OwnerData{Name: zone, RRtypes: NewRRTypeStore()}
	apexWrongType.RRtypes.Set(dns.TypeSOA, core.RRset{RRs: []dns.RR{
		&dns.NS{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeNS}, Ns: "ns1." + zone},
	}})

	tests := []struct {
		name    string
		zd      *ZoneData
		wantErr string
	}{
		{"no apex at all", withOwner(nil), "delivered no apex"},
		{"apex with nil RRtypes", withOwner(&OwnerData{Name: zone}), "carries no RRsets"},
		{"apex without SOA", withOwner(apexNoSOA), "apex with no SOA"},
		{"apex SOA RRset holding a non-SOA", withOwner(apexWrongType), "holds a *dns.NS"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			soa, err := tc.zd.transferredApexSOA("192.0.2.1:53")
			if err == nil {
				t.Fatalf("transferredApexSOA returned SOA %v, want error", soa)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

// The success path still yields the serial the caller reports upward.
func TestTransferredApexSOAReturnsSerial(t *testing.T) {
	const zone = "example."

	zd := &ZoneData{ZoneName: zone, Data: core.NewCmap[OwnerData]()}
	od := OwnerData{Name: zone, RRtypes: NewRRTypeStore()}
	od.RRtypes.Set(dns.TypeSOA, core.RRset{RRs: []dns.RR{
		&dns.SOA{
			Hdr:    dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA},
			Ns:     "ns1." + zone,
			Mbox:   "hostmaster." + zone,
			Serial: 2026082301,
		},
	}})
	zd.Data.Set(zone, od)

	soa, err := zd.transferredApexSOA("192.0.2.1:53")
	if err != nil {
		t.Fatalf("transferredApexSOA: %v", err)
	}
	if soa.Serial != 2026082301 {
		t.Errorf("serial = %d, want 2026082301", soa.Serial)
	}
}
