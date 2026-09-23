package tdns

import (
	"fmt"
	"log"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// DelegationDataChangedNG's whole output, pinned: the NS deltas, the glue
// deltas and their record forms, and the DS block. tdns-mp reads all of it
// (its MPPreRefresh), and the proxy reads the NS and glue deltas, but the
// proxy's own tests only look at NsAdds, NsRemoves and one bool. These pin the
// rest, so the function can be split without anything moving.

const ddcngZoneName = "deleg.example."

const (
	ddcngNS1      = "deleg.example. 3600 IN NS ns1.deleg.example."
	ddcngNS2      = "deleg.example. 3600 IN NS ns2.deleg.example."
	ddcngNS3      = "deleg.example. 3600 IN NS ns3.deleg.example."
	ddcngNSOut    = "deleg.example. 3600 IN NS ns.other.example."
	ddcngNSOut2   = "deleg.example. 3600 IN NS ns2.other.example."
	ddcngNS1A     = "ns1.deleg.example. 3600 IN A 192.0.2.1"
	ddcngNS1A2    = "ns1.deleg.example. 3600 IN A 192.0.2.11"
	ddcngNS1AAAA  = "ns1.deleg.example. 3600 IN AAAA 2001:db8::1"
	ddcngNS1AAAA2 = "ns1.deleg.example. 3600 IN AAAA 2001:db8::11"
	ddcngNS2A     = "ns2.deleg.example. 3600 IN A 192.0.2.2"
	ddcngNS3A     = "ns3.deleg.example. 3600 IN A 192.0.2.3"
	ddcngNS3AAAA  = "ns3.deleg.example. 3600 IN AAAA 2001:db8::3"
	ddcngKSK1     = "deleg.example. 3600 IN DNSKEY 257 3 15 f2ASuP3EaOR2T0VmM7HkCB1xClIUsLJzvUoHRiWZMJM="
	ddcngKSK2     = "deleg.example. 3600 IN DNSKEY 257 3 15 FeZKiLqntwtMwohFWaBta7KMd1vd6zwOcA0Y7c3CBis="
	ddcngZSK1     = "deleg.example. 3600 IN DNSKEY 256 3 15 q2og6Taj0NoTuSiqwsKmNn76Uy4F4lJixfyGEitgt5A="
	ddcngZSK2     = "deleg.example. 3600 IN DNSKEY 256 3 15 C4RKfg3IUwpjc+CnISaCuDX4OGpxsUIe7dqRVXj0KdU="
)

// ddcngZone is the zone text for a given serial and set of records.
func ddcngZone(serial int, rrs ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s 3600 IN SOA ns1.%s hostmaster.%s %d 7200 1800 604800 3600\n",
		ddcngZoneName, ddcngZoneName, ddcngZoneName, serial)
	for _, rr := range rrs {
		b.WriteString(rr + "\n")
	}
	return b.String()
}

// The served zone every case starts from: two in-bailiwick nameservers (one
// with A and AAAA glue, one with A only), one out-of-bailiwick nameserver, a
// KSK and a ZSK.
func ddcngServedZone() string {
	return ddcngZone(1, ddcngNS1, ddcngNS2, ddcngNSOut, ddcngKSK1, ddcngZSK1,
		ddcngNS1A, ddcngNS1AAAA, ddcngNS2A)
}

// ddcngRRs renders records as sorted strings. A record's class is part of its
// string, so a removal written as class NONE and one written as class IN
// compare different, as they should here.
func ddcngRRs(rrs []dns.RR) []string {
	var out []string
	for _, rr := range rrs {
		out = append(out, rr.String())
	}
	slices.Sort(out)
	return out
}

// ddcngWant renders zone-file records the way ddcngRRs renders the output.
// class, when not empty, replaces the record's class (a removal is class NONE).
func ddcngWant(t *testing.T, class string, rrs ...string) []string {
	t.Helper()
	var out []string
	for _, s := range rrs {
		rr, err := dns.NewRR(s)
		if err != nil {
			t.Fatalf("dns.NewRR(%q): %v", s, err)
		}
		if class != "" {
			rr.Header().Class = dns.StringToClass[class]
		}
		out = append(out, rr.String())
	}
	slices.Sort(out)
	return out
}

// ddcngDS is the SHA-256 DS of a DNSKEY record, as the DS block derives it.
func ddcngDS(t *testing.T, key string) string {
	t.Helper()
	rr, err := dns.NewRR(key)
	if err != nil {
		t.Fatalf("dns.NewRR(%q): %v", key, err)
	}
	return rr.(*dns.DNSKEY).ToDS(dns.SHA256).String()
}

// ddcngIncoming is the incoming zone as the refresh paths hand it to the
// pre-refresh hooks: parsed, Ready, and never published (see
// scratchZoneLikeTransfer, which is fixed to another zone name).
func ddcngIncoming(t *testing.T, zoneStr string) *ZoneData {
	t.Helper()
	zd := &ZoneData{
		ZoneName:  ddcngZoneName,
		ZoneStore: MapZone,
		Logger:    log.New(os.Stderr, "", 0),
	}
	if _, _, err := zd.ReadZoneData(zoneStr, true); err != nil {
		t.Fatalf("ReadZoneData: %v", err)
	}
	zd.Ready = true
	if zd.publishedSnapshot() != nil {
		t.Fatal("the incoming zone must have no published snapshot")
	}
	return zd
}

func TestDelegationDataChangedNGOutputIsPinned(t *testing.T) {
	ds1 := func(t *testing.T) []string { return []string{ddcngDS(t, ddcngKSK1)} }
	ds2 := func(t *testing.T) []string { return []string{ddcngDS(t, ddcngKSK2)} }
	none := func(*testing.T) []string { return nil }

	cases := []struct {
		name     string
		incoming string
		changed  bool

		nsAdds, nsRemoves     func(*testing.T) []string
		aAdds, aRemoves       func(*testing.T) []string
		aaaaAdds, aaaaRemoves func(*testing.T) []string
		dsAdds, dsRemoves     func(*testing.T) []string
		newDS                 func(*testing.T) []string
		newDSKnown            bool
	}{
		{
			name:     "serial only",
			incoming: ddcngZone(2, ddcngNS1, ddcngNS2, ddcngNSOut, ddcngKSK1, ddcngZSK1, ddcngNS1A, ddcngNS1AAAA, ddcngNS2A),
			changed:  false,
		},
		{
			// Glue is taken for the in-bailiwick nameserver only.
			name: "nameservers added, one in bailiwick with glue, one out of bailiwick",
			incoming: ddcngZone(2, ddcngNS1, ddcngNS2, ddcngNS3, ddcngNSOut, ddcngNSOut2, ddcngKSK1, ddcngZSK1,
				ddcngNS1A, ddcngNS1AAAA, ddcngNS2A, ddcngNS3A, ddcngNS3AAAA),
			changed:  true,
			nsAdds:   func(t *testing.T) []string { return ddcngWant(t, "", ddcngNS3, ddcngNSOut2) },
			aAdds:    func(t *testing.T) []string { return ddcngWant(t, "", ddcngNS3A) },
			aaaaAdds: func(t *testing.T) []string { return ddcngWant(t, "", ddcngNS3AAAA) },
		},
		{
			// The glue removal is class NONE, and listed once although both
			// the removed-NS pass and the glue pass find it.
			name:      "in-bailiwick nameserver removed with its glue",
			incoming:  ddcngZone(2, ddcngNS1, ddcngNSOut, ddcngKSK1, ddcngZSK1, ddcngNS1A, ddcngNS1AAAA),
			changed:   true,
			nsRemoves: func(t *testing.T) []string { return ddcngWant(t, "", ddcngNS2) },
			aRemoves:  func(t *testing.T) []string { return ddcngWant(t, "NONE", ddcngNS2A) },
		},
		{
			// The removed-NS pass takes the served zone's address records,
			// whether or not the incoming zone still has them.
			name:      "in-bailiwick nameserver removed, its address record kept",
			incoming:  ddcngZone(2, ddcngNS1, ddcngNSOut, ddcngKSK1, ddcngZSK1, ddcngNS1A, ddcngNS1AAAA, ddcngNS2A),
			changed:   true,
			nsRemoves: func(t *testing.T) []string { return ddcngWant(t, "", ddcngNS2) },
			aRemoves:  func(t *testing.T) []string { return ddcngWant(t, "NONE", ddcngNS2A) },
		},
		{
			// A changed address is removed as the served record, class IN.
			name:        "glue addresses changed",
			incoming:    ddcngZone(2, ddcngNS1, ddcngNS2, ddcngNSOut, ddcngKSK1, ddcngZSK1, ddcngNS1A2, ddcngNS1AAAA2, ddcngNS2A),
			changed:     true,
			aAdds:       func(t *testing.T) []string { return ddcngWant(t, "", ddcngNS1A2) },
			aRemoves:    func(t *testing.T) []string { return ddcngWant(t, "", ddcngNS1A) },
			aaaaAdds:    func(t *testing.T) []string { return ddcngWant(t, "", ddcngNS1AAAA2) },
			aaaaRemoves: func(t *testing.T) []string { return ddcngWant(t, "", ddcngNS1AAAA) },
		},
		{
			// As found: when a nameserver that stays has no records left at
			// all, its glue is listed for removal but the delegation is
			// reported unchanged.
			name:        "in-bailiwick nameserver kept, all its records gone",
			incoming:    ddcngZone(2, ddcngNS1, ddcngNS2, ddcngNSOut, ddcngKSK1, ddcngZSK1, ddcngNS2A),
			changed:     false,
			aRemoves:    func(t *testing.T) []string { return ddcngWant(t, "NONE", ddcngNS1A) },
			aaaaRemoves: func(t *testing.T) []string { return ddcngWant(t, "NONE", ddcngNS1AAAA) },
		},
		{
			// A transfer from an unsigned upstream into a zone that signs
			// itself: nothing but the keys is gone, and the DS block reports
			// the KSK's DS removed with no new DS set known.
			name:       "keys gone",
			incoming:   ddcngZone(2, ddcngNS1, ddcngNS2, ddcngNSOut, ddcngNS1A, ddcngNS1AAAA, ddcngNS2A),
			changed:    true,
			dsRemoves:  ds1,
			newDSKnown: false,
		},
		{
			name:       "KSK replaced",
			incoming:   ddcngZone(2, ddcngNS1, ddcngNS2, ddcngNSOut, ddcngKSK2, ddcngZSK1, ddcngNS1A, ddcngNS1AAAA, ddcngNS2A),
			changed:    true,
			dsAdds:     ds2,
			dsRemoves:  ds1,
			newDS:      ds2,
			newDSKnown: true,
		},
		{
			// Only SEP keys make a DS.
			name:     "ZSK replaced",
			incoming: ddcngZone(2, ddcngNS1, ddcngNS2, ddcngNSOut, ddcngKSK1, ddcngZSK2, ddcngNS1A, ddcngNS1AAAA, ddcngNS2A),
			changed:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			zd := testZone(t, ddcngZoneName, ddcngServedZone())
			newzd := ddcngIncoming(t, tc.incoming)

			changed, dss, err := zd.DelegationDataChangedNG(newzd)
			if err != nil {
				t.Fatalf("DelegationDataChangedNG: %v", err)
			}
			if changed != tc.changed {
				t.Errorf("changed = %v, want %v", changed, tc.changed)
			}
			if dss.InSync != !tc.changed {
				t.Errorf("InSync = %v, want %v", dss.InSync, !tc.changed)
			}

			check := func(field string, got []dns.RR, want func(*testing.T) []string) {
				t.Helper()
				if want == nil {
					want = none
				}
				if g, w := ddcngRRs(got), want(t); !slices.Equal(g, w) {
					t.Errorf("%s:\n got  %q\n want %q", field, g, w)
				}
			}
			check("NsAdds", dss.NsAdds, tc.nsAdds)
			check("NsRemoves", dss.NsRemoves, tc.nsRemoves)
			check("AAdds", dss.AAdds, tc.aAdds)
			check("ARemoves", dss.ARemoves, tc.aRemoves)
			check("AAAAAdds", dss.AAAAAdds, tc.aaaaAdds)
			check("AAAARemoves", dss.AAAARemoves, tc.aaaaRemoves)
			check("DSAdds", dss.DSAdds, tc.dsAdds)
			check("DSRemoves", dss.DSRemoves, tc.dsRemoves)
			check("NewDS", dss.NewDS, tc.newDS)
			if dss.NewDSKnown != tc.newDSKnown {
				t.Errorf("NewDSKnown = %v, want %v", dss.NewDSKnown, tc.newDSKnown)
			}
		})
	}
}

// On a first load there is no served zone to compare with, and that is not a
// change.
func TestDelegationDataChangedNGFirstLoadIsNoChange(t *testing.T) {
	served := &ZoneData{ZoneName: ddcngZoneName, ZoneStore: MapZone} // not Ready: nothing loaded yet
	newzd := ddcngIncoming(t, ddcngServedZone())

	changed, dss, err := served.DelegationDataChangedNG(newzd)
	if err != nil {
		t.Fatalf("DelegationDataChangedNG: %v", err)
	}
	if changed || !dss.InSync {
		t.Errorf("first load: changed = %v, InSync = %v; want false, true", changed, dss.InSync)
	}
	if n := len(dss.NsAdds) + len(dss.AAdds) + len(dss.AAAAAdds) + len(dss.DSAdds); n != 0 {
		t.Errorf("first load reported %d additions, want none", n)
	}
}

// The split: diffNSAndGlue reports DelegationDataChangedNG's NS and glue deltas
// exactly, and nothing of DS. A change to the keys alone, which is what a
// transfer from an unsigned upstream into a zone that signs itself looks like,
// is no NS or glue change.
func TestDiffNSAndGlueIsTheNSAndGluePartAlone(t *testing.T) {
	cases := []struct {
		name     string
		incoming string
		nsOrGlue bool
	}{
		{"serial only", ddcngZone(2, ddcngNS1, ddcngNS2, ddcngNSOut, ddcngKSK1, ddcngZSK1, ddcngNS1A, ddcngNS1AAAA, ddcngNS2A), false},
		{"nameserver added", ddcngZone(2, ddcngNS1, ddcngNS2, ddcngNS3, ddcngNSOut, ddcngKSK1, ddcngZSK1, ddcngNS1A, ddcngNS1AAAA, ddcngNS2A, ddcngNS3A), true},
		{"nameserver removed", ddcngZone(2, ddcngNS1, ddcngNSOut, ddcngKSK1, ddcngZSK1, ddcngNS1A, ddcngNS1AAAA), true},
		{"glue changed", ddcngZone(2, ddcngNS1, ddcngNS2, ddcngNSOut, ddcngKSK1, ddcngZSK1, ddcngNS1A2, ddcngNS1AAAA, ddcngNS2A), true},
		{"keys gone", ddcngZone(2, ddcngNS1, ddcngNS2, ddcngNSOut, ddcngNS1A, ddcngNS1AAAA, ddcngNS2A), false},
		{"KSK replaced", ddcngZone(2, ddcngNS1, ddcngNS2, ddcngNSOut, ddcngKSK2, ddcngZSK1, ddcngNS1A, ddcngNS1AAAA, ddcngNS2A), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			zd := testZone(t, ddcngZoneName, ddcngServedZone())
			newzd := ddcngIncoming(t, tc.incoming)

			_, whole, err := zd.DelegationDataChangedNG(newzd)
			if err != nil {
				t.Fatalf("DelegationDataChangedNG: %v", err)
			}
			oldapex, newapex, err := zd.delegationApexes(newzd)
			if err != nil || oldapex == nil || newapex == nil {
				t.Fatalf("delegationApexes: %v, %v, %v", oldapex, newapex, err)
			}
			part := DelegationSyncStatus{InSync: true}
			zd.diffNSAndGlue(newzd, oldapex, newapex, &part)

			if part.InSync == tc.nsOrGlue {
				t.Errorf("InSync = %v, want %v", part.InSync, !tc.nsOrGlue)
			}
			for _, f := range []struct {
				field       string
				part, whole []dns.RR
			}{
				{"NsAdds", part.NsAdds, whole.NsAdds},
				{"NsRemoves", part.NsRemoves, whole.NsRemoves},
				{"AAdds", part.AAdds, whole.AAdds},
				{"ARemoves", part.ARemoves, whole.ARemoves},
				{"AAAAAdds", part.AAAAAdds, whole.AAAAAdds},
				{"AAAARemoves", part.AAAARemoves, whole.AAAARemoves},
			} {
				if p, w := ddcngRRs(f.part), ddcngRRs(f.whole); !slices.Equal(p, w) {
					t.Errorf("%s: diffNSAndGlue %q, DelegationDataChangedNG %q", f.field, p, w)
				}
			}
			if n := len(part.DSAdds) + len(part.DSRemoves) + len(part.NewDS); n != 0 || part.NewDSKnown {
				t.Errorf("diffNSAndGlue set DS fields: %d records, NewDSKnown %v", n, part.NewDSKnown)
			}
		})
	}
}

// There is nothing to compare on a first load, and when the incoming zone has
// no apex.
func TestDelegationApexesNothingToCompare(t *testing.T) {
	served := &ZoneData{ZoneName: ddcngZoneName, ZoneStore: MapZone} // not Ready
	if o, n, err := served.delegationApexes(ddcngIncoming(t, ddcngServedZone())); o != nil || n != nil || err != nil {
		t.Errorf("first load: %v, %v, %v; want nil, nil, nil", o, n, err)
	}

	zd := testZone(t, ddcngZoneName, ddcngServedZone())
	apexless := &ZoneData{ZoneName: ddcngZoneName, ZoneStore: MapZone, Ready: true}
	if o, n, err := zd.delegationApexes(apexless); o != nil || n != nil || err != nil {
		t.Errorf("no incoming apex: %v, %v, %v; want nil, nil, nil", o, n, err)
	}
}
