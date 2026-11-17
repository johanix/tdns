/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */

package core

import (
	"testing"

	"github.com/miekg/dns"
)

// fromWire returns rr as a receiver reads it: packed, then unpacked.
func fromWire(t *testing.T, rr dns.RR) dns.RR {
	t.Helper()
	buf := make([]byte, dns.Len(rr)+1)
	off, err := dns.PackRR(dns.Copy(rr), buf, 0, nil, false)
	if err != nil {
		t.Fatalf("PackRR %s: %v", rr, err)
	}
	out, _, err := dns.UnpackRR(buf[:off], 0)
	if err != nil {
		t.Fatalf("UnpackRR %s: %v", rr, err)
	}
	return out
}

func mustRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("NewRR %q: %v", s, err)
	}
	return rr
}

// A record read from text and the same record read from the wire are
// duplicates, whatever case the text wrote a hex or base32 field in (#843).
func TestIsDuplicateTextAgainstWire(t *testing.T) {
	for _, s := range []string{
		"child.example. 3600 IN DS 53763 15 2 6F2095DB0A1B2C3D4E5F60718293A4B5C6D7E8F90112233445566778DFEE1027",
		"child.example. 3600 IN CDS 53763 15 2 6F2095DB0A1B2C3D4E5F60718293A4B5C6D7E8F90112233445566778DFEE1027",
		"host.example. 3600 IN SSHFP 4 2 0A1B2C3D4E5F60718293A4B5C6D7E8F90112233445566778DFEE10276F2095DB",
		"_443._tcp.www.example. 3600 IN TLSA 3 1 1 0A1B2C3D4E5F60718293A4B5C6D7E8F90112233445566778DFEE10276F2095DB",
		"2vptu5timamqttgl4luu9kg21e0aor3s.example. 3600 IN NSEC3 1 0 10 AABBCCDD 2t7b4g4vsa5smi47k61mv5bv1a22bojr A RRSIG",
		"www.example. 3600 IN NS NS1.EXAMPLE.",
	} {
		text := mustRR(t, s)
		wire := fromWire(t, text)
		if !IsDuplicate(text, wire) || !IsDuplicate(wire, text) {
			t.Errorf("%s does not match itself read from the wire:\n  text %#v\n  wire %#v", s, text, wire)
		}
	}
}

// The wire comparison adds no false matches: different RDATA, type, owner or
// class still differ, and the TTL is still ignored.
func TestIsDuplicateStillDistinguishes(t *testing.T) {
	const ds = "child.example. 3600 IN DS 53763 15 2 6F2095DB0A1B2C3D4E5F60718293A4B5C6D7E8F90112233445566778DFEE1027"
	base := mustRR(t, ds)
	for _, tc := range []struct {
		name string
		rr   string
		want bool
	}{
		{"other TTL", "child.example. 60 IN DS 53763 15 2 6f2095db0a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778dfee1027", true},
		{"owner case", "CHILD.example. 3600 IN DS 53763 15 2 6f2095db0a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778dfee1027", true},
		{"other digest", "child.example. 3600 IN DS 53763 15 2 6f2095db0a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778dfee1028", false},
		{"other key tag", "child.example. 3600 IN DS 53764 15 2 6f2095db0a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778dfee1027", false},
		{"other type", "child.example. 3600 IN CDS 53763 15 2 6f2095db0a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778dfee1027", false},
		{"other owner", "other.example. 3600 IN DS 53763 15 2 6f2095db0a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778dfee1027", false},
	} {
		if got := IsDuplicate(base, fromWire(t, mustRR(t, tc.rr))); got != tc.want {
			t.Errorf("%s: IsDuplicate = %v, want %v", tc.name, got, tc.want)
		}
	}

	// A delete as it arrives, class NONE, is not the zone's class IN record;
	// the caller sets the class first.
	del := fromWire(t, base)
	del.Header().Class = dns.ClassNONE
	if IsDuplicate(base, del) {
		t.Error("a class NONE record matched the class IN one")
	}
}

// RemoveRR reports whether it removed anything.
func TestRemoveRRReportsRemoval(t *testing.T) {
	const ds = "child.example. 3600 IN DS 53763 15 2 6F2095DB0A1B2C3D4E5F60718293A4B5C6D7E8F90112233445566778DFEE1027"
	rrset := RRset{Name: "child.example.", RRtype: dns.TypeDS, RRs: []dns.RR{mustRR(t, ds)}}
	other := mustRR(t, "child.example. 3600 IN DS 11111 15 2 FFEEDDCCBBAA99887766554433221100FFEEDDCCBBAA99887766554433221100")
	if rrset.RemoveRR(fromWire(t, other), false, false) {
		t.Error("RemoveRR reported removing a record that was not there")
	}
	if !rrset.RemoveRR(fromWire(t, mustRR(t, ds)), false, false) {
		t.Error("RemoveRR did not remove the record read from the wire")
	}
	if len(rrset.RRs) != 0 {
		t.Errorf("%d RRs left, want 0", len(rrset.RRs))
	}
}
