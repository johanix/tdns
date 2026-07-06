package tdns

import (
	"testing"

	"github.com/miekg/dns"
)

// U-b: replace-mode parent UPDATE. CreateChildReplaceUpdate builds a DNS UPDATE
// that DELETEs the child's delegation RRsets (ClassANY) and ADDs the current
// authoritative members. This is the path re-enabled in SyncZoneDelegationViaUpdate
// (the old "replace mode broken" refusal was an upstream-miekg/dns workaround,
// fixed in the tdns fork).

func mustRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return rr
}

func TestCreateChildReplaceUpdateStructure(t *testing.T) {
	parent := "example."
	child := "child.example."
	newNS := []dns.RR{
		mustRR(t, "child.example. 3600 IN NS ns1.child.example."),
		mustRR(t, "child.example. 3600 IN NS ns2.child.example."),
	}
	newA := []dns.RR{mustRR(t, "ns1.child.example. 3600 IN A 192.0.2.1")}
	newAAAA := []dns.RR{mustRR(t, "ns1.child.example. 3600 IN AAAA 2001:db8::1")}
	newDS := []dns.RR{mustRR(t, "child.example. 3600 IN DS 12345 15 2 "+
		"0000000000000000000000000000000000000000000000000000000000000000")}

	m, err := CreateChildReplaceUpdate(parent, child, newNS, newA, newAAAA, newDS)
	if err != nil {
		t.Fatalf("CreateChildReplaceUpdate: %v", err)
	}
	if m == nil {
		t.Fatal("nil update message")
	}
	if m.Opcode != dns.OpcodeUpdate {
		t.Fatalf("opcode = %d, want UPDATE", m.Opcode)
	}
	// The UPDATE zone (Question) must be the parent.
	if len(m.Question) != 1 || m.Question[0].Name != dns.Fqdn(parent) {
		t.Fatalf("update zone = %v, want parent %q", m.Question, parent)
	}

	// Tally the update (Ns) section: ClassANY deletes vs ClassINET adds, per type.
	var anyNS, anyDS, addNS, addA, addAAAA, addDS int
	for _, rr := range m.Ns {
		h := rr.Header()
		switch {
		case h.Class == dns.ClassANY && h.Rrtype == dns.TypeNS:
			anyNS++
		case h.Class == dns.ClassANY && h.Rrtype == dns.TypeDS:
			anyDS++
		case h.Class == dns.ClassINET && h.Rrtype == dns.TypeNS:
			addNS++
		case h.Class == dns.ClassINET && h.Rrtype == dns.TypeA:
			addA++
		case h.Class == dns.ClassINET && h.Rrtype == dns.TypeAAAA:
			addAAAA++
		case h.Class == dns.ClassINET && h.Rrtype == dns.TypeDS:
			addDS++
		}
	}

	// A whole-RRset replace: at least one ClassANY delete for NS and DS, and the
	// new members added.
	if anyNS == 0 {
		t.Error("missing ClassANY delete of the NS RRset")
	}
	if anyDS == 0 {
		t.Error("missing ClassANY delete of the DS RRset")
	}
	if addNS != 2 {
		t.Errorf("added NS = %d, want 2", addNS)
	}
	if addA != 1 {
		t.Errorf("added A glue = %d, want 1", addA)
	}
	if addAAAA != 1 {
		t.Errorf("added AAAA glue = %d, want 1", addAAAA)
	}
	if addDS != 1 {
		t.Errorf("added DS = %d, want 1", addDS)
	}
}

// Replace with no DS (unsigned zone) still replaces NS+glue and does not add a
// DS — the unsigned-zone case the UPDATE path serves that NOTIFY cannot.
func TestCreateChildReplaceUpdateUnsigned(t *testing.T) {
	m, err := CreateChildReplaceUpdate("example.", "child.example.",
		[]dns.RR{mustRR(t, "child.example. 3600 IN NS ns1.child.example.")},
		[]dns.RR{mustRR(t, "ns1.child.example. 3600 IN A 192.0.2.1")},
		nil, nil)
	if err != nil {
		t.Fatalf("CreateChildReplaceUpdate (unsigned): %v", err)
	}
	for _, rr := range m.Ns {
		if rr.Header().Rrtype == dns.TypeDS {
			t.Fatalf("unsigned replace must not touch DS, got %v", rr)
		}
	}
}
