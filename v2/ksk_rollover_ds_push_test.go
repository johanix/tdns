package tdns

import (
	"testing"

	"github.com/miekg/dns"
)

func TestBuildChildWholeDSUpdate(t *testing.T) {
	ds, err := dns.NewRR("child.example. 3600 IN DS 12345 8 2 ABCD")
	if err != nil {
		t.Fatal(err)
	}
	m, err := BuildChildWholeDSUpdate("example.", "child.example.", []dns.RR{ds})
	if err != nil {
		t.Fatal(err)
	}
	if m.Opcode != dns.OpcodeUpdate {
		t.Fatalf("opcode: got %d want UPDATE", m.Opcode)
	}
	if len(m.Question) != 1 || m.Question[0].Name != "example." {
		t.Fatalf("question: %+v", m.Question)
	}
	if len(m.Ns) < 1 {
		t.Fatalf("expected prereq/update section, got len(Ns)=%d", len(m.Ns))
	}
}
