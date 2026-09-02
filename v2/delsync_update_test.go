package tdns

import (
	"context"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestSendDelegationUpdatePreconditions(t *testing.T) {
	zd := &ZoneData{ZoneName: "child.example.", Parent: "example."}
	kdb := newTestKeyDB(t)

	_, _, _, err := zd.SendDelegationUpdate(context.Background(), kdb, DelegationSyncStatus{}, nil, UpdateModeDelta)
	if err == nil || !strings.Contains(err.Error(), "no usable UPDATE target") {
		t.Fatalf("nil target: %v", err)
	}

	_, _, _, err = zd.SendDelegationUpdate(context.Background(), kdb, DelegationSyncStatus{},
		&DsyncTarget{Addresses: []string{"192.0.2.1"}}, UpdateModeDelta)
	if err == nil || !strings.Contains(err.Error(), "no active SIG(0) key") {
		t.Fatalf("no SIG(0) key: %v", err)
	}

	zd.Parent = ""
	_, _, _, err = zd.SendDelegationUpdate(context.Background(), kdb, DelegationSyncStatus{},
		&DsyncTarget{Addresses: []string{"192.0.2.1"}}, UpdateModeDelta)
	if err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("unknown parent: %v", err)
	}
}

func TestResolveParentZoneDotSentinel(t *testing.T) {
	prev := Globals.ImrEngine
	Globals.ImrEngine = nil
	t.Cleanup(func() { Globals.ImrEngine = prev })

	zd := &ZoneData{ZoneName: "example.", Parent: "example."}
	if err := zd.resolveParentZone(); err != nil {
		t.Fatalf("known parent: %v", err)
	}

	zd.Parent = "."
	if err := zd.resolveParentZone(); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("dot sentinel with no IMR: %v", err)
	}
	zd.Parent = ""
	if err := zd.resolveParentZone(); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("empty parent with no IMR: %v", err)
	}
}

func TestBuildDelegationUpdateMode(t *testing.T) {
	ns, err := dns.NewRR("child.example. 3600 IN NS ns.child.example.")
	if err != nil {
		t.Fatal(err)
	}
	ss := DelegationSyncStatus{
		NewNS:      []dns.RR{ns},
		NewDSKnown: true,
		NsAdds:     []dns.RR{ns},
	}

	replace, err := buildDelegationUpdate("example.", "child.example.", ss, UpdateModeReplace)
	if err != nil {
		t.Fatal(err)
	}
	var sawAnyNS bool
	for _, rr := range replace.Ns {
		if rr.Header().Rrtype == dns.TypeNS && rr.Header().Class == dns.ClassANY {
			sawAnyNS = true
		}
	}
	if !sawAnyNS {
		t.Fatal("replace mode must DELETE the existing NS RRset")
	}

	delta, err := buildDelegationUpdate("example.", "child.example.", ss, UpdateModeDelta)
	if err != nil {
		t.Fatal(err)
	}
	var sawAdd bool
	for _, rr := range delta.Ns {
		if dns.IsDuplicate(rr, ns) && rr.Header().Class == dns.ClassINET {
			sawAdd = true
		}
	}
	if !sawAdd {
		t.Fatal("delta mode must ADD the NS from NsAdds")
	}
}

func TestCreateChildUpdateParentIsRoot(t *testing.T) {
	ns, err := dns.NewRR("example. 3600 IN NS ns.example.")
	if err != nil {
		t.Fatal(err)
	}
	m, err := CreateChildUpdate(".", "example.", []dns.RR{ns}, nil)
	if err != nil {
		t.Fatalf("child of the root must be able to UPDATE: %v", err)
	}
	if m.Question[0].Name != "." {
		t.Fatalf("update zone = %q, want .", m.Question[0].Name)
	}
	m, err = CreateChildReplaceUpdateWithDS(".", "example.", []dns.RR{ns}, nil, nil, nil, false)
	if err != nil {
		t.Fatalf("replace to the root: %v", err)
	}
	if m.Question[0].Name != "." {
		t.Fatalf("replace update zone = %q, want .", m.Question[0].Name)
	}
}
