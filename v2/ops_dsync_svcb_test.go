package tdns

import (
	"context"
	"testing"

	"github.com/miekg/dns"
)

func TestExpandDsyncTemplateRoot(t *testing.T) {
	if got := expandDsyncTemplate("updates.{ZONENAME}", "."); got != "updates.root." {
		t.Fatalf("root expansion = %q", got)
	}
	if got := expandDsyncTemplate("updates.{ZONENAME}", "example."); got != "updates.example." {
		t.Fatalf("zone expansion = %q", got)
	}
	if got := expandDsyncTemplate("", "example."); got != "" {
		t.Fatalf("empty template = %q", got)
	}
}

func TestDsyncOwnerNameRoot(t *testing.T) {
	if got := dsyncOwnerName("."); got != "_dsync.root." {
		t.Fatalf("root owner = %q", got)
	}
	if got := dsyncOwnerName("example."); got != "_dsync.example." {
		t.Fatalf("zone owner = %q", got)
	}
}

func TestDsyncPerChildLookupNameRoot(t *testing.T) {
	if got := dsyncPerChildLookupName("example", "."); got != "example._dsync.root." {
		t.Fatalf("tld under root = %q", got)
	}
	if got := dsyncPerChildLookupName("child", "example."); got != "child._dsync.example." {
		t.Fatalf("child under example = %q", got)
	}
}

func TestBootstrapSVCBReconcile(t *testing.T) {
	target := "updates.example."
	desired := "at-apex,at-ns"

	if got := bootstrapSVCBReconcile(target, desired, nil, 7200); len(got) != 1 {
		t.Fatalf("empty existing, want one ADD, got %d", len(got))
	} else if got[0].Header().Class != dns.ClassINET || got[0].Header().Rrtype != dns.TypeSVCB {
		t.Fatalf("want IN SVCB add, got %s class %d", dns.TypeToString[got[0].Header().Rrtype], got[0].Header().Class)
	}

	match := []dns.RR{newBootstrapSVCB(target, desired, 7200)}
	if got := bootstrapSVCBReconcile(target, desired, match, 7200); got != nil {
		t.Fatalf("matching SVCB should be a no-op, got %d actions", len(got))
	}

	stale := []dns.RR{newBootstrapSVCB(target, "unsigned", 7200)}
	got := bootstrapSVCBReconcile(target, desired, stale, 7200)
	if len(got) != 2 {
		t.Fatalf("policy change: want DELETE+ADD, got %d", len(got))
	}
	if got[0].Header().Class != dns.ClassANY {
		t.Fatal("first action must be ClassANY delete")
	}
	if data, _ := publishedBootstrapSVCBData([]dns.RR{got[1]}); data != desired {
		t.Fatalf("ADD data = %q, want %q", data, desired)
	}

	got = bootstrapSVCBReconcile(target, "", stale, 7200)
	if len(got) != 1 || got[0].Header().Class != dns.ClassANY {
		t.Fatalf("empty desired should only delete, got %d", len(got))
	}
}

func TestPublishDsyncRRsReconcilesSVCBForExistingDSYNC(t *testing.T) {
	prev := DelegationSyncConfig()
	t.Cleanup(func() { _ = SetDelegationSyncConfig(*prev) })
	if err := SetDelegationSyncConfig(DelegationSyncConf{
		Parent: DelegationSyncParentConf{
			Schemes: []string{"update"},
			Update: DsyncUpdateSchemeConf{
				DsyncDnsSchemeConf: DsyncDnsSchemeConf{
					Types:     []string{"ANY"},
					Port:      53,
					Target:    "updates.{ZONENAME}",
					Addresses: []string{"192.0.2.1"},
				},
			},
		},
	}); err != nil {
		t.Fatal(err)
	}

	zone := `example. 3600 IN SOA ns.example. hostmaster.example. 1 7200 1800 604800 7200
example. 3600 IN NS ns.example.
ns.example. 3600 IN A 192.0.2.1
_dsync.example. 7200 IN DSYNC ANY UPDATE 53 updates.example.
`
	q := make(chan UpdateRequest, 1)
	zd := testZone(t, "example.", zone)
	zd.KeyDB = &KeyDB{UpdateQ: q}
	p := DefaultDelegationPolicy()
	zd.DelegationPolicy = &p

	if err := zd.PublishDsyncRRs(context.Background()); err != nil {
		t.Fatal(err)
	}
	ur := <-q
	target := DsyncUpdateTargetName("example.")
	var sawSVCB bool
	for _, rr := range ur.Actions {
		if rr.Header().Name == target && rr.Header().Rrtype == dns.TypeSVCB && rr.Header().Class == dns.ClassINET {
			sawSVCB = true
			if data, _ := publishedBootstrapSVCBData([]dns.RR{rr}); data != "at-apex,at-ns" {
				t.Fatalf("SVCB data = %q", data)
			}
		}
	}
	if !sawSVCB {
		t.Fatal("already-published DSYNC must still publish the bootstrap SVCB")
	}
}

func TestPublishDsyncRRsPolicyControlsSVCB(t *testing.T) {
	prev := DelegationSyncConfig()
	t.Cleanup(func() { _ = SetDelegationSyncConfig(*prev) })
	if err := SetDelegationSyncConfig(DelegationSyncConf{
		Parent: DelegationSyncParentConf{
			Schemes: []string{"update"},
			Update: DsyncUpdateSchemeConf{
				DsyncDnsSchemeConf: DsyncDnsSchemeConf{
					Types:     []string{"ANY"},
					Port:      53,
					Target:    "updates.{ZONENAME}",
					Addresses: []string{"192.0.2.1"},
				},
			},
		},
	}); err != nil {
		t.Fatal(err)
	}

	publish := func(name, zone string, pol DelegationPolicy) string {
		t.Helper()
		q := make(chan UpdateRequest, 1)
		zd := testZone(t, name, zone)
		zd.KeyDB = &KeyDB{UpdateQ: q}
		zd.DelegationPolicy = &pol
		if err := zd.PublishDsyncRRs(context.Background()); err != nil {
			t.Fatal(err)
		}
		ur := <-q
		target := DsyncUpdateTargetName(name)
		for _, rr := range ur.Actions {
			if rr.Header().Name == target && rr.Header().Rrtype == dns.TypeSVCB && rr.Header().Class == dns.ClassINET {
				data, _ := publishedBootstrapSVCBData([]dns.RR{rr})
				return data
			}
		}
		t.Fatalf("%s: no bootstrap SVCB in publish", name)
		return ""
	}

	zoneA := `a.example. 3600 IN SOA ns.a.example. hostmaster.a.example. 1 7200 1800 604800 7200
a.example. 3600 IN NS ns.a.example.
ns.a.example. 3600 IN A 192.0.2.1
`
	zoneB := `b.example. 3600 IN SOA ns.b.example. hostmaster.b.example. 1 7200 1800 604800 7200
b.example. 3600 IN NS ns.b.example.
ns.b.example. 3600 IN A 192.0.2.2
`
	def := DefaultDelegationPolicy()
	locked := DelegationPolicy{Name: "locked-down", Mechanisms: []string{}, RequireDnssec: true, Manual: true}
	gotA := publish("a.example.", zoneA, def)
	gotB := publish("b.example.", zoneB, locked)
	if gotA == gotB {
		t.Fatalf("different policies produced the same SVCB %q", gotA)
	}
	if gotA != "at-apex,at-ns" {
		t.Fatalf("default SVCB = %q", gotA)
	}
	if gotB != "manual" {
		t.Fatalf("locked-down SVCB = %q", gotB)
	}
}

func TestBootstrapSVCBActionsSkipsZoneApex(t *testing.T) {
	t.Cleanup(func() { _ = SetDelegationSyncConfig(DelegationSyncConf{}) })
	if err := SetDelegationSyncConfig(DelegationSyncConf{
		Parent: DelegationSyncParentConf{
			Schemes: []string{"update"},
			Update: DsyncUpdateSchemeConf{
				DsyncDnsSchemeConf: DsyncDnsSchemeConf{Target: "{ZONENAME}"},
			},
		},
	}); err != nil {
		t.Fatal(err)
	}
	zd := &ZoneData{ZoneName: "example."}
	if got := zd.bootstrapSVCBActions(7200); got != nil {
		t.Fatalf("apex target must not emit SVCB actions, got %d", len(got))
	}
}
