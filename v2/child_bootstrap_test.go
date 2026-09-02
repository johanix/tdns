package tdns

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

func TestSelectChildBootstrapMethod(t *testing.T) {
	tests := []struct {
		name    string
		adv     []string
		present bool
		willing []string
		want    string
		wantErr string
	}{
		{
			name:    "no SVCB falls back to child strongest",
			willing: []string{"at-apex", "at-ns"},
			want:    "at-apex",
		},
		{
			name:    "unsigned parent vs default child is empty",
			adv:     []string{"unsigned", "manual"},
			present: true,
			willing: []string{"at-apex", "at-ns"},
			wantErr: "no overlapping",
		},
		{
			name:    "unsigned parent with opted-in child",
			adv:     []string{"unsigned", "manual"},
			present: true,
			willing: []string{"at-apex", "unsigned"},
			want:    "unsigned",
		},
		{
			name:    "prefer at-apex over at-ns over unsigned",
			adv:     []string{"unsigned", "at-ns", "at-apex"},
			present: true,
			willing: []string{"unsigned", "at-ns", "at-apex"},
			want:    "at-apex",
		},
		{
			name:    "manual only",
			adv:     []string{"manual"},
			present: true,
			willing: []string{"at-apex", "manual"},
			want:    "manual",
		},
		{
			name:    "empty child list refuses",
			willing: []string{},
			wantErr: "no SIG(0) bootstrap method configured",
		},
		{
			name:    "present empty advertisement refuses",
			adv:     []string{},
			present: true,
			willing: []string{"at-apex"},
			wantErr: "no overlapping",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := selectChildBootstrapMethod(tc.adv, tc.present, tc.willing)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err=%v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestChildBootstrapMethodsProxyDropsAtNs(t *testing.T) {
	var dsc DelegationSyncConf
	dsc.Child.Update.Bootstrap.Methods = []string{"at-apex", "at-ns", "unsigned"}
	if err := SetDelegationSyncConfig(dsc); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = SetDelegationSyncConfig(DelegationSyncConf{}) })

	if got := childBootstrapMethods(false, true); !reflect.DeepEqual(got, []string{"at-apex", "at-ns", "unsigned"}) {
		t.Fatalf("auth with a signal target: %v", got)
	}
	if got := childBootstrapMethods(false, false); !reflect.DeepEqual(got, []string{"at-apex", "unsigned"}) {
		t.Fatalf("auth without a signal target: %v", got)
	}
	if got := childBootstrapMethods(true, true); !reflect.DeepEqual(got, []string{"at-apex", "unsigned"}) {
		t.Fatalf("proxy: %v", got)
	}
}

func TestZoneChildBootstrapMethodsUsesProxyOption(t *testing.T) {
	var dsc DelegationSyncConf
	dsc.Child.Update.Bootstrap.Methods = []string{"at-apex", "at-ns"}
	if err := SetDelegationSyncConfig(dsc); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = SetDelegationSyncConfig(DelegationSyncConf{}) })

	// signalTarget gives the zone an in-bailiwick NS (ns.<zone>), so the
	// zone itself -- primary here -- owns the _signal name: at-ns is satisfiable.
	auth, _ := signalTarget("auth.example.", nil)
	auth.Options[OptDelSyncChild] = true
	proxy, _ := signalTarget("proxy.example.", nil)
	proxy.Options[OptDelSyncProxy] = true
	registerZones(t, auth, proxy)

	if got := auth.zoneChildBootstrapMethods(); !reflect.DeepEqual(got, []string{"at-apex", "at-ns"}) {
		t.Fatalf("auth zone: %v", got)
	}
	// A proxy never offers at-ns, even when the signal name would be local.
	if got := proxy.zoneChildBootstrapMethods(); !reflect.DeepEqual(got, []string{"at-apex"}) {
		t.Fatalf("proxy zone: %v", got)
	}
}

// at-ns is in the omit-default, but a zone only offers it when this server
// can publish the KEY at one of its NS signal names (D-6).
func TestZoneChildBootstrapMethodsRequiresSignalTarget(t *testing.T) {
	if err := SetDelegationSyncConfig(DelegationSyncConf{}); err != nil { // omit -> default list
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = SetDelegationSyncConfig(DelegationSyncConf{}) })

	local, _ := signalTarget("local.example.", nil)
	local.Options[OptDelSyncChild] = true
	away := newMapZone("away.example.", Primary, map[string][]dns.RR{
		"away.example.": {
			mustRR(t, "away.example. 3600 IN SOA ns.elsewhere.net. h.away.example. 1 3600 600 604800 300"),
			mustRR(t, "away.example. 3600 IN NS ns.elsewhere.net."),
		},
	})
	away.Options[OptDelSyncChild] = true
	registerZones(t, local, away)

	if got := local.zoneChildBootstrapMethods(); !reflect.DeepEqual(got, []string{"at-apex", "at-ns"}) {
		t.Fatalf("local signal target: %v", got)
	}
	if got := away.zoneChildBootstrapMethods(); !reflect.DeepEqual(got, []string{"at-apex"}) {
		t.Fatalf("no local signal target: %v (at-ns must be dropped)", got)
	}
}

// classifyAdvertisementLookup: a failed lookup is errBootstrapAdvertisementLookup
// (retryable), an empty answer -- the IMR's NXDOMAIN/NODATA shape -- is "nothing
// published", which is the case for most parents today and must not fail.
func TestClassifyAdvertisementLookup(t *testing.T) {
	svcb := newBootstrapSVCB("updates.example.", "at-apex", 300)
	cases := []struct {
		name    string
		resp    *ImrResponse
		err     error
		wantRRs int
		wantErr bool
	}{
		{"transport error", nil, errors.New("timeout"), 0, true},
		{"nil response", nil, nil, 0, true},
		{"resolver failure", &ImrResponse{Error: true, ErrorMsg: "failed to resolve"}, nil, 0, true},
		{"NXDOMAIN or NODATA is absent, not failed", &ImrResponse{Msg: "NXDOMAIN (negative response type 3)"}, nil, 0, false},
		{"published", &ImrResponse{RRset: &core.RRset{RRs: []dns.RR{svcb}}}, nil, 1, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rrs, err := classifyAdvertisementLookup("updates.example.", c.resp, c.err)
			if c.wantErr {
				if !errors.Is(err, errBootstrapAdvertisementLookup) {
					t.Fatalf("err = %v, want errBootstrapAdvertisementLookup", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(rrs) != c.wantRRs {
				t.Fatalf("rrs = %d, want %d", len(rrs), c.wantRRs)
			}
		})
	}
}

func TestBootstrapAdvertisementUsable(t *testing.T) {
	cases := []struct {
		dsync, svcb, insecure, want bool
	}{
		{true, true, false, true},
		{true, false, false, false},
		{false, true, false, false},
		{false, false, false, false},
		{false, false, true, true},
		{true, false, true, true},
	}
	for _, c := range cases {
		if got := bootstrapAdvertisementUsable(c.dsync, c.svcb, c.insecure); got != c.want {
			t.Errorf("usable(dsync=%v svcb=%v insecure=%v) = %v, want %v", c.dsync, c.svcb, c.insecure, got, c.want)
		}
	}
}

// The parent's SVCB bootstrap advertisement is parent-derived input the child
// acts on (D-7 rider): it counts only when both the DSYNC that named the
// target and the SVCB itself DNSSEC-validated, or under allow-insecure.
// Otherwise it is treated as absent, so the child falls back to its own list
// rather than being steered by a forged advertisement.
func TestAdvertisedBootstrapMethodsRequiresAuthentication(t *testing.T) {
	const target = "updates.parent.example."
	imr := newTestImr(t)
	svcb := newBootstrapSVCB(target, "at-apex,manual", 300)
	imr.Cache.Set(target, dns.TypeSVCB, &cache.CachedRRset{
		Name: target, RRtype: dns.TypeSVCB,
		RRset:   &core.RRset{Name: target, RRtype: dns.TypeSVCB, RRs: []dns.RR{svcb}},
		Context: cache.ContextAnswer,
		State:   cache.ValidationStateSecure,
	})
	ctx := context.Background()

	got, present, err := advertisedBootstrapMethods(ctx, imr, &DsyncTarget{Name: target, Validated: true}, false)
	if err != nil || !present || !reflect.DeepEqual(got, []string{"at-apex", "manual"}) {
		t.Fatalf("validated: got %v present=%v err=%v", got, present, err)
	}
	if _, present, err := advertisedBootstrapMethods(ctx, imr, &DsyncTarget{Name: target, Validated: false}, false); present || err != nil {
		t.Fatalf("unvalidated DSYNC: advertisement must be ignored, not failed (present=%v err=%v)", present, err)
	}
	got, present, err = advertisedBootstrapMethods(ctx, imr, &DsyncTarget{Name: target, Validated: false}, true)
	if err != nil || !present || !reflect.DeepEqual(got, []string{"at-apex", "manual"}) {
		t.Fatalf("unvalidated DSYNC under allow-insecure: got %v present=%v err=%v", got, present, err)
	}
	if _, present, err := advertisedBootstrapMethods(ctx, imr, nil, true); present || err != nil {
		t.Fatal("nil target must be absent")
	}
}
