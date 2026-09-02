package tdns

import (
	"context"
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

	if got := childBootstrapMethods(false); !reflect.DeepEqual(got, []string{"at-apex", "at-ns", "unsigned"}) {
		t.Fatalf("auth: %v", got)
	}
	if got := childBootstrapMethods(true); !reflect.DeepEqual(got, []string{"at-apex", "unsigned"}) {
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

	auth := &ZoneData{Options: map[ZoneOption]bool{OptDelSyncChild: true}}
	if got := auth.zoneChildBootstrapMethods(); !reflect.DeepEqual(got, []string{"at-apex", "at-ns"}) {
		t.Fatalf("auth zone: %v", got)
	}
	proxy := &ZoneData{Options: map[ZoneOption]bool{OptDelSyncProxy: true}}
	if got := proxy.zoneChildBootstrapMethods(); !reflect.DeepEqual(got, []string{"at-apex"}) {
		t.Fatalf("proxy zone: %v", got)
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

	got, present := advertisedBootstrapMethods(ctx, imr, &DsyncTarget{Name: target, Validated: true}, false)
	if !present || !reflect.DeepEqual(got, []string{"at-apex", "manual"}) {
		t.Fatalf("validated: got %v present=%v", got, present)
	}
	if _, present := advertisedBootstrapMethods(ctx, imr, &DsyncTarget{Name: target, Validated: false}, false); present {
		t.Fatal("unvalidated DSYNC: advertisement must be ignored")
	}
	got, present = advertisedBootstrapMethods(ctx, imr, &DsyncTarget{Name: target, Validated: false}, true)
	if !present || !reflect.DeepEqual(got, []string{"at-apex", "manual"}) {
		t.Fatalf("unvalidated DSYNC under allow-insecure: got %v present=%v", got, present)
	}
	if _, present := advertisedBootstrapMethods(ctx, imr, nil, true); present {
		t.Fatal("nil target must be absent")
	}
}
