package tdns

import (
	"reflect"
	"testing"
	"time"
)

func TestCompileDelegationPolicyEmptyMechanismsStayEmpty(t *testing.T) {
	p, err := compileDelegationPolicy("locked-down", DelegationPolicyConf{
		Bootstrap: DelegationBootstrapConf{
			Mechanisms: []string{},
			Manual:     true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Mechanisms) != 0 {
		t.Fatalf("empty mechanisms filled to %v; locked-down must not inherit [at-apex, at-ns]", p.Mechanisms)
	}
	if !p.Manual {
		t.Fatal("manual flag dropped")
	}
}

func TestBootstrapSVCBMethods(t *testing.T) {
	tests := []struct {
		name string
		p    DelegationPolicy
		want []string
	}{
		{"default", DefaultDelegationPolicy(), []string{"at-apex", "at-ns"}},
		{"permissive", DelegationPolicy{Mechanisms: []string{"at-apex", "at-ns"}, Manual: true}, []string{"unsigned", "manual"}},
		{"locked-down", DelegationPolicy{Mechanisms: []string{}, RequireDnssec: true, Manual: true}, []string{"manual"}},
		{"nothing", DelegationPolicy{}, nil},
		{"at-apex only", DelegationPolicy{Mechanisms: []string{"at-apex"}, RequireDnssec: true}, []string{"at-apex"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.p.BootstrapSVCBMethods()
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestBindDelegationPolicyUnknownQuarantines(t *testing.T) {
	SetDelegationSyncConfig(DelegationSyncConf{})
	t.Cleanup(func() { SetDelegationSyncConfig(DelegationSyncConf{}) })
	_, err := bindDelegationPolicy(&ZoneConf{DelegationPolicy: "no-such"})
	if err == nil {
		t.Fatal("unknown policy must fail closed")
	}
}

func TestBindDelegationPolicyOmittedGetsDefault(t *testing.T) {
	SetDelegationSyncConfig(DelegationSyncConf{})
	t.Cleanup(func() { SetDelegationSyncConfig(DelegationSyncConf{}) })
	p, err := bindDelegationPolicy(&ZoneConf{})
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "default" || !p.RequireDnssec || p.AllowUnvalidatedUpload {
		t.Fatalf("omit did not bind default: %+v", p)
	}
}

func TestCompileDelegationPolicyRetryAndRequireDnssec(t *testing.T) {
	f := false
	p, err := compileDelegationPolicy("permissive", DelegationPolicyConf{
		Bootstrap: DelegationBootstrapConf{
			Mechanisms:             []string{"at-apex"},
			RequireDnssec:          &f,
			AllowUnvalidatedUpload: true,
			Retry:                  DelegationRetryConf{MaxAttempts: 3, Interval: 30 * time.Second},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.RequireDnssec {
		t.Fatal("explicit false require-dnssec became true")
	}
	if p.RetryMaxAttempts != 3 || p.RetryInterval != 30*time.Second {
		t.Fatalf("retry = %d/%s", p.RetryMaxAttempts, p.RetryInterval)
	}
}

func TestCompileDelegationPolicyUnknownMechanismFails(t *testing.T) {
	_, err := compileDelegationPolicy("typo", DelegationPolicyConf{
		Bootstrap: DelegationBootstrapConf{Mechanisms: []string{"at-apx"}},
	})
	if err == nil {
		t.Fatal("unknown mechanism must fail closed")
	}
}

func TestCompileChildBootstrapMethods(t *testing.T) {
	got, err := compileChildBootstrapMethods(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"at-apex"}) {
		t.Fatalf("omit defaulted to %v", got)
	}
	empty, err := compileChildBootstrapMethods([]string{})
	if err != nil {
		t.Fatal(err)
	}
	if len(empty) != 0 {
		t.Fatalf("empty list filled to %v", empty)
	}
	if _, err := compileChildBootstrapMethods([]string{"at-apex", "nope"}); err == nil {
		t.Fatal("unknown child method must fail closed")
	}
}

func TestFindParentZoneSkipsTheChild(t *testing.T) {
	child := &ZoneData{ZoneName: "child.example."}
	parent := &ZoneData{
		ZoneName: "example.",
		DelegationPolicy: &DelegationPolicy{
			Name:       "manual",
			Mechanisms: []string{"at-apex"},
			Manual:     true,
		},
	}
	registerZones(t, child, parent)

	if got := FindZone("child.example."); got != child {
		t.Fatalf("FindZone returned %v, want the child", zoneName(got))
	}
	if got := FindParentZone("child.example."); got != parent {
		t.Fatalf("FindParentZone returned %v, want the parent", zoneName(got))
	}
	pol := parentDelegationPolicy("child.example.")
	if pol.Name != "manual" {
		t.Fatalf("parentDelegationPolicy used %q, want the parent's manual policy", pol.Name)
	}
}

func TestParentDelegationPolicyUnknownUsesCompiledDefault(t *testing.T) {
	if err := SetDelegationSyncConfig(DelegationSyncConf{
		Policies: map[string]DelegationPolicyConf{
			"default": {Bootstrap: DelegationBootstrapConf{Mechanisms: []string{"at-ns"}}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = SetDelegationSyncConfig(DelegationSyncConf{}) })

	pol := parentDelegationPolicy("orphan.example.")
	if pol.Name != "default" || !reflect.DeepEqual(pol.Mechanisms, []string{"at-ns"}) {
		t.Fatalf("unknown parent must use compiled default, got %+v", pol)
	}
}

func TestRebindLiveDelegationPoliciesOnSetConfig(t *testing.T) {
	if err := SetDelegationSyncConfig(DelegationSyncConf{
		Policies: map[string]DelegationPolicyConf{
			"default": {Bootstrap: DelegationBootstrapConf{Mechanisms: []string{"at-apex"}}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = SetDelegationSyncConfig(DelegationSyncConf{}) })

	p, _ := lookupDelegationPolicy("default")
	zd := &ZoneData{ZoneName: "rebind-t1.example.", DelegationPolicy: &p}
	Zones.Set(zd.ZoneName, zd)
	t.Cleanup(func() { Zones.Remove(zd.ZoneName) })

	if err := SetDelegationSyncConfig(DelegationSyncConf{
		Policies: map[string]DelegationPolicyConf{
			"default": {Bootstrap: DelegationBootstrapConf{Mechanisms: []string{"at-ns"}}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	got := zd.boundDelegationPolicy()
	if len(got.Mechanisms) != 1 || got.Mechanisms[0] != "at-ns" {
		t.Fatalf("stale snapshot after SetDelegationSyncConfig: %+v", got)
	}
}

func zoneName(zd *ZoneData) string {
	if zd == nil {
		return "<nil>"
	}
	return zd.ZoneName
}
