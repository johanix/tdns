package tdns

import (
	"reflect"
	"testing"
	"time"
)

func TestCompileDelegationPolicyEmptyMechanismsStayEmpty(t *testing.T) {
	p := compileDelegationPolicy("locked-down", DelegationPolicyConf{
		Bootstrap: DelegationBootstrapConf{
			Mechanisms: []string{},
			Manual:     true,
		},
	})
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
	p := compileDelegationPolicy("permissive", DelegationPolicyConf{
		Bootstrap: DelegationBootstrapConf{
			Mechanisms:             []string{"at-apex"},
			RequireDnssec:          &f,
			AllowUnvalidatedUpload: true,
			Retry:                  DelegationRetryConf{MaxAttempts: 3, Interval: 30 * time.Second},
		},
	})
	if p.RequireDnssec {
		t.Fatal("explicit false require-dnssec became true")
	}
	if p.RetryMaxAttempts != 3 || p.RetryInterval != 30*time.Second {
		t.Fatalf("retry = %d/%s", p.RetryMaxAttempts, p.RetryInterval)
	}
}
