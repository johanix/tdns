package tdns

import (
	"reflect"
	"strings"
	"testing"
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
