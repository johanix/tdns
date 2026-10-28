/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import "testing"

func TestDnssecValidationNotEnforced(t *testing.T) {
	yes, no := true, false
	for _, tc := range []struct {
		name    string
		active  *bool
		require *bool
		running *Imr // the published resolver; nil: not up yet
		want    bool
	}{
		{"default", nil, nil, nil, false},
		{"required", nil, &yes, nil, false},
		{"configured not enforced", nil, &no, nil, true},
		{"configured not enforced, no resolver", &no, &no, nil, false},
		{"running, required", nil, &no, &Imr{RequireDnssecValidation: true}, false},
		{"running, not enforced", nil, nil, &Imr{RequireDnssecValidation: false}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf := &Config{}
			conf.Imr.Active = tc.active
			conf.Imr.RequireDnssecValidation = tc.require
			conf.Internal.ImrReady = NewImrReadiness()
			if tc.running != nil {
				conf.Internal.ImrEngine = tc.running
				conf.Internal.ImrReady.Publish()
			}
			if got := conf.DnssecValidationNotEnforced(); got != tc.want {
				t.Errorf("DnssecValidationNotEnforced() = %v, want %v", got, tc.want)
			}
		})
	}
	var none *Config
	if none.DnssecValidationNotEnforced() {
		t.Error("a nil config reports validation not enforced")
	}
}
