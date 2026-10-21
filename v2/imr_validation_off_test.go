/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import "testing"

func TestDnssecValidationOff(t *testing.T) {
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
		{"configured off", nil, &no, nil, true},
		{"configured off, no resolver", &no, &no, nil, false},
		{"running, required", nil, &no, &Imr{RequireDnssecValidation: true}, false},
		{"running, off", nil, nil, &Imr{RequireDnssecValidation: false}, true},
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
			if got := conf.DnssecValidationOff(); got != tc.want {
				t.Errorf("DnssecValidationOff() = %v, want %v", got, tc.want)
			}
		})
	}
	var none *Config
	if none.DnssecValidationOff() {
		t.Error("a nil config reports validation off")
	}
}
