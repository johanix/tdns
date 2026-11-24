/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"strings"
	"testing"
)

// config check and the daemon's load (ValidateConfig) refuse the qmin tuning
// NewImr refuses, and pass absent keys, which get the defaults. A minimal file
// fails later, in the required-section check for the app type, so the passing
// cases only check that the error is not a qmin one.
func TestValidateConfigQminTuning(t *testing.T) {
	tuning := func(body string) string {
		return writeCfg(t, "imrengine:\n   tuning:\n"+body)
	}
	refused := []struct{ name, body, want string }{
		{"max 0", "      qmin-max-iterations: 0\n", "qmin-max-iterations"},
		{"one-label equal to max", "      qmin-max-iterations: 5\n      qmin-one-label: 5\n", "qmin-one-label"},
		{"one-label above the default max", "      qmin-one-label: 10\n", "qmin-one-label"},
		{"negative one-label", "      qmin-one-label: -1\n", "qmin-one-label"},
	}
	for _, tc := range refused {
		err := ValidateConfig(nil, tuning(tc.body))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: ValidateConfig = %v, want an error naming %s", tc.name, err, tc.want)
		}
	}
	passed := []struct{ name, cfg string }{
		{"no imrengine section", writeCfg(t, "log:\n   file: /dev/null\n")},
		{"tuning without qmin keys", tuning("      query-budget: 8s\n")},
		{"valid qmin keys", tuning("      qmin-max-iterations: 6\n      qmin-one-label: 2\n")},
	}
	for _, tc := range passed {
		if err := ValidateConfig(nil, tc.cfg); err != nil && strings.Contains(err.Error(), "qmin") {
			t.Errorf("%s: ValidateConfig = %v, want no qmin error", tc.name, err)
		}
	}
}
