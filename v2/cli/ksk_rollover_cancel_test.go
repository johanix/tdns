package cli

import (
	"strings"
	"testing"
)

// The --alg-roll abort must be confirmed by the daemon. A 200 carrying only
// {"cleared":true} is the manual-request path, not an abort, and used to be
// reported as one.
func TestCancelResponseMessageAlgRoll(t *testing.T) {
	cases := []struct {
		name, body, want, wantErr string
	}{
		{"cleared-only is not an abort", `{"zone":"z.","cleared":true}`, "", "did not confirm"},
		{"aborted with detail", `{"zone":"z.","cleared":true,"aborted":true,"detail":"removed KSK 12345"}`, "removed KSK 12345", ""},
		{"aborted without detail", `{"zone":"z.","cleared":true,"aborted":true}`, "aborted the KSK algorithm rollover for zone z.", ""},
		{"garbage", `not json`, "", "parsing rollover/cancel response"},
	}
	for _, c := range cases {
		got, err := cancelResponseMessage([]byte(c.body), true, "KSK", "z.")
		switch {
		case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
			t.Errorf("%s: err = %v, want containing %q", c.name, err, c.wantErr)
		case c.wantErr == "" && err != nil:
			t.Errorf("%s: unexpected error %v", c.name, err)
		case c.wantErr == "" && got != c.want:
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
	if got, err := cancelResponseMessage([]byte(`{"cleared":true}`), false, "ZSK", "z."); err != nil || got != "cleared manual ZSK rollover request for zone z." {
		t.Errorf("manual clear: got %q, %v", got, err)
	}
}
