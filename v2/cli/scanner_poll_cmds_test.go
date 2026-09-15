package cli

import (
	"testing"

	tdns "github.com/johanix/tdns/v2"
	"github.com/spf13/cobra"
)

func TestFormatScannerPoll(t *testing.T) {
	for _, tc := range []struct {
		resp tdns.ScannerPollResponse
		want string
	}{
		{tdns.ScannerPollResponse{Enabled: true}, "polling on\n"},
		{tdns.ScannerPollResponse{Enabled: false}, "polling off\n"},
		{tdns.ScannerPollResponse{Enabled: false, Msg: "polling switched off; a round in progress starts no more children"},
			"polling switched off; a round in progress starts no more children\npolling off\n"},
	} {
		if got := formatScannerPoll(tc.resp); got != tc.want {
			t.Errorf("formatScannerPoll(%+v) = %q, want %q", tc.resp, got, tc.want)
		}
	}
}

// Both the canonical auth tree and every instance tree offer the switch.
func TestAuthTreesOfferScannerPoll(t *testing.T) {
	for _, root := range []*cobra.Command{AuthCmd, NewAuthTree("sectdns", "sectdns")} {
		c, _, err := root.Find([]string{"scanner", "poll"})
		if err != nil || c == nil || c.Name() != "poll" {
			t.Errorf("%s: no \"scanner poll\" command (%v)", root.Name(), err)
		}
	}
}
