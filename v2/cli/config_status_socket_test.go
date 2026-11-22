package cli

import (
	"strings"
	"testing"

	tdns "github.com/johanix/tdns/v2"
)

// `config status` names the local admin socket for every daemon that has one
// (tdns-imr has its own printer and once left the line out), and says when
// the configured socket is not being served.
func TestConfigStatusNamesTheAdminSocket(t *testing.T) {
	const sock = "/var/run/tdns/tdns-imr.sock"
	notServed := tdns.ServerError{Category: tdns.ErrCatTransport, Subtype: tdns.ErrSubApiSocket, Message: "not served"}
	other := tdns.ServerError{Category: tdns.ErrCatUpstream, Subtype: tdns.ErrSubImrPriming, Message: "no roots"}

	for _, tc := range []struct {
		name    string
		resp    tdns.ConfigResponse
		want    string
		notWant string
	}{
		{name: "no socket", resp: tdns.ConfigResponse{}},
		{
			name: "socket served",
			resp: tdns.ConfigResponse{ApiServer: tdns.ApiServerConf{Socket: sock}, ServerErrors: []tdns.ServerError{other}},
			want: "local admin socket " + sock, notWant: "NOT served",
		},
		{
			name: "socket configured but not served",
			resp: tdns.ConfigResponse{ApiServer: tdns.ApiServerConf{Socket: sock}, ServerErrors: []tdns.ServerError{other, notServed}},
			want: "local admin socket " + sock + " is configured but NOT served",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := apiSocketStatusLine(tc.resp)
			if tc.want == "" {
				if got != "" {
					t.Fatalf("line = %q, want none", got)
				}
				return
			}
			if !strings.Contains(got, tc.want) {
				t.Errorf("line = %q, want it to contain %q", got, tc.want)
			}
			if tc.notWant != "" && strings.Contains(got, tc.notWant) {
				t.Errorf("line = %q, should not contain %q", got, tc.notWant)
			}
		})
	}
}

// A socket-only tdns-auth config is valid, so `config check` must not fail it
// for having no apiserver.addresses; with neither, it still fails.
func TestConfigCheckAcceptsASocketOnlyApiServer(t *testing.T) {
	for _, tc := range []struct {
		name     string
		socket   string
		wantFail bool
	}{
		{name: "socket, no addresses", socket: "/var/run/tdns/tdns-auth.sock"},
		{name: "no socket, no addresses", wantFail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &tdns.Config{}
			cfg.ApiServer.Socket = tc.socket
			rep := newCCReport()
			checkApiServer(cfg, "", rep)
			var addrFail bool
			for _, r := range rep.byGroup["API server"] {
				if r.check == "addresses" && r.level == ccFAIL {
					addrFail = true
				}
			}
			if addrFail != tc.wantFail {
				t.Errorf("addresses check failed = %v, want %v", addrFail, tc.wantFail)
			}
		})
	}
}
