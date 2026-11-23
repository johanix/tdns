package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"

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
		addrs    []string
		wantFail bool
		certFail bool // no certfile/keyfile is a failure only with addresses
		sockWarn bool
	}{
		{name: "socket, no addresses", socket: "/var/run/tdns/tdns-auth.sock"},
		{name: "no socket, no addresses", wantFail: true},
		// The daemon refuses a relative path, so nothing is served.
		{name: "relative socket, no addresses", socket: "admin.sock", wantFail: true},
		{name: "relative socket, addresses", socket: "admin.sock", addrs: []string{"127.0.0.1:8989"}, certFail: true, sockWarn: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &tdns.Config{}
			cfg.ApiServer.Socket = tc.socket
			cfg.ApiServer.Addresses = tc.addrs
			rep := newCCReport()
			checkApiServer(cfg, "", rep)
			var addrFail, certFail, sockWarn bool
			for _, r := range rep.byGroup["API server"] {
				switch {
				case r.check == "addresses" && r.level == ccFAIL:
					addrFail = true
				case r.check == "cert" && r.level == ccFAIL:
					certFail = true
				case r.check == "socket" && r.level == ccWARN:
					sockWarn = true
				}
			}
			if addrFail != tc.wantFail {
				t.Errorf("addresses check failed = %v, want %v", addrFail, tc.wantFail)
			}
			if certFail != tc.certFail {
				t.Errorf("cert check failed = %v, want %v", certFail, tc.certFail)
			}
			if sockWarn != tc.sockWarn {
				t.Errorf("socket warning = %v, want %v", sockWarn, tc.sockWarn)
			}
		})
	}
}

// tdns-imr builds its API router, and stops if that fails, whatever the
// addresses say: the key is needed for a socket-only resolver too. A socket
// path the daemon refuses is not reported as served.
func TestImrConfigCheckSocketOnly(t *testing.T) {
	for _, tc := range []struct {
		name       string
		socket     string
		key        string
		keyFail    bool
		sockWarn   bool
		servedInfo bool
	}{
		{name: "socket and key", socket: "/var/run/tdns/tdns-imr.sock", key: "k", servedInfo: true},
		{name: "socket, no key", socket: "/var/run/tdns/tdns-imr.sock", keyFail: true, servedInfo: true},
		{name: "relative socket", socket: "imr.sock", key: "k", sockWarn: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &tdns.Config{}
			cfg.ApiServer.Socket = tc.socket
			cfg.ApiServer.ApiKey = tdns.SensitiveString(tc.key)
			rep := newCCReport()
			checkImrApiServer(cfg, viper.New(), rep)
			var keyFail, sockWarn, servedInfo bool
			for _, r := range rep.byGroup["API server"] {
				switch {
				case r.check == "apikey" && r.level == ccFAIL:
					keyFail = true
				case r.check == "socket" && r.level == ccWARN:
					sockWarn = true
				case r.check == "addresses" && strings.Contains(r.msg, "served only on the local admin socket"):
					servedInfo = true
				}
			}
			if keyFail != tc.keyFail || sockWarn != tc.sockWarn || servedInfo != tc.servedInfo {
				t.Errorf("key fail %v, socket warning %v, served on the socket %v; want %v, %v, %v",
					keyFail, sockWarn, servedInfo, tc.keyFail, tc.sockWarn, tc.servedInfo)
			}
		})
	}
}

// config check decodes with viper, which does not apply the daemon's own
// default usetls: true. Without applyDaemonDefaults an access-file config with
// no usetls: line was reported as plaintext while the daemon served TLS. An
// explicit usetls: false with an access file is a failure: the daemon refuses
// it.
func TestConfigCheckUseTLSDefault(t *testing.T) {
	dir := t.TempDir()
	access := filepath.Join(dir, "access.yaml")
	if err := os.WriteFile(access, []byte("clients: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, usetls string
		fail         bool
	}{
		{"no usetls line", "", false},
		{"usetls: true", "   usetls: true\n", false},
		{"usetls: false", "   usetls: false\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := viper.New()
			v.SetConfigType("yaml")
			doc := "apiserver:\n   addresses: [ 127.0.0.1:8989 ]\n   socket: /var/run/tdns/tdns-auth.sock\n   access-file: " + access + "\n" + tc.usetls
			if err := v.ReadConfig(strings.NewReader(doc)); err != nil {
				t.Fatal(err)
			}
			var cfg tdns.Config
			if err := v.Unmarshal(&cfg); err != nil {
				t.Fatal(err)
			}
			applyDaemonDefaults(v, &cfg)
			rep := newCCReport()
			checkApiAccessFile(&cfg, rep)
			var failed bool
			for _, r := range rep.byGroup["API access file"] {
				if r.check == "usetls" && r.level == ccFAIL {
					failed = true
				}
			}
			if failed != tc.fail {
				t.Errorf("usetls failure = %v, want %v (UseTLS decoded as %v)", failed, tc.fail, cfg.ApiServer.UseTLS)
			}
		})
	}
}

// `config status` reports the plaintext TCP listeners an access file closed
// whether the daemon still runs a policy or not (removing the file does not
// reopen them), and says which of the two it is.
func TestConfigStatusReportsStoppedListeners(t *testing.T) {
	stopped := []string{"192.0.2.1:8080"}
	if out := captureStdout(t, func() { printApiTCPStopped(nil, "", true) }); out != "" {
		t.Errorf("nothing stopped: printed %q", out)
	}
	const file = "/etc/tdns/tdns-auth-access.yaml"
	for _, tc := range []struct {
		name   string
		by     string
		policy bool
		want   string
	}{
		{"policy in force", file, true, "access file requires TLS:\n    " + file + "\n"},
		{"access file removed", file, false, "came into force:\n    " + file + "\n  no access file is set now"},
		{"a daemon that does not name the file", "", true, "access file requires TLS;"},
		{"removed, file not named", "", false, "no access\n  file is set now"},
	} {
		out := captureStdout(t, func() { printApiTCPStopped(stopped, tc.by, tc.policy) })
		if !strings.HasPrefix(out, "TCP API STOPPED on 192.0.2.1:8080:\n") || !strings.Contains(out, tc.want) {
			t.Errorf("%s: printed %q, want it to contain %q", tc.name, out, tc.want)
		}
		for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
			if len(line) > 72 {
				t.Errorf("%s: line over 72 characters: %q", tc.name, line)
			}
		}
	}
}

// tdns-imr has its own `config status` printer, which must report the TCP
// API an access file stopped too, with the file, with the policy in force and
// after the file is removed.
func TestImrConfigStatusReportsStoppedListeners(t *testing.T) {
	const file = "/etc/tdns/tdns-imr-access.yaml"
	base := tdns.ConfigResponse{Msg: "tdns-imr: Configuration is ok", ApiTCPStopped: []string{"192.0.2.1:8080"}, ApiTCPStoppedBy: file}
	withPolicy := base
	withPolicy.Access = &tdns.ApiAccessStatus{File: file, KeyAuth: true}
	for _, tc := range []struct {
		name string
		resp tdns.ConfigResponse
		want string
	}{
		{"policy in force", withPolicy, "access file requires TLS:\n    " + file + "\n"},
		{"access file removed", base, "came into force:\n    " + file + "\n  no access file is set now"},
	} {
		out := captureStdout(t, func() { printImrConfigStatus(tc.resp) })
		if !strings.Contains(out, "TCP API STOPPED on 192.0.2.1:8080:\n") || !strings.Contains(out, tc.want) {
			t.Errorf("%s: printed %q, want the stopped listener and %q", tc.name, out, tc.want)
		}
	}
	if out := captureStdout(t, func() { printImrConfigStatus(tdns.ConfigResponse{Msg: "ok"}) }); strings.Contains(out, "STOPPED") {
		t.Errorf("nothing stopped: printed %q", out)
	}
}
