package cli

import (
	"os"
	"path/filepath"
	"slices"
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

// A socket-only resolver is served on its socket, and needs no API key (there
// is none). A socket path the daemon refuses is not reported as served.
func TestImrConfigCheckSocketOnly(t *testing.T) {
	for _, tc := range []struct {
		name       string
		socket     string
		sockWarn   bool
		servedInfo bool
	}{
		{name: "socket", socket: "/var/run/tdns/tdns-imr.sock", servedInfo: true},
		{name: "relative socket", socket: "imr.sock", sockWarn: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &tdns.Config{}
			cfg.ApiServer.Socket = tc.socket
			rep := newCCReport()
			checkImrApiServer(cfg, viper.New(), rep)
			var keyFail, sockWarn, servedInfo bool
			for _, r := range rep.byGroup["API server"] {
				switch {
				case r.check == "apikey":
					keyFail = true
				case r.check == "socket" && r.level == ccWARN:
					sockWarn = true
				case r.check == "addresses" && strings.Contains(r.msg, "served only on the local admin socket"):
					servedInfo = true
				}
			}
			if keyFail || sockWarn != tc.sockWarn || servedInfo != tc.servedInfo {
				t.Errorf("key checked %v, socket warning %v, served on the socket %v; want false, %v, %v",
					keyFail, sockWarn, servedInfo, tc.sockWarn, tc.servedInfo)
			}
		})
	}
}

// config check names the lines of the API key era, which the daemon ignores
// (with a warning), and says a missing access file is no remote clients,
// with the touch line: info, not a failure.
func TestConfigCheckObsoleteKeysAndMissingAccessFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "tdns-auth.yaml")
	v := viper.New()
	v.SetConfigType("yaml")
	doc := "apiserver:\n   addresses: [ 127.0.0.1:8989 ]\n   apikey: k\n   usetls: false\n"
	if err := v.ReadConfig(strings.NewReader(doc)); err != nil {
		t.Fatal(err)
	}
	var cfg tdns.Config
	if err := v.Unmarshal(&cfg); err != nil {
		t.Fatal(err)
	}
	applyDaemonDefaults(v, &cfg, cfgPath)
	if want := filepath.Join(dir, "tdns-auth-access.yaml"); cfg.ApiServer.AccessFile != want {
		t.Fatalf("access file %q, want the default %s", cfg.ApiServer.AccessFile, want)
	}
	rep := newCCReport()
	checkObsoleteApiKeys(v, rep)
	checkApiAccessFile(&cfg, rep)
	warned := map[string]bool{}
	for _, r := range rep.byGroup["API server"] {
		if r.level == ccWARN {
			warned[r.check] = true
		}
	}
	if !warned["apikey"] || !warned["usetls"] {
		t.Errorf("warnings %v, want apikey and usetls", warned)
	}
	var info string
	for _, r := range rep.byGroup["API access file"] {
		if r.level == ccFAIL {
			t.Errorf("a missing access file failed the check: %s", r.msg)
		}
		info += r.msg
	}
	if !strings.Contains(info, "touch "+cfg.ApiServer.AccessFile) {
		t.Errorf("access file report %q, want the touch line", info)
	}
	// A file that others may write fails, with the fix.
	if err := os.WriteFile(cfg.ApiServer.AccessFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	os.Chmod(cfg.ApiServer.AccessFile, 0o666)
	rep = newCCReport()
	checkApiAccessFile(&cfg, rep)
	if r := rep.byGroup["API access file"]; len(r) != 1 || r[0].level != ccFAIL || !strings.Contains(r[0].msg, "chmod go-w") {
		t.Errorf("a world-writable access file: %+v, want a failure with chmod", r)
	}
}

// `config status` reports the TCP listeners the daemon did not start because
// it could not write its default API pair, with the certificate, instead of
// listing them as listening. Both printers (auth/agent and imr) do.
func TestConfigStatusReportsListenersNotStarted(t *testing.T) {
	addrs := []string{"127.0.0.1:8991", "10.6.0.4:8991"}
	const cert = "/etc/tdns/certs/tdns-auth-api.crt"
	if out := captureStdout(t, func() { printApiTCPNotStarted(nil, cert) }); out != "" {
		t.Errorf("nothing not started: printed %q", out)
	}
	for _, tc := range []struct {
		name, cert, want string
	}{
		{"cert named", cert, "TCP API NOT STARTED on 127.0.0.1:8991, 10.6.0.4:8991:\n" +
			"  no API certificate; the daemon could not write its default pair:\n" +
			"    " + cert + "\n" +
			"  the daemon's log says why; fix that and restart the daemon\n" +
			"  (the local socket works)\n"},
		{"a daemon that does not name the cert", "", "TCP API NOT STARTED on 127.0.0.1:8991, 10.6.0.4:8991:\n" +
			"  no API certificate; the daemon could not write its default pair\n" +
			"  the daemon's log says why; fix that and restart the daemon\n" +
			"  (the local socket works)\n"},
	} {
		out := captureStdout(t, func() { printApiTCPNotStarted(addrs, tc.cert) })
		if out != tc.want {
			t.Errorf("%s: printed\n%s\nwant\n%s", tc.name, out, tc.want)
		}
		for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
			if len(line) > 72 {
				t.Errorf("%s: line over 72 characters: %q", tc.name, line)
			}
		}
	}

	resp := tdns.ConfigResponse{Msg: "tdns-imr: Configuration is ok", ApiTCPNotStarted: addrs, ApiTCPNoCert: cert}
	if out := captureStdout(t, func() { printImrConfigStatus(resp) }); !strings.Contains(out, "TCP API NOT STARTED on 127.0.0.1:8991, 10.6.0.4:8991:\n") || !strings.Contains(out, "    "+cert+"\n") {
		t.Errorf("imr: printed %q, want the listeners not started and %s", out, cert)
	}
}

// `config status` reports the TCP listeners the daemon could not bind (or
// whose server stopped with an error), each with its error, rather than
// leaving them out. Both printers (auth/agent and imr) do.
func TestConfigStatusReportsFailedListeners(t *testing.T) {
	if out := captureStdout(t, func() { printApiTCPFailed(nil) }); out != "" {
		t.Errorf("nothing failed: printed %q", out)
	}
	one := []tdns.ApiTCPFailure{{Address: "127.0.0.1:8991", Error: "bind: address already in use"}}
	two := append(slices.Clone(one), tdns.ApiTCPFailure{Address: "10.6.0.4:8991", Error: "bind: can't assign requested address"})
	for _, tc := range []struct {
		name   string
		failed []tdns.ApiTCPFailure
		want   string
	}{
		{"one", one, "TCP API FAILED on 127.0.0.1:8991:\n" +
			"  bind: address already in use\n" +
			"  fix that and restart the daemon (the local socket works)\n"},
		{"two", two, "TCP API FAILED on 127.0.0.1:8991, 10.6.0.4:8991:\n" +
			"  127.0.0.1:8991: bind: address already in use\n" +
			"  10.6.0.4:8991: bind: can't assign requested address\n" +
			"  fix that and restart the daemon (the local socket works)\n"},
	} {
		out := captureStdout(t, func() { printApiTCPFailed(tc.failed) })
		if out != tc.want {
			t.Errorf("%s: printed\n%s\nwant\n%s", tc.name, out, tc.want)
		}
		for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
			if len(line) > 72 {
				t.Errorf("%s: line over 72 characters: %q", tc.name, line)
			}
		}
	}

	resp := tdns.ConfigResponse{Msg: "tdns-imr: Configuration is ok", ApiTCPFailed: one}
	if out := captureStdout(t, func() { printImrConfigStatus(resp) }); !strings.Contains(out, "TCP API FAILED on 127.0.0.1:8991:\n  bind: address already in use\n") {
		t.Errorf("imr: printed %q, want the failed listener and its error", out)
	}
}

// The ApiServer line lists the TCP listeners the daemon says listen, not the
// configured addresses: not those it did not start for want of a
// certificate, nor those an access file stopped, nor one that failed to bind.
func TestConfigStatusListeningLine(t *testing.T) {
	addrs := []string{"127.0.0.1:8991", "10.6.0.4:8991"}
	conf := tdns.ApiServerConf{Addresses: addrs}
	failed := []tdns.ApiTCPFailure{{Address: addrs[1], Error: "bind: address already in use"}}
	for _, tc := range []struct {
		name string
		resp tdns.ConfigResponse
		want string
	}{
		{"no addresses", tdns.ConfigResponse{}, "ApiServer: not listening on any addresses"},
		{"all started", tdns.ConfigResponse{ApiServer: conf, ApiTCPListening: addrs},
			"ApiServer: listening on [127.0.0.1:8991 10.6.0.4:8991]"},
		{"no certificate", tdns.ConfigResponse{ApiServer: conf, ApiTCPNotStarted: addrs},
			"ApiServer: NOT listening on any TCP address (see TCP API below)"},
		{"one failed to bind", tdns.ConfigResponse{ApiServer: conf, ApiTCPListening: addrs[:1], ApiTCPFailed: failed},
			"ApiServer: listening on [127.0.0.1:8991]"},
		{"none listening, one failed", tdns.ConfigResponse{ApiServer: conf, ApiTCPFailed: failed},
			"ApiServer: NOT listening on any TCP address (see TCP API below)"},
		{"configured, but none started (added by a reload)", tdns.ConfigResponse{ApiServer: conf},
			"ApiServer: not listening on any addresses"},
	} {
		if got := apiListeningLine(tc.resp); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}
