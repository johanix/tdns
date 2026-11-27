package tdns

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/mux"
)

// freeTCPAddr is a loopback address nothing listens on (as far as a test can
// tell: it was free a moment ago).
func freeTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func listening(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// resetApiDispatch puts the process-wide dispatcher state back when the test
// ends: the server registry, the record of what the listeners started with,
// and the test hook.
func resetApiDispatch(t *testing.T) {
	t.Cleanup(func() {
		apiTCPServers.Lock()
		apiTCPServers.srvs = nil
		apiTCPServers.noCert, apiTCPServers.noCertFile = nil, ""
		apiTCPServers.failed, apiTCPServers.pins = nil, nil
		apiTCPServers.Unlock()
		apiListenersStarted.Store(nil)
		apiServeHook = nil
	})
}

// tlsApiConf is a daemon that starts TCP listeners on addrs with the API
// certificate the test writes, and no access file.
func tlsApiConf(t *testing.T, addrs ...string) (*Config, string) {
	t.Helper()
	cert, key, pin := testApiCertFiles(t)
	conf := &Config{}
	conf.Internal.ApiAccess = &apiAccessHolder{}
	conf.Internal.ServerErrors = NewServerErrorRegistry()
	conf.ApiServer.Addresses = addrs
	conf.ApiServer.CertFile, conf.ApiServer.KeyFile = cert, key
	conf.ApiServer.AccessFile = filepath.Join(t.TempDir(), "access.yaml")
	return conf, pin
}

func startDispatcher(t *testing.T, conf *Config) {
	t.Helper()
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	if err := APIdispatcher(conf, mux.NewRouter(), done); err != nil {
		t.Fatal(err)
	}
}

// configStatusOverSocket is the daemon's `config status` reply, asked for
// over e's local admin socket, as tdns-cli asks.
func configStatusOverSocket(t *testing.T, e *authEnv) ConfigResponse {
	t.Helper()
	st, body := e.callSocket(t, "/api/v1/config", `{"Command":"status"}`)
	var cr ConfigResponse
	if err := json.Unmarshal([]byte(body), &cr); st != http.StatusOK || err != nil {
		t.Fatalf("config status: %d %v %q", st, err, body)
	}
	return cr
}

// The TCP listeners speak TLS 1.3, with the certificate whose pin /access
// reports, whatever the config says: there is no plaintext TCP API.
func TestDispatcherServesTLS13WithThePin(t *testing.T) {
	resetApiDispatch(t)
	addr := freeTCPAddr(t)
	conf, pin := tlsApiConf(t, addr)
	startDispatcher(t, conf)
	if got := apiServedPins(); !slices.Equal(got, []string{pin}) {
		t.Errorf("served pins %v, want [%s]", got, pin)
	}
	c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	cs := c.ConnectionState()
	if cs.Version != tls.VersionTLS13 || SPKISHA256(cs.PeerCertificates[0]) != pin {
		t.Errorf("version %x, pin %s; want TLS 1.3 and %s", cs.Version, SPKISHA256(cs.PeerCertificates[0]), pin)
	}
	// Plain HTTP on the same port is not answered as HTTP.
	resp, err := http.Post("http://"+addr+"/api/v1/ping", "application/json", nil)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Errorf("plain HTTP got 200, want no plaintext API")
		}
	}
}

// An address that cannot be bound is logged, as ListenAndServe's failure was,
// and the other listeners start; the dispatcher returns no error. config
// status lists only the bound one as listening, and the other as failed, with
// the bind error, so it is neither listed as listening nor left out.
func TestBindFailureLeavesTheOtherListeners(t *testing.T) {
	resetApiDispatch(t)
	e := newAuthEnv(t, "-", nil)
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	free := freeTCPAddr(t)
	conf, _ := tlsApiConf(t, busy.Addr().String(), free)
	startDispatcher(t, conf)
	if !listening(free) {
		t.Errorf("no listener on %s after %s failed to bind", free, busy.Addr())
	}
	apiTCPServers.Lock()
	n := len(apiTCPServers.srvs)
	var got string
	if n == 1 {
		got = apiTCPServers.srvs[0].srv.Addr
	}
	apiTCPServers.Unlock()
	if n != 1 || got != free {
		t.Errorf("registered %d server(s) (%q), want the one on %s", n, got, free)
	}

	cr := configStatusOverSocket(t, e)
	if !slices.Equal(cr.ApiTCPListening, []string{free}) {
		t.Errorf("status: listening %v, want [%s]", cr.ApiTCPListening, free)
	}
	want := []ApiTCPFailure{{Address: busy.Addr().String(), Error: "bind: " + syscall.EADDRINUSE.Error()}}
	if !slices.Equal(cr.ApiTCPFailed, want) {
		t.Errorf("status: failed %+v, want %+v", cr.ApiTCPFailed, want)
	}
	if len(cr.ApiTCPNotStarted) != 0 {
		t.Errorf("status: not started %v; want none", cr.ApiTCPNotStarted)
	}
}

// A listener whose certificate does not load is not started: config status
// does not list it as listening, reports it failed with the error, and
// nothing answers there.
func TestServeFailureIsNotReportedAsListening(t *testing.T) {
	resetApiDispatch(t)
	e := newAuthEnv(t, "-", nil)
	addr := freeTCPAddr(t)
	conf, _ := tlsApiConf(t, addr)
	dir := t.TempDir()
	conf.ApiServer.CertFile = filepath.Join(dir, "missing.crt")
	conf.ApiServer.KeyFile = filepath.Join(dir, "missing.key")
	startDispatcher(t, conf)

	cr := configStatusOverSocket(t, e) // decided before APIdispatcher returned
	if len(cr.ApiTCPListening) != 0 {
		t.Errorf("status: listening %v, want none", cr.ApiTCPListening)
	}
	if len(cr.ApiTCPFailed) != 1 || cr.ApiTCPFailed[0].Address != addr || !strings.Contains(cr.ApiTCPFailed[0].Error, "missing.crt") {
		t.Errorf("status: failed %+v, want %s with the certificate's error", cr.ApiTCPFailed, addr)
	}
	if listening(addr) {
		t.Errorf("%s still accepts connections after its server failed", addr)
	}
}
