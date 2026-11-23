package tdns

import (
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
// and the test hooks.
func resetApiDispatch(t *testing.T) {
	t.Cleanup(func() {
		apiTCPServers.Lock()
		apiTCPServers.srvs, apiTCPServers.plaintext, apiTCPServers.stopped, apiTCPServers.stoppedBy = nil, false, nil, ""
		apiTCPServers.Unlock()
		apiListenersStarted.Store(nil)
		apiDispatchLockedHook, apiServeHook = nil, nil
	})
}

// dispatchTestAccessFile is an access file that loads (no clients).
func dispatchTestAccessFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "access.yaml")
	if err := os.WriteFile(path, []byte("clients: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// plaintextApiConf is a daemon that starts one plaintext TCP listener on
// addr, with no access file.
func plaintextApiConf(addr string) *Config {
	conf := &Config{}
	conf.Internal.ApiAccess = &apiAccessHolder{}
	conf.Internal.ApiAccess.p.Store(&accessState{}) // no access file at start
	conf.Internal.ServerErrors = NewServerErrorRegistry()
	conf.ApiServer.Addresses = []string{addr}
	conf.ApiServer.UseTLS = false
	return conf
}

// reloadAddingAccessFile is a reload whose new config has an access file,
// and usetls: true, which a running listener does not take up.
func reloadAddingAccessFile(conf *Config, accessFile string) string {
	conf.ApiServer.AccessFile = accessFile
	conf.ApiServer.UseTLS = true
	return conf.reloadApiAccess()
}

func startDispatcher(t *testing.T, conf *Config) {
	t.Helper()
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	if err := APIdispatcher(conf, mux.NewRouter(), done); err != nil {
		t.Fatal(err)
	}
}

// A reload that puts an access file in force while the daemon starts, on
// either side of APIdispatcher registering its TCP servers, leaves no
// plaintext TCP listener: before, the dispatcher sees the policy and starts
// none; after, the reload finds the servers registered and closes them, by the
// transport they started with, whatever the reload made of usetls. (These
// two run one after the other; TestReloadHeldAtTheRegistrationBoundary puts
// the reload in between.) The listeners are bound before APIdispatcher
// returns, so what listens is known at once.
func TestReloadDuringStartLeavesNoPlaintextListener(t *testing.T) {
	resetApiDispatch(t)
	accessFile := dispatchTestAccessFile(t)

	// The reload first: its policy is in force when the dispatcher
	// registers, so the plaintext server is not started.
	addr := freeTCPAddr(t)
	conf := plaintextApiConf(addr)
	if msg := reloadAddingAccessFile(conf, accessFile); !strings.Contains(msg, "Access file reloaded") {
		t.Fatalf("reload: %q", msg)
	}
	conf.ApiServer.AccessFile, conf.ApiServer.UseTLS = "", false // what the dispatcher started from
	startDispatcher(t, conf)
	if listening(addr) {
		t.Errorf("reload before registration: a plaintext listener runs on %s with the access file in force", addr)
	}
	if !slices.Contains(stoppedPlaintextApiListeners(), addr) || apiTCPStoppedBy() != accessFile {
		t.Errorf("reload before registration: %s not reported as stopped by %s: %v by %q", addr, accessFile, stoppedPlaintextApiListeners(), apiTCPStoppedBy())
	}

	// The dispatcher first: the server is registered as plaintext, as it
	// started, and the reload closes it, though the reloaded config says TLS.
	addr = freeTCPAddr(t)
	conf = plaintextApiConf(addr)
	startDispatcher(t, conf)
	if !listening(addr) {
		t.Fatalf("no plaintext listener on %s before the reload", addr)
	}
	if msg := reloadAddingAccessFile(conf, accessFile); !strings.Contains(msg, "STOPPED") || !strings.Contains(msg, addr) {
		t.Fatalf("reload after registration: %q, want %s stopped", msg, addr)
	}
	if listening(addr) {
		t.Errorf("reload after registration: the plaintext listener on %s still answers", addr)
	}
}

// A reload that comes while start-up is between the policy check and the
// registration waits for the registration: it cannot put its policy in force
// in between (the dispatcher would then start a plaintext listener it had
// already decided was allowed). When it goes ahead it finds the server
// registered and closes it, so no plaintext listener answers.
func TestReloadHeldAtTheRegistrationBoundary(t *testing.T) {
	resetApiDispatch(t)
	accessFile := dispatchTestAccessFile(t)
	addr := freeTCPAddr(t)
	conf := plaintextApiConf(addr)

	reloaded := make(chan string, 1)
	held := false
	apiDispatchLockedHook = func() {
		held = true
		reloading := make(chan struct{})
		go func() {
			close(reloading)
			reloaded <- reloadAddingAccessFile(conf, accessFile)
		}()
		<-reloading
		// Proving that something does not happen takes a window. Unheld,
		// the reload finishes in well under it; a slow machine can only
		// make this miss a regression, never fail a correct build.
		select {
		case msg := <-reloaded:
			reloaded <- msg
			t.Errorf("the reload finished while start-up was held between the policy check and the registration: %q", msg)
		case <-time.After(300 * time.Millisecond):
		}
		if apiAccessInForce(conf) {
			t.Error("the access policy came into force while start-up was held between the policy check and the registration")
		}
	}
	startDispatcher(t, conf)
	apiDispatchLockedHook = nil
	if !held {
		t.Fatal("start-up never reached the registration boundary")
	}

	var msg string
	select {
	case msg = <-reloaded:
	case <-time.After(5 * time.Second):
		t.Fatal("the reload did not finish after start-up released the lock")
	}
	if !strings.Contains(msg, "STOPPED") || !strings.Contains(msg, addr) {
		t.Errorf("reload held at the boundary: %q, want %s stopped", msg, addr)
	}
	if !apiAccessInForce(conf) {
		t.Error("the access policy is not in force after the reload")
	}
	if listening(addr) {
		t.Errorf("a plaintext listener answers on %s with the access file in force", addr)
	}
}

// APIdispatcher reads apiserver.access-file once, with the rest: a reload on
// the socket (served before the TCP listeners) that adds an access file
// after that does not make the listener TLS 1.3 only while it is recorded as
// started without one, which would leave a later reload that removes the file
// without its restart notice. The running policy still holds every handshake
// to TLS 1.3 while the access file is in force.
func TestDispatcherReadsTheAccessFileOnce(t *testing.T) {
	resetApiDispatch(t)
	addr := freeTCPAddr(t)
	conf := plaintextApiConf(addr)
	conf.ApiServer.UseTLS = true
	apiServeHook = func(string, func()) {} // nothing served: this is about the setup
	apiDispatchLockedHook = func() {
		conf.ApiServer.AccessFile = dispatchTestAccessFile(t) // the reload over the socket
	}
	startDispatcher(t, conf)
	apiDispatchLockedHook, apiServeHook = nil, nil

	apiTCPServers.Lock()
	srvs := slices.Clone(apiTCPServers.srvs)
	apiTCPServers.Unlock()
	if len(srvs) != 1 {
		t.Fatalf("%d TCP servers registered, want 1", len(srvs))
	}
	tc := srvs[0].srv.TLSConfig
	rec := apiListenersStarted.Load()
	if rec == nil || rec.TLS13Only || tc.MinVersion == tls.VersionTLS13 {
		t.Errorf("started without an access file: listener MinVersion %#x, recorded %+v; want neither TLS 1.3 only", tc.MinVersion, rec)
	}

	// The reload's policy, once in force, is held to at the handshake.
	if msg := conf.reloadApiAccess(); !strings.Contains(msg, "Access file reloaded") {
		t.Fatalf("reload: %q", msg)
	}
	c, err := tc.GetConfigForClient(&tls.ClientHelloInfo{SupportedVersions: []uint16{tls.VersionTLS12}})
	if err != nil || c == nil || c.MinVersion != tls.VersionTLS13 {
		t.Errorf("TLS 1.2 client with the access file in force: config %+v, %v; want a TLS 1.3 only one", c, err)
	}
}

// A plaintext server that activation closes never accepts a connection
// afterwards, wherever its goroutine is: the dispatcher binds the socket
// before the server starts and activation closes the socket with the server,
// so there is no bind after the policy is in force. Here the goroutine is
// held until after the reload, then let go.
func TestClosedByActivationNeverAccepts(t *testing.T) {
	resetApiDispatch(t)
	addr := freeTCPAddr(t)
	conf := plaintextApiConf(addr)
	release, served := make(chan struct{}), make(chan struct{})
	apiServeHook = func(_ string, serve func()) {
		<-release
		serve()
		close(served)
	}
	startDispatcher(t, conf)
	apiServeHook = nil
	if !listening(addr) {
		t.Fatalf("no socket bound on %s when APIdispatcher returned", addr)
	}

	if msg := reloadAddingAccessFile(conf, dispatchTestAccessFile(t)); !strings.Contains(msg, "STOPPED") || !strings.Contains(msg, addr) {
		t.Fatalf("reload: %q, want %s stopped", msg, addr)
	}
	if listening(addr) {
		t.Errorf("%s accepts a connection after activation closed it, before its server started", addr)
	}
	close(release)
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("the closed server's goroutine did not return")
	}
	if listening(addr) {
		t.Errorf("%s accepts a connection after activation closed it and its server ran", addr)
	}
	// Nothing holds the port any more.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Errorf("%s is still bound after activation closed it: %v", addr, err)
	} else {
		ln.Close()
	}
}

// An address that cannot be bound is logged, as ListenAndServe's failure was,
// and the other listeners start; the dispatcher returns no error.
func TestBindFailureLeavesTheOtherListeners(t *testing.T) {
	resetApiDispatch(t)
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	free := freeTCPAddr(t)
	conf := plaintextApiConf(busy.Addr().String())
	conf.ApiServer.Addresses = append(conf.ApiServer.Addresses, free)
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
}
