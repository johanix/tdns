package tdns

import (
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

// A reload that puts an access file in force while the daemon starts, on
// either side of APIdispatcher registering its TCP servers, leaves no
// plaintext TCP listener: before, the dispatcher sees the policy and starts
// none; after, the reload finds the servers registered and closes them, by the
// transport they started with, whatever the reload made of usetls.
func TestReloadDuringStartLeavesNoPlaintextListener(t *testing.T) {
	t.Cleanup(func() {
		apiTCPServers.Lock()
		apiTCPServers.srvs, apiTCPServers.plaintext, apiTCPServers.stopped = nil, false, nil
		apiTCPServers.Unlock()
	})
	accessFile := filepath.Join(t.TempDir(), "access.yaml")
	if err := os.WriteFile(accessFile, []byte("clients: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	newConf := func(addr string) *Config {
		conf := &Config{}
		conf.Internal.ApiAccess = &apiAccessHolder{}
		conf.Internal.ApiAccess.p.Store(&accessState{}) // no access file at start
		conf.Internal.ServerErrors = NewServerErrorRegistry()
		conf.ApiServer.Addresses = []string{addr}
		conf.ApiServer.UseTLS = false
		return conf
	}
	reload := func(conf *Config) string {
		conf.ApiServer.AccessFile = accessFile
		conf.ApiServer.UseTLS = true // the new config says TLS; a running listener does not
		return conf.reloadApiAccess()
	}

	// The reload first: its policy is in force when the dispatcher
	// registers, so the plaintext server is not started.
	addr := freeTCPAddr(t)
	conf := newConf(addr)
	if msg := reload(conf); !strings.Contains(msg, "Access file reloaded") {
		t.Fatalf("reload: %q", msg)
	}
	conf.ApiServer.AccessFile, conf.ApiServer.UseTLS = "", false // what the dispatcher started from
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	if err := APIdispatcher(conf, mux.NewRouter(), done); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond) // a goroutine that was started would be listening by now
	if listening(addr) {
		t.Errorf("reload before registration: a plaintext listener runs on %s with the access file in force", addr)
	}
	if !slices.Contains(stoppedPlaintextApiListeners(), addr) {
		t.Errorf("reload before registration: %s not reported as stopped: %v", addr, stoppedPlaintextApiListeners())
	}

	// The dispatcher first: the server is registered as plaintext, as it
	// started, and the reload closes it, though the reloaded config says TLS.
	addr = freeTCPAddr(t)
	conf = newConf(addr)
	done2 := make(chan struct{})
	t.Cleanup(func() { close(done2) })
	if err := APIdispatcher(conf, mux.NewRouter(), done2); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !listening(addr) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !listening(addr) {
		t.Fatalf("no plaintext listener on %s before the reload", addr)
	}
	if msg := reload(conf); !strings.Contains(msg, "STOPPED") || !strings.Contains(msg, addr) {
		t.Fatalf("reload after registration: %q, want %s stopped", msg, addr)
	}
	if listening(addr) {
		t.Errorf("reload after registration: the plaintext listener on %s still answers", addr)
	}
}
