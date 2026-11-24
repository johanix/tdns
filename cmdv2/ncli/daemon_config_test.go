package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
)

// A fix config add prints (tdns-ncli <role> client ... --daemon-config
// <file>, config reload --daemon-config <file>) runs as printed on a host
// where root has no CLI config: --daemon-config names the daemon, and
// PersistentPreRun does not stop for the missing file. Without the flag
// it still does.
//
// The binary's tree, run in a child process (log.Fatalf ends it), with
// --config naming a file that does not exist.
func TestDaemonConfigRunsWithoutACliConfig(t *testing.T) {
	if os.Getenv("NCLI_TEST_ARGS") != "" {
		rootCmd.SetArgs(strings.Split(os.Getenv("NCLI_TEST_ARGS"), "\x1f"))
		if err := rootCmd.Execute(); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}

	dir := t.TempDir()
	sockDir, err := os.MkdirTemp("/tmp", "ncli") // short: a socket path has a limit
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	sock := filepath.Join(sockDir, "auth2.sock")
	af := filepath.Join(dir, "tdns-auth2-access.yaml")
	d := filepath.Join(dir, "tdns-auth2.yaml")
	if err := os.WriteFile(af, []byte("keyauth: true\nclients: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := ln.Addr().String()
	ln.Close()
	cfg := "service:\n   name: TDNS-AUTH\napiserver:\n   addresses: [ " + closed + " ]\n   apikey: k\n   socket: " + sock + "\n   access-file: " + af + "\n"
	if err := os.WriteFile(d, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	// The daemon of d, on its local admin socket. It runs the policy it
	// loaded from af, at its start and at each reload, and says so on
	// status, as a daemon does: an edit checks that it runs the file
	// written.
	load := func() *tdns.ApiAccessStatus {
		data, err := os.ReadFile(af)
		if err != nil {
			return &tdns.ApiAccessStatus{File: af, Error: err.Error()}
		}
		a, err := tdns.ParseAccessFile(data)
		if err != nil {
			return &tdns.ApiAccessStatus{File: af, Error: err.Error()}
		}
		st := &tdns.ApiAccessStatus{File: af, KeyAuth: a.KeyAuthOn(), Clients: []tdns.ApiAccessStatusClient{}}
		for _, c := range a.Clients {
			st.Clients = append(st.Clients, tdns.ApiAccessStatusClient{Name: c.Name, Pin: c.Pin, Role: c.Role, Disabled: c.Disabled})
		}
		return st
	}
	var mu sync.Mutex
	running := load()
	uln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var cp tdns.ConfigPost
		json.NewDecoder(r.Body).Decode(&cp)
		mu.Lock()
		defer mu.Unlock()
		resp := tdns.ConfigResponse{ConfigFile: d}
		if cp.Command == "reload" {
			running = load()
			resp.Msg = fmt.Sprintf("Config reloaded. Access file reloaded: %d client(s), keyauth on.", len(running.Clients))
		}
		resp.Access = running
		json.NewEncoder(w).Encode(resp)
	})}
	go srv.Serve(uln)
	t.Cleanup(func() { srv.Close() })

	sum := sha256.Sum256([]byte("tester"))
	pin := base64.StdEncoding.EncodeToString(sum[:])
	missing := filepath.Join(dir, "no-such-cli-config.yaml")
	run := func(t *testing.T, args ...string) (string, error) {
		t.Helper()
		cmd := exec.Command(os.Args[0], "-test.run=^TestDaemonConfigRunsWithoutACliConfig$")
		cmd.Env = append(os.Environ(), "NCLI_TEST_ARGS="+strings.Join(append([]string{"--config", missing}, args...), "\x1f"))
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	for _, args := range [][]string{
		{"auth", "client", "add", "tester", "--pin", pin, "--role", "read-write", "--daemon-config", d},
		{"auth", "client", "enable", "tester", "--daemon-config", d},
		{"auth", "client", "list", "--daemon-config", d},
		{"auth", "config", "reload", "--daemon-config", d},
	} {
		if out, err := run(t, args...); err != nil || strings.Contains(out, "No CLI config") {
			t.Errorf("tdns-ncli %s, no CLI config: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	if data, err := os.ReadFile(af); err != nil || !strings.Contains(string(data), pin) {
		t.Errorf("%s: %v\n%s\nwant the pin enrolled", af, err, data)
	}
	if out, err := run(t, "auth", "client", "list"); err == nil || !strings.Contains(out, "No CLI config") {
		t.Errorf("tdns-ncli auth client list, no CLI config, no flag: %v\n%s\nwant it stopped, as before", err, out)
	}
}
