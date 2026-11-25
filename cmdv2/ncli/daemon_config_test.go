package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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

// The client commands and config reload, given --daemon-config <file>, run
// on a host where root has no CLI config: --daemon-config names the daemon,
// and PersistentPreRun does not stop for the missing file. Each goes to the
// daemon's local socket, naming its config. Without the flag the missing
// CLI config still stops them.
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
	d := filepath.Join(dir, "tdns-auth2.yaml")
	cfg := "service:\n   name: TDNS-AUTH\napiserver:\n   addresses: [ 127.0.0.1:1 ]\n   apikey: k\n   socket: " + sock + "\n"
	if err := os.WriteFile(d, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	// The daemon of d, on its local admin socket: it records what it is
	// asked, and by which config.
	var mu sync.Mutex
	var got []string
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var post struct{ Command, Pin string }
		json.NewDecoder(r.Body).Decode(&post)
		mu.Lock()
		got = append(got, r.URL.Path+" "+post.Command+" "+post.Pin+" "+r.Header.Get(tdns.ExpectConfigFileHeader))
		mu.Unlock()
		if r.URL.Path == "/api/v1/config" {
			json.NewEncoder(w).Encode(tdns.ConfigResponse{Msg: "Config reloaded.", ConfigFile: d})
			return
		}
		json.NewEncoder(w).Encode(tdns.AccessResponse{Msg: "done", ConfigFile: d})
	})}
	go srv.Serve(ln)
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
		{"auth", "client", "list", "--daemon-config", d},
		{"auth", "config", "reload", "--daemon-config", d},
	} {
		if out, err := run(t, args...); err != nil || strings.Contains(out, "No CLI config") {
			t.Errorf("tdns-ncli %s, no CLI config: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	mu.Lock()
	want := []string{"/api/v1/access add " + pin + " " + d, "/api/v1/access list  " + d, "/api/v1/config reload  " + d}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("the daemon was asked\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	mu.Unlock()
	if out, err := run(t, "auth", "client", "list"); err == nil || !strings.Contains(out, "No CLI config") {
		t.Errorf("tdns-ncli auth client list, no CLI config, no flag: %v\n%s\nwant it stopped, as before", err, out)
	}
}
