package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	tdns "github.com/johanix/tdns/v2"
)

// testDaemonCert is a certificate the daemon configs of the tests present
// (daemonYAML names it as apiserver.certfile), and testDaemonPin its pin: a
// new https entry is written only when config add can pin the daemon.
var testDaemonCert, testDaemonPin string

func TestMain(m *testing.M) {
	// No default admin socket in /var/run: a test that wants one sets
	// apiserver.socket, or tdns.DefaultApiSocketDir to a directory of its own.
	tdns.DefaultApiSocketDir = ""
	dir, err := os.MkdirTemp("", "ncli-daemon-cert")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	testDaemonCert = filepath.Join(dir, "api.crt")
	if testDaemonPin, _, err = ensureClientCert(testDaemonCert, filepath.Join(dir, "api.key"), "test-daemon"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	rc := m.Run()
	os.RemoveAll(dir)
	os.Exit(rc)
}
