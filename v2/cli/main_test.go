package cli

import (
	"os"
	"testing"

	tdns "github.com/johanix/tdns/v2"
)

func TestMain(m *testing.M) {
	// No default admin socket in /var/run: a test that wants one sets
	// apiserver.socket, or tdns.DefaultApiSocketDir to a directory of its own.
	tdns.DefaultApiSocketDir = ""
	os.Exit(m.Run())
}
