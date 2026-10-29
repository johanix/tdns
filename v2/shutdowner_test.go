package tdns

import (
	"errors"
	"os"
	"os/exec"
	"testing"
)

// A daemon that Shutdowner stops exits 1, so that a supervisor sees the
// failed start as a failure (#977). It exited 0 before.
func TestShutdownerExitsWithAFailureStatus(t *testing.T) {
	if os.Getenv(shutdownerProbeEnv) == "1" {
		Shutdowner(&Config{}, "a start that failed")
		return // not reached: Shutdowner exits
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestShutdownerExitsWithAFailureStatus$", "-test.timeout=30s")
	cmd.Env = append(os.Environ(), shutdownerProbeEnv+"=1")
	out, err := cmd.CombinedOutput()

	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("the child exited without an error (err %v), want exit status 1\n%s", err, out)
	}
	if code := exitErr.ExitCode(); code != 1 {
		t.Fatalf("Shutdowner exited %d, want 1\n%s", code, out)
	}
}

// shutdownerProbeEnv tells the test binary it is the child of
// TestShutdownerExitsWithAFailureStatus and should call Shutdowner.
const shutdownerProbeEnv = "TDNS_SHUTDOWNER_PROBE"
