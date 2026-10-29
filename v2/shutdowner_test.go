package tdns

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// A daemon that Shutdowner stops exits 1, so that a supervisor sees the
// failed start as a failure (#977). It exited 0 before.
func TestShutdownerExitsWithAFailureStatus(t *testing.T) {
	if os.Getenv(shutdownerProbeEnv) == "start" {
		Shutdowner(&Config{}, "a start that failed")
		return // not reached: Shutdowner exits
	}

	if code, out := runShutdownerProbe(t, "TestShutdownerExitsWithAFailureStatus", "start"); code != 1 {
		t.Fatalf("Shutdowner exited %d, want 1\n%s", code, out)
	}
}

// A stop that Shutdowner makes from another goroutine while MainLoop runs,
// such as one after a zone reload, also exits 1. Before, MainLoop returned on
// APIStopCh and main returned, so the process exited 0 before Shutdowner got
// to os.Exit.
func TestAFailedStopDuringMainLoopExitsWithAFailureStatus(t *testing.T) {
	if os.Getenv(shutdownerProbeEnv) == "running" {
		conf := &Config{}
		conf.Internal.APIStopCh = make(chan struct{})
		ctx, cancel := context.WithCancel(context.Background())
		go Shutdowner(conf, "a reload that failed")
		conf.MainLoop(ctx, cancel)
		return // as main returns after MainLoop
	}

	if code, out := runShutdownerProbe(t, "TestAFailedStopDuringMainLoopExitsWithAFailureStatus", "running"); code != 1 {
		t.Fatalf("a failed stop during MainLoop exited %d, want 1\n%s", code, out)
	}
}

// After a failed stop, MainLoop waits for the engines only up to
// failedStopDrainLimit: one that never finishes does not keep the daemon up.
func TestAFailedStopDoesNotWaitForAStuckEngine(t *testing.T) {
	if os.Getenv(shutdownerProbeEnv) == "stuck" {
		failedStopDrainLimit = 300 * time.Millisecond
		engineWg.Add(1) // an engine that never finishes
		conf := &Config{}
		conf.Internal.APIStopCh = make(chan struct{})
		ctx, cancel := context.WithCancel(context.Background())
		go Shutdowner(conf, "a reload that failed")
		conf.MainLoop(ctx, cancel)
		return
	}

	code, out := runShutdownerProbe(t, "TestAFailedStopDoesNotWaitForAStuckEngine", "stuck")
	if code != 1 {
		t.Fatalf("a failed stop with a stuck engine exited %d, want 1\n%s", code, out)
	}
	if !strings.Contains(out, "exiting anyway") {
		t.Fatalf("no log line about the engines still running\n%s", out)
	}
}

// runShutdownerProbe runs the test named again in a child test process, with
// shutdownerProbeEnv set to probe, and returns the child's exit status and
// output.
func runShutdownerProbe(t *testing.T, name, probe string) (int, string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^"+name+"$", "-test.timeout=30s")
	cmd.Env = append(os.Environ(), shutdownerProbeEnv+"="+probe)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return 0, string(out)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("running the child: %v\n%s", err, out)
	}
	return exitErr.ExitCode(), string(out)
}

// shutdownerProbeEnv tells the test binary it is the child of one of the
// tests above, and which stop to make.
const shutdownerProbeEnv = "TDNS_SHUTDOWNER_PROBE"
