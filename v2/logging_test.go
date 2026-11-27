package tdns

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSetupLoggingPropagatesDefaultLevelToExistingSubsystems is the
// regression test for #1204: subsystem loggers created before
// SetupLogging runs snapshot the default level (Info) at creation, so
// log.level never reached them. SetupLogging must propagate log.level
// to every subsystem not listed in log.subsystems, while conn-retry
// keeps its Error default unless it is listed.
func TestSetupLoggingPropagatesDefaultLevelToExistingSubsystems(t *testing.T) {
	// Created before SetupLogging, as at start-up.
	engine := Logger("engine")
	connRetry := Logger("conn-retry")

	// Snapshot the level of every subsystem logger registered so far,
	// so the cleanup below restores exactly the levels this test found.
	// Restoring only engine and conn-retry would leave any other
	// subsystem, for example one starting at Error, at the level
	// SetupLogging propagated to it.
	prevLevels := make(map[string]slog.Level)
	subsystemMu.RLock()
	for name, lv := range subsystemLevels {
		prevLevels[name] = lv.Level()
	}
	subsystemMu.RUnlock()
	prevDefault := defaultLevel.Level()
	prevHandler := slog.Default().Handler()
	t.Cleanup(func() {
		defaultLevel.Set(prevDefault)
		for name, level := range prevLevels {
			getOrCreateLevel(name).Set(level)
		}
		slog.SetDefault(slog.New(prevHandler))
	})

	ctx := context.Background()
	dir := t.TempDir()

	// level: debug, no subsystems: the engine logger must emit debug lines.
	logfile := filepath.Join(dir, "tdns.log")
	cfg := writeCfg(t, "log:\n   file: "+logfile+"\n   level: debug\n")
	if _, err := SetupLogging(cfg); err != nil {
		t.Fatalf("SetupLogging: %v", err)
	}
	if got := getOrCreateLevel("engine").Level(); got != slog.LevelDebug {
		t.Fatalf("engine level = %v, want %v", got, slog.LevelDebug)
	}
	if !engine.Enabled(ctx, slog.LevelDebug) {
		t.Fatalf("engine logger does not enable debug at log.level debug")
	}
	if got := getOrCreateLevel("conn-retry").Level(); got != slog.LevelError {
		t.Fatalf("conn-retry level = %v, want %v (its Error default)", got, slog.LevelError)
	}
	if connRetry.Enabled(ctx, slog.LevelWarn) {
		t.Fatalf("conn-retry logger enables warn, want only Error and above")
	}
	engine.Debug("engine-debug-probe")
	engine.Info("engine-info-probe")
	logged, err := os.ReadFile(logfile)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if !strings.Contains(string(logged), "engine-debug-probe") {
		t.Fatalf("debug line missing from log file at log.level debug:\n%s", logged)
	}
	if !strings.Contains(string(logged), "engine-info-probe") {
		t.Fatalf("info line missing from log file at log.level debug:\n%s", logged)
	}

	// level: warn, no subsystems: the engine logger must hide info lines.
	logfileWarn := filepath.Join(dir, "tdns-warn.log")
	cfg = writeCfg(t, "log:\n   file: "+logfileWarn+"\n   level: warn\n")
	if _, err := SetupLogging(cfg); err != nil {
		t.Fatalf("SetupLogging: %v", err)
	}
	if got := getOrCreateLevel("engine").Level(); got != slog.LevelWarn {
		t.Fatalf("engine level = %v, want %v", got, slog.LevelWarn)
	}
	if engine.Enabled(ctx, slog.LevelInfo) {
		t.Fatalf("engine logger still enables info at log.level warn")
	}
	engine.Info("engine-info-probe-warn")
	engine.Warn("engine-warn-probe")
	logged, err = os.ReadFile(logfileWarn)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if strings.Contains(string(logged), "engine-info-probe-warn") {
		t.Fatalf("info line present in log file at log.level warn:\n%s", logged)
	}
	if !strings.Contains(string(logged), "engine-warn-probe") {
		t.Fatalf("warn line missing from log file at log.level warn:\n%s", logged)
	}
}
