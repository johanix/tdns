/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"database/sql"
	"errors"
	"os"
	"syscall"
	"time"
)

// WriteRolloverDaemonSentinel records the running daemon's PID and
// start time in the single-row RolloverDaemonSentinel table. CLI
// --offline writers read this on each invocation, kill -0 the
// recorded PID, and refuse to run if a daemon is alive — preventing
// races with the in-process rollover tick.
//
// Called from the auth daemon's main on startup, after the keystore
// is initialized. INSERT-OR-REPLACE on id=1 means restarts overwrite
// the previous PID without leaving stale rows.
func WriteRolloverDaemonSentinel(kdb *KeyDB) error {
	if kdb == nil {
		return nil
	}
	pid := os.Getpid()
	now := time.Now().UTC().Format(time.RFC3339)
	appname := Globals.App.Name
	_, err := kdb.DB.Exec(`INSERT INTO RolloverDaemonSentinel (id, pid, started_at, appname)
VALUES (1, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
  pid = excluded.pid,
  started_at = excluded.started_at,
  appname = excluded.appname`, pid, now, appname)
	return err
}

// ClearRolloverDaemonSentinel removes the sentinel row on graceful
// daemon shutdown. Best-effort: a SIGKILL'd or crashed daemon leaves
// the row populated, but the kill -0 check in LiveRolloverDaemon
// will see the dead PID and treat the sentinel as stale.
func ClearRolloverDaemonSentinel(kdb *KeyDB) error {
	if kdb == nil {
		return nil
	}
	_, err := kdb.DB.Exec(`DELETE FROM RolloverDaemonSentinel WHERE id = 1`)
	return err
}

// LiveRolloverDaemon returns the running daemon's PID, app name,
// start time, and a boolean indicating liveness. "Live" means a
// sentinel row exists AND kill -0 on the recorded PID succeeds (or
// returns EPERM, which means the process exists but we can't signal
// it — treated as alive for safety).
//
// Returns (0, "", "", false) when no sentinel row, when the
// recorded PID has gone away (ESRCH), or on any DB error.
//
// Unix-only: the syscall.Signal(0) probe is the standard Unix
// liveness check. TDNS targets NetBSD / Linux / macOS; Windows is
// not on the supported-platform list. If Windows support is ever
// needed, split the probe into a *_unix.go / *_windows.go pair via
// build tags and add a Windows-appropriate liveness check.
func LiveRolloverDaemon(kdb *KeyDB) (pid int, appname, startedAt string, alive bool) {
	if kdb == nil {
		return 0, "", "", false
	}
	var p int
	var s, name sql.NullString
	err := kdb.DB.QueryRow(`SELECT pid, started_at, appname FROM RolloverDaemonSentinel WHERE id = 1`).Scan(&p, &s, &name)
	if err == sql.ErrNoRows {
		return 0, "", "", false
	}
	if err != nil {
		return 0, "", "", false
	}
	if name.Valid {
		appname = name.String
	}
	if s.Valid {
		startedAt = s.String
	}
	pid = p

	// Probe the PID with signal 0. On Unix, os.FindProcess always
	// succeeds; the actual liveness check is the Signal call.
	// ESRCH = no such process (dead or recycled). EPERM = exists
	// but we can't signal — treat as alive (conservative).
	proc, err := os.FindProcess(p)
	if err != nil {
		return pid, appname, startedAt, false
	}
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return pid, appname, startedAt, false
		}
		// EPERM or other: daemon exists but we lack permission.
		// Conservatively treat as alive so --offline writers refuse.
		return pid, appname, startedAt, true
	}
	return pid, appname, startedAt, true
}
