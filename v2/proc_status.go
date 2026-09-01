/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Process-resource observability for the config-status API (#443).
 *
 * The #443 wedge — a forwarding resolver serving SERVFAIL for everything
 * uncached, silently, until restarted — was diagnosed as fd exhaustion:
 * every outbound dial failed instantly while cached answers kept flowing.
 * The mechanism fix (DoH connection bounds) landed with #445; this makes
 * the resource itself visible, so the diagnosis is confirmable in the
 * field with one `config status` call and the NEXT leak of this class is
 * visible while it grows instead of after it bites.
 */
package tdns

import (
	"runtime"
	"syscall"
)

// ProcStatus is the process-resource block of the config-status response.
// OpenFDs semantics depend on FDMethod: "procfs" and "devfd" are exact
// counts of open descriptors; "maxfd" (NetBSD) is the HIGHEST fd currently
// in use — an upper-bound watermark rather than a count, but it grows
// toward the limit just the same when descriptors leak.
type ProcStatus struct {
	OpenFDs    int    `json:"open_fds"`           // -1 when FDMethod is "unavailable"
	FDMethod   string `json:"fd_method"`          // "procfs" | "devfd" | "maxfd" | "unavailable"
	FDLimit    uint64 `json:"fd_limit,omitempty"` // RLIMIT_NOFILE soft limit; 0 = unknown
	Goroutines int    `json:"goroutines"`
}

// CollectProcStatus samples the process's descriptor and goroutine state.
// Cheap enough to run on every config-status request.
func CollectProcStatus() *ProcStatus {
	ps := &ProcStatus{Goroutines: runtime.NumGoroutine()}
	ps.OpenFDs, ps.FDMethod = countOpenFDs()
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err == nil {
		ps.FDLimit = uint64(rl.Cur)
	}
	return ps
}
