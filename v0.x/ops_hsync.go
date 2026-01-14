package tdns

import (
	"time"
)

// HsyncAgentStatus represents the current status of a remote agent
type HsyncAgentStatus struct {
	Identity    string
	LastContact time.Time
	State       string   // "discovered", "contact_attempted", "connected", "failed"
	LastError   string   // If state is "failed"
	Endpoints   []string // Discovered API/DNS endpoints
}
