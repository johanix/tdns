/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Bootstrap-configure library: live-server gate.
 *
 * Before overwriting a running server's config, probe its API
 * using the *existing* credentials (the new apikey is not yet
 * accepted by the running server). A responsive server requires
 * a typed confirmation string per role, e.g.
 * `yes, reconfigure mpagent`.
 *
 * Refusing any gate aborts the entire write. This library does
 * not support partial apply of coordinated configs.
 */
package configure

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	tdns "github.com/johanix/tdns/v2"
)

// LiveTarget is the per-role input the gate needs. The app
// builds these from its parsed *existing* config.
type LiveTarget struct {
	Role      string // short label for messages, e.g. "mpagent"
	Path      string // config path this target corresponds to
	BaseURL   string // https://host:port/api/v1
	APIKey    string
	HasConfig bool // false if no existing config file was found
}

// isAlive returns true if the API at t.BaseURL accepts a ping
// signed with t.APIKey. All errors (connection refused, timeout,
// auth failure) are treated as "not alive".
//
// Uses "insecure" TLS on purpose: in a bootstrap context the
// server's cert is commonly self-signed (this very tool may have
// generated it on a prior run) and we have no trust store yet.
// The goal here is a liveness probe, not authentication — a
// responsive apikey-accepting HTTPS endpoint is all we need to
// gate the rewrite. Switching this to verified TLS would require
// the operator to thread a rootCA path through config bootstrap,
// which defeats the purpose of an interactive bootstrap tool.
func (t LiveTarget) isAlive() bool {
	if !t.HasConfig || t.BaseURL == "" || t.APIKey == "" {
		return false
	}
	c := tdns.NewClient(t.Role, t.BaseURL, t.APIKey, "X-API-Key", "insecure")
	if c == nil {
		return false
	}
	_, err := c.SendPing(1, false)
	return err == nil
}

// gateLiveServers probes each target whose config is about to
// change and, for every live one, requires a typed confirmation.
// Returns nil iff the gate clears. A non-nil error means the user
// refused or input was interrupted — abort the write.
func gateLiveServers(
	w io.Writer,
	in *bufio.Reader,
	targets []LiveTarget,
	changes []FileChange,
) error {
	changing := make(map[string]bool, len(changes))
	for _, c := range changes {
		if c.Changed() {
			changing[c.Path] = true
		}
	}

	fmt.Fprintln(w, "\nProbing live servers…")
	var live []LiveTarget
	for _, t := range targets {
		if !changing[t.Path] {
			continue
		}
		if t.isAlive() {
			fmt.Fprintf(w, "  %s: LIVE (existing config responds to ping)\n", t.Role)
			live = append(live, t)
		} else {
			fmt.Fprintf(w, "  %s: quiet\n", t.Role)
		}
	}
	if len(live) == 0 {
		return nil
	}

	fmt.Fprintln(w, "\nOne or more target servers are currently running.")
	fmt.Fprintln(w, "Rewriting their configs will not affect the running")
	fmt.Fprintln(w, "daemon until it is restarted, but a mismatched apikey")
	fmt.Fprintln(w, "or identity can surprise operators who restart later.")
	fmt.Fprintln(w, "Confirm each live server explicitly.")

	for _, t := range live {
		want := "yes, reconfigure " + t.Role
		fmt.Fprintf(w, "\n  type exactly '%s' to proceed: ", want)
		line, err := in.ReadString('\n')
		if err != nil && line == "" {
			return fmt.Errorf("aborted: input closed during live-server gate")
		}
		if strings.TrimRight(line, "\r\n") != want {
			return fmt.Errorf("aborted: confirmation string mismatch for %s", t.Role)
		}
	}
	return nil
}
