/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ScannerPollPost is the body of POST /scanner/poll.
type ScannerPollPost struct {
	// Command is "status" (also an empty body), "on", "off" or "follow-config".
	// on and off override scanner.poll.enabled until follow-config or a restart.
	Command string `json:"command"`
}

// ScannerPollResponse says whether the scanner polls, after the command.
type ScannerPollResponse struct {
	Enabled bool   `json:"enabled"`
	Msg     string `json:"msg,omitempty"` // what the command did
}

// APIscannerPoll handles POST /scanner/poll: switch the poll scan of all
// children on or off while tdns-auth runs, hand the decision back to
// scanner.poll.enabled, or report whether it polls. The switch lives in memory;
// a restart polls as the config file says.
func APIscannerPoll(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var req ScannerPollPost
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			http.Error(w, fmt.Sprintf("bad request: %v", err), http.StatusBadRequest)
			return
		}
		scanner := conf.Internal.GetScanner()
		if scanner == nil {
			http.Error(w, "the scanner is not running", http.StatusServiceUnavailable)
			return
		}

		var msg string
		switch strings.ToLower(strings.TrimSpace(req.Command)) {
		case "", "status":
		case "on":
			scanner.setPollSwitch(pollSwitchOn)
			msg = "polling switched on; the next round starts within scanner.interval"
		case "off":
			scanner.setPollSwitch(pollSwitchOff)
			msg = "polling switched off; a round in progress starts no more children"
		case "follow-config":
			scanner.setPollSwitch(pollSwitchConfig)
			msg = "polling follows scanner.poll.enabled again"
		default:
			http.Error(w, fmt.Sprintf("unknown command %q: want status, on, off or follow-config", req.Command), http.StatusBadRequest)
			return
		}

		_ = json.NewEncoder(w).Encode(ScannerPollResponse{Enabled: scanner.pollConf().Enabled, Msg: msg})
	}
}
