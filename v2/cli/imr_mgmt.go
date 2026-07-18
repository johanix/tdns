/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cli

import (
	"encoding/json"
	"fmt"

	tdns "github.com/johanix/tdns/v2"
)

// SendImrMgmtCmd POSTs an ImrMgmtPost to the configured daemon's
// /imr endpoint. The role argument selects which ApiClient to use --
// "agent" (tdns-agent), "auth" (tdns-auth), or "imr" (tdns-imr).
// This is the IMR-only sibling of SendAgentMgmtCmd (which targets
// /agent and is kept around for non-IMR commands like parentsync-*).
func SendImrMgmtCmd(role string, req *tdns.ImrMgmtPost) (*tdns.ImrMgmtResponse, error) {
	api, err := GetApiClient(role, true)
	if err != nil {
		return nil, fmt.Errorf("getting API client for role %q: %w", role, err)
	}

	_, buf, err := api.RequestNG("POST", "/imr", req, true)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %v", err)
	}

	var amr tdns.ImrMgmtResponse
	if err := json.Unmarshal(buf, &amr); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}
	return &amr, nil
}
