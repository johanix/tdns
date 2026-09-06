/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cli

import (
	"encoding/json"
	"fmt"
	"log"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

// SendAgentMgmtCmd POSTs an AgentMgmtPost to the agent daemon's /agent
// endpoint. Every caller in this package talks to the agent, so the
// role is fixed rather than inferred from the Cobra tree.
func SendAgentMgmtCmd(req *tdns.AgentMgmtPost) (*tdns.AgentMgmtResponse, error) {
	api, err := GetApiClient("agent", true)
	if err != nil {
		return nil, fmt.Errorf("getting API client: %w", err)
	}

	_, buf, err := api.RequestNG("POST", "/agent", req, true)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %v", err)
	}

	var amr tdns.AgentMgmtResponse
	if err := json.Unmarshal(buf, &amr); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	return &amr, nil
}

// newAgentParentSyncElectionCmd returns a fresh "election" command.
//
// The one parentsync verb that is genuinely agent-side: it asks the agent to
// re-run leader election among the providers for a zone, over the agent
// management API, and has no counterpart on an authoritative server. Every
// other verb posts to /zone/parentsync, which both daemons serve, and now
// comes from newZoneParentSyncCmd for both roles.
//
// A constructor rather than a package-level var because it is attached in two
// places -- under "agent zone parentsync" and under the retired top-level
// "agent parentsync" alias -- and cobra keeps the parent pointer in the
// command, so one instance cannot hang off both.
func newAgentParentSyncElectionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "election",
		Short: "Trigger leader re-election for a zone",
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs("zonename")
			amr, err := SendAgentMgmtCmd(&tdns.AgentMgmtPost{
				Command: "parentsync-election",
				Zone:    tdns.ZoneName(dns.Fqdn(tdns.Globals.Zonename)),
			})
			if err != nil {
				log.Fatalf("Error: %v", err)
			}
			if amr.Error {
				log.Fatalf("Error from agent: %s", amr.ErrorMsg)
			}
			fmt.Printf("%s\n", amr.Msg)
		},
	}
}
