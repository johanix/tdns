/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"

	"github.com/johanix/tdns/tdns"
	"github.com/spf13/cobra"
)

var AgentCmd = &cobra.Command{
	Use:   "agent",
	Short: "TDNS Agent commands",
}

var agentLocalAgentCmd = &cobra.Command{
	Use:   "local-agent",
	Short: "Show details of the local agent config",
	Run: func(cmd *cobra.Command, args []string) {
		prefixcmd, _ := getCommandContext("local-agent")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := tdns.AgentMgmtPost{
			Command: "config",
		}

		_, buf, err := api.RequestNG("POST", "/agent", req, true)
		if err != nil {
			log.Fatalf("API request failed: %v", err)
		}

		var resp tdns.AgentMgmtResponse
		if err := json.Unmarshal(buf, &resp); err != nil {
			log.Fatalf("Failed to parse response: %v", err)
		}

		if resp.Error {
			log.Fatalf("API error: %s", resp.ErrorMsg)
		}

		var prettyJSON bytes.Buffer

		err = json.Indent(&prettyJSON, buf, "", "  ")
		if err != nil {
			log.Println("JSON parse error: ", err)
		}
		fmt.Printf("Agent config:\n%s\n", prettyJSON.String())
	},
}

func init() {
	AgentCmd.AddCommand(agentLocalAgentCmd)
}
