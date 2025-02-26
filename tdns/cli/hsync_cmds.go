package cli

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/johanix/tdns/tdns"
	"github.com/spf13/cobra"
)

func init() {
	AgentCmd.AddCommand(hsyncCmd)
	hsyncCmd.AddCommand(hsyncStatusCmd)
}

var hsyncCmd = &cobra.Command{
	Use:   "hsync",
	Short: "HSYNC related commands",
}

var hsyncStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show HSYNC status for a zone",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")
		parent, _ := getCommandContext("hsync")

		api, err := getApiClient(parent, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := tdns.AgentPost{
			Command: "hsync-status",
			Zone:    tdns.Globals.Zonename,
		}

		_, buf, err := api.RequestNG("POST", "/agent", req, true)
		if err != nil {
			log.Fatalf("API request failed: %v", err)
		}

		var resp tdns.AgentResponse
		if err := json.Unmarshal(buf, &resp); err != nil {
			log.Fatalf("Failed to parse response: %v", err)
		}

		if resp.Error {
			log.Fatalf("API error: %s", resp.ErrorMsg)
		}

		fmt.Printf("HSYNC status for zone %s:\n", tdns.Globals.Zonename)
		fmt.Printf("\nHSYNC Records:\n")
		for _, rr := range resp.HsyncRRs {
			fmt.Printf("  %s\n", rr)
		}

		if len(resp.HsyncStatus) > 0 {
			fmt.Printf("\nRemote Agents:\n")
			for _, agent := range resp.HsyncStatus {
				fmt.Printf("  Agent: %s\n", agent.Identity)
				fmt.Printf("    State: %s\n", agent.State)
				fmt.Printf("    Last Contact: %s\n", agent.LastContact)
				if agent.LastError != "" {
					fmt.Printf("    Last Error: %s\n", agent.LastError)
				}
				if len(agent.Endpoints) > 0 {
					fmt.Printf("    Endpoints:\n")
					for _, ep := range agent.Endpoints {
						fmt.Printf("      %s\n", ep)
					}
				}
				fmt.Println()
			}
		}
	},
}
