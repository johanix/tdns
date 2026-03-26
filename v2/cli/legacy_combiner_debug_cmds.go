/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package cli

import (
	"encoding/json"
	"fmt"
	"log"
	"sort"

	"github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

var CombinerShowDataCmd = &cobra.Command{
	Use:   "show-combiner-data",
	Short: "Show the combiner's local data store (merged + per-agent)",
	Long: `Display the combiner's CombinerData (merged view) and AgentContributions
(per-agent breakdown) for all zones or a specific zone.

Example:
  tdns-cliv2 combiner show-combiner-data
  tdns-cliv2 combiner show-combiner-data --zone whisky.dnslab.`,
	Run: func(cmd *cobra.Command, args []string) {
		zone, _ := cmd.Flags().GetString("zone")

		resp, err := SendCombinerDebugCmd(tdns.CombinerDebugPost{
			Command: "show-combiner-data",
			Zone:    zone,
		})
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp.Error {
			log.Fatalf("Error: %s", resp.ErrorMsg)
		}

		hasMerged := len(resp.CombinerData) > 0
		hasContribs := len(resp.AgentContributions) > 0

		if !hasMerged && !hasContribs {
			fmt.Printf("No combiner data stored\n")
			return
		}

		// Display per-agent contributions first (more detailed)
		if hasContribs {
			fmt.Printf("Per-Agent Contributions\n")
			fmt.Printf("=======================\n\n")

			// Sort zones
			zones := sortedKeys(resp.AgentContributions)
			for _, zoneName := range zones {
				agentMap := resp.AgentContributions[zoneName]
				fmt.Printf("Zone: %s\n", zoneName)
				fmt.Printf("────────────────────────────────────────\n")

				// Sort agents
				agents := sortedKeys(agentMap)
				for _, agentID := range agents {
					ownerMap := agentMap[agentID]
					fmt.Printf("  Agent: %s\n", agentID)

					// Sort owners
					owners := sortedKeys(ownerMap)
					for _, owner := range owners {
						rrTypeMap := ownerMap[owner]
						// Sort RR types
						rrTypes := sortedKeys(rrTypeMap)
						for _, rrTypeName := range rrTypes {
							rrs := rrTypeMap[rrTypeName]
							fmt.Printf("    %s %s (%d records):\n", owner, rrTypeName, len(rrs))
							for _, rr := range rrs {
								fmt.Printf("      %s\n", rr)
							}
						}
					}
				}
				fmt.Printf("\n")
			}
		}

		// Display merged CombinerData
		if hasMerged {
			fmt.Printf("Merged CombinerData\n")
			fmt.Printf("===================\n\n")

			// Sort zones
			zones := sortedKeys(resp.CombinerData)
			for _, zoneName := range zones {
				ownerMap := resp.CombinerData[zoneName]
				fmt.Printf("Zone: %s\n", zoneName)
				fmt.Printf("────────────────────────────────────────\n")

				// Sort owners
				owners := sortedKeys(ownerMap)
				for _, ownerName := range owners {
					rrTypeMap := ownerMap[ownerName]
					rrTypes := sortedKeys(rrTypeMap)
					for _, rrTypeName := range rrTypes {
						rrs := rrTypeMap[rrTypeName]
						fmt.Printf("  %s %s (%d records):\n", ownerName, rrTypeName, len(rrs))
						for _, rr := range rrs {
							fmt.Printf("    %s\n", rr)
						}
					}
				}
				fmt.Printf("\n")
			}
		}
	},
}

// sortedKeys returns the sorted keys of a map[string]T.
func sortedKeys[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func SendCombinerDebugCmd(req tdns.CombinerDebugPost) (*tdns.CombinerDebugResponse, error) {
	// Always use the combiner API client — this command only talks to the combiner.
	api, err := GetApiClient("combiner", true)
	if err != nil {
		return nil, fmt.Errorf("error getting API client: %w", err)
	}

	if req.Zone != "" {
		req.Zone = dns.Fqdn(req.Zone)
	}

	status, buf, err := api.RequestNG("POST", "/combiner/debug", req, true)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}

	if status != 200 {
		return nil, fmt.Errorf("API request to %s/combiner/debug returned HTTP %d: %s",
			api.BaseUrl, status, string(buf))
	}

	var resp tdns.CombinerDebugResponse
	if err := json.Unmarshal(buf, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response from %s/combiner/debug: %w",
			api.BaseUrl, err)
	}

	if resp.Error {
		return nil, fmt.Errorf("API error: %s", resp.ErrorMsg)
	}

	return &resp, nil
}

func init() {
	CombinerCmd.AddCommand(CombinerShowDataCmd)

	CombinerShowDataCmd.Flags().String("zone", "", "Filter by specific zone")
}
