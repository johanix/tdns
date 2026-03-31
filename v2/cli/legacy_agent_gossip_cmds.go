/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package cli

import (
	"fmt"
	"log"
	"os"
	"strings"

	tdns "github.com/johanix/tdns/v2"
	"github.com/spf13/cobra"
)

var agentGossipCmd = &cobra.Command{
	Use:   "gossip",
	Short: "Gossip protocol commands",
}

var agentGossipGroupCmd = &cobra.Command{
	Use:   "group",
	Short: "Provider group commands",
}

var agentGossipGroupListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all provider groups this agent belongs to",
	Run: func(cmd *cobra.Command, args []string) {
		amr, err := SendAgentMgmtCmd(&tdns.AgentMgmtPost{
			Command: "gossip-group-list",
		}, "gossip")
		if err != nil {
			log.Fatalf("Request failed: %v", err)
		}
		if amr.Error {
			fmt.Fprintf(os.Stderr, "Error: %s\n", amr.ErrorMsg)
			os.Exit(1)
		}

		groups, ok := amr.Data.([]interface{})
		if !ok || len(groups) == 0 {
			fmt.Println("No provider groups found.")
			return
		}

		// Print header
		fmt.Printf("%-12s %-40s %s\n", "GROUP", "MEMBERS", "ZONES")
		fmt.Printf("%-12s %-40s %s\n", "-----", "-------", "-----")

		for _, g := range groups {
			entry, ok := g.(map[string]interface{})
			if !ok {
				continue
			}

			name, _ := entry["name"].(string)
			zoneCount := 0
			if zc, ok := entry["zone_count"].(float64); ok {
				zoneCount = int(zc)
			}

			// Format members
			var memberStrs []string
			if members, ok := entry["members"].([]interface{}); ok {
				for _, m := range members {
					if s, ok := m.(string); ok {
						memberStrs = append(memberStrs, s)
					}
				}
			}
			membersStr := strings.Join(memberStrs, ", ")

			// Format sample zones
			var sampleStrs []string
			if samples, ok := entry["sample_zones"].([]interface{}); ok {
				for _, s := range samples {
					if str, ok := s.(string); ok {
						sampleStrs = append(sampleStrs, str)
					}
				}
			}
			zonesStr := strings.Join(sampleStrs, " ")
			if zoneCount > len(sampleStrs) {
				zonesStr += fmt.Sprintf(" (+%d more)", zoneCount-len(sampleStrs))
			}

			fmt.Printf("%-12s %-40s %s\n", name, membersStr, zonesStr)
		}
	},
}

var gossipGroupStateName string

var agentGossipGroupStateCmd = &cobra.Command{
	Use:   "state",
	Short: "Show gossip state matrix for a provider group",
	Long: `Display the NxN state matrix for a provider group.
Each row is a reporting agent; each column shows that reporter's
view of another agent's state. A healthy group shows OPERATIONAL
in every non-diagonal cell.`,
	Run: func(cmd *cobra.Command, args []string) {
		if gossipGroupStateName == "" {
			log.Fatal("--group flag is required")
		}

		amr, err := SendAgentMgmtCmd(&tdns.AgentMgmtPost{
			Command: "gossip-group-state",
			Data: map[string]interface{}{
				"group": gossipGroupStateName,
			},
		}, "gossip")
		if err != nil {
			log.Fatalf("Request failed: %v", err)
		}
		if amr.Error {
			fmt.Fprintf(os.Stderr, "Error: %s\n", amr.ErrorMsg)
			os.Exit(1)
		}

		data, ok := amr.Data.(map[string]interface{})
		if !ok {
			fmt.Println("No data received")
			return
		}

		// Print header
		groupName, _ := data["group_name"].(string)
		groupHash, _ := data["group_hash"].(string)
		fmt.Printf("Group: %s (hash: %s)\n", groupName, groupHash)

		// Print election state
		if el, ok := data["election"].(map[string]interface{}); ok {
			status, _ := el["status"].(string)
			switch status {
			case "active":
				leader, _ := el["leader"].(string)
				term, _ := el["term"].(float64)
				expiresIn, _ := el["expires_in"].(string)
				fmt.Printf("Leader: %s (term %d, expires in %s)\n", leader, int(term), expiresIn)
			case "no_election":
				fmt.Println("Leader: no election held")
			case "invalidated":
				term, _ := el["term"].(float64)
				fmt.Printf("Leader: election invalidated (group degraded, last term %d)\n", int(term))
			case "expired":
				leader, _ := el["leader"].(string)
				term, _ := el["term"].(float64)
				fmt.Printf("Leader: expired (was %s, term %d)\n", leader, int(term))
			}
		}
		fmt.Println()

		// Get members list
		var members []string
		if mlist, ok := data["members"].([]interface{}); ok {
			for _, m := range mlist {
				if s, ok := m.(string); ok {
					members = append(members, s)
				}
			}
		}

		if len(members) == 0 {
			fmt.Println("No members found")
			return
		}

		// Compute short names for columns (use last two labels of FQDN)
		shortNames := make(map[string]string)
		for _, m := range members {
			parts := strings.Split(strings.TrimSuffix(m, "."), ".")
			if len(parts) >= 2 {
				shortNames[m] = parts[len(parts)-2] + "." + parts[len(parts)-1]
			} else {
				shortNames[m] = m
			}
		}

		// Determine column width
		colWidth := 14
		for _, sn := range shortNames {
			if len(sn)+2 > colWidth {
				colWidth = len(sn) + 2
			}
		}

		// Print column headers
		fmt.Printf("%-20s", "REPORTER / PEER")
		for _, m := range members {
			fmt.Printf("%-*s", colWidth, shortNames[m])
		}
		fmt.Printf("%-6s\n", "AGE")

		// Print matrix rows
		matrix, _ := data["matrix"].([]interface{})
		for _, row := range matrix {
			r, ok := row.(map[string]interface{})
			if !ok {
				continue
			}
			reporter, _ := r["reporter"].(string)
			age, _ := r["age"].(string)
			peerStates, _ := r["peer_states"].(map[string]interface{})

			fmt.Printf("%-20s", shortNames[reporter])
			for _, m := range members {
				if m == reporter {
					fmt.Printf("%-*s", colWidth, "—")
				} else if state, ok := peerStates[m].(string); ok {
					fmt.Printf("%-*s", colWidth, state)
				} else {
					fmt.Printf("%-*s", colWidth, "?")
				}
			}
			fmt.Printf("%-6s\n", age)
		}
	},
}

func init() {
	AgentCmd.AddCommand(agentGossipCmd)
	agentGossipCmd.AddCommand(agentGossipGroupCmd)
	agentGossipGroupCmd.AddCommand(agentGossipGroupListCmd)
	agentGossipGroupCmd.AddCommand(agentGossipGroupStateCmd)
	agentGossipGroupStateCmd.Flags().StringVar(&gossipGroupStateName, "group", "", "Provider group name or hash (required)")
}
