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

func init() {
	AgentCmd.AddCommand(agentGossipCmd)
	agentGossipCmd.AddCommand(agentGossipGroupCmd)
	agentGossipGroupCmd.AddCommand(agentGossipGroupListCmd)
}
