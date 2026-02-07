/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * CLI commands for DNS message router introspection.
 */

package cli

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	tdns "github.com/johanix/tdns/v2"
	"github.com/spf13/cobra"
)

var agentRouterCmd = &cobra.Command{
	Use:   "router",
	Short: "DNS message router introspection commands",
	Long: `Inspect the DNS message router state including registered handlers,
middleware chain, and routing metrics.`,
}

var agentRouterListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all registered message handlers",
	Long: `List all registered message handlers grouped by message type.
Shows handler names, priorities, and basic statistics.

Example:
  tdns-cli agent router list`,
	Run: func(cmd *cobra.Command, args []string) {
		prefixcmd, _ := getCommandContext("agent")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := tdns.AgentMgmtPost{
			Command: "router-list",
		}

		_, buf, err := api.RequestNG("POST", "/agent", req, true)
		if err != nil {
			log.Fatalf("API request failed: %v", err)
		}

		var amr tdns.AgentMgmtResponse
		if err := json.Unmarshal(buf, &amr); err != nil {
			log.Fatalf("Failed to parse response: %v", err)
		}

		if amr.Error {
			log.Fatalf("API error: %s", amr.ErrorMsg)
		}

		// Parse router list from response
		if amr.Data == nil {
			fmt.Println("No router data available")
			return
		}

		routerData, ok := amr.Data.(map[string]interface{})
		if !ok {
			log.Fatalf("Unexpected response format")
		}

		handlers, ok := routerData["handlers"].(map[string]interface{})
		if !ok {
			fmt.Println("No handlers registered")
			return
		}

		fmt.Println("DNS Message Router - Registered Handlers")
		fmt.Println("=========================================")
		fmt.Println()

		for msgType, handlerList := range handlers {
			handlerSlice, ok := handlerList.([]interface{})
			if !ok {
				continue
			}

			fmt.Printf("%s (%d handlers):\n", msgType, len(handlerSlice))
			for i, h := range handlerSlice {
				handler, ok := h.(map[string]interface{})
				if !ok {
					continue
				}

				name := handler["name"].(string)
				priority := int(handler["priority"].(float64))
				callCount := int(handler["call_count"].(float64))
				errorCount := int(handler["error_count"].(float64))

				fmt.Printf("  %d. %s (priority=%d)\n", i+1, name, priority)
				fmt.Printf("     Calls: %d, Errors: %d\n", callCount, errorCount)

				if desc, ok := handler["description"].(string); ok && desc != "" {
					fmt.Printf("     Description: %s\n", desc)
				}
			}
			fmt.Println()
		}
	},
}

var agentRouterDescribeCmd = &cobra.Command{
	Use:   "describe",
	Short: "Show detailed router state",
	Long: `Show detailed information about the DNS message router including:
- Middleware chain
- Registered handlers with full details
- Router-level metrics
- Unhandled message types

Example:
  tdns-cli agent router describe`,
	Run: func(cmd *cobra.Command, args []string) {
		prefixcmd, _ := getCommandContext("agent")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := tdns.AgentMgmtPost{
			Command: "router-describe",
		}

		_, buf, err := api.RequestNG("POST", "/agent", req, true)
		if err != nil {
			log.Fatalf("API request failed: %v", err)
		}

		var amr tdns.AgentMgmtResponse
		if err := json.Unmarshal(buf, &amr); err != nil {
			log.Fatalf("Failed to parse response: %v", err)
		}

		if amr.Error {
			log.Fatalf("API error: %s", amr.ErrorMsg)
		}

		// The router's Describe() method returns a formatted string
		if description, ok := amr.Data.(string); ok {
			fmt.Println(description)
		} else {
			fmt.Println("No router description available")
		}
	},
}

var agentRouterMetricsCmd = &cobra.Command{
	Use:   "metrics",
	Short: "Show router metrics",
	Long: `Show router-level metrics including:
- Total messages processed
- Unknown/unhandled message types
- Middleware and handler error counts
- Per-handler statistics

Example:
  tdns-cli agent router metrics`,
	Run: func(cmd *cobra.Command, args []string) {
		prefixcmd, _ := getCommandContext("agent")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := tdns.AgentMgmtPost{
			Command: "router-metrics",
		}

		_, buf, err := api.RequestNG("POST", "/agent", req, true)
		if err != nil {
			log.Fatalf("API request failed: %v", err)
		}

		var amr tdns.AgentMgmtResponse
		if err := json.Unmarshal(buf, &amr); err != nil {
			log.Fatalf("Failed to parse response: %v", err)
		}

		if amr.Error {
			log.Fatalf("API error: %s", amr.ErrorMsg)
		}

		if amr.Data == nil {
			fmt.Println("No metrics available")
			return
		}

		metrics, ok := amr.Data.(map[string]interface{})
		if !ok {
			log.Fatalf("Unexpected metrics format")
		}

		fmt.Println("DNS Message Router - Metrics")
		fmt.Println("============================")
		fmt.Println()

		fmt.Printf("Total Messages:      %d\n", int(metrics["total_messages"].(float64)))
		fmt.Printf("Unknown Messages:    %d\n", int(metrics["unknown_messages"].(float64)))
		fmt.Printf("Middleware Errors:   %d\n", int(metrics["middleware_errors"].(float64)))
		fmt.Printf("Handler Errors:      %d\n", int(metrics["handler_errors"].(float64)))

		if unhandled, ok := metrics["unhandled_types"].(map[string]interface{}); ok && len(unhandled) > 0 {
			fmt.Println("\nUnhandled Message Types:")
			for msgType, count := range unhandled {
				fmt.Printf("  %s: %d\n", msgType, int(count.(float64)))
			}
		}
	},
}

var agentRouterWalkCmd = &cobra.Command{
	Use:   "walk",
	Short: "Walk all handlers with visitor pattern",
	Long: `Walk through all registered handlers using the visitor pattern.
This is primarily useful for programmatic inspection of the router state.

Example:
  tdns-cli agent router walk`,
	Run: func(cmd *cobra.Command, args []string) {
		prefixcmd, _ := getCommandContext("agent")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := tdns.AgentMgmtPost{
			Command: "router-walk",
		}

		_, buf, err := api.RequestNG("POST", "/agent", req, true)
		if err != nil {
			log.Fatalf("API request failed: %v", err)
		}

		var amr tdns.AgentMgmtResponse
		if err := json.Unmarshal(buf, &amr); err != nil {
			log.Fatalf("Failed to parse response: %v", err)
		}

		if amr.Error {
			log.Fatalf("API error: %s", amr.ErrorMsg)
		}

		if amr.Data == nil {
			fmt.Println("No handlers found")
			return
		}

		walkResults, ok := amr.Data.([]interface{})
		if !ok {
			log.Fatalf("Unexpected walk results format")
		}

		fmt.Println("DNS Message Router - Handler Walk")
		fmt.Println("==================================")
		fmt.Println()

		for i, item := range walkResults {
			handler, ok := item.(map[string]interface{})
			if !ok {
				continue
			}

			msgType := handler["message_type"].(string)
			name := handler["name"].(string)
			priority := int(handler["priority"].(float64))
			registered := handler["registered"].(string)

			fmt.Printf("%d. [%s] %s\n", i+1, msgType, name)
			fmt.Printf("   Priority: %d, Registered: %s\n", priority, registered)

			if desc, ok := handler["description"].(string); ok && desc != "" {
				fmt.Printf("   Description: %s\n", desc)
			}
			fmt.Println()
		}

		fmt.Printf("Total handlers: %d\n", len(walkResults))
	},
}

var agentRouterResetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Reset router metrics",
	Long: `Reset all router metrics to zero. This clears:
- Total message counts
- Error counters
- Per-handler statistics (call counts, error counts, latencies)

This is primarily useful for testing or after troubleshooting.

Example:
  tdns-cli agent router reset`,
	Run: func(cmd *cobra.Command, args []string) {
		prefixcmd, _ := getCommandContext("agent")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		// Confirm with user
		fmt.Print("This will reset all router metrics. Continue? [y/N]: ")
		var response string
		fmt.Scanln(&response)
		response = strings.ToLower(strings.TrimSpace(response))

		if response != "y" && response != "yes" {
			fmt.Println("Cancelled.")
			os.Exit(0)
		}

		req := tdns.AgentMgmtPost{
			Command: "router-reset",
		}

		_, buf, err := api.RequestNG("POST", "/agent", req, true)
		if err != nil {
			log.Fatalf("API request failed: %v", err)
		}

		var amr tdns.AgentMgmtResponse
		if err := json.Unmarshal(buf, &amr); err != nil {
			log.Fatalf("Failed to parse response: %v", err)
		}

		if amr.Error {
			log.Fatalf("API error: %s", amr.ErrorMsg)
		}

		fmt.Println("Router metrics reset successfully.")
	},
}

func init() {
	// Add router subcommands to agent command
	AgentCmd.AddCommand(agentRouterCmd)

	// Add router introspection commands
	agentRouterCmd.AddCommand(agentRouterListCmd)
	agentRouterCmd.AddCommand(agentRouterDescribeCmd)
	agentRouterCmd.AddCommand(agentRouterMetricsCmd)
	agentRouterCmd.AddCommand(agentRouterWalkCmd)
	agentRouterCmd.AddCommand(agentRouterResetCmd)
}
