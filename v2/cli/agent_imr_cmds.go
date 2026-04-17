/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package cli

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

var agentImrCmd = &cobra.Command{
	Use:   "imr",
	Short: "IMR (Internal Recursive Resolver) cache commands",
}

var agentImrQueryCmd = &cobra.Command{
	Use:   "query <qname> <qtype>",
	Short: "Query the IMR cache (cache-only, no external queries)",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		qname := dns.Fqdn(args[0])
		qtype := args[1]

		amr, err := SendAgentMgmtCmd(&tdns.AgentMgmtPost{
			Command: "imr-query",
			Data: map[string]interface{}{
				"qname": qname,
				"qtype": qtype,
			},
		}, "imr")
		if err != nil {
			log.Fatalf("Request failed: %v", err)
		}
		if amr.Error {
			fmt.Fprintf(os.Stderr, "Error: %s\n", amr.ErrorMsg)
			os.Exit(1)
		}

		fmt.Println(amr.Msg)
		if amr.Data != nil {
			// Pretty-print the cache entry
			data, ok := amr.Data.(map[string]interface{})
			if ok {
				if records, ok := data["records"].([]interface{}); ok {
					for _, rr := range records {
						fmt.Printf("  %s\n", rr)
					}
				}
				fmt.Printf("  TTL: %v  Expires in: %s  Rcode: %s  State: %s  Context: %s\n",
					data["ttl"], data["expires_in"], data["rcode"], data["state"], data["context"])
			} else {
				// Fallback: print as JSON
				buf, _ := json.MarshalIndent(amr.Data, "", "  ")
				fmt.Println(string(buf))
			}
		}
	},
}

var agentImrFlushCmd = &cobra.Command{
	Use:   "flush <qname>",
	Short: "Flush IMR cache entries at and below qname",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		qname := dns.Fqdn(args[0])

		amr, err := SendAgentMgmtCmd(&tdns.AgentMgmtPost{
			Command: "imr-flush",
			Data: map[string]interface{}{
				"qname": qname,
			},
		}, "imr")
		if err != nil {
			log.Fatalf("Request failed: %v", err)
		}
		if amr.Error {
			fmt.Fprintf(os.Stderr, "Error: %s\n", amr.ErrorMsg)
			os.Exit(1)
		}
		fmt.Println(amr.Msg)
	},
}

var agentImrResetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Flush entire IMR cache and re-prime (preserves root NS)",
	Run: func(cmd *cobra.Command, args []string) {
		amr, err := SendAgentMgmtCmd(&tdns.AgentMgmtPost{
			Command: "imr-reset",
		}, "imr")
		if err != nil {
			log.Fatalf("Request failed: %v", err)
		}
		if amr.Error {
			fmt.Fprintf(os.Stderr, "Error: %s\n", amr.ErrorMsg)
			os.Exit(1)
		}
		fmt.Println(amr.Msg)
	},
}

var imrShowID string

var agentImrShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show IMR cache entries related to agent discovery",
	Run: func(cmd *cobra.Command, args []string) {
		if imrShowID == "" {
			log.Fatal("--id flag is required")
		}

		amr, err := SendAgentMgmtCmd(&tdns.AgentMgmtPost{
			Command: "imr-show",
			AgentId: tdns.AgentId(imrShowID),
		}, "imr")
		if err != nil {
			log.Fatalf("Request failed: %v", err)
		}
		if amr.Error {
			fmt.Fprintf(os.Stderr, "Error: %s\n", amr.ErrorMsg)
			os.Exit(1)
		}

		fmt.Println(amr.Msg)
		if amr.Data != nil {
			entries, ok := amr.Data.([]interface{})
			if ok {
				for _, e := range entries {
					entry, ok := e.(map[string]interface{})
					if !ok {
						continue
					}
					fmt.Printf("  %s %s", entry["name"], entry["rrtype"])
					if records, ok := entry["records"].([]interface{}); ok && len(records) > 0 {
						fmt.Println(":")
						for _, rr := range records {
							fmt.Printf("    %s\n", rr)
						}
					} else {
						fmt.Printf("  (rcode: %s)\n", entry["rcode"])
					}
					fmt.Printf("    TTL: %v  Expires in: %s\n", entry["ttl"], entry["expires_in"])
				}
			} else {
				buf, _ := json.MarshalIndent(amr.Data, "", "  ")
				fmt.Println(string(buf))
			}
		}
	},
}

func init() {
	// IMR commands under "agent imr"
	AgentCmd.AddCommand(agentImrCmd)
	agentImrCmd.AddCommand(agentImrQueryCmd)
	agentImrCmd.AddCommand(agentImrFlushCmd)
	agentImrCmd.AddCommand(agentImrResetCmd)
	agentImrCmd.AddCommand(agentImrShowCmd)

	agentImrShowCmd.Flags().StringVar(&imrShowID, "id", "", "Agent identity to show cache entries for (required)")
}
