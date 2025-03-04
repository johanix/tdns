package cli

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/johanix/tdns/tdns"
	"github.com/miekg/dns"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
)

func init() {
	AgentCmd.AddCommand(hsyncCmd)
	hsyncCmd.AddCommand(hsyncStatusCmd)
	hsyncCmd.AddCommand(hsyncLocateCmd)
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

		// fmt.Printf("HSYNC status for zone %s:\n", tdns.Globals.Zonename)
		fmt.Printf("%s  HSYNC RRset:\n", tdns.Globals.Zonename)
		var lines []string
		for _, rr := range resp.HsyncRRs {
			fields := strings.Fields(rr)
			if strings.Contains(rr, resp.Identity) {
				fields = append(fields, "(local agent)")
			}
			lines = append(lines, strings.Join(fields, "|"))
		}
		fmt.Println(columnize.SimpleFormat(lines))

		if len(resp.Agents) > 0 {
			fmt.Printf("\nRemote Agents for zone %s:\n", tdns.Globals.Zonename)
			for _, agent := range resp.Agents {
				if agent.Identity == resp.Identity {
					continue
				}
				fmt.Printf("  Agent: %s\n", agent.Identity)
				for transport, details := range agent.Details {
					displayTransport := transport
					if transport == "https" {
						displayTransport = "api"
					}
					fmt.Printf("    Transport: %s\n", displayTransport)
					fmt.Printf("      State: %s\n", details.State)
					fmt.Printf("      Last Contact: %s\n", details.LastHB.Format(time.RFC3339))
					if details.LastError != "" {
						fmt.Printf("      Last Error: %s\n", details.LastError)
					}
					if len(details.Addrs) > 0 {
						fmt.Printf("      Endpoints:\n")
						for _, addr := range details.Addrs {
							if transport == "dns" {
								target := ""
								if details.UriRR != nil {
									target = details.UriRR.Target
								}
								if target == "" {
									target = addr // fallback if URI target is not available
								}
								fmt.Printf("        Target: %s (%s)\n", target, addr)
								if details.KeyRR != nil {
									fmt.Printf("        SIG(0) KEY RR: %s\n", details.KeyRR.String())
								}
							} else if transport == "api" {
								baseURL := ""
								if details.UriRR != nil {
									baseURL = details.UriRR.Target
								}
								if baseURL == "" {
									baseURL = fmt.Sprintf("https://%s/api/v1", addr)
								}
								fmt.Printf("        Base URL: %s\n", baseURL)
								if details.TlsaRR != nil {
									fmt.Printf("        TLSA RR: %s\n", details.TlsaRR.String())
								}
							} else {
								fmt.Printf("        %s\n", addr)
							}
						}
					}
				}
				fmt.Println()
			}
		} else {
			fmt.Println("\nNo remote agents found in the AgentRegistry")
		}
	},
}

var hsyncLocateCmd = &cobra.Command{
	Use:   "locate <agent-identity>",
	Short: "Locate and attempt to contact a remote agent",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		prefixcmd, _ := getCommandContext("hsync")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		if args[0] == "" {
			log.Fatalf("Agent identity is required")
		}

		req := tdns.AgentPost{
			Command: "hsync-locate",
			AgentId: dns.Fqdn(args[0]),
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

		// Display the located agent info
		if len(resp.Agents) > 0 {
			agent := resp.Agents[0] // Should only be one agent
			fmt.Printf("Located agent: %s\n", agent.Identity)
			for transport, details := range agent.Details {
				fmt.Printf("  Transport: %s\n", transport)
				fmt.Printf("    State: %s\n", details.State)
				if len(details.Addrs) > 0 {
					fmt.Printf("    Endpoints:\n")
					for _, addr := range details.Addrs {
						fmt.Printf("      %s\n", addr)
					}
				}
			}
		}
	},
}
