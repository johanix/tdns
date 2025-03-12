package cli

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strconv"
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
	hsyncCmd.AddCommand(hsyncSendHelloCmd)
}

var hsyncCmd = &cobra.Command{
	Use:   "hsync",
	Short: "HSYNC related commands",
	Long:  `Commands related to HSYNC operations.`,
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
			fmt.Printf("\n%s Remote Agents:\n", tdns.Globals.Zonename)
			for _, agent := range resp.Agents {
				if agent.Identity == resp.Identity {
					continue
				}
				for transport, details := range agent.Details {
					displayTransport := transport
					if transport == "https" {
						displayTransport = "api"
					}
					fmt.Printf("Agent %q: transport %q, state %q, last contact %s\n", agent.Identity, displayTransport, details.State, details.LastHB.Format(time.RFC3339))
					if details.LatestError != "" {
						fmt.Printf("      Latest Error: %s\n", details.LatestError)
					}
					if len(details.Addrs) > 0 {
						// fmt.Printf("      Endpoints:\n")
						//for _, addr := range details.Addrs {
						if transport == "dns" {
							target := ""
							if details.UriRR != nil {
								target = details.UriRR.Target
							}
							if target == "" {
								target = details.Addrs[0] // fallback if URI target is not available
							}
							port := strconv.Itoa(int(details.Port))
							var addrs []string
							for _, a := range details.Addrs {
								addrs = append(addrs, net.JoinHostPort(a, port))
							}

							fmt.Printf(" * Target: %s\n", target)
							fmt.Printf(" * Addresses: %v\n", addrs)
							if details.KeyRR != nil {
								keyStr := details.KeyRR.String()
								parts := strings.Fields(keyStr)
								if len(parts) > 0 {
									key := parts[len(parts)-1] // Get the last field which is the key data
									if len(key) > 20 {
										truncKey := key[:10] + "***" + key[len(key)-10:]
										fmt.Printf(" * SIG(0) KEY RR: %s %s %s %s %s\n",
											parts[0], parts[1], parts[2], parts[3], truncKey)
									} else {
										fmt.Printf(" * SIG(0) KEY RR: %s\n", keyStr)
									}
								}
							}
						} else if transport == "api" {
							baseURL := ""
							if details.UriRR != nil {
								baseURL = details.UriRR.Target
							}
							if baseURL == "" {
								baseURL = fmt.Sprintf("https://%s/api/v1", details.Addrs[0])
							}

							port := strconv.Itoa(int(details.Port))
							var addrs []string
							for _, a := range details.Addrs {
								addrs = append(addrs, net.JoinHostPort(a, port))
							}

							fmt.Printf(" * Base URL: %s\n", baseURL)
							fmt.Printf(" * Addresses: %v\n", addrs)
							if details.TlsaRR != nil {
								tlsaStr := details.TlsaRR.String()
								parts := strings.Fields(tlsaStr)
								if len(parts) > 0 {
									hash := parts[len(parts)-1] // Get the last field which is the hash
									if len(hash) > 20 {
										truncHash := hash[:10] + "***" + hash[len(hash)-10:]
										fmt.Printf(" * TLSA RR: %s %s %s %s %s\n",
											parts[0], parts[1], parts[2], parts[3], truncHash)
									} else {
										fmt.Printf(" * TLSA RR: %s\n", tlsaStr)
									}
								}
							}
						} else {
							fmt.Printf("Error: unknown transport: %q\n", transport)
						}
						// }
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
		PrepArgs("zonename")

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

var hsyncSendHelloCmd = &cobra.Command{
	Use:   "send-hello",
	Short: "Send a hello message to a remote agent",
	Long:  `Send a hello message to a remote agent and display the response.`,
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		// Get the zone (agent identity) from flags
		agentIdentity := tdns.Globals.Zonename

		// Create a new agent registry
		registry := tdns.NewAgentRegistry("cli-temp-identity")
		if registry == nil {
			fmt.Println("Error: failed to create agent registry")
			return
		}

		fmt.Printf("Locating agent %s...\n", agentIdentity)

		// Create a channel to receive the result
		resultCh := make(chan *tdns.Agent, 1)
		errorCh := make(chan error, 1)

		// Start a goroutine to locate the agent
		go func() {
			// First, try to locate the agent
			registry.LocateAgent(agentIdentity, "")

			// Wait for the agent to be located (with timeout)
			timeout := time.After(30 * time.Second)
			ticker := time.NewTicker(1 * time.Second)
			defer ticker.Stop()

			for {
				select {
				case <-timeout:
					errorCh <- fmt.Errorf("timeout waiting for agent to be located")
					return
				case <-ticker.C:
					// Check if the agent is known
					agent, exists := registry.S.Get(agentIdentity)
					if exists && agent.State == tdns.AgentStateKnown {
						resultCh <- agent
						return
					}
				}
			}
		}()

		// Wait for the result or error
		select {
		case agent := <-resultCh:
			fmt.Printf("Agent %s located successfully\n", agentIdentity)

			// Send hello message
			fmt.Printf("Sending HELLO message to agent %s...\n", agentIdentity)

			// Create hello message
			helloMsg := &tdns.AgentMsgPost{
				MessageType: "HELLO",
				Identity:    "cli-temp-identity",
				Time:        time.Now(),
				Zone:        cmd.Flag("zone").Value.String(),
			}

			// Send the hello message
			code, respData, err := agent.SendApiHello(helloMsg)
			if err != nil {
				fmt.Printf("Error sending HELLO: %v\n", err)
				return
			}

			// Parse and display the response
			fmt.Printf("Response status code: %d\n", code)

			var response tdns.AgentMsgResponse
			err = json.Unmarshal(respData, &response)
			if err != nil {
				fmt.Printf("Error parsing response: %v\n", err)
				fmt.Printf("Raw response: %s\n", string(respData))
				return
			}

			// Display the response
			fmt.Printf("Response from agent %s:\n", agentIdentity)
			fmt.Printf("  Time: %s\n", response.Time)
			fmt.Printf("  Message: %s\n", response.Msg)
			if response.Error {
				fmt.Printf("  Error: %s\n", response.ErrorMsg)
			}

		case err := <-errorCh:
			fmt.Printf("Error: %v\n", err)
		}
	},
}
