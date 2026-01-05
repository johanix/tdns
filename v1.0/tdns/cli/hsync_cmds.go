/*
 * Copyright (c) 2025 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package cli

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/johanix/tdns/v1.0/tdns"
	core "github.com/johanix/tdns/v1.0/tdns/core"
	"github.com/miekg/dns"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var syncTransport, syncIdentity, TheAgentId string

func init() {
	AgentCmd.AddCommand(hsyncCmd)
	hsyncCmd.AddCommand(hsyncZoneStatusCmd, hsyncAgentStatusCmd)
	hsyncCmd.AddCommand(hsyncLocateCmd)
	hsyncCmd.AddCommand(hsyncSendHelloCmd)

	hsyncZoneStatusCmd.Flags().StringVarP(&syncTransport, "transport", "T", "", "Transport to show, default both api and dns")
	hsyncAgentStatusCmd.Flags().StringVarP(&syncTransport, "transport", "T", "", "Transport to show, default both api and dns")
	hsyncAgentStatusCmd.Flags().StringVarP(&TheAgentId, "agentid", "", "", "Remote agent identity to show")
	hsyncSendHelloCmd.Flags().StringVarP(&syncIdentity, "id", "I", "", "Identity to claim in the send hello")
}

var hsyncCmd = &cobra.Command{
	Use:   "hsync",
	Short: "HSYNC related commands",
	Long:  `Commands related to HSYNC operations.`,
}

var hsyncZoneStatusCmd = &cobra.Command{
	Use:   "zonestatus",
	Short: "Show HSYNC status for a zone",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")
		parent, _ := getCommandContext("hsync")

		api, err := getApiClient(parent, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := tdns.AgentMgmtPost{
			Command: "hsync-zonestatus",
			Zone:    tdns.ZoneName(tdns.Globals.Zonename),
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

		PrintHsyncRRs(tdns.AgentId(resp.Identity), resp.HsyncRRs)

		if tdns.Globals.Verbose {
			fmt.Printf("\nZone Agent Data:\n")
			fmt.Printf("  My Upstream: %s\n", resp.ZoneAgentData.MyUpstream)
			fmt.Printf("  My Downstreams: %v\n", resp.ZoneAgentData.MyDownstreams)
		}

		if len(resp.ZoneAgentData.Agents) > 0 {
			fmt.Printf("\n%s Remote Agents:\n", tdns.Globals.Zonename)
			for _, agent := range resp.ZoneAgentData.Agents {
				if agent.Identity == resp.Identity {
					continue
				}
				err := PrintAgent(agent, true)
				if err != nil {
					log.Printf("Error printing agent: %v", err)
				}
				fmt.Println()
			}
		} else {
			fmt.Printf("\nNo remote agents for zone %q found in the AgentRegistry\n", tdns.Globals.Zonename)
		}
	},
}

var hsyncAgentStatusCmd = &cobra.Command{
	Use:   "agentstatus",
	Short: "Show HSYNC status for an agent",
	Run: func(cmd *cobra.Command, args []string) {
		tdns.Globals.AgentId = tdns.AgentId(TheAgentId)

		PrepArgs("agentid")

		amr, err := SendAgentMgmtCmd(&tdns.AgentMgmtPost{
			Command: "hsync-agentstatus",
			AgentId: tdns.AgentId(tdns.Globals.AgentId),
		}, "hsync")

		if err != nil {
			log.Fatalf("Error sending agent management command: %v", err)
		}

		if amr.Error {
			log.Fatalf("Error response from agent %q: %s", tdns.Globals.AgentId, amr.ErrorMsg)
		}

		if len(amr.Agents) > 0 {

			for _, agent := range amr.Agents {
				err := PrintAgent(agent, true)
				if err != nil {
					log.Printf("Error printing agent: %v", err)
				}
				fmt.Println()
			}
		} else {
			fmt.Printf("\nNo remote agent with identity %q found in the AgentRegistry\n", tdns.Globals.AgentId)
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

		req := tdns.AgentMgmtPost{
			Command: "hsync-locate",
			AgentId: tdns.AgentId(dns.Fqdn(args[0])),
			Zone:    tdns.ZoneName(tdns.Globals.Zonename),
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

		// Display the located agent info
		if len(resp.Agents) > 0 {
			agent := resp.Agents[0] // Should only be one agent
			fmt.Printf("Located agent: %s\n", agent.Identity)
			for transport, details := range map[string]*tdns.AgentDetails{
				"API": agent.ApiDetails,
				"DNS": agent.DnsDetails,
			} {
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
		agentIdentity := tdns.AgentId(tdns.Globals.Zonename)

		myid := tdns.AgentId(dns.Fqdn(syncIdentity))

		var conf tdns.Config
		err := viper.Unmarshal(&conf)
		if err != nil {
			fmt.Printf("Error: failed to unmarshal agent config from viper\n")
			return
		}

		// Create a new agent registry
		registry := conf.NewAgentRegistry()
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
			registry.LocateAgent(agentIdentity, "", nil)

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
			helloMsg := &tdns.AgentHelloPost{
				MessageType: tdns.AgentMsgHello,
				MyIdentity:  myid,
				// Time:        time.Now(),
				// Zone: cmd.Flag("zone").Value.String(),
				Zone: tdns.ZoneName(tdns.Globals.Zonename),
			}

			// Send the hello message
			amr, err := agent.SendApiHello(helloMsg)
			if err != nil {
				fmt.Printf("Error sending HELLO: %v\n", err)
				return
			}

			// Display the response
			fmt.Printf("Response from agent %s:\n", agentIdentity)
			fmt.Printf("  Time: %s\n", amr.Time)
			fmt.Printf("  Message: %s\n", amr.Msg)
			if amr.Error {
				fmt.Printf("  Error: %s\n", amr.ErrorMsg)
			}

		case err := <-errorCh:
			fmt.Printf("Error: %v\n", err)
		}
	},
}

func PrintAgent(agent *tdns.Agent, showZones bool) error {
	fmt.Printf("Remote agent %q: state: %s\n", agent.Identity, tdns.AgentStateToString[agent.State])

	if showZones {
		var zones []string
		for zone := range agent.Zones {
			zones = append(zones, string(zone))
		}
		sort.Strings(zones)
		fmt.Printf(" * Zones shared with this agent: %v\n", zones)
	}

	for transport, details := range map[string]*tdns.AgentDetails{
		"API": agent.ApiDetails,
		"DNS": agent.DnsDetails,
	} {
		if details == nil {
			continue
		}
		if syncTransport != "" && strings.ToUpper(syncTransport) != transport {
			continue
		}
		displayTransport := transport
		if transport == "https" {
			displayTransport = "API"
		}
		fmt.Printf("\n * Transport: %s, State: %s\n",
			displayTransport, tdns.AgentStateToString[details.State])
		if details.LatestError != "" {
			fmt.Printf(" - Latest Error: %s\n", details.LatestError)
			fmt.Printf(" - Time of error: %s (duration of outage: %v)\n",
				details.LatestErrorTime.Format(tdns.TimeLayout), time.Since(details.LatestErrorTime))
		}
		fmt.Printf(" *   Heartbeats: Sent: %d (latest %s), received: %d (latest %s)\n",
			details.SentBeats, details.LatestSBeat.Format(tdns.TimeLayout),
			details.ReceivedBeats, details.LatestRBeat.Format(tdns.TimeLayout))
		if tdns.Globals.Verbose {
			if len(details.Addrs) > 0 {
				// fmt.Printf("      Endpoints:\n")
				//for _, addr := range details.Addrs {
				if transport == "DNS" {
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

					fmt.Printf(" *   Target: %s\n", target)
					fmt.Printf(" *   Addresses: %v\n", addrs)
					if details.KeyRR != nil {
						keyStr := details.KeyRR.String()
						parts := strings.Fields(keyStr)
						if len(parts) > 0 {
							key := parts[len(parts)-1] // Get the last field which is the key data
							if len(key) > 20 {
								truncKey := key[:10] + "***" + key[len(key)-10:]
								fmt.Printf(" *   SIG(0) KEY RR: %s %s %s %s %s\n",
									parts[0], parts[1], parts[2], parts[3], truncKey)
							} else {
								fmt.Printf(" *   SIG(0) KEY RR: %s\n", keyStr)
							}
						}
					}
				} else if transport == "API" {
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

					fmt.Printf(" *   Base URL: %s\n", baseURL)
					fmt.Printf(" *   Addresses: %v\n", addrs)
					if details.TlsaRR != nil {
						tlsaStr := details.TlsaRR.String()
						parts := strings.Fields(tlsaStr)
						if len(parts) > 0 {
							hash := parts[len(parts)-1] // Get the last field which is the hash
							if len(hash) > 20 {
								truncHash := hash[:10] + "***" + hash[len(hash)-10:]
								fmt.Printf(" *   TLSA RR: %s %s %s %s %s\n",
									parts[0], parts[1], parts[2], parts[3], truncHash)
							} else {
								fmt.Printf(" *   TLSA RR: %s\n", tlsaStr)
							}
						}
					}
				} else {
					fmt.Printf("Error: unknown transport: %q\n", transport)
				}
			}
		}
	}
	return nil
}

func PrintHsyncRRs(agentid tdns.AgentId, rrs []string) {
	fmt.Printf("%s  HSYNC RRset:\n", tdns.Globals.Zonename)
	var lines []string
	for _, rrstr := range rrs {
		rr, err := dns.NewRR(rrstr)
		if err != nil {
			log.Printf("Failed to parse HSYNC RR: %v", err)
			continue
		}

		privRR, ok := rr.(*dns.PrivateRR)
		if !ok {
			log.Printf("RR is not a PrivateRR: %v", rr)
			continue
		}

		hsyncRR, ok := privRR.Data.(*core.HSYNC)
		if !ok {
			log.Printf("PrivateRR does not contain HSYNC data: %v", privRR)
			continue
		}

		fields := strings.Fields(rrstr)
		if tdns.AgentId(hsyncRR.Identity) == agentid {
			fields = append(fields, "(local agent)")
		}
		lines = append(lines, strings.Join(fields, "|"))
	}
	fmt.Println(columnize.SimpleFormat(lines))
}
