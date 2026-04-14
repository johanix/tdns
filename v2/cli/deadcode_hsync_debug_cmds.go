//go:build ignore

/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Debug CLI commands for HSYNC (multi-provider DNSSEC coordination).
 * These commands provide visibility into HSYNC operations for testing and debugging.
 */

package cli

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
)

var hsyncPeerID, hsyncSyncType string
var hsyncResolver string // resolver address for hsync query (--imr); Globals.IMR was removed

var hsyncRRs []string

func init() {
	// Add debug subcommands to hsyncCmd
	hsyncCmd.AddCommand(hsyncQueryCmd)

	// Add debug subcommands under debug agent
	DebugAgentCmd.AddCommand(DebugAgentHsyncCmd)
	DebugAgentHsyncCmd.AddCommand(DebugHsyncChunkSendCmd)
	DebugAgentHsyncCmd.AddCommand(DebugHsyncChunkRecvCmd)
	DebugAgentHsyncCmd.AddCommand(DebugHsyncInitDbCmd)

	// Flags for hsync query
	hsyncQueryCmd.Flags().StringVarP(&hsyncResolver, "imr", "", "", "Resolver address for DNS query (e.g. 8.8.8.8:53)")

	// Flags for chunk send
	DebugHsyncChunkSendCmd.Flags().StringVarP(&hsyncPeerID, "peer", "p", "", "Target peer ID")
	DebugHsyncChunkSendCmd.Flags().StringVarP(&hsyncSyncType, "type", "t", "NS", "Sync type (NS, DNSKEY, GLUE, CDS, CSYNC)")
}

// hsyncQueryCmd queries HSYNC RRset directly via DNS
var hsyncQueryCmd = &cobra.Command{
	Use:   "query",
	Short: "Query HSYNC RRset for a zone via DNS",
	Long: `Query the HSYNC RRset for a zone directly via DNS.
This performs a DNS lookup for the HSYNC records at the zone apex.`,
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		zonename := dns.Fqdn(string(tdns.Globals.Zonename))

		// Get resolver address
		resolver := hsyncResolver
		if resolver == "" {
			resolver = "8.8.8.8:53"
		}

		fmt.Printf("Querying HSYNC3 records for zone %s via %s\n\n", zonename, resolver)

		// Create DNS client
		c := new(dns.Client)
		c.Timeout = 5 * time.Second

		// Create query for HSYNC type
		m := new(dns.Msg)
		m.SetQuestion(zonename, core.TypeHSYNC3)
		m.SetEdns0(4096, true)

		// Send query
		r, rtt, err := c.Exchange(m, resolver)
		if err != nil {
			log.Fatalf("DNS query failed: %v", err)
		}

		fmt.Printf("Query completed in %v\n", rtt)
		fmt.Printf("Response code: %s\n", dns.RcodeToString[r.Rcode])
		fmt.Printf("Answer section (%d records):\n\n", len(r.Answer))

		if len(r.Answer) == 0 {
			fmt.Println("No HSYNC3 records found")
			return
		}

		// Parse and display HSYNC3 records (core.HSYNC3: State, Label, Endpoint, Upstream)
		var lines []string
		if tdns.Globals.ShowHeaders {
			lines = append(lines, "Owner|TTL|Class|Type|Label|Identity|Upstream")
		}
		for _, rr := range r.Answer {
			privRR, ok := rr.(*dns.PrivateRR)
			if !ok {
				fmt.Printf("  %s (not a PrivateRR)\n", rr.String())
				continue
			}

			hsync3, ok := privRR.Data.(*core.HSYNC3)
			if !ok {
				fmt.Printf("  %s (not HSYNC3 data)\n", rr.String())
				continue
			}

			lines = append(lines, fmt.Sprintf("%s|%d|IN|HSYNC3|%s|%s|%s",
				rr.Header().Name,
				rr.Header().Ttl,
				hsync3.Label,
				hsync3.Identity,
				hsync3.Upstream))
		}
		fmt.Println(columnize.SimpleFormat(lines))
	},
}

// Debug agent subcommand for HSYNC
var DebugAgentHsyncCmd = &cobra.Command{
	Use:   "hsync",
	Short: "HSYNC debugging commands",
}

// DebugHsyncChunkSendCmd sends a test CHUNK
var DebugHsyncChunkSendCmd = &cobra.Command{
	Use:   "chunk-send",
	Short: "Send a test CHUNK to a peer",
	Long: `Manually send a CHUNK message to a peer for testing.
This is useful for testing DNS transport without full sync operations.`,
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		if hsyncPeerID == "" {
			log.Fatalf("Error: --peer is required")
		}

		parent, _ := GetCommandContext("debug")
		api, err := GetApiClient(parent, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := tdns.AgentMgmtPost{
			Command: "hsync-chunk-send",
			Zone:    tdns.ZoneName(tdns.Globals.Zonename),
			AgentId: tdns.AgentId(hsyncPeerID),
		}

		_, buf, err := api.RequestNG("POST", "/agent/debug", req, true)
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

		fmt.Printf("CHUNK sent successfully to peer %s\n", hsyncPeerID)
		fmt.Printf("Distribution ID: %s\n", resp.Msg)
	},
}

// DebugHsyncChunkRecvCmd shows received CHUNKs
var DebugHsyncChunkRecvCmd = &cobra.Command{
	Use:   "chunk-recv",
	Short: "Show recently received CHUNKs",
	Long:  `Display CHUNK messages received via DNS transport.`,
	Run: func(cmd *cobra.Command, args []string) {
		parent, _ := GetCommandContext("debug")
		api, err := GetApiClient(parent, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := tdns.AgentMgmtPost{
			Command: "hsync-chunk-recv",
		}

		_, buf, err := api.RequestNG("POST", "/agent/debug", req, true)
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

		fmt.Println("Recently received CHUNKs:")
		fmt.Println(resp.Msg)
	},
}

// DebugHsyncInitDbCmd initializes HSYNC database tables
var DebugHsyncInitDbCmd = &cobra.Command{
	Use:   "init-db",
	Short: "Initialize HSYNC database tables",
	Long:  `Create or verify the HSYNC database tables exist.`,
	Run: func(cmd *cobra.Command, args []string) {
		parent, _ := GetCommandContext("debug")
		api, err := GetApiClient(parent, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := tdns.AgentMgmtPost{
			Command: "hsync-init-db",
		}

		_, buf, err := api.RequestNG("POST", "/agent/debug", req, true)
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

		fmt.Println("HSYNC database tables initialized successfully")
	},
}

// DebugHsyncInjectSyncCmd removed (legacy Records-based debug command).
// Use "agent zone addrr/delrr" for Operations-based testing.
