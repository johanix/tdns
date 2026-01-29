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

var hsyncPeerID, hsyncCorrelationID, hsyncSyncType string
var hsyncLimit int
var hsyncResolver string // resolver address for hsync query (--imr); Globals.IMR was removed

var hsyncRRs []string

func init() {
	// Add debug subcommands to hsyncCmd
	hsyncCmd.AddCommand(hsyncQueryCmd)
	hsyncCmd.AddCommand(hsyncPeerStatusCmd)
	hsyncCmd.AddCommand(hsyncSyncOpsCmd)
	hsyncCmd.AddCommand(hsyncConfirmQueryCmd)
	hsyncCmd.AddCommand(hsyncTransportEventsCmd)
	hsyncCmd.AddCommand(hsyncMetricsCmd)

	// Add debug subcommands under debug agent
	DebugAgentCmd.AddCommand(DebugAgentHsyncCmd)
	DebugAgentHsyncCmd.AddCommand(DebugHsyncChunkSendCmd)
	DebugAgentHsyncCmd.AddCommand(DebugHsyncChunkRecvCmd)
	DebugAgentHsyncCmd.AddCommand(DebugHsyncInitDbCmd)
	DebugAgentHsyncCmd.AddCommand(DebugHsyncInjectSyncCmd)

	// Flags for hsync query
	hsyncQueryCmd.Flags().StringVarP(&hsyncResolver, "imr", "", "", "Resolver address for DNS query (e.g. 8.8.8.8:53)")

	// Flags for peer status
	hsyncPeerStatusCmd.Flags().StringVarP(&hsyncPeerID, "peer", "p", "", "Filter by peer ID")
	hsyncPeerStatusCmd.Flags().StringVarP(&syncTransport, "state", "s", "", "Filter by state (needed, known, operational, etc.)")

	// Flags for sync operations
	hsyncSyncOpsCmd.Flags().StringVarP(&hsyncCorrelationID, "correlation", "c", "", "Filter by correlation ID")
	hsyncSyncOpsCmd.Flags().StringVarP(&hsyncSyncType, "type", "t", "", "Filter by sync type (NS, DNSKEY, GLUE, CDS, CSYNC)")
	hsyncSyncOpsCmd.Flags().IntVarP(&hsyncLimit, "limit", "n", 50, "Maximum number of operations to show")

	// Flags for confirm query
	hsyncConfirmQueryCmd.Flags().StringVarP(&hsyncCorrelationID, "correlation", "c", "", "Filter by correlation ID")

	// Flags for transport events
	hsyncTransportEventsCmd.Flags().StringVarP(&hsyncPeerID, "peer", "p", "", "Filter by peer ID")
	hsyncTransportEventsCmd.Flags().IntVarP(&hsyncLimit, "limit", "n", 100, "Maximum number of events to show")

	// Flags for chunk send
	DebugHsyncChunkSendCmd.Flags().StringVarP(&hsyncPeerID, "peer", "p", "", "Target peer ID")
	DebugHsyncChunkSendCmd.Flags().StringVarP(&hsyncSyncType, "type", "t", "NS", "Sync type (NS, DNSKEY, GLUE, CDS, CSYNC)")

	// Flags for inject-sync
	DebugHsyncInjectSyncCmd.Flags().StringVarP(&hsyncPeerID, "sender", "s", "", "Sender agent identity (required)")
	DebugHsyncInjectSyncCmd.Flags().StringArrayVarP(&hsyncRRs, "rr", "r", nil, "RR to inject (can be specified multiple times)")
	DebugHsyncInjectSyncCmd.MarkFlagRequired("sender")
	DebugHsyncInjectSyncCmd.MarkFlagRequired("rr")
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

		fmt.Printf("Querying HSYNC records for zone %s via %s\n\n", zonename, resolver)

		// Create DNS client
		c := new(dns.Client)
		c.Timeout = 5 * time.Second

		// Create query for HSYNC type
		m := new(dns.Msg)
		m.SetQuestion(zonename, core.TypeHSYNC)
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
			fmt.Println("No HSYNC records found")
			return
		}

		// Parse and display HSYNC records (core.HSYNC: State, NSmgmt, Sign, Identity, Upstream)
		var lines []string
		if tdns.Globals.ShowHeaders {
			lines = append(lines, "Owner|TTL|Class|Type|Identity|Sign|NSmgmt|Upstream")
		}
		for _, rr := range r.Answer {
			privRR, ok := rr.(*dns.PrivateRR)
			if !ok {
				fmt.Printf("  %s (not a PrivateRR)\n", rr.String())
				continue
			}

			hsync, ok := privRR.Data.(*core.HSYNC)
			if !ok {
				fmt.Printf("  %s (not HSYNC data)\n", rr.String())
				continue
			}

			lines = append(lines, fmt.Sprintf("%s|%d|IN|HSYNC|%s|%s|%s|%s",
				rr.Header().Name,
				rr.Header().Ttl,
				hsync.Identity,
				core.HsyncSignToString[hsync.Sign],
				core.HsyncNSmgmtToString[hsync.NSmgmt],
				hsync.Upstream))
		}
		fmt.Println(columnize.SimpleFormat(lines))
	},
}

// hsyncPeerStatusCmd shows peer status from the database
var hsyncPeerStatusCmd = &cobra.Command{
	Use:   "peers",
	Short: "Show HSYNC peer status from database",
	Long: `Display the status of HSYNC peers stored in the database.
Shows peer state, transport details, and heartbeat statistics.`,
	Run: func(cmd *cobra.Command, args []string) {
		parent, _ := getCommandContext("hsync")
		api, err := getApiClient(parent, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := tdns.AgentMgmtPost{
			Command: "hsync-peer-status",
			AgentId: tdns.AgentId(hsyncPeerID),
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

		if len(resp.HsyncPeers) == 0 {
			fmt.Println("No peers found in database")
			return
		}

		fmt.Printf("HSYNC Peers (%d):\n\n", len(resp.HsyncPeers))

		var lines []string
		if tdns.Globals.ShowHeaders {
			lines = append(lines, "Peer ID|State|Preferred|API|DNS|Last Contact|Beats Sent|Beats Recv")
		}
		for _, peer := range resp.HsyncPeers {
			apiStatus := "N"
			if peer.APIAvailable {
				apiStatus = "Y"
			}
			dnsStatus := "N"
			if peer.DNSAvailable {
				dnsStatus = "Y"
			}
			lastContact := "never"
			if !peer.LastContactAt.IsZero() {
				lastContact = peer.LastContactAt.Format("2006-01-02 15:04:05")
			}

			lines = append(lines, fmt.Sprintf("%s|%s|%s|%s|%s|%s|%d|%d",
				peer.PeerID,
				peer.State,
				peer.PreferredTransport,
				apiStatus,
				dnsStatus,
				lastContact,
				peer.BeatsSent,
				peer.BeatsReceived))
		}
		fmt.Println(columnize.SimpleFormat(lines))

		// Show detailed info if verbose
		if tdns.Globals.Verbose && len(resp.HsyncPeers) > 0 {
			fmt.Printf("\nDetailed peer information:\n")
			for _, peer := range resp.HsyncPeers {
				fmt.Printf("\n  Peer: %s\n", peer.PeerID)
				fmt.Printf("    State: %s (%s)\n", peer.State, peer.StateReason)
				fmt.Printf("    Discovery: %s at %s\n", peer.DiscoverySource, peer.DiscoveryTime.Format(time.RFC3339))
				if peer.APIAvailable {
					fmt.Printf("    API Endpoint: %s:%d\n", peer.APIHost, peer.APIPort)
				}
				if peer.DNSAvailable {
					fmt.Printf("    DNS Endpoint: %s:%d\n", peer.DNSHost, peer.DNSPort)
				}
				fmt.Printf("    Beat interval: %ds\n", peer.BeatInterval)
			}
		}
	},
}

// hsyncSyncOpsCmd shows sync operations from the database
var hsyncSyncOpsCmd = &cobra.Command{
	Use:   "sync-ops",
	Short: "Show HSYNC sync operations",
	Long: `Display sync operations tracked in the database.
Shows operation details, status, and timestamps.`,
	Run: func(cmd *cobra.Command, args []string) {
		parent, _ := getCommandContext("hsync")
		api, err := getApiClient(parent, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := tdns.AgentMgmtPost{
			Command: "hsync-sync-ops",
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

		if len(resp.HsyncSyncOps) == 0 {
			fmt.Println("No sync operations found")
			return
		}

		fmt.Printf("Sync Operations (%d):\n\n", len(resp.HsyncSyncOps))

		var lines []string
		if tdns.Globals.ShowHeaders {
			lines = append(lines, "Correlation ID|Zone|Type|Direction|Status|Created|Sender|Receiver")
		}
		for _, op := range resp.HsyncSyncOps {
			// Truncate correlation ID for display
			corrID := op.CorrelationID
			if len(corrID) > 16 {
				corrID = corrID[:16] + "..."
			}

			lines = append(lines, fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s",
				corrID,
				op.ZoneName,
				op.SyncType,
				op.Direction,
				op.Status,
				op.CreatedAt.Format("2006-01-02 15:04"),
				op.SenderID,
				op.ReceiverID))
		}
		fmt.Println(columnize.SimpleFormat(lines))
	},
}

// hsyncConfirmQueryCmd queries confirmations
var hsyncConfirmQueryCmd = &cobra.Command{
	Use:   "confirmations",
	Short: "Query HSYNC confirmations",
	Long:  `Display confirmation records for sync operations.`,
	Run: func(cmd *cobra.Command, args []string) {
		parent, _ := getCommandContext("hsync")
		api, err := getApiClient(parent, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := tdns.AgentMgmtPost{
			Command: "hsync-confirmations",
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

		if len(resp.HsyncConfirmations) == 0 {
			fmt.Println("No confirmations found")
			return
		}

		fmt.Printf("Confirmations (%d):\n\n", len(resp.HsyncConfirmations))

		var lines []string
		if tdns.Globals.ShowHeaders {
			lines = append(lines, "Correlation ID|Confirmer|Status|Message|Confirmed At")
		}
		for _, conf := range resp.HsyncConfirmations {
			corrID := conf.CorrelationID
			if len(corrID) > 16 {
				corrID = corrID[:16] + "..."
			}
			msg := conf.Message
			if len(msg) > 30 {
				msg = msg[:30] + "..."
			}

			lines = append(lines, fmt.Sprintf("%s|%s|%s|%s|%s",
				corrID,
				conf.ConfirmerID,
				conf.Status,
				msg,
				conf.ConfirmedAt.Format("2006-01-02 15:04")))
		}
		fmt.Println(columnize.SimpleFormat(lines))
	},
}

// hsyncTransportEventsCmd shows transport events
var hsyncTransportEventsCmd = &cobra.Command{
	Use:   "events",
	Short: "Show HSYNC transport events",
	Long:  `Display recent transport events for debugging connectivity issues.`,
	Run: func(cmd *cobra.Command, args []string) {
		parent, _ := getCommandContext("hsync")
		api, err := getApiClient(parent, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := tdns.AgentMgmtPost{
			Command: "hsync-transport-events",
			AgentId: tdns.AgentId(hsyncPeerID),
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

		if len(resp.HsyncEvents) == 0 {
			fmt.Println("No transport events found")
			return
		}

		fmt.Printf("Transport Events (%d):\n\n", len(resp.HsyncEvents))

		var lines []string
		if tdns.Globals.ShowHeaders {
			lines = append(lines, "Time|Peer|Event Type|Transport|Direction|Success|Error")
		}
		for _, evt := range resp.HsyncEvents {
			success := "Y"
			if !evt.Success {
				success = "N"
			}
			errMsg := evt.ErrorMessage
			if len(errMsg) > 30 {
				errMsg = errMsg[:30] + "..."
			}

			lines = append(lines, fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s",
				evt.EventTime.Format("15:04:05"),
				evt.PeerID,
				evt.EventType,
				evt.Transport,
				evt.Direction,
				success,
				errMsg))
		}
		fmt.Println(columnize.SimpleFormat(lines))
	},
}

// hsyncMetricsCmd shows operational metrics
var hsyncMetricsCmd = &cobra.Command{
	Use:   "metrics",
	Short: "Show HSYNC operational metrics",
	Long:  `Display aggregated operational metrics for HSYNC operations.`,
	Run: func(cmd *cobra.Command, args []string) {
		parent, _ := getCommandContext("hsync")
		api, err := getApiClient(parent, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := tdns.AgentMgmtPost{
			Command: "hsync-metrics",
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

		if resp.HsyncMetrics == nil {
			fmt.Println("No metrics available")
			return
		}

		m := resp.HsyncMetrics
		fmt.Println("HSYNC Operational Metrics:")
		fmt.Println()
		fmt.Printf("  Syncs Sent:      %d\n", m.SyncsSent)
		fmt.Printf("  Syncs Received:  %d\n", m.SyncsReceived)
		fmt.Printf("  Syncs Confirmed: %d\n", m.SyncsConfirmed)
		fmt.Printf("  Syncs Failed:    %d\n", m.SyncsFailed)
		fmt.Println()
		fmt.Printf("  Beats Sent:      %d\n", m.BeatsSent)
		fmt.Printf("  Beats Received:  %d\n", m.BeatsReceived)
		fmt.Printf("  Beats Missed:    %d\n", m.BeatsMissed)
		fmt.Println()
		fmt.Printf("  API Operations:  %d\n", m.APIOperations)
		fmt.Printf("  DNS Operations:  %d\n", m.DNSOperations)
		if m.AvgLatency > 0 {
			fmt.Printf("  Avg Latency:     %dms\n", m.AvgLatency)
			fmt.Printf("  Max Latency:     %dms\n", m.MaxLatency)
		}
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

		parent, _ := getCommandContext("debug")
		api, err := getApiClient(parent, true)
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
		fmt.Printf("Correlation ID: %s\n", resp.Msg)
	},
}

// DebugHsyncChunkRecvCmd shows received CHUNKs
var DebugHsyncChunkRecvCmd = &cobra.Command{
	Use:   "chunk-recv",
	Short: "Show recently received CHUNKs",
	Long:  `Display CHUNK messages received via DNS transport.`,
	Run: func(cmd *cobra.Command, args []string) {
		parent, _ := getCommandContext("debug")
		api, err := getApiClient(parent, true)
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
		parent, _ := getCommandContext("debug")
		api, err := getApiClient(parent, true)
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

// DebugHsyncInjectSyncCmd simulates receiving a sync from a remote agent
var DebugHsyncInjectSyncCmd = &cobra.Command{
	Use:   "inject-sync",
	Short: "Inject a simulated sync from a remote agent",
	Long: `Inject a simulated sync update as if received from a remote agent.

This command simulates the reception of DNS resource records from another
HSYNC agent, allowing you to test the local agent's processing pipeline
without requiring an actual remote agent.

The RRs are specified as standard DNS zone file format strings. Multiple
RRs can be specified to test atomic multi-RRset updates (e.g., NS + glue).

Example:
  tdns-cli debug agent hsync inject-sync -z example.com \
    --sender "agent2.example.com." \
    -r "example.com. 3600 IN NS ns6.example.com." \
    -r "ns6.example.com. 3600 IN A 1.2.3.4" \
    -r "ns6.example.com. 3600 IN AAAA 2001:db8::53"

This tests the atomic update flow: a new NS record with its glue records
are processed as a single transaction.`,
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		if hsyncPeerID == "" {
			log.Fatalf("Error: --sender is required")
		}

		if len(hsyncRRs) == 0 {
			log.Fatalf("Error: at least one --rr is required")
		}

		parent, _ := getCommandContext("debug")
		api, err := getApiClient(parent, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		// Validate RRs by parsing them locally first
		fmt.Println("Validating RRs:")
		for i, rrStr := range hsyncRRs {
			rr, err := dns.NewRR(rrStr)
			if err != nil {
				log.Fatalf("Invalid RR #%d %q: %v", i+1, rrStr, err)
			}
			fmt.Printf("  [%d] %s\n", i+1, rr.String())
		}

		req := tdns.AgentMgmtPost{
			Command: "hsync-inject-sync",
			Zone:    tdns.ZoneName(dns.Fqdn(string(tdns.Globals.Zonename))),
			AgentId: tdns.AgentId(dns.Fqdn(hsyncPeerID)),
			RRs:     hsyncRRs,
		}

		fmt.Printf("\nInjecting sync from %q for zone %q:\n", req.AgentId, req.Zone)

		_, buf, err := api.RequestNG("POST", "/agent/debug", req, true)
		if err != nil {
			log.Fatalf("API request failed: %v", err)
		}

		var resp tdns.AgentMgmtResponse
		if err := json.Unmarshal(buf, &resp); err != nil {
			log.Fatalf("Failed to parse response: %v", err)
		}

		if resp.Error {
			fmt.Printf("\nError: %s\n", resp.ErrorMsg)
		} else {
			fmt.Printf("\nResult: %s\n", resp.Msg)
			if resp.Status != "" {
				fmt.Printf("Status: %s\n", resp.Status)
			}
		}
	},
}
