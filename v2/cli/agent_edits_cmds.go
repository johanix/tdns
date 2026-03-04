/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * CLI commands for inspecting agent SDE (SynchedDataEngine) status.
 * Provides "agent zone edits list [--zone {zone}]" with per-RR
 * tracking state and outbound queue status.
 */
package cli

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
)

var agentZoneEditsCmd = &cobra.Command{
	Use:   "edits",
	Short: "Agent edit/sync status commands",
}

var agentZoneEditsListCmd = &cobra.Command{
	Use:   "list",
	Short: "Show synchronized data and tracking state",
	Long: `Display the agent's SynchedDataEngine state showing contributions from all peer agents.

Without --zone: summary view sorted by zone → source agent → RRtype → RRs
With --zone:    detailed per-RR tracking state and outbound queue status

Example:
  tdns-cliv2 agent zone edits list
  tdns-cliv2 agent zone edits list --zone example.com`,
	Run: func(cmd *cobra.Command, args []string) {
		zone, _ := cmd.Flags().GetString("zone")

		if zone != "" {
			showDetailedZoneStatus(zone)
		} else {
			showSyncedDataSummary()
		}
	},
}

// showSyncedDataSummary displays a zone→agent→rrtype hierarchy.
func showSyncedDataSummary() {
	req := tdns.AgentMgmtPost{
		Command: "dump-zonedatarepo",
	}

	amr, err := SendAgentDebugCmd(req, false)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	if amr.Error {
		log.Fatalf("Error: %s", amr.ErrorMsg)
	}

	if len(amr.ZoneDataRepo) == 0 {
		fmt.Printf("No synchronized data stored in agent %q\n", amr.Identity)
		return
	}

	fmt.Printf("Synchronized Data from Peer Agents\n")
	fmt.Printf("===================================\n\n")

	for zoneName, agentRepo := range amr.ZoneDataRepo {
		fmt.Printf("Zone: %s\n", zoneName)
		fmt.Printf("────────────────────────────────────────\n")

		if len(agentRepo) == 0 {
			fmt.Printf("  (no peer contributions)\n\n")
			continue
		}

		for agentID, rrTypeMap := range agentRepo {
			fmt.Printf("  Source: %s\n", agentID)

			if len(rrTypeMap) == 0 {
				fmt.Printf("    (no RRsets)\n")
				continue
			}

			for rrtype, rrStrings := range rrTypeMap {
				rrTypeName := dns.TypeToString[rrtype]
				if rrTypeName == "" {
					rrTypeName = fmt.Sprintf("TYPE%d", rrtype)
				}

				fmt.Printf("    %s (%d records):\n", rrTypeName, len(rrStrings))
				if rrtype == dns.TypeDNSKEY {
					for _, info := range rrStrings {
						rr, err := dns.NewRR(info.RR)
						if err != nil {
							fmt.Printf("      %s  %s  %s\n", info.RR, info.State, info.UpdatedAt)
							continue
						}
						dnskey, ok := rr.(*dns.DNSKEY)
						if !ok {
							fmt.Printf("      %s  %s  %s\n", info.RR, info.State, info.UpdatedAt)
							continue
						}
						pub := dnskey.PublicKey
						if len(pub) > 15 {
							pub = pub[:10] + "..." + pub[len(pub)-5:]
						}
						flagDesc := "ZSK"
						if dnskey.Flags&0x0001 != 0 {
							flagDesc = "KSK"
						}
						fmt.Printf("      keytag=%-5d  %s (%d)  alg=%-10s  key=%s  [%s %s]\n",
							dnskey.KeyTag(), flagDesc, dnskey.Flags,
							dns.AlgorithmToString[dnskey.Algorithm], pub,
							info.State, info.UpdatedAt)
					}
				} else {
					for _, info := range rrStrings {
						fmt.Printf("      %s\n", info)
					}
				}
			}
			fmt.Printf("\n")
		}
	}
}

// showDetailedZoneStatus displays per-RR tracking state in table format
// and outbound queue status for a single zone.
func showDetailedZoneStatus(zone string) {
	// 1. Get per-RR tracking data
	req := tdns.AgentMgmtPost{
		Command: "dump-zonedatarepo",
		Zone:    tdns.ZoneName(zone),
	}

	amr, err := SendAgentDebugCmd(req, false)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	if amr.Error {
		log.Fatalf("Error: %s", amr.ErrorMsg)
	}

	fmt.Printf("SDE Status for Zone: %s\n", zone)
	fmt.Printf("════════════════════════════════════════\n\n")

	if len(amr.ZoneDataRepo) == 0 {
		fmt.Printf("  (no synchronized data for this zone)\n\n")
	} else {
		for _, agentRepo := range amr.ZoneDataRepo {
			for agentID, rrTypeMap := range agentRepo {
				fmt.Printf("Source: %s\n\n", agentID)

				if len(rrTypeMap) == 0 {
					fmt.Printf("  (no RRsets)\n\n")
					continue
				}

				// Flag KEYSTATE failure
				if ksInfo, ok := amr.KeystateStatus[tdns.ZoneName(zone)]; ok && !ksInfo.OK {
					fmt.Printf("  WARNING: KEYSTATE exchange FAILED: %s\n\n", ksInfo.Error)
				}

				var rows []string
				rows = append(rows, "Type | State | RR / Details")

				for rrtype, rrInfos := range rrTypeMap {
					rrTypeName := dns.TypeToString[rrtype]
					if rrTypeName == "" {
						rrTypeName = fmt.Sprintf("TYPE%d", rrtype)
					}

					for _, info := range rrInfos {
						state := strings.ToUpper(info.State)
						rrDisplay := truncateDNSKEY(info.RR)

						// Main row: Type | State | RR
						rows = append(rows, fmt.Sprintf("%s | %s | %s",
							rrTypeName, state, rrDisplay))

						// Detail row: Updated timestamp
						updatedStr := info.UpdatedAt
						if t, err := time.Parse(time.RFC3339, info.UpdatedAt); err == nil {
							updatedStr = t.Format("2006-01-02 15:04:05")
						}
						rows = append(rows, fmt.Sprintf(" | | Updated: %s", updatedStr))

						// For PENDING: show which recipients are still pending
						if info.State == "pending" && len(info.Confirmations) > 0 {
							var pendingPeers []string
							for recipientID, conf := range info.Confirmations {
								if conf.Status == "pending" {
									pendingPeers = append(pendingPeers, recipientID)
								}
							}
							if len(pendingPeers) > 0 {
								rows = append(rows, fmt.Sprintf(" | | Pending: %s",
									strings.Join(pendingPeers, ", ")))
							}
						}

						// For REJECTED: show who rejected and why
						if info.State == "rejected" {
							if info.Reason != "" {
								rows = append(rows, fmt.Sprintf(" | | Reason: %s", info.Reason))
							}
							for recipientID, conf := range info.Confirmations {
								if conf.Status == "rejected" {
									reason := conf.Reason
									if reason == "" {
										reason = "no reason given"
									}
									rows = append(rows, fmt.Sprintf(" | | Rejected by: %s (%s)",
										recipientID, reason))
								}
							}
						}
					}
				}

				if len(rows) > 1 {
					output := columnize.SimpleFormat(rows)
					fmt.Println(output)
				}
				fmt.Println()
			}
		}
	}

	// 2. Get outbound queue status
	showQueueStatusForZone(zone)
}

// showQueueStatusForZone fetches the reliable message queue status
// and displays only messages pertaining to the specified zone.
func showQueueStatusForZone(zone string) {
	queueReq := tdns.AgentMgmtPost{
		Command: "queue-status",
	}

	api, err := getApiClient("agent", true)
	if err != nil {
		log.Printf("Warning: could not get API client for queue status: %v", err)
		return
	}

	_, buf, err := api.RequestNG("POST", "/agent/debug", queueReq, true)
	if err != nil {
		log.Printf("Warning: queue-status request failed: %v", err)
		return
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(buf, &resp); err != nil {
		log.Printf("Warning: failed to parse queue-status response: %v", err)
		return
	}

	if errVal, ok := resp["error"].(bool); ok && errVal {
		return
	}

	data, ok := resp["data"].(map[string]interface{})
	if !ok {
		fmt.Printf("Outbound Queue (zone %s):\n  (no queue data available)\n", zone)
		return
	}

	messages, ok := data["messages"].([]interface{})
	if !ok || len(messages) == 0 {
		fmt.Printf("Outbound Queue (zone %s):\n  (no pending messages)\n", zone)
		return
	}

	// Filter messages for this zone
	fqdnZone := dns.Fqdn(zone)
	var filtered []map[string]interface{}
	for _, mRaw := range messages {
		m, ok := mRaw.(map[string]interface{})
		if !ok {
			continue
		}
		msgZone := getStringValue(m, "zone")
		if msgZone == zone || msgZone == fqdnZone {
			filtered = append(filtered, m)
		}
	}

	fmt.Printf("Outbound Queue (zone %s):\n", zone)
	if len(filtered) == 0 {
		fmt.Printf("  (no pending messages for this zone)\n")
		return
	}

	var rows []string
	rows = append(rows, "DistID | Recipient | Type | State | Attempts | Age")
	for _, m := range filtered {
		distID := getStringValue(m, "distribution_id")
		if len(distID) > 16 {
			distID = distID[:16] + "..."
		}
		attempts := "0"
		if v, ok := m["attempt_count"].(float64); ok {
			attempts = fmt.Sprintf("%d", int(v))
		}
		rows = append(rows, fmt.Sprintf("%s | %s | %s | %s | %s | %s",
			distID,
			getStringValue(m, "recipient_id"),
			getStringValue(m, "recipient_type"),
			getStringValue(m, "state"),
			attempts,
			getStringValue(m, "age"),
		))
	}
	if len(rows) > 1 {
		output := columnize.SimpleFormat(rows)
		fmt.Println(output)
	}
}

// truncateDNSKEY truncates DNSKEY public key material in an RR string for display.
// Returns the original string for non-DNSKEY records.
func truncateDNSKEY(rrStr string) string {
	rr, err := dns.NewRR(rrStr)
	if err != nil {
		return rrStr
	}
	dnskey, ok := rr.(*dns.DNSKEY)
	if !ok {
		return rrStr
	}
	pub := dnskey.PublicKey
	if len(pub) > 15 {
		pub = pub[:10] + "..." + pub[len(pub)-5:]
	}
	// Reconstruct a readable DNSKEY string with truncated key
	return fmt.Sprintf("%s %d IN DNSKEY %d %d %d %s",
		dnskey.Hdr.Name, dnskey.Hdr.Ttl, dnskey.Flags, dnskey.Protocol, dnskey.Algorithm, pub)
}

func init() {
	AgentZoneCmd.AddCommand(agentZoneEditsCmd)
	agentZoneEditsCmd.AddCommand(agentZoneEditsListCmd)

	agentZoneEditsListCmd.Flags().String("zone", "", "Show detailed status for a specific zone")
}
