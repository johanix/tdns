/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/gookit/goutil/dump"
	"github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
)

var myIdentity, notifyRRtype, rfitype, rfisubtype string

var DebugAgentCmd = &cobra.Command{
	Use:   "debug",
	Short: "TDNS-AGENT debugging commands",
}

var DebugAgentSendNotifyCmd = &cobra.Command{
	Use:   "send-notify",
	Short: "Tell agent to send a NOTIFY message to the other agents",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename", "identity")

		notifyRRtype = strings.ToUpper(notifyRRtype)
		if notifyRRtype != "NS" && notifyRRtype != "DNSKEY" {
			log.Fatalf("Error: RR type must be either NS or DNSKEY (is %q)", notifyRRtype)
		}

		if dnsRecord == "" {
			log.Fatalf("Error: DNS record is required")
		}

		var rr dns.RR
		var err error

		if rr, err = dns.NewRR(dnsRecord); err != nil {
			log.Fatalf("Error: Invalid DNS record (did not parse): %v", err)
		}

		rrs := []string{rr.String()}

		rrtype := dns.StringToType[notifyRRtype]
		if rrtype == 0 {
			log.Fatalf("Error: Invalid RR type: %s", notifyRRtype)
		}

		req := tdns.AgentMgmtPost{
			Command:     "send-notify",
			MessageType: tdns.AgentMsgNotify,
			RRType:      rrtype,
			Zone:        tdns.ZoneName(tdns.Globals.Zonename),
			AgentId:     tdns.Globals.AgentId,
			RRs:         rrs,
		}

		_, err = SendAgentDebugCmd(req, true)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
	},
}

var DebugAgentSendRfiCmd = &cobra.Command{
	Use:   "send-rfi",
	Short: "Tell agent to send an RFI message to another agent",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename", "identity")

		rfitype = strings.ToUpper(rfitype)
		validRfiTypes := map[string]bool{"CONFIG": true, "SYNC": true, "AUDIT": true, "EDITS": true}
		if !validRfiTypes[rfitype] {
			log.Fatalf("Error: RFI type must be one of CONFIG, SYNC, AUDIT, or EDITS (is %q)", rfitype)
		}

		if rfitype == "CONFIG" && rfisubtype == "" {
			log.Fatalf("Error: CONFIG RFI requires --subtype (upstream, downstream, sig0key)")
		}
		rfisubtype = strings.ToLower(rfisubtype)

		req := tdns.AgentMgmtPost{
			Command:     "send-rfi",
			MessageType: tdns.AgentMsgRfi,
			RfiType:     rfitype,
			RfiSubtype:  rfisubtype,
			Zone:        tdns.ZoneName(tdns.Globals.Zonename),
			AgentId:     tdns.Globals.AgentId,
		}

		amr, err := SendAgentDebugCmd(req, false)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if amr.Error {
			log.Fatalf("Error: %s", amr.ErrorMsg)
		}

		fmt.Printf("Result from %s RFI message sent to agent %q:\n", amr.RfiType, amr.Identity)
		if amr.Msg != "" {
			fmt.Printf("%s\n", amr.Msg)
		}
		if len(amr.RfiResponse) > 0 {
			switch {
			case rfitype == "CONFIG" && (rfisubtype == "upstream" || rfisubtype == "downstream"):
				var out []string
				if tdns.Globals.ShowHeaders {
					out = append(out, "Zone|Provider|Where|XFR src|XFR dst|XFR auth")
				}
				for aid, rfidata := range amr.RfiResponse {
					if rfidata.Error {
						fmt.Printf("  %s: error: %s\n", aid, rfidata.ErrorMsg)
						continue
					}
					if len(rfidata.ZoneXfrSrcs) > 0 {
						out = append(out, fmt.Sprintf("%s|%s|upstream|%v|%v|%v", tdns.Globals.Zonename, aid, rfidata.ZoneXfrSrcs, "", rfidata.ZoneXfrAuth))
					}
					if len(rfidata.ZoneXfrDsts) > 0 {
						out = append(out, fmt.Sprintf("%s|%s|downstream|%v|%v|%v", tdns.Globals.Zonename, aid, "", rfidata.ZoneXfrDsts, rfidata.ZoneXfrAuth))
					}
				}
				if len(out) > 0 {
					fmt.Printf("%s\n", columnize.SimpleFormat(out))
				}

			case rfitype == "CONFIG":
				for aid, rfidata := range amr.RfiResponse {
					if rfidata.Error {
						fmt.Printf("  %s: error: %s\n", aid, rfidata.ErrorMsg)
					} else {
						fmt.Printf("  %s: %s\n", aid, rfidata.Msg)
						for k, v := range rfidata.ConfigData {
							fmt.Printf("    %s: %s\n", k, v)
						}
					}
				}

			case rfitype == "SYNC":
				for aid, rfidata := range amr.RfiResponse {
					if rfidata.Error {
						fmt.Printf("  %s: error: %s\n", aid, rfidata.ErrorMsg)
					} else {
						fmt.Printf("  %s: %s\n", aid, rfidata.Msg)
					}
				}

			case rfitype == "AUDIT":
				for aid, rfidata := range amr.RfiResponse {
					if rfidata.Error {
						fmt.Printf("  %s: error: %s\n", aid, rfidata.ErrorMsg)
					} else {
						fmt.Printf("  %s: %s\n", aid, rfidata.Msg)
						if rfidata.AuditData != nil {
							auditJSON, err := json.MarshalIndent(rfidata.AuditData, "    ", "  ")
							if err != nil {
								fmt.Printf("    Error formatting audit data: %v\n", err)
							} else {
								fmt.Printf("    Audit data:\n    %s\n", string(auditJSON))
							}
						}
					}
				}

			case rfitype == "EDITS":
				for aid, rfidata := range amr.RfiResponse {
					if rfidata.Error {
						fmt.Printf("  %s: error: %s\n", aid, rfidata.ErrorMsg)
					} else {
						fmt.Printf("  %s: %s\n", aid, rfidata.Msg)
					}
				}
			}
		} else {
			fmt.Printf("No RFI data in response from agent %q\n", amr.Identity)
		}
	},
}

var DebugAgentDumpAgentRegistryCmd = &cobra.Command{
	Use:   "dump-agentregistry",
	Short: "Dump the agent registry",
	Run: func(cmd *cobra.Command, args []string) {
		req := tdns.AgentMgmtPost{
			Command: "dump-agentregistry",
		}

		amr, err := SendAgentDebugCmd(req, false)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if amr.Error {
			log.Fatalf("Error: %s", amr.ErrorMsg)
		}

		// dump.P(amr.AgentRegistry)
		if len(amr.AgentRegistry.RegularS) == 0 {
			fmt.Printf("No agent registry data in response from agent %q", amr.Identity)
			os.Exit(1)
		}

		if len(amr.AgentRegistry.RegularS) > 0 {
			var agentNames []tdns.AgentId
			for _, agent := range amr.AgentRegistry.RegularS {
				agentNames = append(agentNames, agent.Identity)
			}
			fmt.Printf("Agent registry contains %d agents: %v\n", len(agentNames), agentNames)
			for _, agent := range amr.AgentRegistry.RegularS {
				err := PrintAgent(agent, false)
				if err != nil {
					log.Printf("Error printing agent: %v", err)
				}
				fmt.Println()
			}
		} else {
			fmt.Printf("No remote agents found in the agent registry data from agent %q", amr.Identity)
		}
	},
}

var DebugAgentShowSyncedDataCmd = &cobra.Command{
	Use:   "show-synced-data",
	Short: "Show synchronized data from peer agents (moved to: agent zone edits list)",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("This command has moved to: agent zone edits list")
		fmt.Println("Usage: tdns-cliv2 agent zone edits list [--zone <zone>]")
	},
}

// Keep the old command name as alias for compatibility
var DebugAgentDumpZoneDataRepoCmd = &cobra.Command{
	Use:    "dump-zonedatarepo",
	Short:  "Dump the zone data repo (deprecated: use show-synced-data)",
	Hidden: true,
	Run:    DebugAgentShowSyncedDataCmd.Run,
}

var DebugAgentRegistryCmd = &cobra.Command{
	Use:   "agentregistry",
	Short: "Test the agent registry",
	Run: func(cmd *cobra.Command, args []string) {
		conf := tdns.Config{
			MultiProvider: &tdns.MultiProviderConf{
				Identity: "local",
			},
		}
		ar := conf.NewAgentRegistry()
		ar.LocateInterval = 10
		ar.S.Set("local", &tdns.Agent{
			Identity: "local",
		})

		ar.AddRemoteAgent("agent.example.com", &tdns.Agent{
			Identity: "agent.example.com",
		})

		ar.AddRemoteAgent("agent.example.org", &tdns.Agent{
			Identity: "agent.example.org",
		})

		fmt.Printf("Agent registry:\ntype=%T\n", ar.S)
		fmt.Printf("Agent registry:\n%d shards\n", ar.S.NumShards())
		for item := range ar.S.IterBuffered() {
			// agent, _ := item.Val.(*tdns.Agent)
			fmt.Printf("Agent registry:\n%s\n", item.Key)
			fmt.Printf("Agent registry:\n%+v\n", item.Val)
		}
	},
}

var DebugAgentSyncStateCmd = &cobra.Command{
	Use:   "sync-state",
	Short: "Show sync state for a zone",
	Long: `Display the current synchronization state for a zone.

Example:
  tdns-cliv2 debug agent sync-state --zone example.com`,
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		req := tdns.AgentMgmtPost{
			Command: "hsync-sync-state",
			Zone:    tdns.ZoneName(tdns.Globals.Zonename),
		}

		amr, err := SendAgentDebugCmd(req, false)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if amr.Error {
			log.Fatalf("Error: %s", amr.ErrorMsg)
		}

		fmt.Printf("Sync State for zone %s:\n", tdns.Globals.Zonename)
		fmt.Printf("%s\n", amr.Msg)

		if amr.Data != nil {
			if dataMap, ok := amr.Data.(map[string]interface{}); ok {
				if zdr, ok := dataMap["zone_data_repo"]; ok {
					dump.P(zdr)
				}
			}
		}
	},
}

var DebugAgentShowCombinerDataCmd = &cobra.Command{
	Use:   "show-combiner-data",
	Short: "Show combiner's local modifications store",
	Long: `Display the combiner's stored local modifications that are applied to zones.
Data is sorted by: zone → RRtype → RRs

Example:
  tdns-cliv2 debug agent show-combiner-data
  tdns-cliv2 debug agent show-combiner-data --zone example.com`,
	Run: func(cmd *cobra.Command, args []string) {
		zone, _ := cmd.Flags().GetString("zone")

		req := tdns.AgentMgmtPost{
			Command: "show-combiner-data",
		}
		if zone != "" {
			req.Zone = tdns.ZoneName(zone)
		}

		amr, err := SendAgentDebugCmd(req, false)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if amr.Error {
			log.Fatalf("Error: %s", amr.ErrorMsg)
		}

		if amr.Data == nil {
			fmt.Printf("No combiner data available\n")
			return
		}

		dataMap, ok := amr.Data.(map[string]interface{})
		if !ok {
			fmt.Printf("Invalid combiner data format\n")
			return
		}

		combinerData, ok := dataMap["combiner_data"].(map[string]interface{})
		if !ok || len(combinerData) == 0 {
			fmt.Printf("No local modifications stored in combiner\n")
			return
		}

		fmt.Printf("Combiner Local Modifications\n")
		fmt.Printf("=============================\n\n")

		for zoneName, ownerMapInterface := range combinerData {
			fmt.Printf("Zone: %s\n", zoneName)
			fmt.Printf("────────────────────────────────────────\n")

			ownerMap, ok := ownerMapInterface.(map[string]interface{})
			if !ok || len(ownerMap) == 0 {
				fmt.Printf("  (no modifications)\n\n")
				continue
			}

			for ownerName, rrTypeMapInterface := range ownerMap {
				fmt.Printf("  Owner: %s\n", ownerName)

				rrTypeMap, ok := rrTypeMapInterface.(map[string]interface{})
				if !ok || len(rrTypeMap) == 0 {
					fmt.Printf("    (no RRsets)\n")
					continue
				}

				for rrTypeStr, rrStringsInterface := range rrTypeMap {
					rrStrings, ok := rrStringsInterface.([]interface{})
					if !ok {
						continue
					}

					fmt.Printf("    %s (%d records):\n", rrTypeStr, len(rrStrings))
					for _, rrInterface := range rrStrings {
						if rrStr, ok := rrInterface.(string); ok {
							fmt.Printf("      %s\n", rrStr)
						}
					}
				}
				fmt.Printf("\n")
			}
		}
	},
}

var DebugAgentSendSyncToCmd = &cobra.Command{
	Use:   "send-sync-to <RR> [<RR>...]",
	Short: "Send a SYNC message to a remote agent (real transport)",
	Long: `Create and send a real SYNC message to a specified remote agent.
Uses the actual transport (CHUNK NOTIFY + fallback).
RRs are validated before sending.

Example:
  tdns-cliv2 debug agent send-sync-to \
    --to agent.provider-b.example.com. \
    --zone example.com. \
    "example.com. 3600 IN NS ns1.provider-a.example.com." \
    "example.com. 3600 IN NS ns2.provider-a.example.com."`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		toAgent, _ := cmd.Flags().GetString("to")
		if toAgent == "" {
			log.Fatalf("Error: --to agent ID is required")
		}

		zone, _ := cmd.Flags().GetString("zone")
		if zone == "" {
			log.Fatalf("Error: --zone is required")
		}

		// Validate all RRs by parsing them
		var validRRs []string
		for _, rrStr := range args {
			rr, err := dns.NewRR(rrStr)
			if err != nil {
				log.Fatalf("Error: Invalid DNS record %q: %v", rrStr, err)
			}
			validRRs = append(validRRs, rr.String())
		}

		req := tdns.AgentMgmtPost{
			Command: "send-sync-to",
			Zone:    tdns.ZoneName(zone),
			AgentId: tdns.AgentId(toAgent),
			RRs:     validRRs,
		}

		amr, err := SendAgentDebugCmd(req, false)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if amr.Error {
			log.Fatalf("Error: %s", amr.ErrorMsg)
		}

		fmt.Printf("SYNC sent successfully:\n")
		fmt.Printf("  To: %s\n", toAgent)
		fmt.Printf("  Zone: %s\n", zone)
		fmt.Printf("  Records: %d\n", len(validRRs))
		fmt.Printf("\n%s\n", amr.Msg)

		// Show additional details if available
		if amr.Data != nil {
			if dataMap, ok := amr.Data.(map[string]interface{}); ok {
				if corrID, ok := dataMap["distribution_id"]; ok {
					fmt.Printf("  Distribution ID: %v\n", corrID)
				}
				if status, ok := dataMap["status"]; ok {
					fmt.Printf("  Status: %v\n", status)
				}
			}
		}
	},
}

var DebugAgentResyncCmd = &cobra.Command{
	Use:   "resync",
	Short: "Re-send all local changes to combiner and remote agents",
	Long: `Re-send all locally stored synced data for a zone to the combiner and
all remote agents. Use this when the combiner or remote agents have lost
state and need to be brought back in sync.

Example:
  tdns-cliv2 agent debug resync --zone whisky.dnslab.`,
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		req := tdns.AgentMgmtPost{
			Command: "resync",
			Zone:    tdns.ZoneName(tdns.Globals.Zonename),
		}

		amr, err := SendAgentDebugCmd(req, false)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if amr.Error {
			log.Fatalf("Error: %s", amr.ErrorMsg)
		}

		fmt.Printf("Resync for zone %s:\n", tdns.Globals.Zonename)
		if amr.Msg != "" {
			fmt.Printf("  %s\n", amr.Msg)
		}
	},
}

var DebugAgentShowKeyInventoryCmd = &cobra.Command{
	Use:   "show-key-inventory",
	Short: "Show DNSKEY inventory received from signer (KEYSTATE)",
	Long: `Display the last KEYSTATE inventory received from the signer for a zone.
Shows all keys reported by the signer's KeyDB with their state
(created, published, standby, active, retired, foreign).

Keys marked "foreign" are from other providers' signers.

Example:
  tdns-cliv2 agent debug show-key-inventory --zone whisky.dnslab.`,
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		req := tdns.AgentMgmtPost{
			Command: "show-key-inventory",
			Zone:    tdns.ZoneName(tdns.Globals.Zonename),
		}

		amr, err := SendAgentDebugCmd(req, false)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if amr.Error {
			log.Fatalf("Error: %s", amr.ErrorMsg)
		}

		if amr.Data == nil {
			fmt.Println(amr.Msg)
			return
		}

		// Parse the Data field as KeyInventorySnapshot
		dataBytes, err := json.Marshal(amr.Data)
		if err != nil {
			log.Fatalf("Failed to marshal inventory data: %v", err)
		}
		var snapshot tdns.KeyInventorySnapshot
		if err := json.Unmarshal(dataBytes, &snapshot); err != nil {
			log.Fatalf("Failed to parse inventory data: %v", err)
		}

		fmt.Printf("DNSKEY Inventory for zone %s\n", snapshot.Zone)
		fmt.Printf("Received: %s from %s\n", snapshot.Received.Format("2006-01-02 15:04:05"), snapshot.SenderID)
		fmt.Printf("────────────────────────────────────────\n")

		if len(snapshot.Inventory) == 0 {
			fmt.Printf("  (no keys)\n")
			return
		}

		out := []string{"KeyTag|Algorithm|Flags|State|Role|Key data"}
		for _, entry := range snapshot.Inventory {
			role := "local"
			if entry.State == "foreign" {
				role = "REMOTE"
			}
			algStr := dns.AlgorithmToString[entry.Algorithm]
			if algStr == "" {
				algStr = fmt.Sprintf("ALG%d", entry.Algorithm)
			}
			flagDesc := "ZSK"
			if entry.Flags&0x0001 != 0 {
				flagDesc = "KSK"
			}
			keyData := truncatePubKey(entry.KeyRR)
			out = append(out, fmt.Sprintf("%d|%s|%d (%s)|%s|%s|%s",
				entry.KeyTag, algStr, entry.Flags, flagDesc, entry.State, role, keyData))
		}
		fmt.Println(columnize.SimpleFormat(out))
	},
}

var DebugAgentQueueStatusCmd = &cobra.Command{
	Use:   "queue-status",
	Short: "Show reliable message queue status and pending messages",
	Run: func(cmd *cobra.Command, args []string) {
		req := tdns.AgentMgmtPost{
			Command: "queue-status",
		}

		_, buf, err := func() (*tdns.AgentMgmtResponse, []byte, error) {
			prefixcmd, _ := GetCommandContext("debug")
			api, err := GetApiClient(prefixcmd, true)
			if err != nil {
				log.Fatalf("Error getting API client: %v", err)
			}
			_, buf, err := api.RequestNG("POST", "/agent/debug", req, true)
			return nil, buf, err
		}()
		if err != nil {
			log.Fatalf("API request failed: %v", err)
		}

		var resp map[string]interface{}
		if err := json.Unmarshal(buf, &resp); err != nil {
			log.Fatalf("Failed to parse response: %v", err)
		}

		if errVal, ok := resp["error"].(bool); ok && errVal {
			if errMsg, ok := resp["error_msg"].(string); ok {
				log.Fatalf("Error: %s", errMsg)
			}
			log.Fatalf("Error in response")
		}

		if msg, ok := resp["msg"].(string); ok && msg != "" {
			fmt.Println(msg)
		}

		data, ok := resp["data"].(map[string]interface{})
		if !ok {
			fmt.Println("No queue data available")
			return
		}

		// Display stats summary
		if stats, ok := data["stats"].(map[string]interface{}); ok {
			fmt.Println("\nQueue Statistics:")
			if v, ok := stats["total_pending"].(float64); ok {
				fmt.Printf("  Pending:   %d\n", int(v))
			}
			if v, ok := stats["total_delivered"].(float64); ok {
				fmt.Printf("  Delivered: %d\n", int(v))
			}
			if v, ok := stats["total_failed"].(float64); ok {
				fmt.Printf("  Failed:    %d\n", int(v))
			}
			if v, ok := stats["total_expired"].(float64); ok {
				fmt.Printf("  Expired:   %d\n", int(v))
			}
			if byState, ok := stats["by_state"].(map[string]interface{}); ok && len(byState) > 0 {
				fmt.Printf("  By state:  ")
				first := true
				for state, count := range byState {
					if !first {
						fmt.Printf(", ")
					}
					fmt.Printf("%s=%d", state, int(count.(float64)))
					first = false
				}
				fmt.Println()
			}
		}

		// Display pending messages
		messages, ok := data["messages"].([]interface{})
		if !ok || len(messages) == 0 {
			fmt.Println("\nNo pending messages")
			return
		}

		fmt.Printf("\nPending Messages (%d):\n", len(messages))

		verbose := false
		if v, err := cmd.Flags().GetBool("verbose"); err == nil {
			verbose = v
		}

		if verbose {
			for _, mRaw := range messages {
				m, ok := mRaw.(map[string]interface{})
				if !ok {
					continue
				}
				fmt.Println()
				fmt.Printf("  Distribution ID: %s\n", getStringValue(m, "distribution_id"))
				fmt.Printf("  Recipient:       %s (%s)\n", getStringValue(m, "recipient_id"), getStringValue(m, "recipient_type"))
				fmt.Printf("  Zone:            %s\n", getStringValue(m, "zone"))
				fmt.Printf("  State:           %s\n", getStringValue(m, "state"))
				fmt.Printf("  Priority:        %s\n", getStringValue(m, "priority"))
				fmt.Printf("  Attempts:        %s\n", getStringValue(m, "attempt_count"))
				fmt.Printf("  Age:             %s\n", getStringValue(m, "age"))
				fmt.Printf("  Created:         %s\n", getStringValue(m, "created_at"))
				fmt.Printf("  Expires:         %s\n", getStringValue(m, "expires_at"))
				fmt.Printf("  Next attempt:    %s\n", getStringValue(m, "next_attempt"))
				if lastAttempt := getStringValue(m, "last_attempt"); lastAttempt != "" {
					fmt.Printf("  Last attempt:    %s\n", lastAttempt)
				}
				if lastErr := getStringValue(m, "last_error"); lastErr != "" {
					fmt.Printf("  Last error:      %s\n", lastErr)
				}
			}
		} else {
			var rows []string
			rows = append(rows, "DistID | Recipient | Type | Zone | State | Attempts | Age | Error")
			for _, mRaw := range messages {
				m, ok := mRaw.(map[string]interface{})
				if !ok {
					continue
				}
				distID := getStringValue(m, "distribution_id")
				if len(distID) > 16 {
					distID = distID[:16] + "..."
				}
				lastErr := getStringValue(m, "last_error")
				if len(lastErr) > 30 {
					lastErr = lastErr[:30] + "..."
				}
				attempts := "0"
				if v, ok := m["attempt_count"].(float64); ok {
					attempts = fmt.Sprintf("%d", int(v))
				}
				rows = append(rows, fmt.Sprintf("%s | %s | %s | %s | %s | %s | %s | %s",
					distID,
					getStringValue(m, "recipient_id"),
					getStringValue(m, "recipient_type"),
					getStringValue(m, "zone"),
					getStringValue(m, "state"),
					attempts,
					getStringValue(m, "age"),
					lastErr,
				))
			}
			if len(rows) > 1 {
				output := columnize.SimpleFormat(rows)
				fmt.Println(output)
			}
		}
	},
}

func init() {
	DebugCmd.AddCommand(DebugAgentCmd)
	DebugAgentCmd.AddCommand(DebugAgentSendNotifyCmd)
	DebugAgentCmd.AddCommand(DebugAgentSendRfiCmd)
	DebugAgentCmd.AddCommand(DebugAgentDumpAgentRegistryCmd)
	DebugAgentCmd.AddCommand(DebugAgentDumpZoneDataRepoCmd)
	DebugAgentCmd.AddCommand(DebugAgentShowSyncedDataCmd)
	DebugAgentCmd.AddCommand(DebugAgentShowCombinerDataCmd)
	DebugAgentCmd.AddCommand(DebugAgentSendSyncToCmd)
	DebugAgentCmd.AddCommand(DebugAgentRegistryCmd)
	DebugAgentCmd.AddCommand(DebugAgentSyncStateCmd)
	DebugAgentCmd.AddCommand(DebugAgentResyncCmd)
	DebugAgentCmd.AddCommand(DebugAgentShowKeyInventoryCmd)
	DebugAgentCmd.AddCommand(DebugAgentQueueStatusCmd)

	DebugAgentQueueStatusCmd.Flags().BoolP("verbose", "v", false, "Verbose output (show full details for each message)")

	DebugAgentSendNotifyCmd.Flags().StringVarP(&myIdentity, "id", "I", "", "agent identity to claim")
	DebugAgentSendNotifyCmd.Flags().StringVarP(&notifyRRtype, "rrtype", "R", "", "RR type sent notify for")
	DebugAgentSendNotifyCmd.Flags().StringVarP(&dnsRecord, "RR", "", "", "DNS record to send")
	DebugAgentSendRfiCmd.Flags().StringVarP(&myIdentity, "id", "I", "", "agent identity to claim")
	DebugAgentSendRfiCmd.Flags().StringVarP(&rfitype, "rfi", "", "", "RFI type (CONFIG|SYNC|AUDIT|EDITS)")
	DebugAgentSendRfiCmd.Flags().StringVarP(&rfisubtype, "subtype", "", "", "RFI subtype for CONFIG (upstream|downstream|sig0key)")

	// New command flags
	DebugAgentShowSyncedDataCmd.Flags().String("zone", "", "Filter by specific zone")
	DebugAgentShowCombinerDataCmd.Flags().String("zone", "", "Filter by specific zone")
	DebugAgentSendSyncToCmd.Flags().String("to", "", "Target agent ID")
	DebugAgentSendSyncToCmd.Flags().String("zone", "", "Zone name")
	// DebugAgentSendRfiCmd.Flags().StringVarP(&rfiupstream, "upstream", "", "", "Identity of upstream agent")
	// DebugAgentSendRfiCmd.Flags().StringVarP(&rfidownstream, "downstream", "", "", "Identity of downstream agent")
}

// truncatePubKey extracts the public key from a DNSKEY RR string and
// truncates it to "first10...last5" for display. If the RR string is empty
// or unparseable, returns "-".
func truncatePubKey(keyrr string) string {
	if keyrr == "" {
		return "-"
	}
	// Parse the DNSKEY RR to extract the public key field
	rr, err := dns.NewRR(keyrr)
	if err != nil {
		return "-"
	}
	dnskey, ok := rr.(*dns.DNSKEY)
	if !ok {
		return "-"
	}
	pub := dnskey.PublicKey
	if len(pub) <= 15 {
		return pub
	}
	return pub[:10] + "..." + pub[len(pub)-5:]
}

func SendAgentDebugCmd(req tdns.AgentMgmtPost, printJson bool) (*tdns.AgentMgmtResponse, error) {
	api, err := GetApiClient("agent", true)
	if err != nil {
		log.Fatalf("Error getting API client: %v", err)
	}

	// api.Debug = true

	_, buf, err := api.RequestNG("POST", "/agent/debug", req, true)
	if err != nil {
		log.Fatalf("API request failed: %v", err)
	}

	var amr tdns.AgentMgmtResponse
	if err := json.Unmarshal(buf, &amr); err != nil {
		log.Fatalf("Failed to parse response: %v", err)
	}

	if printJson {
		var prettyJSON bytes.Buffer
		err = json.Indent(&prettyJSON, buf, "", "  ")
		if err != nil {
			log.Println("JSON parse error: ", err)
		}
		fmt.Printf("Agent debug response:\n%s\n", prettyJSON.String())
		return &amr, nil
	}

	if amr.Error {
		log.Fatalf("API error: %s", amr.ErrorMsg)
	}

	return &amr, nil
}
