/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cli

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"

	tdns "github.com/johanix/tdns/v2"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
)

// SendAgentMgmtCmd POSTs an AgentMgmtPost to the agent daemon's /agent
// endpoint. Every caller in this package talks to the agent, so the
// role is fixed rather than inferred from the Cobra tree.
func SendAgentMgmtCmd(req *tdns.AgentMgmtPost) (*tdns.AgentMgmtResponse, error) {
	api, err := GetApiClient("agent", true)
	if err != nil {
		return nil, fmt.Errorf("getting API client: %w", err)
	}

	_, buf, err := api.RequestNG("POST", "/agent", req, true)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %v", err)
	}

	var amr tdns.AgentMgmtResponse
	if err := json.Unmarshal(buf, &amr); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	return &amr, nil
}

var agentParentSyncCmd = &cobra.Command{
	Use:    "parentsync",
	Short:  "Parent delegation sync commands",
	Hidden: true,
}

var agentParentSyncStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show parent sync status for a zone",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "zonename")
		zone := cmd.Flag("zone").Value.String()

		api, err := GetApiClient("agent", true)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
		resp, err := SendParentSyncCommand(api, tdns.ZoneParentSyncPost{
			Command: "status",
			Zone:    zone,
		})
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
		if resp.Error {
			log.Fatalf("Error from server: %s", resp.ErrorMsg)
		}
		printParentSyncStatus(resp)
	},
}

var agentParentSyncBootstrapCmd = &cobra.Command{
	Use:   "bootstrap",
	Short: "Trigger SIG(0) KEY bootstrap with parent for a zone",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "zonename")
		zone := cmd.Flag("zone").Value.String()

		api, err := GetApiClient("agent", true)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
		resp, err := SendParentSyncCommand(api, tdns.ZoneParentSyncPost{
			Command: "bootstrap",
			Zone:    zone,
			Scheme:  "update",
		})
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
		if resp.Error {
			log.Fatalf("Error from server: %s", resp.ErrorMsg)
		}
		fmt.Printf("%s\n", resp.Msg)
	},
}

var agentParentSyncInquireCmd = &cobra.Command{
	Use:   "inquire",
	Short: "KeyState EDNS(0) inquiry commands",
}

var agentParentSyncInquireUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Send KeyState EDNS(0) inquiry about the current SIG(0) key to the parent",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "zonename")
		zone := cmd.Flag("zone").Value.String()

		api, err := GetApiClient("agent", true)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
		resp, err := SendParentSyncCommand(api, tdns.ZoneParentSyncPost{
			Command: "inquire",
			Zone:    zone,
		})
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
		if resp.Error {
			log.Fatalf("Error from server: %s", resp.ErrorMsg)
		}

		d := map[string]interface{}{
			"zone":       zone,
			"keyid":      float64(resp.KeyID),
			"state_name": resp.StateName,
			"state":      float64(resp.KeyState),
		}
		displayKeyStateInquiry(d)
	},
}

func displayKeyStateInquiry(d map[string]interface{}) {
	zone, _ := d["zone"].(string)
	keyid, _ := d["keyid"].(float64)
	stateName, _ := d["state_name"].(string)
	state, _ := d["state"].(float64)
	extra, _ := d["extra_text"].(string)

	fmt.Printf("KeyState Inquiry for %s\n", zone)
	fmt.Printf("  KeyID:        %d\n", int(keyid))
	fmt.Printf("  Parent says:  %s (code %d)\n", stateName, int(state))
	if extra != "" {
		fmt.Printf("  Extra:        %s\n", extra)
	}
}

var agentParentSyncElectionCmd = &cobra.Command{
	Use:   "election",
	Short: "Trigger leader re-election for a zone",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "zonename")
		zone := cmd.Flag("zone").Value.String()

		amr, err := SendAgentMgmtCmd(&tdns.AgentMgmtPost{
			Command: "parentsync-election",
			Zone:    tdns.ZoneName(zone),
		})
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
		if amr.Error {
			log.Fatalf("Error from agent: %s", amr.ErrorMsg)
		}

		fmt.Printf("%s\n", amr.Msg)
	},
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func publishedStatus(b bool) string {
	if b {
		return "PUBLISHED"
	}
	return "NOT PUBLISHED"
}

var agentParentSyncDeltaCmd = &cobra.Command{
	Use:   "delta",
	Short: "Compute delta between parent delegation data and child zone data",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")
		// parentsync is agent-only today.
		api, err := GetApiClient("agent", true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		if schemestr != "" {
			val, err := strconv.ParseUint(schemestr, 10, 8)
			if err != nil {
				fmt.Printf("Error: invalid scheme value %q: %s\n", schemestr, err)
				return
			}
			scheme = uint8(val)
		}

		dr, err := SendDelegationCmd(api, tdns.DelegationPost{
			Command: "status",
			Zone:    tdns.Globals.Zonename,
		})
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		if dr.Error {
			fmt.Printf("Error: %s\n", dr.ErrorMsg)
			os.Exit(1)
		}

		fmt.Printf("%s\n", dr.Msg)
		if dr.SyncStatus.InSync {
			fmt.Printf("Delegation information in parent %s is in sync with child %s. No action needed.\n",
				dr.SyncStatus.Parent, dr.SyncStatus.ZoneName)
			os.Exit(0)
		}
		fmt.Printf("Delegation information in parent %q is NOT in sync with child %q. Changes needed:\n",
			dr.SyncStatus.Parent, dr.SyncStatus.ZoneName)
		out := []string{"Change|RR"}
		for _, rr := range dr.SyncStatus.NsAddsStr {
			out = append(out, fmt.Sprintf("ADD NS|%s", rr))
		}
		for _, rr := range dr.SyncStatus.NsRemovesStr {
			out = append(out, fmt.Sprintf("DEL NS|%s", rr))
		}
		for _, rr := range dr.SyncStatus.AAddsStr {
			out = append(out, fmt.Sprintf("ADD IPv4 GLUE|%s", rr))
		}
		for _, rr := range dr.SyncStatus.ARemovesStr {
			out = append(out, fmt.Sprintf("DEL IPv4 GLUE|%s", rr))
		}
		for _, rr := range dr.SyncStatus.AAAAAddsStr {
			out = append(out, fmt.Sprintf("ADD IPv6 GLUE|%s", rr))
		}
		for _, rr := range dr.SyncStatus.AAAARemovesStr {
			out = append(out, fmt.Sprintf("DEL IPv6 GLUE|%s", rr))
		}
		fmt.Printf("%s\n", columnize.SimpleFormat(out))
	},
}

var agentParentSyncSyncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync delegation data in parent zone via DDNS UPDATE",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")
		// parentsync is agent-only today.
		api, err := GetApiClient("agent", true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		if schemestr != "" {
			val, err := strconv.ParseUint(schemestr, 10, 8)
			if err != nil {
				fmt.Printf("Error: invalid scheme value %q: %s\n", schemestr, err)
				return
			}
			scheme = uint8(val)
		}

		dr, err := SendDelegationCmd(api, tdns.DelegationPost{
			Command: "sync",
			Scheme:  scheme,
			Zone:    tdns.Globals.Zonename,
		})
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		if dr.Error {
			fmt.Printf("Error: %s\n", dr.ErrorMsg)
			os.Exit(1)
		}

		fmt.Printf("%s\n", dr.Msg)
	},
}

func init() {
	AgentCmd.AddCommand(agentParentSyncCmd)
	agentParentSyncCmd.AddCommand(agentParentSyncStatusCmd)
	agentParentSyncCmd.AddCommand(agentParentSyncElectionCmd)
	agentParentSyncCmd.AddCommand(agentParentSyncBootstrapCmd)
	agentParentSyncCmd.AddCommand(agentParentSyncInquireCmd)
	agentParentSyncCmd.AddCommand(agentParentSyncDeltaCmd)
	agentParentSyncCmd.AddCommand(agentParentSyncSyncCmd)
	agentParentSyncInquireCmd.AddCommand(agentParentSyncInquireUpdateCmd)

	agentParentSyncStatusCmd.Flags().StringP("zone", "z", "", "Zone name (required)")
	agentParentSyncStatusCmd.MarkFlagRequired("zone")

	agentParentSyncElectionCmd.Flags().StringP("zone", "z", "", "Zone name (required)")
	agentParentSyncElectionCmd.MarkFlagRequired("zone")

	agentParentSyncBootstrapCmd.Flags().StringP("zone", "z", "", "Zone name (required)")
	agentParentSyncBootstrapCmd.MarkFlagRequired("zone")

	agentParentSyncInquireUpdateCmd.Flags().StringP("zone", "z", "", "Zone name (required)")
	agentParentSyncInquireUpdateCmd.MarkFlagRequired("zone")

	agentParentSyncSyncCmd.Flags().StringVarP(&schemestr, "scheme", "S", "", "Scheme to use for synchronization of delegation")
}
