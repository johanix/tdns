/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * CLI commands for managing combiner edit approval workflow.
 * Provides "combiner zone edits {list|approve|reject|clear}".
 */
package cli

import (
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
)

var combinerZoneCmd = &cobra.Command{
	Use:   "zone",
	Short: "Combiner zone management commands",
}

var combinerZoneListCmd = &cobra.Command{
	Use:   "list",
	Short: "List configured zones",
	Run: func(cmd *cobra.Command, args []string) {
		prefixcmd, _ := getCommandContext("zone")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client for %s: %v", prefixcmd, err)
		}

		cr, err := SendZoneCommand(api, tdns.ZonePost{
			Command: "list-zones",
		})
		if err != nil {
			fmt.Printf("Error from %q: %s\n", cr.AppName, err.Error())
			log.Fatalf("Error: %v", err)
		}

		if cr.Msg != "" {
			fmt.Printf("%s\n", cr.Msg)
		}

		switch tdns.Globals.Verbose {
		case true:
			VerboseListZone(cr)
		case false:
			ListZones(cr)
		}
	},
}

var combinerZoneMPListCmd = &cobra.Command{
	Use:   "mplist",
	Short: "List multi-provider zones with HSYNCPARAM details",
	Run: func(cmd *cobra.Command, args []string) {
		prefixcmd, _ := getCommandContext("zone")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client for %s: %v", prefixcmd, err)
		}

		cr, err := SendZoneCommand(api, tdns.ZonePost{
			Command: "list-mp-zones",
		})
		if err != nil {
			fmt.Printf("Error from %q: %s\n", cr.AppName, err.Error())
			log.Fatalf("Error: %v", err)
		}

		ListMPZones(cr)
	},
}

var combinerZoneEditsCmd = &cobra.Command{
	Use:   "edits",
	Short: "Manage pending, approved and rejected edits",
}

var combinerZoneEditsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List edits for a zone (default: current contributions; use --pending/--approved/--rejected)",
	Run: func(cmd *cobra.Command, args []string) {
		zone, _ := cmd.Flags().GetString("zone")
		if zone == "" {
			log.Fatalf("--zone is required")
		}

		showPending, _ := cmd.Flags().GetBool("pending")
		showApproved, _ := cmd.Flags().GetBool("approved")
		showRejected, _ := cmd.Flags().GetBool("rejected")

		// Default to current contributions if no flag specified
		if !showPending && !showApproved && !showRejected {
			listCurrentContributions(zone)
			return
		}

		if showPending {
			listPendingEdits(zone)
		}
		if showApproved {
			listApprovedEdits(zone)
		}
		if showRejected {
			listRejectedEdits(zone)
		}
	},
}

func listCurrentContributions(zone string) {
	resp, err := SendCombinerEditCmd(tdns.CombinerEditPost{
		Command: "list-current",
		Zone:    zone,
	})
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	if len(resp.Current) == 0 {
		fmt.Printf("No current contributions for zone %s\n", dns.Fqdn(zone))
		return
	}

	fmt.Printf("Current Contributions for Zone: %s\n", dns.Fqdn(zone))
	fmt.Printf("═══════════════════════════════════════\n\n")

	// Build table rows grouped by rrtype first, agent second.
	// Collect all (rrtype, agent, rr) tuples then sort by rrtype.
	type contribution struct {
		rrtype string
		agent  string
		rr     string
	}
	var contribs []contribution
	for agentID, rrtypeMap := range resp.Current {
		for rrtype, rrs := range rrtypeMap {
			for _, rr := range rrs {
				contribs = append(contribs, contribution{rrtype: rrtype, agent: agentID, rr: rr})
			}
		}
	}

	// Sort by rrtype then agent
	sort.Slice(contribs, func(i, j int) bool {
		if contribs[i].rrtype != contribs[j].rrtype {
			return contribs[i].rrtype < contribs[j].rrtype
		}
		return contribs[i].agent < contribs[j].agent
	})

	var rows []string
	rows = append(rows, "Type | Origin | Record")
	for _, c := range contribs {
		rows = append(rows, fmt.Sprintf("%s | %s | %s",
			c.rrtype, c.agent, truncateDNSKEY(c.rr)))
	}

	output := columnize.SimpleFormat(rows)
	fmt.Println(output)
	fmt.Println()
}

func listPendingEdits(zone string) {
	resp, err := SendCombinerEditCmd(tdns.CombinerEditPost{
		Command: "list",
		Zone:    zone,
	})
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	if len(resp.Pending) == 0 {
		fmt.Printf("No pending edits for zone %s\n", dns.Fqdn(zone))
		return
	}

	fmt.Printf("Pending Edits for Zone: %s\n", dns.Fqdn(zone))
	fmt.Printf("═══════════════════════════════════════\n\n")

	for _, rec := range resp.Pending {
		fmt.Printf("  #%d  From: %s  Received: %s  DistID: %s\n",
			rec.EditID, rec.SenderID,
			rec.ReceivedAt.Format(time.RFC3339),
			rec.DistributionID)

		for _, rrs := range rec.Records {
			for _, rr := range rrs {
				fmt.Printf("      %s\n", rr)
			}
		}
		fmt.Println()
	}
}

func listApprovedEdits(zone string) {
	resp, err := SendCombinerEditCmd(tdns.CombinerEditPost{
		Command: "list-approved",
		Zone:    zone,
	})
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	if len(resp.Approved) == 0 {
		fmt.Printf("No approved edits for zone %s\n", dns.Fqdn(zone))
		return
	}

	fmt.Printf("Approved Edits for Zone: %s\n", dns.Fqdn(zone))
	fmt.Printf("═══════════════════════════════════════\n\n")

	for _, rec := range resp.Approved {
		fmt.Printf("  #%d  From: %s  Received: %s  Approved: %s\n",
			rec.EditID, rec.SenderID,
			rec.ReceivedAt.Format(time.RFC3339),
			rec.ApprovedAt.Format(time.RFC3339))

		for _, rrs := range rec.Records {
			for _, rr := range rrs {
				fmt.Printf("      %s\n", rr)
			}
		}
		fmt.Println()
	}
}

func listRejectedEdits(zone string) {
	resp, err := SendCombinerEditCmd(tdns.CombinerEditPost{
		Command: "list-rejected",
		Zone:    zone,
	})
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	if len(resp.Rejected) == 0 {
		fmt.Printf("No rejected edits for zone %s\n", dns.Fqdn(zone))
		return
	}

	fmt.Printf("Rejected Edits for Zone: %s\n", dns.Fqdn(zone))
	fmt.Printf("═══════════════════════════════════════\n\n")

	for _, rec := range resp.Rejected {
		fmt.Printf("  #%d  From: %s  Received: %s  Rejected: %s\n",
			rec.EditID, rec.SenderID,
			rec.ReceivedAt.Format(time.RFC3339),
			rec.RejectedAt.Format(time.RFC3339))
		fmt.Printf("      Reason: %s\n", rec.Reason)

		for _, rrs := range rec.Records {
			for _, rr := range rrs {
				fmt.Printf("      %s\n", rr)
			}
		}
		fmt.Println()
	}
}

var combinerZoneEditsApproveCmd = &cobra.Command{
	Use:   "approve",
	Short: "Approve a pending edit",
	Run: func(cmd *cobra.Command, args []string) {
		zone, _ := cmd.Flags().GetString("zone")
		editID, _ := cmd.Flags().GetInt("edit")

		if zone == "" {
			log.Fatalf("--zone is required")
		}
		if editID <= 0 {
			log.Fatalf("--edit is required (positive integer)")
		}

		resp, err := SendCombinerEditCmd(tdns.CombinerEditPost{
			Command: "approve",
			Zone:    zone,
			EditID:  editID,
		})
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		fmt.Println(resp.Msg)
	},
}

var combinerZoneEditsRejectCmd = &cobra.Command{
	Use:   "reject",
	Short: "Reject a pending edit",
	Run: func(cmd *cobra.Command, args []string) {
		zone, _ := cmd.Flags().GetString("zone")
		editID, _ := cmd.Flags().GetInt("edit")
		reason, _ := cmd.Flags().GetString("reason")

		if zone == "" {
			log.Fatalf("--zone is required")
		}
		if editID <= 0 {
			log.Fatalf("--edit is required (positive integer)")
		}
		if strings.TrimSpace(reason) == "" {
			log.Fatalf("--reason is required for rejection")
		}

		resp, err := SendCombinerEditCmd(tdns.CombinerEditPost{
			Command: "reject",
			Zone:    zone,
			EditID:  editID,
			Reason:  reason,
		})
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		fmt.Println(resp.Msg)
	},
}

var combinerZoneEditsClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Clear edit tables (default: all; use --pending/--approved/--rejected/--current to select)",
	Run: func(cmd *cobra.Command, args []string) {
		zone, _ := cmd.Flags().GetString("zone")
		showPending, _ := cmd.Flags().GetBool("pending")
		showApproved, _ := cmd.Flags().GetBool("approved")
		showRejected, _ := cmd.Flags().GetBool("rejected")
		showCurrent, _ := cmd.Flags().GetBool("current")

		var tables []string
		if showPending {
			tables = append(tables, "pending")
		}
		if showApproved {
			tables = append(tables, "approved")
		}
		if showRejected {
			tables = append(tables, "rejected")
		}
		if showCurrent {
			tables = append(tables, "current")
		}
		// Empty tables list means "all"

		resp, err := SendCombinerEditCmd(tdns.CombinerEditPost{
			Command: "clear",
			Zone:    zone,
			Tables:  tables,
		})
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		fmt.Println(resp.Msg)
	},
}

// SendCombinerEditCmd sends a combiner edit management request to the combiner API.
func SendCombinerEditCmd(req tdns.CombinerEditPost) (*tdns.CombinerEditResponse, error) {
	api, err := getApiClient("combiner", true)
	if err != nil {
		return nil, fmt.Errorf("error getting API client: %w", err)
	}

	if req.Zone != "" {
		req.Zone = dns.Fqdn(req.Zone)
	}

	status, buf, err := api.RequestNG("POST", "/combiner/edits", req, true)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}

	if status != 200 {
		return nil, fmt.Errorf("API request to %s/combiner/edits returned HTTP %d: %s",
			api.BaseUrl, status, string(buf))
	}

	var resp tdns.CombinerEditResponse
	if err := json.Unmarshal(buf, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response from %s/combiner/edits: %w",
			api.BaseUrl, err)
	}

	if resp.Error {
		return nil, fmt.Errorf("%s", resp.ErrorMsg)
	}

	return &resp, nil
}

var combinerZoneEditsReapplyCmd = &cobra.Command{
	Use:   "reapply",
	Short: "Reload contributions from DB and re-apply to zone data",
	Run: func(cmd *cobra.Command, args []string) {
		zone, _ := cmd.Flags().GetString("zone")
		if zone == "" {
			log.Fatalf("--zone is required")
		}

		resp, err := SendCombinerEditCmd(tdns.CombinerEditPost{
			Command: "reapply",
			Zone:    zone,
		})
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		fmt.Println(resp.Msg)
	},
}

var combinerZoneReloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Request re-loading a zone on the combiner",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")
		api, err := getApiClient("combiner", true)
		if err != nil {
			log.Fatalf("Error getting API client for combiner: %v", err)
		}

		cr, err := SendZoneCommand(api, tdns.ZonePost{
			Command: "reload",
			Zone:    dns.Fqdn(tdns.Globals.Zonename),
			Force:   force,
		})
		if err != nil {
			fmt.Printf("Error from %q: %s\n", cr.AppName, err.Error())
			log.Fatalf("Error: %v", err)
		}

		if cr.Msg != "" {
			fmt.Printf("%s\n", cr.Msg)
		}
	},
}

var combinerZoneBumpCmd = &cobra.Command{
	Use:   "bump",
	Short: "Bump SOA serial for a zone on the combiner",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")
		api, err := getApiClient("combiner", true)
		if err != nil {
			log.Fatalf("Error getting API client for combiner: %v", err)
		}

		cr, err := SendZoneCommand(api, tdns.ZonePost{
			Command: "bump",
			Zone:    tdns.Globals.Zonename,
		})
		if err != nil {
			fmt.Printf("Error from %q: %s\n", cr.AppName, err.Error())
			log.Fatalf("Error: %v", err)
		}

		if cr.Msg != "" {
			fmt.Printf("%s\n", cr.Msg)
		}
	},
}

func init() {
	CombinerCmd.AddCommand(combinerZoneCmd)
	combinerZoneCmd.AddCommand(combinerZoneListCmd, combinerZoneMPListCmd)
	combinerZoneCmd.AddCommand(combinerZoneBumpCmd)
	combinerZoneCmd.AddCommand(combinerZoneReloadCmd)
	combinerZoneCmd.AddCommand(combinerZoneEditsCmd)

	combinerZoneCmd.PersistentFlags().BoolVarP(&force, "force", "F", false, "Force operation")

	combinerZoneEditsCmd.AddCommand(combinerZoneEditsListCmd)
	combinerZoneEditsCmd.AddCommand(combinerZoneEditsApproveCmd)
	combinerZoneEditsCmd.AddCommand(combinerZoneEditsRejectCmd)
	combinerZoneEditsCmd.AddCommand(combinerZoneEditsClearCmd)
	combinerZoneEditsCmd.AddCommand(combinerZoneEditsReapplyCmd)

	// Flags for reapply
	combinerZoneEditsReapplyCmd.Flags().String("zone", "", "Zone to reapply contributions for (required)")

	// Flags for list
	combinerZoneEditsListCmd.Flags().String("zone", "", "Zone to list edits for")
	combinerZoneEditsListCmd.Flags().Bool("pending", false, "Show pending edits")
	combinerZoneEditsListCmd.Flags().Bool("approved", false, "Show approved edits (transaction history)")
	combinerZoneEditsListCmd.Flags().Bool("rejected", false, "Show rejected edits")

	// Flags for clear
	combinerZoneEditsClearCmd.Flags().String("zone", "", "Scope to zone (default: all zones)")
	combinerZoneEditsClearCmd.Flags().Bool("pending", false, "Clear pending edits")
	combinerZoneEditsClearCmd.Flags().Bool("approved", false, "Clear approved edits")
	combinerZoneEditsClearCmd.Flags().Bool("rejected", false, "Clear rejected edits")
	combinerZoneEditsClearCmd.Flags().Bool("current", false, "Clear current contributions")

	// Flags for approve
	combinerZoneEditsApproveCmd.Flags().String("zone", "", "Zone the edit belongs to")
	combinerZoneEditsApproveCmd.Flags().Int("edit", 0, "Edit ID to approve")

	// Flags for reject
	combinerZoneEditsRejectCmd.Flags().String("zone", "", "Zone the edit belongs to")
	combinerZoneEditsRejectCmd.Flags().Int("edit", 0, "Edit ID to reject")
	combinerZoneEditsRejectCmd.Flags().String("reason", "", "Reason for rejection (required)")
}
