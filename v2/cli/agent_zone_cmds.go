/*
 * Copyright (c) 2025 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cli

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
)

// AgentZoneCmd is the agent-specific "zone" command group.
// It contains only the zone subcommands relevant to the agent,
// plus the new addrr/delrr commands for managing synced RRs.
var AgentZoneCmd = &cobra.Command{
	Use:   "zone",
	Short: "Agent zone management commands",
}

// --- Zone subcommands relevant to the agent ---

var agentZoneListCmd = &cobra.Command{
	Use:   "list",
	Short: "List configured zones",
	Run:   func(cmd *cobra.Command, args []string) { RunZoneList("agent", args) },
}

func RunZoneList(parent string, args []string) {
	api, err := GetApiClient(parent, true)
	if err != nil {
		log.Fatalf("Error getting API client for %s: %v", parent, err)
	}

	cr, err := SendZoneCommand(api, tdns.ZonePost{
		Command: "list-zones",
	})
	if err != nil {
		fmt.Printf("Error from %q: %s\n", cr.AppName, err.Error())
		os.Exit(1)
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
}

var agentZoneMPListCmd = &cobra.Command{
	Use:   "mplist",
	Short: "List multi-provider zones with HSYNCPARAM details",
	Run:   func(cmd *cobra.Command, args []string) { RunZoneMPList("agent", args) },
}

var agentZoneReloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Request re-loading a zone",
	Run:   func(cmd *cobra.Command, args []string) { RunZoneReload("agent", args) },
}

var agentZoneWriteCmd = &cobra.Command{
	Use:   "write",
	Short: "Write a zone to disk",
	Run:   func(cmd *cobra.Command, args []string) { RunZoneWrite("agent", args) },
}

var agentZoneUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Create and ultimately send a DNS UPDATE msg for zone auth data",
}

var agentZoneUpdateCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create and ultimately send a DNS UPDATE msg for zone auth data",
	Long: `Will query for details about the DNS UPDATE via (add|del|show|set-ttl) commands.
When the message is complete it may be signed and sent by the 'send' command. After a
message has been send the loop will start again with a new, empty message to create.
Loop ends on the command "QUIT"

The zone to update is mandatory to specify on the command line with the --zone flag.`,
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")
		CreateUpdate("zone")
	},
}

var agentZoneReadFakeCmd = &cobra.Command{
	Use:   "readfake",
	Short: "Create a fake zone from a compiled in string",
	Run: func(cmd *cobra.Command, args []string) {
		err := ReadZoneData(dns.Fqdn(tdns.Globals.Zonename))
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
	},
}

// --- Dsync subcommands ---

var agentZoneDsyncCmd = &cobra.Command{
	Use:   "dsync",
	Short: "Prefix command, not useable by itself",
}

var agentZoneDsyncStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Send dsync status command to tdns-auth",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		prefixcmd, _ := GetCommandContext("zone")
		api, err := GetApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client for %s: %v", prefixcmd, err)
		}

		resp, err := SendDsyncCommand(api, tdns.ZoneDsyncPost{
			Command: "status",
			Zone:    dns.Fqdn(tdns.Globals.Zonename),
		})

		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			os.Exit(1)
		}
		if resp.Error {
			fmt.Printf("Error from tdns-auth: %s\n", resp.ErrorMsg)
			os.Exit(1)
		}

		if resp.Msg != "" {
			fmt.Printf("%s\n", resp.Msg)
		}
		out := []string{}
		for key, status := range resp.Functions {
			out = append(out, fmt.Sprintf("%s|%s", key, status))
		}

		sort.Strings(out)
		if tdns.Globals.ShowHeaders {
			out = append([]string{"Function|Status"}, out...)
		}

		fmt.Printf("%s\n", columnize.SimpleFormat(out))
		if len(resp.Todo) > 0 {
			fmt.Printf("\nTODO:\n")
			for _, todo := range resp.Todo {
				fmt.Printf("--> %s\n", todo)
			}
		}
	},
}

var agentZoneDsyncBootstrapCmd = &cobra.Command{
	Use:   "bootstrap-sig0-key",
	Short: "Send dsync bootstrap command to tdns-auth",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename", "algorithm")

		prefixcmd, _ := GetCommandContext("zone")
		api, err := GetApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client for %s: %v", prefixcmd, err)
		}

		resp, err := SendDsyncCommand(api, tdns.ZoneDsyncPost{
			Command:   "bootstrap-sig0-key",
			Zone:      dns.Fqdn(tdns.Globals.Zonename),
			Algorithm: dns.StringToAlgorithm[tdns.Globals.Algorithm],
		})
		PrintUpdateResult(resp.UpdateResult)
		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			os.Exit(1)
		}
		if resp.Error {
			fmt.Printf("Error from tdns-auth: %s\n", resp.ErrorMsg)
			os.Exit(1)
		}
		if resp.Msg != "" {
			fmt.Printf("%s\n", resp.Msg)
		}
	},
}

var agentZoneDsyncRollKeyCmd = &cobra.Command{
	Use:   "roll-sig0-key",
	Short: "Send dsync rollover command to tdns-auth",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename", "algorithm", "rollaction")

		prefixcmd, _ := GetCommandContext("zone")
		api, err := GetApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client for %s: %v", prefixcmd, err)
		}

		resp, err := SendDsyncCommand(api, tdns.ZoneDsyncPost{
			Command:   "roll-sig0-key",
			Zone:      dns.Fqdn(tdns.Globals.Zonename),
			Algorithm: dns.StringToAlgorithm[tdns.Globals.Algorithm],
			Action:    agentRollaction,
		})
		PrintUpdateResult(resp.UpdateResult)
		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			os.Exit(1)
		}
		if resp.Error {
			fmt.Printf("Error from tdns-auth: %s\n", resp.ErrorMsg)
			os.Exit(1)
		}
		if resp.Msg != "" {
			fmt.Printf("%s\n", resp.Msg)
		}
	},
}

var agentZoneDsyncPublishCmd = &cobra.Command{
	Use:   "publish",
	Short: "Send dsync publish-dsync-rrset command to tdns-auth",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		prefixcmd, _ := GetCommandContext("zone")
		api, err := GetApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client for %s: %v", prefixcmd, err)
		}

		resp, err := SendDsyncCommand(api, tdns.ZoneDsyncPost{
			Command: "publish-dsync-rrset",
			Zone:    dns.Fqdn(tdns.Globals.Zonename),
		})
		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			os.Exit(1)
		}
		if resp.Error {
			fmt.Printf("Error from tdns-auth: %s\n", resp.ErrorMsg)
			os.Exit(1)
		}
		if resp.Msg != "" {
			fmt.Printf("%s\n", resp.Msg)
		}
	},
}

var agentZoneDsyncUnpublishCmd = &cobra.Command{
	Use:   "unpublish",
	Short: "Send dsync unpublish-dsync-rrset command to tdns-auth",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		prefixcmd, _ := GetCommandContext("zone")
		api, err := GetApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client for %s: %v", prefixcmd, err)
		}

		resp, err := SendDsyncCommand(api, tdns.ZoneDsyncPost{
			Command: "unpublish-dsync-rrset",
			Zone:    dns.Fqdn(tdns.Globals.Zonename),
		})
		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			os.Exit(1)
		}
		if resp.Error {
			fmt.Printf("Error from tdns-auth: %s\n", resp.ErrorMsg)
			os.Exit(1)
		}
		if resp.Msg != "" {
			fmt.Printf("%s\n", resp.Msg)
		}
	},
}

// --- New addrr/delrr commands ---

var agentZoneAddRRCmd = &cobra.Command{
	Use:   "addrr",
	Short: "Add a resource record to a zone and sync with peers and combiner",
	Long: `Add a resource record to the specified zone. Supported RR types: NS, DNSKEY, CDS, CSYNC.
The RR type is inferred from the --rr argument.

This will:
- Add the RR to the local synced data store
- Send sync operations to all remote agents for this zone
- Send the update to the combiner

Examples:
  tdns-cliv2 agent zone addrr --zone whisky.dnslab. --rr "whisky.dnslab. IN NS ns.alpha.dnslab."
  tdns-cliv2 agent zone addrr --zone whisky.dnslab. --rr "whisky.dnslab. 300 IN DNSKEY 257 3 13 <base64>"`,
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		if agentZoneRR == "" {
			log.Fatalf("Error: --rr flag is required")
		}

		rr, err := dns.NewRR(agentZoneRR)
		if err != nil {
			log.Fatalf("Error: Invalid DNS record: %v", err)
		}

		if !tdns.AllowedLocalRRtypes[rr.Header().Rrtype] {
			allowed := allowedRRtypeNames()
			log.Fatalf("Error: RR type %s is not allowed (must be one of: %s)",
				dns.TypeToString[rr.Header().Rrtype], strings.Join(allowed, ", "))
		}

		if dns.Fqdn(rr.Header().Name) != dns.Fqdn(tdns.Globals.Zonename) {
			log.Fatalf("Error: Record owner (%s) must match zone (%s)", rr.Header().Name, tdns.Globals.Zonename)
		}

		agentZoneForce, _ := cmd.Flags().GetBool("force")
		req := tdns.AgentMgmtPost{
			Command: "add-rr",
			Zone:    tdns.ZoneName(tdns.Globals.Zonename),
			RRs:     []string{rr.String()},
		}
		if agentZoneForce {
			req.Data = map[string]interface{}{"force": true}
		}

		prefixcmd, _ := GetCommandContext("zone")
		api, err := GetApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		_, buf, err := api.RequestNG("POST", "/agent", req, true)
		if err != nil {
			log.Fatalf("API request failed: %v", err)
		}
		var amr tdns.AgentMgmtResponse
		if err := json.Unmarshal(buf, &amr); err != nil {
			log.Fatalf("Failed to parse response: %v", err)
		}

		if amr.Error {
			log.Fatalf("Error: %s", amr.ErrorMsg)
		}

		rrtype := dns.TypeToString[rr.Header().Rrtype]
		fmt.Printf("Successfully added %s record to zone %s\n", rrtype, tdns.Globals.Zonename)
		fmt.Printf("  Record: %s\n", rr.String())
		if amr.Msg != "" {
			fmt.Printf("  %s\n", amr.Msg)
		}
	},
}

var agentZoneDelRRCmd = &cobra.Command{
	Use:   "delrr",
	Short: "Delete a resource record from a zone and sync with peers and combiner",
	Long: `Delete a resource record from the specified zone. Supported RR types: NS, DNSKEY, CDS, CSYNC.
The RR type is inferred from the --rr argument.

This will:
- Remove the RR from the local synced data store
- Send sync operations to all remote agents for this zone
- Send the update to the combiner

Examples:
  tdns-cliv2 agent zone delrr --zone whisky.dnslab. --rr "whisky.dnslab. IN NS ns.alpha.dnslab."
  tdns-cliv2 agent zone delrr --zone whisky.dnslab. --rr "whisky.dnslab. 300 IN DNSKEY 257 3 13 <base64>"`,
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		if agentZoneRR == "" {
			log.Fatalf("Error: --rr flag is required")
		}

		rr, err := dns.NewRR(agentZoneRR)
		if err != nil {
			log.Fatalf("Error: Invalid DNS record: %v", err)
		}

		if !tdns.AllowedLocalRRtypes[rr.Header().Rrtype] {
			allowed := allowedRRtypeNames()
			log.Fatalf("Error: RR type %s is not allowed (must be one of: %s)",
				dns.TypeToString[rr.Header().Rrtype], strings.Join(allowed, ", "))
		}

		if dns.Fqdn(rr.Header().Name) != dns.Fqdn(tdns.Globals.Zonename) {
			log.Fatalf("Error: Record owner (%s) must match zone (%s)", rr.Header().Name, tdns.Globals.Zonename)
		}

		agentZoneForce, _ := cmd.Flags().GetBool("force")
		req := tdns.AgentMgmtPost{
			Command: "del-rr",
			Zone:    tdns.ZoneName(tdns.Globals.Zonename),
			RRs:     []string{rr.String()},
		}
		if agentZoneForce {
			req.Data = map[string]interface{}{"force": true}
		}

		prefixcmd, _ := GetCommandContext("zone")
		api, err := GetApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		_, buf, err := api.RequestNG("POST", "/agent", req, true)
		if err != nil {
			log.Fatalf("API request failed: %v", err)
		}
		var amr tdns.AgentMgmtResponse
		if err := json.Unmarshal(buf, &amr); err != nil {
			log.Fatalf("Failed to parse response: %v", err)
		}

		if amr.Error {
			log.Fatalf("Error: %s", amr.ErrorMsg)
		}

		rrtype := dns.TypeToString[rr.Header().Rrtype]
		fmt.Printf("Successfully removed %s record from zone %s\n", rrtype, tdns.Globals.Zonename)
		fmt.Printf("  Record: %s\n", rr.String())
		if amr.Msg != "" {
			fmt.Printf("  %s\n", amr.Msg)
		}
	},
}

// --- Helper ---

func allowedRRtypeNames() []string {
	names := make([]string, 0, len(tdns.AllowedLocalRRtypes))
	for rrtype := range tdns.AllowedLocalRRtypes {
		names = append(names, dns.TypeToString[rrtype])
	}
	sort.Strings(names)
	return names
}

// --- Local variables for flags ---

var agentZoneRR string
var agentRollaction string

// --- init ---

func init() {
	AgentCmd.AddCommand(AgentZoneCmd)

	// Zone subcommands relevant to the agent
	AgentZoneCmd.AddCommand(agentZoneListCmd, agentZoneMPListCmd, agentZoneReloadCmd, agentZoneWriteCmd)
	AgentZoneCmd.AddCommand(agentZoneUpdateCmd, agentZoneReadFakeCmd)
	AgentZoneCmd.AddCommand(agentZoneDsyncCmd)

	// New addrr/delrr commands
	AgentZoneCmd.AddCommand(agentZoneAddRRCmd, agentZoneDelRRCmd)

	// Dsync subcommands
	agentZoneDsyncCmd.AddCommand(agentZoneDsyncStatusCmd, agentZoneDsyncBootstrapCmd,
		agentZoneDsyncRollKeyCmd, agentZoneDsyncPublishCmd, agentZoneDsyncUnpublishCmd)

	// Update subcommands
	agentZoneUpdateCmd.AddCommand(agentZoneUpdateCreateCmd)
	agentZoneUpdateCreateCmd.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone to update")

	// Flags
	AgentZoneCmd.PersistentFlags().BoolVarP(&force, "force", "F", false, "force operation")

	agentZoneListCmd.Flags().BoolVarP(&showfile, "file", "f", false, "Show zone input file")
	agentZoneListCmd.Flags().BoolVarP(&shownotify, "notify", "N", false, "Show zone downstream notify addresses")
	agentZoneListCmd.Flags().BoolVarP(&showprimary, "primary", "P", false, "Show zone primary nameserver")

	agentZoneAddRRCmd.Flags().StringVarP(&agentZoneRR, "rr", "", "", "DNS record to add")
	agentZoneAddRRCmd.Flags().Bool("force", false, "Bypass dedup check and always send transaction")
	agentZoneDelRRCmd.Flags().StringVarP(&agentZoneRR, "rr", "", "", "DNS record to delete")
	agentZoneDelRRCmd.Flags().Bool("force", false, "Bypass dedup check and always send transaction")

	agentZoneDsyncRollKeyCmd.PersistentFlags().StringVarP(&tdns.Globals.Algorithm, "algorithm", "a", "ED25519", "Algorithm to use for the new SIG(0) key")
	agentZoneDsyncBootstrapCmd.PersistentFlags().StringVarP(&tdns.Globals.Algorithm, "algorithm", "a", "ED25519", "Algorithm to use for the new SIG(0) key")
	agentZoneDsyncRollKeyCmd.PersistentFlags().StringVarP(&agentRollaction, "rollaction", "r", "complete", "[debug] Phase of the rollover to perform: complete, add, remove, update-local")
	agentZoneDsyncRollKeyCmd.PersistentFlags().MarkHidden("rollaction")
}
