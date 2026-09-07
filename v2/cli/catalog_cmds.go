/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cli

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"

	tdns "github.com/johanix/tdns/v2"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
)

var catalogName string
var zoneName string
var groupName string
var groupNames []string // For --groups flag (multiple groups)
var notifyAddress string

// CatalogCmd is the root command for catalog zone management
func newCatalogCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "catalog",
		Short: "Manage catalog zones (RFC 9432)",
		Long:  `Create and manage catalog zones, add/remove member zones and groups.`,
	}
}

// catalogCreateCmd creates a new catalog zone
func newCatalogCreateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "create --cat <catalog-zone>",
		Short: "Create a new catalog zone",
		Run: func(cmd *cobra.Command, args []string) {
			if catalogName == "" {
				fmt.Println("Error: --cat is required")
				os.Exit(1)
			}

			// CatalogCmd is only registered under rootCmd in cliv2 → role "auth".
			api, err := GetApiClientForCmd(cmd, true)
			if err != nil {
				log.Fatalf("Error getting API client: %v", err)
			}

			resp, err := SendCatalogCommand(api, tdns.CatalogPost{
				Command:     "create",
				CatalogZone: catalogName,
			})

			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}

			if resp.Error {
				fmt.Printf("Error: %s\n", resp.ErrorMsg)
				os.Exit(1)
			}

			if resp.Msg != "" {
				fmt.Printf("%s\n", resp.Msg)
			}
		},
	}
}

// catalogDeleteCmd deletes an entire catalog zone
func newCatalogDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete --cat <catalog-zone>",
		Short: "Delete an entire catalog zone",
		Run: func(cmd *cobra.Command, args []string) {
			if catalogName == "" {
				fmt.Println("Error: --cat is required")
				os.Exit(1)
			}

			// CatalogCmd is only registered under rootCmd in cliv2 → role "auth".
			api, err := GetApiClientForCmd(cmd, true)
			if err != nil {
				log.Fatalf("Error getting API client: %v", err)
			}

			resp, err := SendCatalogCommand(api, tdns.CatalogPost{
				Command:     "delete",
				CatalogZone: catalogName,
			})

			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}

			if resp.Error {
				fmt.Printf("Error: %s\n", resp.ErrorMsg)
				os.Exit(1)
			}

			if resp.Msg != "" {
				fmt.Printf("%s\n", resp.Msg)
			}
		},
	}
}

// CatalogZoneCmd is the subcommand group for zone operations
func newCatalogZoneCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "zone",
		Short: "Manage member zones in catalog",
	}
}

// catalogZoneAddCmd adds a zone to a catalog
func newCatalogZoneAddCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add --cat <catalog-zone> --zone <zone-name> [--groups <group1,group2,...>]",
		Short: "Add a zone to the catalog with optional groups",
		Run: func(cmd *cobra.Command, args []string) {
			if catalogName == "" || zoneName == "" {
				fmt.Println("Error: --cat and --zone are required")
				os.Exit(1)
			}

			// CatalogCmd is only registered under rootCmd in cliv2 → role "auth".
			api, err := GetApiClientForCmd(cmd, true)
			if err != nil {
				log.Fatalf("Error getting API client: %v", err)
			}

			resp, err := SendCatalogCommand(api, tdns.CatalogPost{
				Command:     "zone-add",
				CatalogZone: catalogName,
				Zone:        zoneName,
				Groups:      groupNames, // Pass the list of groups
			})

			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}

			if resp.Error {
				fmt.Printf("Error: %s\n", resp.ErrorMsg)
				os.Exit(1)
			}

			if resp.Msg != "" {
				fmt.Printf("%s\n", resp.Msg)
			}
		},
	}
}

// catalogZoneDeleteCmd removes a zone from a catalog
func newCatalogZoneDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete --cat <catalog-zone> --zone <zone-name>",
		Short: "Remove a zone from the catalog",
		Run: func(cmd *cobra.Command, args []string) {
			if catalogName == "" || zoneName == "" {
				fmt.Println("Error: --cat and --zone are required")
				os.Exit(1)
			}

			// CatalogCmd is only registered under rootCmd in cliv2 → role "auth".
			api, err := GetApiClientForCmd(cmd, true)
			if err != nil {
				log.Fatalf("Error getting API client: %v", err)
			}

			resp, err := SendCatalogCommand(api, tdns.CatalogPost{
				Command:     "zone-delete",
				CatalogZone: catalogName,
				Zone:        zoneName,
			})

			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}

			if resp.Error {
				fmt.Printf("Error: %s\n", resp.ErrorMsg)
				os.Exit(1)
			}

			if resp.Msg != "" {
				fmt.Printf("%s\n", resp.Msg)
			}
		},
	}
}

// catalogZoneListCmd lists zones in a catalog
func newCatalogZoneListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list --cat <catalog-zone>",
		Short: "List zones in the catalog with their groups",
		Run: func(cmd *cobra.Command, args []string) {
			if catalogName == "" {
				fmt.Println("Error: --cat is required")
				os.Exit(1)
			}

			// CatalogCmd is only registered under rootCmd in cliv2 → role "auth".
			api, err := GetApiClientForCmd(cmd, true)
			if err != nil {
				log.Fatalf("Error getting API client: %v", err)
			}

			resp, err := SendCatalogCommand(api, tdns.CatalogPost{
				Command:     "zone-list",
				CatalogZone: catalogName,
			})

			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}

			if resp.Error {
				fmt.Printf("Error: %s\n", resp.ErrorMsg)
				os.Exit(1)
			}

			if len(resp.Zones) == 0 {
				fmt.Printf("No zones in catalog %s\n", catalogName)
				return
			}

			// Format output
			lines := []string{"Zone Name | Hash | Service Groups | Signing Group | Config Group"}

			// Sort zones by name
			zoneNames := make([]string, 0, len(resp.Zones))
			for zname := range resp.Zones {
				zoneNames = append(zoneNames, zname)
			}
			sort.Strings(zoneNames)

			for _, zname := range zoneNames {
				member := resp.Zones[zname]
				serviceGroups := strings.Join(member.ServiceGroups, ", ")
				if serviceGroups == "" {
					serviceGroups = "-"
				}
				signing := member.SigningGroup
				if signing == "" {
					signing = "-"
				}
				meta := member.MetaGroup
				if meta == "" {
					meta = "-"
				}
				lines = append(lines, fmt.Sprintf("%s | %s | %s | %s | %s",
					zname, member.Hash[:12]+"...", serviceGroups, signing, meta))
			}

			fmt.Println(columnize.SimpleFormat(lines))
		},
	}
}

// CatalogGroupCmd is the subcommand group for group operations
func newCatalogGroupCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "group",
		Short: "Manage groups in catalog",
	}
}

// catalogGroupAddCmd adds a group to the catalog's group list
func newCatalogGroupAddCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add --cat <catalog-zone> --group <group-name>",
		Short: "Add a group to the catalog's group list",
		Run: func(cmd *cobra.Command, args []string) {
			if catalogName == "" || groupName == "" {
				fmt.Println("Error: --cat and --group are required")
				os.Exit(1)
			}

			// CatalogCmd is only registered under rootCmd in cliv2 → role "auth".
			api, err := GetApiClientForCmd(cmd, true)
			if err != nil {
				log.Fatalf("Error getting API client: %v", err)
			}

			resp, err := SendCatalogCommand(api, tdns.CatalogPost{
				Command:     "group-add",
				CatalogZone: catalogName,
				Group:       groupName,
			})

			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}

			if resp.Error {
				fmt.Printf("Error: %s\n", resp.ErrorMsg)
				os.Exit(1)
			}

			if resp.Msg != "" {
				fmt.Printf("%s\n", resp.Msg)
			}
		},
	}
}

// catalogGroupDeleteCmd removes a group from the catalog's group list
func newCatalogGroupDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete --cat <catalog-zone> --group <group-name>",
		Short: "Remove a group from the catalog's group list",
		Run: func(cmd *cobra.Command, args []string) {
			if catalogName == "" || groupName == "" {
				fmt.Println("Error: --cat and --group are required")
				os.Exit(1)
			}

			// CatalogCmd is only registered under rootCmd in cliv2 → role "auth".
			api, err := GetApiClientForCmd(cmd, true)
			if err != nil {
				log.Fatalf("Error getting API client: %v", err)
			}

			resp, err := SendCatalogCommand(api, tdns.CatalogPost{
				Command:     "group-delete",
				CatalogZone: catalogName,
				Group:       groupName,
			})

			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}

			if resp.Error {
				fmt.Printf("Error: %s\n", resp.ErrorMsg)
				os.Exit(1)
			}

			if resp.Msg != "" {
				fmt.Printf("%s\n", resp.Msg)
			}
		},
	}
}

// catalogGroupListCmd lists groups in the catalog
func newCatalogGroupListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list --cat <catalog-zone>",
		Short: "List groups in the catalog",
		Run: func(cmd *cobra.Command, args []string) {
			if catalogName == "" {
				fmt.Println("Error: --cat is required")
				os.Exit(1)
			}

			// CatalogCmd is only registered under rootCmd in cliv2 → role "auth".
			api, err := GetApiClientForCmd(cmd, true)
			if err != nil {
				log.Fatalf("Error getting API client: %v", err)
			}

			resp, err := SendCatalogCommand(api, tdns.CatalogPost{
				Command:     "group-list",
				CatalogZone: catalogName,
			})

			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}

			if resp.Error {
				fmt.Printf("Error: %s\n", resp.ErrorMsg)
				os.Exit(1)
			}

			if len(resp.Groups) == 0 {
				fmt.Printf("No groups defined in catalog %s\n", catalogName)
				return
			}

			fmt.Printf("Groups in catalog %s:\n", catalogName)
			groups := resp.Groups
			sort.Strings(groups)
			for _, grp := range groups {
				fmt.Printf("  %s\n", grp)
			}
		},
	}
}

// CatalogZoneGroupCmd is the subcommand group for zone-group associations
func newCatalogZoneGroupCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "group",
		Short: "Manage group associations for zones",
	}
}

// catalogZoneGroupAddCmd adds a group to a zone
func newCatalogZoneGroupAddCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add --cat <catalog-zone> --zone <zone-name> --group <group-name>",
		Short: "Add a group to a zone",
		Run: func(cmd *cobra.Command, args []string) {
			if catalogName == "" || zoneName == "" || groupName == "" {
				fmt.Println("Error: --cat, --zone, and --group are required")
				os.Exit(1)
			}

			// CatalogCmd is only registered under rootCmd in cliv2 → role "auth".
			api, err := GetApiClientForCmd(cmd, true)
			if err != nil {
				log.Fatalf("Error getting API client: %v", err)
			}

			resp, err := SendCatalogCommand(api, tdns.CatalogPost{
				Command:     "zone-group-add",
				CatalogZone: catalogName,
				Zone:        zoneName,
				Group:       groupName,
			})

			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}

			if resp.Error {
				fmt.Printf("Error: %s\n", resp.ErrorMsg)
				os.Exit(1)
			}

			if resp.Msg != "" {
				fmt.Printf("%s\n", resp.Msg)
			}
		},
	}
}

// catalogZoneGroupDeleteCmd removes a group from a zone
func newCatalogZoneGroupDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete --cat <catalog-zone> --zone <zone-name> --group <group-name>",
		Short: "Remove a group from a zone",
		Run: func(cmd *cobra.Command, args []string) {
			if catalogName == "" || zoneName == "" || groupName == "" {
				fmt.Println("Error: --cat, --zone, and --group are required")
				os.Exit(1)
			}

			// CatalogCmd is only registered under rootCmd in cliv2 → role "auth".
			api, err := GetApiClientForCmd(cmd, true)
			if err != nil {
				log.Fatalf("Error getting API client: %v", err)
			}

			resp, err := SendCatalogCommand(api, tdns.CatalogPost{
				Command:     "zone-group-delete",
				CatalogZone: catalogName,
				Zone:        zoneName,
				Group:       groupName,
			})

			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}

			if resp.Error {
				fmt.Printf("Error: %s\n", resp.ErrorMsg)
				os.Exit(1)
			}

			if resp.Msg != "" {
				fmt.Printf("%s\n", resp.Msg)
			}
		},
	}
}

// SendCatalogCommand sends a catalog command to the API
func SendCatalogCommand(api *tdns.ApiClient, data tdns.CatalogPost) (*tdns.CatalogResponse, error) {
	status, buf, err := api.RequestNG(http.MethodPost, "/catalog", data, true)
	if err != nil {
		return nil, fmt.Errorf("error from API request: %v", err)
	}

	var resp tdns.CatalogResponse
	err = json.Unmarshal(buf, &resp)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling response: %v", err)
	}

	if status != 200 {
		if resp.ErrorMsg != "" {
			return &resp, fmt.Errorf("%s", resp.ErrorMsg)
		}
		return &resp, fmt.Errorf("status code: %d", status)
	}

	return &resp, nil
}

// NewCatalogCmd builds the catalog subtree for one daemon instance.
//
// Was an init() wiring package-level command vars. A *cobra.Command has
// exactly one parent, so those vars could only ever hang off one tree --
// which is what kept `catalog` off a second tdns-auth instance. Nothing about
// the tree's SHAPE changed in the conversion; only who owns the commands.
//
// The flag variables (catalogName, zoneName, ...) stay package-level and are
// bound once per instantiation. That is safe because exactly one command runs
// per invocation: cobra parses only the flagset of the command it dispatched.
func NewCatalogCmd(role string) *cobra.Command {
	catalog := newCatalogCmd()
	TagRole(catalog, role)

	create := newCatalogCreateCmd()
	del := newCatalogDeleteCmd()
	zone := newCatalogZoneCmd()
	group := newCatalogGroupCmd()
	notify := newCatalogNotifyCmd()

	zoneAdd := newCatalogZoneAddCmd()
	zoneDelete := newCatalogZoneDeleteCmd()
	zoneList := newCatalogZoneListCmd()
	zoneGroup := newCatalogZoneGroupCmd()

	zoneGroupAdd := newCatalogZoneGroupAddCmd()
	zoneGroupDelete := newCatalogZoneGroupDeleteCmd()

	groupAdd := newCatalogGroupAddCmd()
	groupDelete := newCatalogGroupDeleteCmd()
	groupList := newCatalogGroupListCmd()

	notifyAdd := newCatalogNotifyAddCmd()
	notifyRemove := newCatalogNotifyRemoveCmd()
	notifyList := newCatalogNotifyListCmd()

	// Root catalog command
	catalog.AddCommand(create, del, zone, group, notify)

	// Zone subcommands
	zone.AddCommand(zoneAdd, zoneDelete, zoneList, zoneGroup)

	// Zone group subcommands
	zoneGroup.AddCommand(zoneGroupAdd, zoneGroupDelete)

	// Group subcommands
	group.AddCommand(groupAdd, groupDelete, groupList)

	// Notify subcommands
	notify.AddCommand(notifyAdd, notifyRemove, notifyList)

	// Flags for catalog create/delete
	create.Flags().StringVar(&catalogName, "cat", "", "Catalog zone name (required)")
	del.Flags().StringVar(&catalogName, "cat", "", "Catalog zone name (required)")

	// Flags for zone operations
	zoneAdd.Flags().StringVar(&catalogName, "cat", "", "Catalog zone name (required)")
	zoneAdd.Flags().StringVar(&zoneName, "zone", "", "Member zone name (required)")
	zoneAdd.Flags().StringSliceVar(&groupNames, "groups", []string{}, "Optional: comma-separated list of groups to add to the zone")

	zoneDelete.Flags().StringVar(&catalogName, "cat", "", "Catalog zone name (required)")
	zoneDelete.Flags().StringVar(&zoneName, "zone", "", "Member zone name (required)")

	zoneList.Flags().StringVar(&catalogName, "cat", "", "Catalog zone name (required)")

	// Flags for group operations
	groupAdd.Flags().StringVar(&catalogName, "cat", "", "Catalog zone name (required)")
	groupAdd.Flags().StringVar(&groupName, "group", "", "Group name (required)")

	groupDelete.Flags().StringVar(&catalogName, "cat", "", "Catalog zone name (required)")
	groupDelete.Flags().StringVar(&groupName, "group", "", "Group name (required)")

	groupList.Flags().StringVar(&catalogName, "cat", "", "Catalog zone name (required)")

	// Flags for zone-group operations
	zoneGroupAdd.Flags().StringVar(&catalogName, "cat", "", "Catalog zone name (required)")
	zoneGroupAdd.Flags().StringVar(&zoneName, "zone", "", "Member zone name (required)")
	zoneGroupAdd.Flags().StringVar(&groupName, "group", "", "Group name (required)")

	zoneGroupDelete.Flags().StringVar(&catalogName, "cat", "", "Catalog zone name (required)")
	zoneGroupDelete.Flags().StringVar(&zoneName, "zone", "", "Member zone name (required)")
	zoneGroupDelete.Flags().StringVar(&groupName, "group", "", "Group name (required)")

	// Flags for notify operations
	notifyAdd.Flags().StringVar(&catalogName, "cat", "", "Catalog zone name (required)")
	notifyAdd.Flags().StringVar(&notifyAddress, "addr", "", "Notify address in IP:port format (required)")

	notifyRemove.Flags().StringVar(&catalogName, "cat", "", "Catalog zone name (required)")
	notifyRemove.Flags().StringVar(&notifyAddress, "addr", "", "Notify address in IP:port format (required)")

	notifyList.Flags().StringVar(&catalogName, "cat", "", "Catalog zone name (required)")

	return catalog
}

// CatalogCmd is the canonical instance's catalog subtree, kept so the existing
// wiring in cmdv2/cli/shared_cmds.go and cmdv2/cli/root.go compiles unchanged.
var CatalogCmd = NewCatalogCmd("auth")

// CatalogNotifyCmd is the subcommand group for notify address operations
func newCatalogNotifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "notify",
		Short: "Manage notify addresses for catalog zones",
	}
}

// catalogNotifyAddCmd adds a notify address to a catalog zone
func newCatalogNotifyAddCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add --cat <catalog-zone> --addr <IP:port>",
		Short: "Add a notify address to a catalog zone",
		Run: func(cmd *cobra.Command, args []string) {
			if catalogName == "" || notifyAddress == "" {
				fmt.Println("Error: --cat and --addr are required")
				os.Exit(1)
			}

			// CatalogCmd is only registered under rootCmd in cliv2 → role "auth".
			api, err := GetApiClientForCmd(cmd, true)
			if err != nil {
				log.Fatalf("Error getting API client: %v", err)
			}

			resp, err := SendCatalogCommand(api, tdns.CatalogPost{
				Command:     "notify-add",
				CatalogZone: catalogName,
				Address:     notifyAddress,
			})

			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}

			if resp.Error {
				fmt.Printf("Error: %s\n", resp.ErrorMsg)
				os.Exit(1)
			}

			if resp.Msg != "" {
				fmt.Printf("%s\n", resp.Msg)
			}
		},
	}
}

// catalogNotifyRemoveCmd removes a notify address from a catalog zone
func newCatalogNotifyRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove --cat <catalog-zone> --addr <IP:port>",
		Short: "Remove a notify address from a catalog zone",
		Run: func(cmd *cobra.Command, args []string) {
			if catalogName == "" || notifyAddress == "" {
				fmt.Println("Error: --cat and --addr are required")
				os.Exit(1)
			}

			// CatalogCmd is only registered under rootCmd in cliv2 → role "auth".
			api, err := GetApiClientForCmd(cmd, true)
			if err != nil {
				log.Fatalf("Error getting API client: %v", err)
			}

			resp, err := SendCatalogCommand(api, tdns.CatalogPost{
				Command:     "notify-remove",
				CatalogZone: catalogName,
				Address:     notifyAddress,
			})

			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}

			if resp.Error {
				fmt.Printf("Error: %s\n", resp.ErrorMsg)
				os.Exit(1)
			}

			if resp.Msg != "" {
				fmt.Printf("%s\n", resp.Msg)
			}
		},
	}
}

// catalogNotifyListCmd lists all notify addresses for a catalog zone
func newCatalogNotifyListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list --cat <catalog-zone>",
		Short: "List all notify addresses for a catalog zone",
		Run: func(cmd *cobra.Command, args []string) {
			if catalogName == "" {
				fmt.Println("Error: --cat is required")
				os.Exit(1)
			}

			// CatalogCmd is only registered under rootCmd in cliv2 → role "auth".
			api, err := GetApiClientForCmd(cmd, true)
			if err != nil {
				log.Fatalf("Error getting API client: %v", err)
			}

			resp, err := SendCatalogCommand(api, tdns.CatalogPost{
				Command:     "notify-list",
				CatalogZone: catalogName,
			})

			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}

			if resp.Error {
				fmt.Printf("Error: %s\n", resp.ErrorMsg)
				os.Exit(1)
			}

			if len(resp.NotifyAddresses) == 0 {
				fmt.Printf("No notify addresses configured for catalog zone %s\n", catalogName)
				return
			}

			fmt.Printf("Notify addresses for catalog zone %s:\n", catalogName)
			for _, addr := range resp.NotifyAddresses {
				fmt.Printf("  %s\n", addr)
			}
		},
	}
}
