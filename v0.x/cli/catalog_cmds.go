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

	tdns "github.com/johanix/tdns/v0.x"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
)

var catalogName string
var zoneName string
var groupName string

// CatalogCmd is the root command for catalog zone management
var CatalogCmd = &cobra.Command{
	Use:   "catalog",
	Short: "Manage catalog zones (RFC 9432)",
	Long:  `Create and manage catalog zones, add/remove member zones and groups.`,
}

// catalogCreateCmd creates a new catalog zone
var catalogCreateCmd = &cobra.Command{
	Use:   "create --name <catalog-zone>",
	Short: "Create a new catalog zone",
	Run: func(cmd *cobra.Command, args []string) {
		if catalogName == "" {
			fmt.Println("Error: --name is required")
			os.Exit(1)
		}

		prefixcmd, _ := getCommandContext("catalog")
		api, err := getApiClient(prefixcmd, true)
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

// CatalogZoneCmd is the subcommand group for zone operations
var CatalogZoneCmd = &cobra.Command{
	Use:   "zone",
	Short: "Manage member zones in catalog",
}

// catalogZoneAddCmd adds a zone to a catalog
var catalogZoneAddCmd = &cobra.Command{
	Use:   "add --cat <catalog-zone> --zone <zone-name>",
	Short: "Add a zone to the catalog",
	Run: func(cmd *cobra.Command, args []string) {
		if catalogName == "" || zoneName == "" {
			fmt.Println("Error: --cat and --zone are required")
			os.Exit(1)
		}

		prefixcmd, _ := getCommandContext("catalog")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		resp, err := SendCatalogCommand(api, tdns.CatalogPost{
			Command:     "zone-add",
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

// catalogZoneDeleteCmd removes a zone from a catalog
var catalogZoneDeleteCmd = &cobra.Command{
	Use:   "delete --cat <catalog-zone> --zone <zone-name>",
	Short: "Remove a zone from the catalog",
	Run: func(cmd *cobra.Command, args []string) {
		if catalogName == "" || zoneName == "" {
			fmt.Println("Error: --cat and --zone are required")
			os.Exit(1)
		}

		prefixcmd, _ := getCommandContext("catalog")
		api, err := getApiClient(prefixcmd, true)
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

// catalogZoneListCmd lists zones in a catalog
var catalogZoneListCmd = &cobra.Command{
	Use:   "list --cat <catalog-zone>",
	Short: "List zones in the catalog with their groups",
	Run: func(cmd *cobra.Command, args []string) {
		if catalogName == "" {
			fmt.Println("Error: --cat is required")
			os.Exit(1)
		}

		prefixcmd, _ := getCommandContext("catalog")
		api, err := getApiClient(prefixcmd, true)
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
		lines := []string{"Zone Name | Hash | Service Groups | Signing Group | Meta Group"}

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

// CatalogGroupCmd is the subcommand group for group operations
var CatalogGroupCmd = &cobra.Command{
	Use:   "group",
	Short: "Manage groups in catalog",
}

// catalogGroupAddCmd adds a group to the catalog's group list
var catalogGroupAddCmd = &cobra.Command{
	Use:   "add --cat <catalog-zone> --group <group-name>",
	Short: "Add a group to the catalog's group list",
	Run: func(cmd *cobra.Command, args []string) {
		if catalogName == "" || groupName == "" {
			fmt.Println("Error: --cat and --group are required")
			os.Exit(1)
		}

		prefixcmd, _ := getCommandContext("catalog")
		api, err := getApiClient(prefixcmd, true)
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

// catalogGroupDeleteCmd removes a group from the catalog's group list
var catalogGroupDeleteCmd = &cobra.Command{
	Use:   "delete --cat <catalog-zone> --group <group-name>",
	Short: "Remove a group from the catalog's group list",
	Run: func(cmd *cobra.Command, args []string) {
		if catalogName == "" || groupName == "" {
			fmt.Println("Error: --cat and --group are required")
			os.Exit(1)
		}

		prefixcmd, _ := getCommandContext("catalog")
		api, err := getApiClient(prefixcmd, true)
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

// catalogGroupListCmd lists groups in the catalog
var catalogGroupListCmd = &cobra.Command{
	Use:   "list --cat <catalog-zone>",
	Short: "List groups in the catalog",
	Run: func(cmd *cobra.Command, args []string) {
		if catalogName == "" {
			fmt.Println("Error: --cat is required")
			os.Exit(1)
		}

		prefixcmd, _ := getCommandContext("catalog")
		api, err := getApiClient(prefixcmd, true)
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

// CatalogZoneGroupCmd is the subcommand group for zone-group associations
var CatalogZoneGroupCmd = &cobra.Command{
	Use:   "group",
	Short: "Manage group associations for zones",
}

// catalogZoneGroupAddCmd adds a group to a zone
var catalogZoneGroupAddCmd = &cobra.Command{
	Use:   "add --cat <catalog-zone> --zone <zone-name> --group <group-name>",
	Short: "Add a group to a zone",
	Run: func(cmd *cobra.Command, args []string) {
		if catalogName == "" || zoneName == "" || groupName == "" {
			fmt.Println("Error: --cat, --zone, and --group are required")
			os.Exit(1)
		}

		prefixcmd, _ := getCommandContext("catalog")
		api, err := getApiClient(prefixcmd, true)
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

// catalogZoneGroupDeleteCmd removes a group from a zone
var catalogZoneGroupDeleteCmd = &cobra.Command{
	Use:   "delete --cat <catalog-zone> --zone <zone-name> --group <group-name>",
	Short: "Remove a group from a zone",
	Run: func(cmd *cobra.Command, args []string) {
		if catalogName == "" || zoneName == "" || groupName == "" {
			fmt.Println("Error: --cat, --zone, and --group are required")
			os.Exit(1)
		}

		prefixcmd, _ := getCommandContext("catalog")
		api, err := getApiClient(prefixcmd, true)
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

func init() {
	// Root catalog command
	CatalogCmd.AddCommand(catalogCreateCmd)
	CatalogCmd.AddCommand(CatalogZoneCmd)
	CatalogCmd.AddCommand(CatalogGroupCmd)

	// Zone subcommands
	CatalogZoneCmd.AddCommand(catalogZoneAddCmd)
	CatalogZoneCmd.AddCommand(catalogZoneDeleteCmd)
	CatalogZoneCmd.AddCommand(catalogZoneListCmd)
	CatalogZoneCmd.AddCommand(CatalogZoneGroupCmd)

	// Zone group subcommands
	CatalogZoneGroupCmd.AddCommand(catalogZoneGroupAddCmd)
	CatalogZoneGroupCmd.AddCommand(catalogZoneGroupDeleteCmd)

	// Group subcommands
	CatalogGroupCmd.AddCommand(catalogGroupAddCmd)
	CatalogGroupCmd.AddCommand(catalogGroupDeleteCmd)
	CatalogGroupCmd.AddCommand(catalogGroupListCmd)

	// Flags for catalog create
	catalogCreateCmd.Flags().StringVar(&catalogName, "name", "", "Catalog zone name (required)")

	// Flags for zone operations
	catalogZoneAddCmd.Flags().StringVar(&catalogName, "cat", "", "Catalog zone name (required)")
	catalogZoneAddCmd.Flags().StringVar(&zoneName, "zone", "", "Member zone name (required)")

	catalogZoneDeleteCmd.Flags().StringVar(&catalogName, "cat", "", "Catalog zone name (required)")
	catalogZoneDeleteCmd.Flags().StringVar(&zoneName, "zone", "", "Member zone name (required)")

	catalogZoneListCmd.Flags().StringVar(&catalogName, "cat", "", "Catalog zone name (required)")

	// Flags for group operations
	catalogGroupAddCmd.Flags().StringVar(&catalogName, "cat", "", "Catalog zone name (required)")
	catalogGroupAddCmd.Flags().StringVar(&groupName, "group", "", "Group name (required)")

	catalogGroupDeleteCmd.Flags().StringVar(&catalogName, "cat", "", "Catalog zone name (required)")
	catalogGroupDeleteCmd.Flags().StringVar(&groupName, "group", "", "Group name (required)")

	catalogGroupListCmd.Flags().StringVar(&catalogName, "cat", "", "Catalog zone name (required)")

	// Flags for zone-group operations
	catalogZoneGroupAddCmd.Flags().StringVar(&catalogName, "cat", "", "Catalog zone name (required)")
	catalogZoneGroupAddCmd.Flags().StringVar(&zoneName, "zone", "", "Member zone name (required)")
	catalogZoneGroupAddCmd.Flags().StringVar(&groupName, "group", "", "Group name (required)")

	catalogZoneGroupDeleteCmd.Flags().StringVar(&catalogName, "cat", "", "Catalog zone name (required)")
	catalogZoneGroupDeleteCmd.Flags().StringVar(&zoneName, "zone", "", "Member zone name (required)")
	catalogZoneGroupDeleteCmd.Flags().StringVar(&groupName, "group", "", "Group name (required)")
}
