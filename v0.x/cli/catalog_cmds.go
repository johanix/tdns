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
var componentName string

// CatalogCmd is the root command for catalog zone management
var CatalogCmd = &cobra.Command{
	Use:   "catalog",
	Short: "Manage catalog zones (RFC 9432)",
	Long:  `Create and manage catalog zones, add/remove member zones and components.`,
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
	Short: "List zones in the catalog with their components",
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
		lines := []string{"Zone Name | Hash | Service Components | Signing Component | Meta Component"}

		// Sort zones by name
		zoneNames := make([]string, 0, len(resp.Zones))
		for zname := range resp.Zones {
			zoneNames = append(zoneNames, zname)
		}
		sort.Strings(zoneNames)

		for _, zname := range zoneNames {
			member := resp.Zones[zname]
			serviceComps := strings.Join(member.ServiceComponents, ", ")
			if serviceComps == "" {
				serviceComps = "-"
			}
			signing := member.SigningComponent
			if signing == "" {
				signing = "-"
			}
			meta := member.MetaComponent
			if meta == "" {
				meta = "-"
			}
			lines = append(lines, fmt.Sprintf("%s | %s | %s | %s | %s",
				zname, member.Hash[:12]+"...", serviceComps, signing, meta))
		}

		fmt.Println(columnize.SimpleFormat(lines))
	},
}

// CatalogComponentCmd is the subcommand group for component operations
var CatalogComponentCmd = &cobra.Command{
	Use:   "component",
	Short: "Manage components in catalog",
}

// catalogComponentAddCmd adds a component to the catalog's component list
var catalogComponentAddCmd = &cobra.Command{
	Use:   "add --cat <catalog-zone> --comp <component-name>",
	Short: "Add a component to the catalog's component list",
	Run: func(cmd *cobra.Command, args []string) {
		if catalogName == "" || componentName == "" {
			fmt.Println("Error: --cat and --comp are required")
			os.Exit(1)
		}

		prefixcmd, _ := getCommandContext("catalog")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		resp, err := SendCatalogCommand(api, tdns.CatalogPost{
			Command:     "component-add",
			CatalogZone: catalogName,
			Component:   componentName,
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

// catalogComponentDeleteCmd removes a component from the catalog's component list
var catalogComponentDeleteCmd = &cobra.Command{
	Use:   "delete --cat <catalog-zone> --comp <component-name>",
	Short: "Remove a component from the catalog's component list",
	Run: func(cmd *cobra.Command, args []string) {
		if catalogName == "" || componentName == "" {
			fmt.Println("Error: --cat and --comp are required")
			os.Exit(1)
		}

		prefixcmd, _ := getCommandContext("catalog")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		resp, err := SendCatalogCommand(api, tdns.CatalogPost{
			Command:     "component-delete",
			CatalogZone: catalogName,
			Component:   componentName,
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

// catalogComponentListCmd lists components in the catalog
var catalogComponentListCmd = &cobra.Command{
	Use:   "list --cat <catalog-zone>",
	Short: "List components in the catalog",
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
			Command:     "component-list",
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

		if len(resp.Components) == 0 {
			fmt.Printf("No components defined in catalog %s\n", catalogName)
			return
		}

		fmt.Printf("Components in catalog %s:\n", catalogName)
		components := resp.Components
		sort.Strings(components)
		for _, comp := range components {
			fmt.Printf("  %s\n", comp)
		}
	},
}

// CatalogZoneComponentCmd is the subcommand group for zone-component associations
var CatalogZoneComponentCmd = &cobra.Command{
	Use:   "component",
	Short: "Manage component associations for zones",
}

// catalogZoneComponentAddCmd adds a component to a zone
var catalogZoneComponentAddCmd = &cobra.Command{
	Use:   "add --cat <catalog-zone> --zone <zone-name> --comp <component-name>",
	Short: "Add a component to a zone",
	Run: func(cmd *cobra.Command, args []string) {
		if catalogName == "" || zoneName == "" || componentName == "" {
			fmt.Println("Error: --cat, --zone, and --comp are required")
			os.Exit(1)
		}

		prefixcmd, _ := getCommandContext("catalog")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		resp, err := SendCatalogCommand(api, tdns.CatalogPost{
			Command:     "zone-component-add",
			CatalogZone: catalogName,
			Zone:        zoneName,
			Component:   componentName,
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

// catalogZoneComponentDeleteCmd removes a component from a zone
var catalogZoneComponentDeleteCmd = &cobra.Command{
	Use:   "delete --cat <catalog-zone> --zone <zone-name> --comp <component-name>",
	Short: "Remove a component from a zone",
	Run: func(cmd *cobra.Command, args []string) {
		if catalogName == "" || zoneName == "" || componentName == "" {
			fmt.Println("Error: --cat, --zone, and --comp are required")
			os.Exit(1)
		}

		prefixcmd, _ := getCommandContext("catalog")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		resp, err := SendCatalogCommand(api, tdns.CatalogPost{
			Command:     "zone-component-delete",
			CatalogZone: catalogName,
			Zone:        zoneName,
			Component:   componentName,
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
	CatalogCmd.AddCommand(CatalogComponentCmd)

	// Zone subcommands
	CatalogZoneCmd.AddCommand(catalogZoneAddCmd)
	CatalogZoneCmd.AddCommand(catalogZoneDeleteCmd)
	CatalogZoneCmd.AddCommand(catalogZoneListCmd)
	CatalogZoneCmd.AddCommand(CatalogZoneComponentCmd)

	// Zone component subcommands
	CatalogZoneComponentCmd.AddCommand(catalogZoneComponentAddCmd)
	CatalogZoneComponentCmd.AddCommand(catalogZoneComponentDeleteCmd)

	// Component subcommands
	CatalogComponentCmd.AddCommand(catalogComponentAddCmd)
	CatalogComponentCmd.AddCommand(catalogComponentDeleteCmd)
	CatalogComponentCmd.AddCommand(catalogComponentListCmd)

	// Flags for catalog create
	catalogCreateCmd.Flags().StringVar(&catalogName, "name", "", "Catalog zone name (required)")

	// Flags for zone operations
	catalogZoneAddCmd.Flags().StringVar(&catalogName, "cat", "", "Catalog zone name (required)")
	catalogZoneAddCmd.Flags().StringVar(&zoneName, "zone", "", "Member zone name (required)")

	catalogZoneDeleteCmd.Flags().StringVar(&catalogName, "cat", "", "Catalog zone name (required)")
	catalogZoneDeleteCmd.Flags().StringVar(&zoneName, "zone", "", "Member zone name (required)")

	catalogZoneListCmd.Flags().StringVar(&catalogName, "cat", "", "Catalog zone name (required)")

	// Flags for component operations
	catalogComponentAddCmd.Flags().StringVar(&catalogName, "cat", "", "Catalog zone name (required)")
	catalogComponentAddCmd.Flags().StringVar(&componentName, "comp", "", "Component name (required)")

	catalogComponentDeleteCmd.Flags().StringVar(&catalogName, "cat", "", "Catalog zone name (required)")
	catalogComponentDeleteCmd.Flags().StringVar(&componentName, "comp", "", "Component name (required)")

	catalogComponentListCmd.Flags().StringVar(&catalogName, "cat", "", "Catalog zone name (required)")

	// Flags for zone-component operations
	catalogZoneComponentAddCmd.Flags().StringVar(&catalogName, "cat", "", "Catalog zone name (required)")
	catalogZoneComponentAddCmd.Flags().StringVar(&zoneName, "zone", "", "Member zone name (required)")
	catalogZoneComponentAddCmd.Flags().StringVar(&componentName, "comp", "", "Component name (required)")

	catalogZoneComponentDeleteCmd.Flags().StringVar(&catalogName, "cat", "", "Catalog zone name (required)")
	catalogZoneComponentDeleteCmd.Flags().StringVar(&zoneName, "zone", "", "Member zone name (required)")
	catalogZoneComponentDeleteCmd.Flags().StringVar(&componentName, "comp", "", "Component name (required)")
}
