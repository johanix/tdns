/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"

	"github.com/johanix/tdns/tdns"
	"github.com/miekg/dns"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
)

var zoneReloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Send reload zone command to tdnsd",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Reloading zone: %v\n", args)
		if tdns.Globals.Zonename == "" {
			fmt.Printf("Error: zone name not specified. Terminating.\n")
			os.Exit(1)
		}

		prefixcmd, _ := getCommandContext("zone")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client for %s: %v", prefixcmd, err)
		}

		resp, err := SendZoneCommand(api, tdns.ZonePost{
			Command: "reload",
			Zone:    dns.Fqdn(tdns.Globals.Zonename),
			Force:   force,
		})

		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			os.Exit(1)
		}
		if resp.Error {
			fmt.Printf("Error from tdnsd: %s\n", resp.ErrorMsg)
			os.Exit(1)
		}

		if resp.Msg != "" {
			fmt.Printf("%s\n", resp.Msg)
		}
	},
}

var zoneNsecCmd = &cobra.Command{
	Use:   "nsec",
	Short: "A brief description of your command",
}

var zoneSignCmd = &cobra.Command{
	Use:   "sign",
	Short: "Send a zone sign command to tdnsd",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("childzone")

		prefixcmd, _ := getCommandContext("zone")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client for %s: %v", prefixcmd, err)
		}

		cr, err := SendZoneCommand(api, tdns.ZonePost{
			Command: "sign-zone",
			Zone:    tdns.Globals.Zonename,
			Force:   force,
		})
		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			os.Exit(1)
		}
		if cr.Error {
			fmt.Printf("Error from tdnsd: %s\n", cr.ErrorMsg)
			os.Exit(1)
		}

		if cr.Msg != "" {
			fmt.Printf("%s\n", cr.Msg)
		}
	},
}

var zoneWriteCmd = &cobra.Command{
	Use:   "write",
	Short: "Send a zone write command to tdnsd",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("childzone")

		prefixcmd, _ := getCommandContext("zone")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client for %s: %v", prefixcmd, err)
		}

		cr, err := SendZoneCommand(api, tdns.ZonePost{
			Command: "write-zone",
			Zone:    tdns.Globals.Zonename,
			Force:   force,
		})
		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			os.Exit(1)
		}
		if cr.Error {
			fmt.Printf("Error from tdnsd: %s\n", cr.ErrorMsg)
			os.Exit(1)
		}

		if cr.Msg != "" {
			fmt.Printf("%s\n", cr.Msg)
		}
	},
}

var zoneNsecGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Send an NSEC generate command to tdnsd",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("childzone")

		prefixcmd, _ := getCommandContext("zone")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client for %s: %v", prefixcmd, err)
		}

		cr, err := SendZoneCommand(api, tdns.ZonePost{
			Command: "generate-nsec",
			Zone:    tdns.Globals.Zonename,
			Force:   force,
		})
		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			os.Exit(1)
		}
		if cr.Error {
			fmt.Printf("Error from tdnsd: %s\n", cr.ErrorMsg)
			os.Exit(1)
		}

		if cr.Msg != "" {
			fmt.Printf("%s\n", cr.Msg)
		}
	},
}

var zoneNsecShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Send an NSEC show command to tdnsd",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("childzone")
		prefixcmd, _ := getCommandContext("zone")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client for %s: %v", prefixcmd, err)
		}

		cr, err := SendZoneCommand(api, tdns.ZonePost{
			Command: "show-nsec-chain",
			Zone:    tdns.Globals.Zonename,
			Force:   force,
		})
		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			os.Exit(1)
		}
		if cr.Error {
			fmt.Printf("Error from tdnsd: %s\n", cr.ErrorMsg)
			os.Exit(1)
		}

		if cr.Msg != "" {
			fmt.Printf("%s\n", cr.Msg)
		}
		fmt.Printf("NSEC chain for zone \"%s\":\n", cr.Zone)
		for _, name := range cr.Names {
			fmt.Printf("%s\n", name)
		}
	},
}

var zoneFreezeCmd = &cobra.Command{
	Use:   "freeze",
	Short: "Tell tdnsd to freeze a zone (i.e. no longer accept changes to the zone data)",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("childzone")

		prefixcmd, _ := getCommandContext("zone")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client for %s: %v", prefixcmd, err)
		}

		cr, err := SendZoneCommand(api, tdns.ZonePost{
			Command: "freeze",
			Zone:    tdns.Globals.Zonename,
			Force:   force,
		})
		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			os.Exit(1)
		}
		if cr.Error {
			fmt.Printf("Error from tdnsd: %s\n", cr.ErrorMsg)
			os.Exit(1)
		}

		if cr.Msg != "" {
			fmt.Printf("%s\n", cr.Msg)
		}
	},
}

var zoneThawCmd = &cobra.Command{
	Use:   "thaw",
	Short: "Tell tdnsd to thaw a zone (i.e. accept changes to the zone data again)",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("childzone")
		prefixcmd, _ := getCommandContext("zone")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client for %s: %v", prefixcmd, err)
		}

		cr, err := SendZoneCommand(api, tdns.ZonePost{
			Command: "thaw",
			Zone:    tdns.Globals.Zonename,
			Force:   force,
		})
		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			os.Exit(1)
		}
		if cr.Error {
			fmt.Printf("Error from tdns-server: %s\n", cr.ErrorMsg)
			os.Exit(1)
		}

		if cr.Msg != "" {
			fmt.Printf("%s\n", cr.Msg)
		}
	},
}

var ZoneCmd = &cobra.Command{
	Use:   "zone",
	Short: "Prefix command, not useable by itself",
}

var zoneListCmd = &cobra.Command{
	Use:   "list",
	Short: "Send an zone list command to tdnsd",
	Run: func(cmd *cobra.Command, args []string) {

		prefixcmd, _ := getCommandContext("zone")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client for %s: %v", prefixcmd, err)
		}

		// fmt.Printf("zoneListCmd: prefix: %q, api: %v\n", prefixcmd, api)

		cr, err := SendZoneCommand(api, tdns.ZonePost{
			Command: "list-zones",
		})
		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			os.Exit(1)
		}
		if cr.Error {
			fmt.Printf("Error from %q: %s\n", cr.AppName, cr.ErrorMsg)
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
	},
}

var zoneSerialBumpCmd = &cobra.Command{
	Use:   "bump",
	Short: "Bump SOA serial and epoch (if any) in tdnsd version of zone",
	Run: func(cmd *cobra.Command, args []string) {
		prefixcmd, _ := getCommandContext("zone")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client for %s: %v", prefixcmd, err)
		}

		PrepArgs("childzone")
		resp, err := SendZoneCommand(api, tdns.ZonePost{
			Command: "bump",
			Zone:    tdns.Globals.Zonename,
		})

		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			os.Exit(1)
		}
		if resp.Error {
			fmt.Printf("Error from tdnsd: %s\n", resp.ErrorMsg)
			os.Exit(1)
		}

		if resp.Msg != "" {
			fmt.Printf("%s\n", resp.Msg)
		}
	},
}

func init() {
	ZoneCmd.AddCommand(zoneListCmd, zoneNsecCmd, zoneSignCmd, zoneReloadCmd, zoneSerialBumpCmd)
	ZoneCmd.AddCommand(zoneWriteCmd, zoneFreezeCmd, zoneThawCmd)

	zoneNsecCmd.AddCommand(zoneNsecGenerateCmd, zoneNsecShowCmd)

	ZoneCmd.PersistentFlags().BoolVarP(&force, "force", "F", false, "force operation")

	zoneListCmd.Flags().BoolVarP(&showfile, "file", "f", false, "Show zone input file")
	zoneListCmd.Flags().BoolVarP(&shownotify, "notify", "N", false, "Show zone downstream notify addresses")
	zoneListCmd.Flags().BoolVarP(&showprimary, "primary", "P", false, "Show zone primary nameserver")
}

func SendZoneCommand(api *tdns.ApiClient, data tdns.ZonePost) (tdns.ZoneResponse, error) {
	var cr tdns.ZoneResponse
	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := api.Post("/zone", bytebuf.Bytes())
	if err != nil {
		log.Println("Error from Api Post:", err)
		return cr, fmt.Errorf("error from api post: %v", err)
	}
	if tdns.Globals.Verbose {
		fmt.Printf("Status: %d\n", status)
	}

	err = json.Unmarshal(buf, &cr)
	if err != nil {
		return cr, fmt.Errorf("error from json.Unmarshal: %v json: %q", err, string(buf))
	}

	if cr.Error {
		return cr, fmt.Errorf("error from %s: %s", cr.AppName, cr.ErrorMsg)
	}

	return cr, nil
}

func ListZones(cr tdns.ZoneResponse) {
	hdr := "Zone|Type|Store|"
	if showprimary {
		hdr += "Primary|"
	}
	if shownotify {
		hdr += "Notify|"
	}
	if showfile {
		hdr += "Zonefile|"
	}
	hdr += "Frozen|Dirty|Options"
	out := []string{}
	if tdns.Globals.ShowHeaders {
		out = append(out, hdr)
	}
	zoneLines := []string{}
	for zname, zconf := range cr.Zones {
		if zconf.Error {
			line := fmt.Sprintf("%s|%s||||Error[%s]: %s", zname, "ERROR", tdns.ErrorTypeToString[zconf.ErrorType], zconf.ErrorMsg)
			zoneLines = append(zoneLines, line)
			continue
		}
		opts := []string{}
		for _, opt := range zconf.Options {
			opts = append(opts, tdns.ZoneOptionToString[opt])
		}
		sort.Strings(opts)
		line := fmt.Sprintf("%s|%s|%s|", zname, zconf.Type, zconf.Store)
		if showprimary {
			line += fmt.Sprintf("%s|", zconf.Primary)
		}
		if shownotify {
			line += fmt.Sprintf("%s|", zconf.Notify)
		}
		if showfile {
			line += fmt.Sprintf("%s|", zconf.Zonefile)
		}
		line += fmt.Sprintf("%t|%t|%v", zconf.Frozen, zconf.Dirty, opts)
		zoneLines = append(zoneLines, line)
	}
	sort.Slice(zoneLines, func(i, j int) bool {
		return zoneLines[i] < zoneLines[j]
	})
	out = append(out, zoneLines...)
	fmt.Printf("%s\n", columnize.SimpleFormat(out))
}

func VerboseListZone(cr tdns.ZoneResponse) {
	hdr := "Zone|Type|Store|"
	if showprimary {
		hdr += "Primary|"
	}
	if shownotify {
		hdr += "Notify|"
	}
	if showfile {
		hdr += "Zonefile|"
	}
	hdr += "Frozen|Dirty|Options"
	out := []string{}
	if tdns.Globals.ShowHeaders {
		out = append(out, hdr)
	}
	zoneLines := []string{}
	for zname, zconf := range cr.Zones {
		line := fmt.Sprintf("zone: %s\n", zname)
		if zconf.Error {
			line += fmt.Sprintf("\tState: ERROR ErrorType: %s ErrorMsg: %s\n", tdns.ErrorTypeToString[zconf.ErrorType], zconf.ErrorMsg)
		}
		opts := []string{}
		for _, opt := range zconf.Options {
			opts = append(opts, tdns.ZoneOptionToString[opt])
		}
		sort.Strings(opts)
		line += fmt.Sprintf("\tType: %s\tStore: %s\tOptions: %v\n", zconf.Type, zconf.Store, opts)

		line += fmt.Sprintf("\tPrimary: %s\tNotify: %s\tFile: %s\n", zconf.Primary, zconf.Notify, zconf.Zonefile)
		line += fmt.Sprintf("\tFrozen: %t\tDirty: %t\n", zconf.Frozen, zconf.Dirty)
		zoneLines = append(zoneLines, line)
	}

	sort.Slice(zoneLines, func(i, j int) bool {
		return zoneLines[i] < zoneLines[j]
	})
	fmt.Printf("%s\n", columnize.SimpleFormat(zoneLines))
}
