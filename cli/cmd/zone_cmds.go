/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/johanix/tdns/tdns"
	"github.com/miekg/dns"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
)

var zoneReloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Send reload zone command to tdnsd",
	Run: func(cmd *cobra.Command, args []string) {
		if tdns.Globals.Zonename == "" {
			fmt.Printf("Error: zone name not specified. Terminating.\n")
			os.Exit(1)
		}

		resp, err := SendZoneCommand(tdns.Globals.Api, tdns.ZonePost{
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

		cr, err := SendZoneCommand(tdns.Globals.Api, tdns.ZonePost{
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

		cr, err := SendZoneCommand(tdns.Globals.Api, tdns.ZonePost{
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

		cr, err := SendZoneCommand(tdns.Globals.Api, tdns.ZonePost{
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

		cr, err := SendZoneCommand(tdns.Globals.Api, tdns.ZonePost{
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

		cr, err := SendZoneCommand(tdns.Globals.Api, tdns.ZonePost{
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

		cr, err := SendZoneCommand(tdns.Globals.Api, tdns.ZonePost{
			Command: "thaw",
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

var zoneCmd = &cobra.Command{
	Use:   "zone",
	Short: "Prefix command, not useable by itself",
}

var zoneListCmd = &cobra.Command{
	Use:   "list",
	Short: "Send an zone list command to tdnsd",
	Run: func(cmd *cobra.Command, args []string) {

		cr, err := SendZoneCommand(tdns.Globals.Api, tdns.ZonePost{
			Command: "list-zones",
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
		// hdr += "DelegationSync|OnlineSigning|AllowUpdates|Frozen|Dirty"
		hdr += "Frozen|Dirty|Options"
		out := []string{}
		if showhdr {
			out = append(out, hdr)
		}
		for zname, zconf := range cr.Zones {
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
			line += fmt.Sprintf("%t|%t|%v", zconf.Frozen, zconf.Dirty, zconf.Options)
			out = append(out, line)
		}
		fmt.Printf("%s\n", columnize.SimpleFormat(out))
	},
}

var zoneSerialBumpCmd = &cobra.Command{
	Use:   "bump",
	Short: "Bump SOA serial and epoch (if any) in tdnsd version of zone",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("childzone")

		resp, err := SendZoneCommand(tdns.Globals.Api, tdns.ZonePost{
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
	rootCmd.AddCommand(zoneCmd)

	zoneCmd.AddCommand(zoneListCmd, zoneNsecCmd, zoneSignCmd, zoneReloadCmd, zoneSerialBumpCmd)
	zoneCmd.AddCommand(zoneWriteCmd, zoneFreezeCmd, zoneThawCmd)

	zoneNsecCmd.AddCommand(zoneNsecGenerateCmd, zoneNsecShowCmd)

	zoneCmd.PersistentFlags().BoolVarP(&force, "force", "F", false, "force operation")

	zoneListCmd.Flags().BoolVarP(&showhdr, "headers", "H", false, "Show column headers")
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
	if verbose {
		fmt.Printf("Status: %d\n", status)
	}

	err = json.Unmarshal(buf, &cr)
	if err != nil {
		return cr, fmt.Errorf("error from unmarshal: %v", err)
	}

	if cr.Error {
		return cr, fmt.Errorf("error from tdnsd: %s", cr.ErrorMsg)
	}

	return cr, nil
}