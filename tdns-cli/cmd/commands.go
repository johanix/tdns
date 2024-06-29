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
	"strings"

	"github.com/johanix/tdns/tdns"
	"github.com/miekg/dns"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
)

var debugQname, debugQtype string
var force bool

var debugCmd = &cobra.Command{
	Use:   "debug",
	Short: "A brief description of your command",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("debug called")
	},
}

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Send stop command to tdnsd",
	Run: func(cmd *cobra.Command, args []string) {
		SendCommand("stop", ".")
	},
}

var zoneReloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Send reload zone command to tdnsd",
	Run: func(cmd *cobra.Command, args []string) {
		if tdns.Globals.Zonename == "" {
			fmt.Printf("Error: zone name not specified. Terminating.\n")
			os.Exit(1)
		}

		resp, err := SendCommandNG(api, tdns.CommandPost{
			Command:    "zone",
			SubCommand: "reload",
			Zone:       dns.Fqdn(tdns.Globals.Zonename),
			Force:      force,
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
	Short: "Send an zone sign command to tdnsd",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("childzone")

		cr, err := SendCommandNG(api, tdns.CommandPost{
			Command:    "zone",
			SubCommand: "sign-zone",
			Zone:       tdns.Globals.Zonename,
			Force:      force,
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

		cr, err := SendCommandNG(api, tdns.CommandPost{
			Command:    "zone",
			SubCommand: "generate-nsec",
			Zone:       tdns.Globals.Zonename,
			Force:      force,
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

		cr, err := SendCommandNG(api, tdns.CommandPost{
			Command:    "zone",
			SubCommand: "show-nsec-chain",
			Zone:       tdns.Globals.Zonename,
			Force:      force,
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

		cr, err := SendCommandNG(api, tdns.CommandPost{
			Command:    "zone",
			SubCommand: "freeze",
			Zone:       tdns.Globals.Zonename,
			Force:      force,
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

		cr, err := SendCommandNG(api, tdns.CommandPost{
			Command:    "zone",
			SubCommand: "thaw",
			Zone:       tdns.Globals.Zonename,
			Force:      force,
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

var showhdr, showfile, shownotify, showprimary bool

var zoneListCmd = &cobra.Command{
	Use:   "list",
	Short: "Send an zone list command to tdnsd",
	Run: func(cmd *cobra.Command, args []string) {

		cr, err := SendCommandNG(api, tdns.CommandPost{
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
		hdr += "DelegationSync|OnlineSigning|AllowUpdates|Frozen|Dirty"
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
			line += fmt.Sprintf("%t|%t|%t|%t|%t", zconf.DelegationSync, zconf.OnlineSigning, zconf.AllowUpdates, zconf.Frozen, zconf.Dirty)
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
		//		if tdns.Globals.Zonename == "" {
		//			fmt.Printf("Error: zone name not specified. Terminating.\n")
		//			os.Exit(1)
		//		}

		msg, err := SendCommand("bump", dns.Fqdn(tdns.Globals.Zonename))
		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
		}
		if msg != "" {
			fmt.Printf("%s\n", msg)
		}
	},
}

var zoneSerialBbumpNGCmd = &cobra.Command{
	Use:   "bumpng",
	Short: "Bump SOA serial and epoch (if any) in tdnsd version of zone",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("childzone")

		resp, err := SendCommandNG(api, tdns.CommandPost{
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

var debugRRsetCmd = &cobra.Command{
	Use:   "rrset",
	Short: "Request the contents of a particular RRset from tdnsd",
	Run: func(cmd *cobra.Command, args []string) {
		if tdns.Globals.Zonename == "" {
			fmt.Printf("Error: zone name not specified. Terminating.\n")
			os.Exit(1)
		}
		if debugQname == "" {
			fmt.Printf("Error: qname name not specified. Terminating.\n")
			os.Exit(1)
		}
		if debugQtype == "" {
			fmt.Printf("Error: qtype name not specified. Terminating.\n")
			os.Exit(1)
		}
		qtype := dns.StringToType[strings.ToUpper(debugQtype)]
		if qtype == 0 {
			fmt.Printf("Error: unknown qtype: '%s'. Terminating.\n", debugQtype)
			os.Exit(1)
		}

		dr := SendDebug(api, tdns.DebugPost{
			Command: "rrset",
			Zone:    dns.Fqdn(tdns.Globals.Zonename),
			Qname:   dns.Fqdn(debugQname),
			Qtype:   qtype,
		})
		fmt.Printf("debug response: %v\n", dr)
	},
}

var debugLAVCmd = &cobra.Command{
	Use:   "lav",
	Short: "Request tdnsd to lookup and validate a child RRset",
	Run: func(cmd *cobra.Command, args []string) {
		if debugQname == "" {
			fmt.Printf("Error: qname name not specified. Terminating.\n")
			os.Exit(1)
		}
		if debugQtype == "" {
			fmt.Printf("Error: qtype name not specified. Terminating.\n")
			os.Exit(1)
		}
		qtype := dns.StringToType[strings.ToUpper(debugQtype)]
		if qtype == 0 {
			fmt.Printf("Error: unknown qtype: '%s'. Terminating.\n", debugQtype)
			os.Exit(1)
		}

		dr := SendDebug(api, tdns.DebugPost{
			Command: "lav",
			Qname:   dns.Fqdn(debugQname),
			Qtype:   qtype,
			Verbose: true,
		})
		fmt.Printf("debug response: %v\n", dr)

	},
}
var debugShowTACmd = &cobra.Command{
	Use:   "show-ta",
	Short: "Request tdnsd to return known trust anchors",
	Run: func(cmd *cobra.Command, args []string) {

		dr := SendDebug(api, tdns.DebugPost{
			Command: "show-ta",
			Verbose: true,
		})

		var out = []string{"Type|Signer|KeyID|Trusted|Record"}

		if len(dr.TrustedDnskeys) > 0 {
			fmt.Printf("Known DNSKEYs:\n")
			for k, v := range dr.TrustedDnskeys {
				tmp := strings.Split(k, "::")
				out = append(out, fmt.Sprintf("DNSKEY|%s|%s|%v|%.70s...",
					tmp[0], tmp[1], v.Validated, v.Dnskey.String()))
			}
		}
		fmt.Printf("%s\n", columnize.SimpleFormat(out))

		out = []string{"Type|Signer|KeyID|Trusted|Record"}
		if len(dr.TrustedSig0keys) > 0 {
			fmt.Printf("Known SIG(0) keys:\n")
			for k, v := range dr.TrustedSig0keys {
				tmp := strings.Split(k, "::")
				out = append(out, fmt.Sprintf("KEY|%s|%s|%v|%.70s...\n",
					tmp[0], tmp[1], v.Validated, v.Key.String()))
			}
		}
		fmt.Printf("%s\n", columnize.SimpleFormat(out))
	},
}

func init() {
	rootCmd.AddCommand(stopCmd, debugCmd, zoneCmd)

	zoneCmd.AddCommand(zoneListCmd, zoneNsecCmd, zoneSignCmd, zoneReloadCmd, zoneSerialBumpCmd, zoneSerialBbumpNGCmd)
	zoneCmd.AddCommand(zoneFreezeCmd, zoneThawCmd)

	debugCmd.AddCommand(debugRRsetCmd, debugLAVCmd, debugShowTACmd)
	zoneNsecCmd.AddCommand(zoneNsecGenerateCmd, zoneNsecShowCmd)

	debugCmd.PersistentFlags().StringVarP(&debugQname, "qname", "", "", "qname of rrset to examine")
	debugCmd.PersistentFlags().StringVarP(&debugQtype, "qtype", "", "", "qtype of rrset to examine")
	zoneReloadCmd.Flags().BoolVarP(&force, "force", "F", false, "force reloading, ignoring SOA serial")

	zoneListCmd.Flags().BoolVarP(&showhdr, "headers", "H", false, "Show column headers")
	zoneListCmd.Flags().BoolVarP(&showfile, "file", "F", false, "Show zone input file")
	zoneListCmd.Flags().BoolVarP(&shownotify, "notify", "N", false, "Show zone downstream notify addresses")
	zoneListCmd.Flags().BoolVarP(&showprimary, "primary", "P", false, "Show zone primary nameserver")
	// ddnsCmd.PersistentFlags().StringVarP(&Globals.Sig0Keyfile, "keyfile", "k", "", "name of file with private SIG(0) key")
	// ddnsCmd.PersistentFlags().StringVarP(&childpri, "primary", "p", "", "Address:port of child primary namserver")
	// ddnsCmd.PersistentFlags().StringVarP(&parpri, "pprimary", "P", "", "Address:port of parent primary nameserver")
}

func SendCommand(cmd, zone string) (string, error) {

	data := tdns.CommandPost{
		Command: cmd,
		Zone:    zone,
	}

	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := api.Post("/command", bytebuf.Bytes())
	if err != nil {

		return "", fmt.Errorf("Error from Api Post: %v", err)
	}
	if verbose {
		fmt.Printf("Status: %d\n", status)
	}

	var cr tdns.CommandResponse

	err = json.Unmarshal(buf, &cr)
	if err != nil {
		return "", fmt.Errorf("Error from unmarshal: %v\n", err)
	}

	if cr.Error {
		return "", fmt.Errorf("Error from tdnsd: %s\n", cr.ErrorMsg)
	}

	return cr.Msg, nil
}

func SendCommandNG(api *tdns.Api, data tdns.CommandPost) (tdns.CommandResponse, error) {
	var cr tdns.CommandResponse
	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := api.Post("/command", bytebuf.Bytes())
	if err != nil {
		log.Println("Error from Api Post:", err)
		return cr, fmt.Errorf("Error from api post: %v", err)
	}
	if verbose {
		fmt.Printf("Status: %d\n", status)
	}

	err = json.Unmarshal(buf, &cr)
	if err != nil {
		return cr, fmt.Errorf("Error from unmarshal: %v\n", err)
	}

	if cr.Error {
		return cr, fmt.Errorf("Error from tdnsd: %s\n", cr.ErrorMsg)
	}

	return cr, nil
}

func SendDebug(api *tdns.Api, data tdns.DebugPost) tdns.DebugResponse {

	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := api.Post("/debug", bytebuf.Bytes())
	if err != nil {
		log.Fatalf("Error from Api Post:", err)

	}
	if verbose {
		fmt.Printf("Status: %d\n", status)
	}

	var dr tdns.DebugResponse

	err = json.Unmarshal(buf, &dr)
	if err != nil {
		log.Fatalf("Error from unmarshal: %v\n", err)
	}

	if dr.Error {
		fmt.Printf("Error: %s\n", dr.ErrorMsg)
	}

	fmt.Printf("Message: %s\n", dr.Msg)
	return dr
}
