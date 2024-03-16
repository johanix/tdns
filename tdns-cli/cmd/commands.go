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

var reloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Send reload zone command to tdnsd",
	Run: func(cmd *cobra.Command, args []string) {
		if tdns.Globals.Zonename == "" {
			fmt.Printf("Error: zone name not specified. Terminating.\n")
			os.Exit(1)
		}

		msg, err := SendCommandNG(api, tdns.CommandPost{
			Command: "reload",
			Zone:    dns.Fqdn(tdns.Globals.Zonename),
			Force:   force,
		})
		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
		}
		if msg != "" {
			fmt.Printf("%s\n", msg)
		}
	},
}

var bumpCmd = &cobra.Command{
	Use:   "bump",
	Short: "Bump SOA serial and epoch (if any) in tdnsd version of zone",
	Run: func(cmd *cobra.Command, args []string) {
		if tdns.Globals.Zonename == "" {
			fmt.Printf("Error: zone name not specified. Terminating.\n")
			os.Exit(1)
		}

		msg, err := SendCommand("bump", dns.Fqdn(tdns.Globals.Zonename))
		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
		}
		if msg != "" {
			fmt.Printf("%s\n", msg)
		}
	},
}

var bumpNGCmd = &cobra.Command{
	Use:   "bumpng",
	Short: "Bump SOA serial and epoch (if any) in tdnsd version of zone",
	Run: func(cmd *cobra.Command, args []string) {
		if tdns.Globals.Zonename == "" {
			fmt.Printf("Error: zone name not specified. Terminating.\n")
			os.Exit(1)
		}

		msg, err := SendCommandNG(api, tdns.CommandPost{
			Command: "bump",
			Zone:    dns.Fqdn(tdns.Globals.Zonename),
		})
		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
		}
		if msg != "" {
			fmt.Printf("%s\n", msg)
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

		var out = []string{"Type|Signer|KeyID|Record"}

		if len(dr.TrustedDnskeys) > 0 {
			fmt.Printf("Trusted DNSKEYs:\n")
			for k, v := range dr.TrustedDnskeys {
				tmp := strings.Split(k, "::")
				out = append(out, fmt.Sprintf("DNSKEY|%s|%s|%.70s...",
					tmp[0], tmp[1], v.String()))
			}
		}
		fmt.Printf("%s\n", columnize.SimpleFormat(out))

		out = []string{"Type|Signer|KeyID|Record"}
		if len(dr.TrustedSig0keys) > 0 {
			fmt.Printf("Trusted SIG(0) keys:\n")
			for k, v := range dr.TrustedSig0keys {
				tmp := strings.Split(k, "::")
				out = append(out, fmt.Sprintf("KEY|%s|%s|%.70s...\n",
					tmp[0], tmp[1], v.String()))
			}
		}
		fmt.Printf("%s\n", columnize.SimpleFormat(out))
	},
}

func init() {
	rootCmd.AddCommand(bumpCmd, stopCmd, reloadCmd, debugCmd)
	debugCmd.AddCommand(debugRRsetCmd, debugLAVCmd, debugShowTACmd)

	debugCmd.PersistentFlags().StringVarP(&debugQname, "qname", "", "", "qname of rrset to examine")
	debugCmd.PersistentFlags().StringVarP(&debugQtype, "qtype", "", "", "qtype of rrset to examine")
	reloadCmd.Flags().BoolVarP(&force, "force", "F", false, "force reloading, ignoring SOA serial")
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

func SendCommandNG(api *tdns.Api, data tdns.CommandPost) (string, error) {

	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := api.Post("/command", bytebuf.Bytes())
	if err != nil {
		log.Println("Error from Api Post:", err)
		return "", fmt.Errorf("Error from api post: %v", err)
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
