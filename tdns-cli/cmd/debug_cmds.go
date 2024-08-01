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
	"time"

	"github.com/johanix/tdns/tdns"
	"github.com/miekg/dns"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
)

var debugQname, debugQtype string

var debugCmd = &cobra.Command{
	Use:   "debug",
	Short: "A brief description of your command",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("debug called")
	},
}

var debugRRsetCmd = &cobra.Command{
	Use: "rrset",

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

		dr := SendDebug(tdns.Globals.Api, tdns.DebugPost{
			Command: "rrset",
			Zone:    dns.Fqdn(tdns.Globals.Zonename),
			Qname:   dns.Fqdn(debugQname),
			Qtype:   qtype,
		})
		fmt.Printf("debug response: %v\n", dr)
	},
}

var debugValidateRRsetCmd = &cobra.Command{
	Use: "validate-rrset",

	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("childzone")
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

		dr := SendDebug(tdns.Globals.Api, tdns.DebugPost{
			Command: "validate-rrset",
			Zone:    dns.Fqdn(tdns.Globals.Zonename),
			Qname:   dns.Fqdn(debugQname),
			Qtype:   qtype,
		})

		if dr.Msg != "" {
			fmt.Printf("%s\n", dr.Msg)
		}

		if tdns.Globals.Debug {
			fmt.Printf("debug response: %v\n", dr)
		}
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

		dr := SendDebug(tdns.Globals.Api, tdns.DebugPost{
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

		dr := SendDebug(tdns.Globals.Api, tdns.DebugPost{
			Command: "show-ta",
			Verbose: true,
		})

		var out = []string{"Type|Signer|KeyID|Validated|Trusted|Record"}

		if len(dr.TrustedDnskeys) > 0 {
			fmt.Printf("Known DNSKEYs:\n")
			for _, ta := range dr.TrustedDnskeys {
				out = append(out, fmt.Sprintf("DNSKEY|%s|%d|%v|%v|%.70s...",
					ta.Name, ta.Keyid, ta.Validated, ta.Trusted, ta.Dnskey.String()))
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

var debugShowRRsetCacheCmd = &cobra.Command{
	Use:   "show-rrsetcache",
	Short: "Request tdnsd to return cached RRsets",
	Run: func(cmd *cobra.Command, args []string) {

		dr := SendDebug(tdns.Globals.Api, tdns.DebugPost{
			Command: "show-rrsetcache",
			Verbose: true,
		})

		var out = []string{"Name|RRtype|Expire|Record"}

		if len(dr.TrustedDnskeys) > 0 {
			fmt.Printf("Cached RRsets:\n")
			for _, crrset := range dr.CachedRRsets {
				for _, rr := range crrset.RRset.RRs {
					out = append(out, fmt.Sprintf("%s|%s|%v|%v",
						crrset.Name, crrset.RRtype, time.Until(crrset.Expiration).Seconds(), rr.String()))
				}
			}
		}
		fmt.Printf("%s\n", columnize.SimpleFormat(out))
	},
}

func init() {
	rootCmd.AddCommand(stopCmd, debugCmd)

	debugCmd.AddCommand(debugRRsetCmd, debugValidateRRsetCmd, debugLAVCmd, debugShowTACmd, debugShowRRsetCacheCmd)

	debugCmd.PersistentFlags().StringVarP(&debugQname, "qname", "", "", "qname of rrset to examine")
	debugCmd.PersistentFlags().StringVarP(&debugQtype, "qtype", "", "", "qtype of rrset to examine")

	// ddnsCmd.PersistentFlags().StringVarP(&Globals.Sig0Keyfile, "keyfile", "k", "", "name of file with private SIG(0) key")
	// ddnsCmd.PersistentFlags().StringVarP(&childpri, "primary", "p", "", "Address:port of child primary namserver")
	// ddnsCmd.PersistentFlags().StringVarP(&parpri, "pprimary", "P", "", "Address:port of parent primary nameserver")
}

func SendDebug(api *tdns.ApiClient, data tdns.DebugPost) tdns.DebugResponse {

	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := api.Post("/debug", bytebuf.Bytes())
	if err != nil {
		log.Fatalf("error from api post: %v", err)

	}
	if verbose {
		fmt.Printf("Status: %d\n", status)
	}

	var dr tdns.DebugResponse

	err = json.Unmarshal(buf, &dr)
	if err != nil {
		log.Fatalf("error from unmarshal: %v", err)
	}

	if dr.Error {
		fmt.Printf("error: %s", dr.ErrorMsg)
	}

	fmt.Printf("Message: %s\n", dr.Msg)
	return dr
}
