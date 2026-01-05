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
	"strings"
	"time"

	"github.com/johanix/tdns/v1.0/tdns"
	cache "github.com/johanix/tdns/v1.0/tdns/cache"
	"github.com/miekg/dns"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var debugQname, debugQtype string

var DebugCmd = &cobra.Command{
	Use:   "debug",
	Short: "A brief description of your command",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("debug called")
	},
}

var debugSig0Cmd = &cobra.Command{
	Use:   "sig0",
	Short: "A brief description of your command",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("debug sig0 called")
	},
}

var debugSig0GenerateCmd = &cobra.Command{
	Use: "generate",

	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")
		PrepArgs("algorithm")
		PrepArgs("rrtype")

		kdb, err := tdns.NewKeyDB(viper.GetString("db.file"), false, nil)
		if err != nil {
			fmt.Printf("Error from NewKeyDB(): %v\n", err)
			os.Exit(1)
		}

		rrtype := dns.StringToType[strings.ToUpper(tdns.Globals.Rrtype)]
		algorithm := dns.StringToAlgorithm[strings.ToUpper(tdns.Globals.Algorithm)]

		fmt.Printf("Calling generate sig0 with zone: %s algorithm: %s rrtype: %s\n",
			tdns.Globals.Zonename, tdns.Globals.Algorithm, tdns.Globals.Rrtype)

		pkc, msg, err := kdb.GenerateKeypair(tdns.Globals.Zonename, "tdns-cli", "active", rrtype, algorithm, "", nil) // nil = no tx
		if err != nil {
			fmt.Printf("Error: %s\n", err)
			os.Exit(1)
		}
		fmt.Printf("Generated keypair:\n* Private key: %s\n* Public key: %s\n* KeyID: %d\n", pkc.PrivateKey, pkc.KeyRR.String(), pkc.KeyId)
		fmt.Printf("Message: %s\n", msg)

		var rr dns.RR
		rr = &pkc.KeyRR
		if rrtype == dns.TypeDNSKEY {
			rr = &pkc.DnskeyRR
		}
		fmt.Printf("Generated keypair:\n* Private key: %s\n* Public key: %s\n* KeyID: %d\n", pkc.PrivateKey, rr.String(), pkc.KeyId)
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
	Short: "Lookup and validate a child RRset",
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
	Short: "List known DNSSEC trust anchors",
	Run: func(cmd *cobra.Command, args []string) {

		dr := SendDebug(tdns.Globals.Api, tdns.DebugPost{
			Command: "show-ta",
			Verbose: true,
		})

		var out = []string{"Type|Signer|KeyID|State|Record"}

		if len(dr.TrustedDnskeys) > 0 {
			fmt.Printf("Known DNSKEYs:\n")
			for _, dk := range dr.TrustedDnskeys {
				out = append(out, fmt.Sprintf("DNSKEY|%s|%d|%s|%.70s...",
					dk.Name, dk.Keyid, cache.ValidationStateToString[dk.State], dk.Dnskey.String()))
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
	Short: "List cached RRsets",
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
						crrset.Name, dns.TypeToString[crrset.RRtype], time.Until(crrset.Expiration).Seconds(), rr.String()))
				}
			}
		}
		fmt.Printf("%s\n", columnize.SimpleFormat(out))
	},
}

func init() {
	DebugCmd.AddCommand(debugRRsetCmd, debugValidateRRsetCmd, debugLAVCmd, debugShowTACmd, debugShowRRsetCacheCmd)

	DebugCmd.AddCommand(debugSig0Cmd)
	debugSig0Cmd.AddCommand(debugSig0GenerateCmd)

	DebugCmd.PersistentFlags().StringVarP(&debugQname, "qname", "", "", "qname of rrset to examine")
	DebugCmd.PersistentFlags().StringVarP(&debugQtype, "qtype", "", "", "qtype of rrset to examine")

	defalg := viper.GetString("delegationsync.child.update.keygen.algorithm")
	debugSig0Cmd.PersistentFlags().StringVarP(&tdns.Globals.Algorithm, "algorithm", "a", defalg, "algorithm to use for SIG(0)")
	debugSig0Cmd.PersistentFlags().StringVarP(&tdns.Globals.Rrtype, "rrtype", "r", "", "rrtype to use for SIG(0)")
}

func SendDebug(api *tdns.ApiClient, data tdns.DebugPost) tdns.DebugResponse {

	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := api.Post("/debug", bytebuf.Bytes())
	if err != nil {
		log.Fatalf("error from api post: %v", err)

	}
	if tdns.Globals.Verbose {
		fmt.Printf("Status: %d\n", status)
	}

	var dr tdns.DebugResponse

	err = json.Unmarshal(buf, &dr)
	if err != nil {
		log.Fatalf("error from unmarshal: %v", err)
	}

	if dr.Error {
		fmt.Printf("Error from %s: %s\n", dr.AppName, dr.ErrorMsg)
	}

	fmt.Printf("Message: %s\n", dr.Msg)
	return dr
}
