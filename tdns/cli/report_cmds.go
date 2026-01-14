/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package cli

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	tdns "github.com/johanix/tdns/tdns"
	core "github.com/johanix/tdns/tdns/core"
	edns0 "github.com/johanix/tdns/tdns/edns0"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

var reportSender, reportDetails string
var reportTsig bool
var dsyncPort int
var dsyncTarget string
var edeCode int
var targetIP string
var port string

var ReportCmd = &cobra.Command{
	Use:   "report <qname>",
	Short: "Send a report and (optionally) discover DSYNC via the internal resolver (imr)",
	Run: func(cmd *cobra.Command, args []string) {
		// qname := dns.Fqdn(args[0])
		PrepArgs("zonename")
		dsyncLookup := true
		if dsyncTarget != "" && dsyncPort != 0 {
			dsyncLookup = false
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		tdns.Globals.App.Type = tdns.AppTypeCli
		if tdns.Globals.Debug {
			fmt.Printf("ReportCmd: Calling Conf.MainInit(%q)\n", tdns.DefaultCliCfgFile)
		}
		if err := Conf.MainInit(ctx, tdns.DefaultCliCfgFile); err != nil {
			tdns.Shutdowner(&Conf, fmt.Sprintf("Error initializing tdns-cli: %v", err))
		}

		if reportSender == "" {
			fmt.Printf("Error: sender not specified\n")
			return
		}

		// TSIG requirements are only enforced when TSIG signing is requested

		if dsyncLookup {

			// Initialize internal IMR
			_, cancel, imr, err := StartImrForCli("") // "" means use the default root hints
			if err != nil {
				log.Fatalf("Error initializing IMR: %v", err)
			}
			defer cancel()

			// Discover DSYNC via IMR for the zone that contains qname
			log.Printf("ReportCmd: Discovering DSYNC via IMR for %s", tdns.Globals.Zonename)

			// New approach: use imr.DsyncDiscovery() directly
			dsyncRes, derr := imr.DsyncDiscovery(ctx, tdns.Globals.Zonename, tdns.Globals.Verbose)
			if derr != nil {
				log.Printf("ReportCmd: DSYNC discovery error: %v", derr)
				return
			}

			// Find DSYNC record with REPORT scheme
			var reportDSYNC *core.DSYNC
			for _, ds := range dsyncRes.Rdata {
				if ds.Scheme == core.SchemeReport {
					reportDSYNC = ds
					break
				}
			}

			if reportDSYNC == nil {
				log.Printf("ReportCmd: no DSYNC REPORT found for %s, aborting report", tdns.Globals.Zonename)
				return
			}

			targetIP = reportDSYNC.Target
			port = strconv.Itoa(int(reportDSYNC.Port))
		} else {
			targetIP = dsyncTarget
			port = strconv.Itoa(dsyncPort)
		}

		if edeCode == 0 {
			edeCode = int(edns0.EDEMPZoneXfrFailure)
		}
		// Prepare DNS message
		m := new(dns.Msg)
		m.SetNotify(tdns.Globals.Zonename)
		err := edns0.AddReportOptionToMessage(m, &edns0.ReportOption{
			ZoneName: tdns.Globals.Zonename,
			EDECode:  uint16(edeCode),
			Severity: 17,
			Sender:   reportSender,
			Details:  reportDetails,
		})
		if err != nil {
			log.Printf("ReportCmd: failed to build report EDNS0 option: %v", err)
			return
		}

		log.Printf("ReportCmd: sending report to %s:%s (from DSYNC REPORT)", targetIP, port)

		// Send the report
		c := core.NewDNSClient(core.TransportDo53, port, nil)

		if reportTsig {
			// Lookup TSIG key only when signing is requested
			// At the moment we require the name of the key to be {sender}.key.
			tsig := tdns.Globals.TsigKeys[reportSender+".key."]
			if tsig == nil {
				fmt.Printf("Error: tsig key not found for sender: %s\n", reportSender)
				return
			}

			// There is no built-in map or function in miekg/dns for this, so we use a switch.
			var alg string
			switch strings.ToLower(tsig.Algorithm) {
			case "hmac-sha1":
				alg = dns.HmacSHA1
			case "hmac-sha256":
				alg = dns.HmacSHA256
			case "hmac-sha384":
				alg = dns.HmacSHA384
			case "hmac-sha512":
				alg = dns.HmacSHA512
			default:
				alg = tsig.Algorithm // fallback to whatever is provided
			}
			if tdns.Globals.Debug {
				fmt.Printf("TSIG signing the report with %s\n", tsig.Name)
			}

			tsigMap := map[string]string{tsig.Name: tsig.Secret}
			if c.DNSClientUDP != nil {
				c.DNSClientUDP.TsigSecret = tsigMap
			}
			if c.DNSClientTCP != nil {
				c.DNSClientTCP.TsigSecret = tsigMap
			}
			if c.DNSClientTLS != nil {
				c.DNSClientTLS.TsigSecret = tsigMap
			}
			m.SetTsig(tsig.Name, alg, 300, time.Now().Unix())
		}

		if tdns.Globals.Debug {
			fmt.Printf("%s\n", m.String())
		}

		resp, _, err := c.Exchange(m, targetIP, false)
		if err != nil {
			fmt.Printf("ReportCmd: error sending report: %v\n", err)
			os.Exit(1)
		}
		rcode := resp.Rcode
		if rcode == dns.RcodeSuccess {
			fmt.Printf("Report accepted (rcode: %s)\n", dns.RcodeToString[rcode])
		} else {
			hasede, edecode, edemsg := edns0.ExtractEDEFromMsg(resp)
			if hasede {
				fmt.Printf("Error: rcode: %s, EDE Message: %s (EDE code: %d)\n", dns.RcodeToString[rcode], edemsg, edecode)
			} else {
				fmt.Printf("Error: rcode: %s\n", dns.RcodeToString[rcode])
				fmt.Printf("Response msg:\n%s\n", resp.String())
			}
			os.Exit(1)
		}
	},
}

func init() {
	ReportCmd.Flags().StringVarP(&reportSender, "sender", "S", "", "Report sender")
	ReportCmd.Flags().StringVarP(&reportDetails, "details", "D", "", "Report details")
	ReportCmd.Flags().BoolVarP(&reportTsig, "tsig", "T", true, "TSIG sign the report")
	ReportCmd.Flags().IntVarP(&edeCode, "ede", "", 0, "Manual override of EDE code (513-523 locally defined)")
	ReportCmd.Flags().IntVarP(&dsyncPort, "port", "", 0, "Manual override of DSYNC port")
	ReportCmd.Flags().StringVarP(&dsyncTarget, "target", "", "", "Manual override of DSYNC target")
}
