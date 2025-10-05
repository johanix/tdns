/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package cli

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	tdns "github.com/johanix/tdns/tdns"
	edns0 "github.com/johanix/tdns/tdns/edns0"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

var reportSender, reportDetails string

var ReportCmd = &cobra.Command{
	Use:   "report",
	Short: "Send a report",
	Run: func(cmd *cobra.Command, args []string) {
        fmt.Printf("%v\n", args)

        tdns.Globals.App.Type = tdns.AppTypeCli

        if tdns.Globals.Debug {
            fmt.Printf("initImr: Calling conf.MainInit(%q)\n", tdns.DefaultImrCfgFile)
        }

        err := Conf.MainInit(tdns.DefaultCliCfgFile)
        if err != nil {
            tdns.Shutdowner(&Conf, fmt.Sprintf("Error initializing tdns-cli: %v", err))
        }

        // Starting Imr
        log.Printf("Starting RecursorEngine")
        Conf.Internal.RecursorCh = make(chan tdns.ImrRequest, 10)
        stopCh := make(chan struct{}, 10)
        go Conf.RecursorEngine(stopCh)

        qname := dns.Fqdn(args[0])
        qtype := dns.StringToType[strings.ToUpper(args[1])]
        ede := args[2]

        resp := make(chan tdns.ImrResponse, 1)
        Conf.Internal.RecursorCh <- tdns.ImrRequest{
            Qname:      qname,
            Qclass:     dns.ClassINET,
            Qtype:      qtype,
            ResponseCh: resp,
        }

        select {
        case r := <-resp:
            if r.RRset != nil {
                // fmt.Printf("%v\n", r.RRset)
                for _, rr := range r.RRset.RRs {
                    switch rr.Header().Rrtype {
                    case qtype, dns.TypeCNAME:
                        fmt.Printf("%s\n", rr.String())
                    default:
                        fmt.Printf("Not printing: %q\n", rr.String())
                    }
                }
                for _, rr := range r.RRset.RRSIGs {
                    fmt.Printf("%s\n", rr.String())
                }
            } else if r.Error {
                fmt.Printf("Error: %s\n", r.ErrorMsg)
            } else {
                fmt.Printf("No records found: %s\n", r.Msg)
            }
        case <-time.After(3 * time.Second):
            fmt.Println("Timeout waiting for response")
            return
        }

        fmt.Printf("Sending %s report...\n", ede)
	},
}


var RawReportCmd = &cobra.Command{
	Use:   "rawreport",
	Short: "Send a rawreport",
	Run: func(cmd *cobra.Command, args []string) {
        PrepArgs("zonename")

        if reportSender == "" {
            fmt.Printf("Error: sender not specified\n")
            return
        }

        tsig := tdns.Globals.TsigKeys[reportSender + ".key."]
        if tsig == nil {
            fmt.Printf("Error: tsig key not found for sender: %s\n", reportSender)
            return
        }

        m := new(dns.Msg)
        m.SetNotify(tdns.Globals.Zonename)

        err := edns0.AddReporterOptionToMessage(m, &edns0.ReporterOption{
            ZoneName: tdns.Globals.Zonename,
            EDECode: edns0.EDEMPZoneXfrFailure,
            Severity: 17,
            Sender: reportSender,
            Details: reportDetails,
        })
        if err != nil {
            log.Fatal(err)
        }

        // fmt.Printf("%s\n", m.String())
        c := tdns.NewDNSClient(tdns.TransportDo53, "9998", nil)
        c.DNSClient.TsigSecret = map[string]string{tsig.Name: tsig.Secret}

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
        m.SetTsig(tsig.Name, alg, 300, time.Now().Unix())

        // fmt.Printf("Sending report...\n")
        // fmt.Printf("%s\n", m.String())

        resp, _, err := c.Exchange(m, "127.0.0.1")
        if err != nil {
            log.Fatal(err)
        }
        rcode := resp.Rcode
        if rcode == dns.RcodeSuccess {
            fmt.Printf("Report accepted (rcode: %s)\n", dns.RcodeToString[rcode])
        } else {
            fmt.Printf("Error: Rcode: %s\n", dns.RcodeToString[rcode])
            fmt.Printf("Response msg:\n%s\n", resp.String())
            os.Exit(1)
        }
	},
}

func init() {
	RawReportCmd.Flags().StringVarP(&reportSender, "sender", "S", "", "Report sender")
	RawReportCmd.Flags().StringVarP(&reportDetails, "details", "D", "", "Report details")
}

