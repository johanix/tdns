/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package cli

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	tdns "github.com/johanix/tdns/tdns"
	edns0 "github.com/johanix/tdns/tdns/edns0"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var reportSender, reportDetails string
var reportTsig bool
var dsyncPort int
var dsyncTarget string
var edeCode int
var targetIP string
var port string

func imrQuery(qname string, qtype uint16, timeout time.Duration) (tdns.ImrResponse, error) {
	var empty tdns.ImrResponse

	if !strings.HasSuffix(qname, ".") {
		qname = dns.Fqdn(qname)
	}
	respCh := make(chan tdns.ImrResponse, 1)

	// send request to RecursorEngine
	Conf.Internal.RecursorCh <- tdns.ImrRequest{
		Qname:      qname,
		Qclass:     dns.ClassINET,
		Qtype:      qtype,
		ResponseCh: respCh,
	}

	select {
	case r := <-respCh:
		return r, nil
	case <-time.After(timeout):
		return empty, fmt.Errorf("timeout waiting for imr response for %s", qname)
	}
}

// parseDSYNCFromImrResponse inspects an ImrResponse and returns any DSYNC RRs found
// in the Answer section (same expectation as DsyncQuery).
// It also returns the parent inferred from an SOA in the authority section if present.
func parseDSYNCFromImrResponse(r tdns.ImrResponse) (dsyncrrs []*tdns.DSYNC, parent string) {
	dsyncrrs = []*tdns.DSYNC{}

	if r.RRset != nil {
		for _, rr := range r.RRset.RRs {
			if prr, ok := rr.(*dns.PrivateRR); ok {
				if dsync, ok := prr.Data.(*tdns.DSYNC); ok {
					dsyncrrs = append(dsyncrrs, dsync)
				} else if tdns.Globals.Debug {
					log.Printf("parseDSYNCFromImrResponse: PrivateRR but not DSYNC: %s", rr.String())
				}
			} else if _, ok := rr.(*dns.RRSIG); !ok && tdns.Globals.Debug {
				log.Printf("parseDSYNCFromImrResponse: answer not PrivateRR: %s", rr.String())
			}
		}
	}

	return dsyncrrs, parent
}

// discoverDSYNCViaImr implements the same 3-step algorithm as DsyncDiscovery but using imrQuery.
// child should be a FQDN (or will be normalized).
func discoverDSYNCViaImr(child string, timeout time.Duration) (tdns.DsyncResult, error) {
	var dr tdns.DsyncResult

	labels := dns.SplitDomainName(child)
	if len(labels) == 0 {
		return dr, fmt.Errorf("invalid child name: %s", child)
	}

	prefix := labels[0]
	parentGuess := dns.Fqdn(strings.Join(labels[1:], "."))

	// Step 1: one-level-up: <label>._dsync.<parentGuess>
	try1 := prefix + "._dsync." + parentGuess
	if tdns.Globals.Debug {
		log.Printf("discoverDSYNCViaImr: trying %s (step 1)\n", try1)
	}
	r1, err := imrQuery(try1, tdns.TypeDSYNC, timeout)
	if err == nil {
		dsyncrrs, parent := parseDSYNCFromImrResponse(r1)
		if len(dsyncrrs) > 0 {
			dr = tdns.DsyncResult{Qname: try1, Rdata: dsyncrrs, Parent: parentGuess}
			return dr, nil
		}
		if parent != "" {
			childNoDot := strings.TrimSuffix(child, ".")
			parentNoDot := strings.TrimSuffix(parent, ".")
			prefixPart, ok := strings.CutSuffix(childNoDot, "."+parentNoDot)
			if ok {
				try2 := prefixPart + "._dsync." + parent
				if tdns.Globals.Debug {
					log.Printf("discoverDSYNCViaImr: trying %s (step 2)\n", try2)
				}
				r2, err2 := imrQuery(try2, tdns.TypeDSYNC, timeout)
				if err2 == nil {
					dsyncrrs2, _ := parseDSYNCFromImrResponse(r2)
					if len(dsyncrrs2) > 0 {
						dr = tdns.DsyncResult{Qname: try2, Rdata: dsyncrrs2, Parent: parent}
						return dr, nil
					}
				} else if tdns.Globals.Debug {
					log.Printf("discoverDSYNCViaImr: step2 imrQuery error: %v", err2)
				}
			}
		}
	} else if tdns.Globals.Debug {
		log.Printf("discoverDSYNCViaImr: step1 imrQuery error: %v", err)
	}

	// Step 3: apex _dsync.<parentGuess>
	try3 := "_dsync." + parentGuess
	if tdns.Globals.Debug {
		log.Printf("discoverDSYNCViaImr: trying %s (step 3)\n", try3)
	}
	r3, err3 := imrQuery(try3, tdns.TypeDSYNC, timeout)
	if err3 == nil {
		dsyncrrs3, parent := parseDSYNCFromImrResponse(r3)
		dr = tdns.DsyncResult{Qname: try3, Rdata: dsyncrrs3, Parent: parent}
		return dr, nil
	}
	return dr, nil
}

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

        if reportSender == "" {
            fmt.Printf("Error: sender not specified\n")
            return
        }

        tsig := tdns.Globals.TsigKeys[reportSender + ".key."]
        if tsig == nil {
            fmt.Printf("Error: tsig key not found for sender: %s\n", reportSender)
            return
        }

		tdns.Globals.App.Type = tdns.AppTypeCli
		if tdns.Globals.Debug {
			fmt.Printf("ReportCmd: Calling Conf.MainInit(%q)\n", tdns.DefaultCliCfgFile)
		}
		if err := Conf.MainInit(tdns.DefaultCliCfgFile); err != nil {
			tdns.Shutdowner(&Conf, fmt.Sprintf("Error initializing tdns-cli: %v", err))
		}

        if dsyncLookup {

        // Start RecursorEngine (IMR)
		viper.Set("recursorengine.active", true)
		viper.Set("recursorengine.root-hints", "/etc/tdns/root.hints")
		// log.Printf("ReportCmd: Starting RecursorEngine")
		Conf.Internal.RecursorCh = make(chan tdns.ImrRequest, 10)
		stopCh := make(chan struct{}, 10)
		go Conf.RecursorEngine(stopCh)

		// Discover DSYNC via IMR for the zone that contains qname
		log.Printf("ReportCmd: Discovering DSYNC via IMR for %s", tdns.Globals.Zonename)
		dsyncRes, derr := discoverDSYNCViaImr(tdns.Globals.Zonename, 3*time.Second)
		var reporterDSYNC *tdns.DSYNC
		if derr != nil {
			log.Printf("ReportCmd: DSYNC discovery error: %v", derr)
			close(stopCh)
			return
		} else {
			for _, ds := range dsyncRes.Rdata {
				if ds.Scheme == tdns.SchemeReporter {
					reporterDSYNC = ds
					break
				}
			}
		}

		if reporterDSYNC == nil {
			log.Printf("ReportCmd: no DSYNC REPORTER found for %s, aborting report", tdns.Globals.Zonename)
			return
		}
        close(stopCh)
    
        targetIP = reporterDSYNC.Target
        port = strconv.Itoa(int(reporterDSYNC.Port))
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
		err := edns0.AddReporterOptionToMessage(m, &edns0.ReporterOption{
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


//        targetIP := reporterDSYNC.Target
//		port := "9998"
//		if reporterDSYNC.Port != 0 {
//			port = strconv.Itoa(int(reporterDSYNC.Port))
//		}

		log.Printf("ReportCmd: sending report to %s:%s (from DSYNC REPORTER)", targetIP, port)

		// Send the report
		c := tdns.NewDNSClient(tdns.TransportDo53, port, nil)

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

        if reportTsig {
           fmt.Printf("TSIG signing the report\n")
           c.DNSClient.TsigSecret = map[string]string{tsig.Name: tsig.Secret}
           m.SetTsig(tsig.Name, alg, 300, time.Now().Unix())
        }

        if tdns.Globals.Debug {
           fmt.Printf("%s\n", m.String())
        }

		resp, _, err := c.Exchange(m, targetIP)
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

