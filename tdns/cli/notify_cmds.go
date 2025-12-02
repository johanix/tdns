/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package cli

import (
	"fmt"
	"log"
	"os"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"

	"github.com/johanix/tdns/tdns"
)

var NotifyCmd = &cobra.Command{
	Use:   "notify",
	Short: "The 'notify' command is only usable via defined sub-commands",
}

var notifySendCmd = &cobra.Command{
	Use:   "send",
	Short: "The 'notify send' command is only usable via defined sub-commands",
}

var notifySendCdsCmd = &cobra.Command{
	Use:   "cds",
	Short: "Send a Notify(CDS) to parent of zone",
	Run: func(cmd *cobra.Command, args []string) {
		SendNotify(dns.Fqdn(tdns.Globals.Zonename), "CDS")
	},
}

var notifySendCsyncCmd = &cobra.Command{
	Use:   "csync",
	Short: "Send a Notify(CSYNC) to parent of zone",
	Run: func(cmd *cobra.Command, args []string) {
		SendNotify(dns.Fqdn(tdns.Globals.Zonename), "CSYNC")
	},
}

var notifySendDnskeyCmd = &cobra.Command{
	Use:   "dnskey",
	Short: "Send a Notify(DNSKEY) to other signers of zone (multi-signer setup)",
	Run: func(cmd *cobra.Command, args []string) {
		SendNotify(dns.Fqdn(tdns.Globals.Zonename), "DNSKEY")
	},
}

var notifySendSoaCmd = &cobra.Command{
	Use:   "soa",
	Short: "Send a normal Notify(SOA) to someone",
	Run: func(cmd *cobra.Command, args []string) {
		SendNotify(dns.Fqdn(tdns.Globals.Zonename), "SOA")
	},
}

func init() {
	NotifyCmd.AddCommand(notifySendCmd)
	notifySendCmd.AddCommand(notifySendCdsCmd, notifySendCsyncCmd, notifySendDnskeyCmd,
		notifySendSoaCmd)

	notifySendCmd.PersistentFlags().StringVarP(&childpri, "primary", "p", "", "Address:port of child primary namserver")
	notifySendCmd.PersistentFlags().StringVarP(&parpri, "pprimary", "P", "", "Address:port of parent primary nameserver")
}

var childpri, parpri string

func SendNotify(zonename string, ntype string) {
	var dsynctarget *tdns.DsyncTarget
	var err error

	if zonename == "." {
		fmt.Printf("Error: zone name not specified. Terminating.\n")
		os.Exit(1)
	}

	const notify_scheme = 1
	dtype := dns.StringToType[ntype]

	// Old approach: using external IMR and manual parent zone specification (commented out)
	// var lookupzone, lookupserver string
	// if childpri == "" {
	// 	log.Fatalf("Error: child primary nameserver not specified.")
	// }
	// switch ntype {
	// case "DNSKEY":
	// 	lookupzone = zonename
	// 	lookupserver = childpri
	// default:
	// 	if tdns.Globals.ParentZone == "" {
	// 		log.Fatalf("Error: parent zone name not specified.")
	// 	}
	// 	tdns.Globals.ParentZone = dns.Fqdn(tdns.Globals.ParentZone)
	// 	if parpri == "" {
	// 		log.Fatalf("Error: parent primary nameserver not specified.")
	// 	}
	// 	lookupzone = tdns.Globals.ParentZone
	// 	lookupserver = parpri
	// }
	// dsynctarget, err = tdns.LookupDSYNCTarget(lookupzone, lookupserver, dtype, notify_scheme)

	// New approach: use internal IMR
	// LookupDSYNCTarget will discover the parent zone internally for CDS/CSYNC
	_, cancel, imr, err := StartImrForCli("")
	if err != nil {
		log.Fatalf("Error initializing IMR: %v", err)
	}
	defer cancel()

	dsynctarget, err = imr.LookupDSYNCTarget(zonename, dtype, notify_scheme)
	if err != nil {
		log.Fatalf("Error from LookupDSYNCTarget(%s): %v", zonename, err)
	}

	for _, dst := range dsynctarget.Addresses {
		if tdns.Globals.Verbose {
			fmt.Printf("Sending NOTIFY(%s) to %s on address %s\n",
				ntype, dsynctarget.Name, dst)
		}

		m := new(dns.Msg)
		m.SetNotify(zonename)

		// remove SOA, add ntype
		m.Question = []dns.Question{dns.Question{Name: zonename, Qtype: dns.StringToType[ntype], Qclass: dns.ClassINET}}

		if tdns.Globals.Debug {
			fmt.Printf("Sending Notify:\n%s\n", m.String())
		}

		// dst is already in addr:port format from LookupDSYNCTarget
		res, err := dns.Exchange(m, dst)
		if err != nil {
			log.Fatalf("Error from dns.Exchange(%s, NOTIFY(%s)): %v", dst, ntype, err)
		}

		if res.Rcode != dns.RcodeSuccess {
			if tdns.Globals.Verbose {
				fmt.Printf("... and got rcode %s back (bad)\n",
					dns.RcodeToString[res.Rcode])
			}
			log.Printf("Error: Rcode: %s", dns.RcodeToString[res.Rcode])
		} else {
			fmt.Printf("... and got rcode NOERROR back (good)\n")
			break
		}
	}
}
