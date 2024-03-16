/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"crypto"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// var zonename string
var imr = "8.8.8.8:53"
var pzone, childpri, parpri string

var DdnsCmd = &cobra.Command{
	Use:   "ddns",
	Short: "Send a DDNS update. Only usable via sub-commands.",
}

var DdnsSyncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Send a DDNS update to sync parent delegation info with child data",
	Run: func(cmd *cobra.Command, args []string) {
		if Globals.Zonename == "" {
			log.Fatalf("Error: child zone name not specified.")
		}
		Globals.Zonename = dns.Fqdn(Globals.Zonename)

		if pzone == "" {
			log.Fatalf("Error: parent zone name not specified.")
		}
		pzone = dns.Fqdn(pzone)

		if childpri == "" {
			log.Fatalf("Error: child primary nameserver not specified.")
		}
		if parpri == "" {
			log.Fatalf("Error: parent primary nameserver not specified.")
		}

		keyrr, cs := LoadSigningKey(Globals.Sig0Keyfile)

		var differ bool
		var adds, removes []dns.RR

		if viper.GetBool("ddns.update-ns") {
			differ, adds, removes = ComputeRRDiff(childpri, parpri,
				Globals.Zonename, dns.TypeNS)
		} else {
			fmt.Printf("*** Note: configured NOT to update NS RRset.\n")
		}

		child_ns_inb, parent_ns_inb := ComputeBailiwickNS(childpri, parpri,
			      		       				Globals.Zonename)
		for _, ns := range child_ns_inb {
			fmt.Printf("Child in-bailiwick NS: %s\n", ns)
		}
		for _, ns := range parent_ns_inb {
			fmt.Printf("Parent in-bailiwick NS: %s\n", ns)
		}

		for _, ns := range child_ns_inb {
			if viper.GetBool("ddns.update-a") {
				fmt.Printf("Comparing A glue for child NS %s:\n", ns)
				gluediff, a_glue_adds, a_glue_removes := ComputeRRDiff(childpri,
					parpri, ns, dns.TypeA)
				if gluediff {
					differ = true
					for _, rr := range a_glue_removes {
						removes = append(removes, rr)
					}
					for _, rr := range a_glue_adds {
						adds = append(adds, rr)
					}
				}
			} else {
			  fmt.Printf("*** Note: configured NOT to update A glue.\n")
			}

			if viper.GetBool("ddns.update-aaaa") {
				fmt.Printf("Comparing AAAA glue for child NS %s:\n", ns)
				gluediff, aaaa_glue_adds, aaaa_glue_removes := ComputeRRDiff(childpri,
					parpri, ns, dns.TypeAAAA)
				if gluediff {
					differ = true
					for _, rr := range aaaa_glue_removes {
						removes = append(removes, rr)
					}
					for _, rr := range aaaa_glue_adds {
						adds = append(adds, rr)
					}
				}
			} else {
			  fmt.Printf("*** Note: configured NOT to update AAAA glue.\n")
			}
		}

		if !differ {
			fmt.Printf("Parent delegation data is in sync with child. No update needed.\n")
			os.Exit(0)
		}

		const update_scheme = 2
		dsynctarget, err := LookupDSYNCTarget(pzone, parpri, dns.StringToType["ANY"], update_scheme)
		if err != nil {
			log.Fatalf("Error from LookupDDNSTarget(%s, %s): %v", pzone, parpri, err)
		}

		msg, err := CreateUpdate(pzone, Globals.Zonename, adds, removes)
		if err != nil {
			log.Fatalf("Error from SendUpdate(%v): %v", dsynctarget, err)
		}

		if Globals.Sig0Keyfile != "" {
			fmt.Printf("Signing update.\n")
			msg, err = SignMsgNG(msg, Globals.Zonename, cs, keyrr)
			if err != nil {
				log.Fatalf("Error from SendUpdate(%v): %v", dsynctarget, err)
			}
		} else {
			fmt.Printf("Keyfile not specified, not signing message.\n")
		}

		err = SendUpdate(msg, pzone, dsynctarget)
		if err != nil {
			log.Fatalf("Error from SendUpdate(%v): %v", dsynctarget, err)
		}
	},
}

func init() {
     DdnsCmd.AddCommand(DdnsSyncCmd)

     DdnsCmd.PersistentFlags().StringVarP(&Globals.Sig0Keyfile, "keyfile", "k", "", "name of file with private SIG(0) key")
     DdnsCmd.PersistentFlags().StringVarP(&childpri, "primary", "p", "", "Address:port of child primary namserver")
     DdnsCmd.PersistentFlags().StringVarP(&parpri, "pprimary", "P", "", "Address:port of parent primary nameserver")
}

func LoadSigningKey(keyfile string) (*dns.KEY, crypto.Signer) {
        var keyrr *dns.KEY
	var cs crypto.Signer
	var rr dns.RR

	if keyfile != "" {
		var ktype string
		var err error
		_, cs, rr, ktype, err = ReadKey(keyfile)
		if err != nil {
			log.Fatalf("Error reading key '%s': %v", keyfile, err)
		}

		if ktype != "KEY" {
			log.Fatalf("Key must be a KEY RR")
		}

		keyrr = rr.(*dns.KEY)
	}
	return keyrr, cs
}

func SendUpdate(msg dns.Msg, zonename string, target DSYNCTarget) error {
	if zonename == "." {
		fmt.Printf("Error: zone name not specified. Terminating.\n")
		os.Exit(1)
	}

	for _, dst := range target.Addresses {
		if Globals.Verbose {
			fmt.Printf("Sending DDNS update for parent zone %s to %s on address %s:%d\n", zonename, target.Name, dst, target.Port)
		}

		if Globals.Debug {
			fmt.Printf("Sending Update:\n%s\n", msg.String())
		}

		dst = net.JoinHostPort(dst, fmt.Sprintf("%d", target.Port))
		res, err := dns.Exchange(&msg, dst)
		if err != nil {
			log.Fatalf("Error from dns.Exchange(%s, UPDATE): %v", dst, err)
		}

		if res.Rcode != dns.RcodeSuccess {
			if Globals.Verbose {
				fmt.Printf("... and got rcode %s back (bad)\n", dns.RcodeToString[res.Rcode])
			}
			log.Printf("Error: Rcode: %s", dns.RcodeToString[res.Rcode])
		} else {
			if Globals.Verbose {
				fmt.Printf("... and got rcode NOERROR back (good)\n")
			}
			break
		}
	}
	return nil
}

func CreateUpdate(parent, child string, adds, removes []dns.RR) (dns.Msg, error) {
	if parent == "." {
		log.Fatalf("Error: parent zone name not specified. Terminating.\n")
	}
	if child == "." {
		log.Fatalf("Error: child zone name not specified. Terminating.\n")
	}

	m := new(dns.Msg)
	m.SetUpdate(parent)

	m.Remove(removes)
	m.Insert(adds)

	for _, nsr := range removes {
		if ns, ok := nsr.(*dns.NS); ok { // if removing an NS, then also remove any glue
			if strings.HasSuffix(ns.Ns, child) {
				rrA := new(dns.A)
				rrA.Hdr = dns.RR_Header{Name: ns.Ns, Rrtype: dns.TypeA, Class: dns.ClassANY, Ttl: 3600}
				rrAAAA := new(dns.AAAA)
				rrAAAA.Hdr = dns.RR_Header{Name: ns.Ns, Rrtype: dns.TypeAAAA, Class: dns.ClassANY, Ttl: 3600}
				m.RemoveRRset([]dns.RR{rrA, rrAAAA})
			}
		}
	}

	if Globals.Debug {
		fmt.Printf("Creating update msg:\n%s\n", m.String())
	}
	return *m, nil
}

func ComputeRRDiff(childpri, parpri, owner string, rrtype uint16) (bool, []dns.RR, []dns.RR) {
	fmt.Printf("*** ComputeRRDiff(%s, %s)\n", owner, dns.TypeToString[rrtype])
	rrname := dns.TypeToString[rrtype]
	rrs_parent, err := AuthQuery(owner, parpri, rrtype)
	if err != nil {
		log.Fatalf("Error: looking up child %s %s RRset in parent primary %s: %v",
			Globals.Zonename, rrname, parpri, err)
	}

	rrs_child, err := AuthQuery(owner, childpri, rrtype)
	if err != nil {
		log.Fatalf("Error: looking up child %s %s RRset in child primary %s: %v",
			Globals.Zonename, rrname, childpri, err)
	}

	fmt.Printf("%d %s RRs from parent, %d %s RRs from child\n",
		len(rrs_parent), rrname, len(rrs_child), rrname)
	if Globals.Debug {
		for _, rrp := range rrs_parent {
			fmt.Printf("Parent: %s\n", rrp.String())
		}

		for _, rrc := range rrs_child {
			fmt.Printf("Child:  %s\n", rrc.String())
		}
	}

	differ, adds, removes := RRsetDiffer(owner, rrs_child, rrs_parent, rrtype, log.Default())
	if differ {
		fmt.Printf("Parent and child %s RRsets differ. To get parent in sync:\n", rrname)
		for _, rr := range removes {
			fmt.Printf("Remove: %s\n", rr.String())
		}
		for _, rr := range adds {
			fmt.Printf("Add:   %s\n", rr.String())
		}
	}
	return differ, adds, removes
}

func ComputeBailiwickNS(childpri, parpri, owner string) ([]string, []string) {
	rrname := dns.TypeToString[dns.TypeNS]
	ns_parent, err := AuthQuery(owner, parpri, dns.TypeNS)
	if err != nil {
		log.Fatalf("Error: looking up child %s %s RRset in parent primary %s: %v",
			Globals.Zonename, rrname, parpri, err)
	}

	ns_child, err := AuthQuery(Globals.Zonename, childpri, dns.TypeNS)
	if err != nil {
		log.Fatalf("Error: looking up child %s %s RRset in child primary %s: %v",
			Globals.Zonename, rrname, childpri, err)
	}

	fmt.Printf("%d %s RRs from parent, %d %s RRs from child\n",
		len(ns_parent), rrname, len(ns_child), rrname)
	if Globals.Debug {
		for _, rrp := range ns_parent {
			fmt.Printf("Parent: %s\n", rrp.String())
		}

		for _, rrc := range ns_child {
			fmt.Printf("Child:  %s\n", rrc.String())
		}
	}

	var parent_ns_inb, child_ns_inb []string

	for _, rr := range ns_parent {
		if ns, ok := rr.(*dns.NS); ok {
			if strings.HasSuffix(ns.Ns, owner) {
				parent_ns_inb = append(parent_ns_inb, ns.Ns)
			}
		}
	}
	for _, rr := range ns_child {
		if ns, ok := rr.(*dns.NS); ok {
			if strings.HasSuffix(ns.Ns, owner) {
				child_ns_inb = append(child_ns_inb, ns.Ns)
			}
		}
	}

	return child_ns_inb, parent_ns_inb
}
