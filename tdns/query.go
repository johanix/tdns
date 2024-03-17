/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

// var Zonename string

var DsyncDiscoveryCmd = &cobra.Command{
	Use:   "dsync-query",
	Short: "Send a DNS query for 'zone. DSYNC' and present the result.",
	Run: func(cmd *cobra.Command, args []string) {
		Globals.Zonename = dns.Fqdn(Globals.Zonename)
		rrs, err := DsyncDiscovery(Globals.Zonename, Globals.IMR)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if len(rrs) == 0 {
			fmt.Printf("No DSYNC record associated with '%s'\n", Globals.Zonename)
		} else {
			for _, nr := range rrs {
				fmt.Printf("%s\n", nr.String())
			}
		}
	},
}

func init() {
	//	DsyncQueryCmd.PersistentFlags().StringVarP(&Globals.Zonename, "zone", "z", "", "Zone to query for the DSYNC RRset in")
	DsyncDiscoveryCmd.PersistentFlags().StringVarP(&Globals.IMR, "imr", "i", "", "IMR to send the query to")
}

func DsyncDiscovery(child, imr string) ([]*dns.PrivateRR, error) {
	fmt.Printf("Discovering DSYNC for %s ...\n", child)

	// Step 1: One level up
	labels := dns.SplitDomainName(child)
	prefix := labels[0]
	parent_guess := dns.Fqdn(strings.Join(labels[1:], "."))
	name := prefix + "._dsync." + parent_guess
	fmt.Printf("Trying %s ...\n", name)
	prrs, parent, err := DsyncQuery(name, imr)
	if err != nil {
		log.Printf("Error: during DsyncQuery: %v\n", err)
	}
	if len(prrs) > 0 {
		return prrs, err
	}

	// Step 2: Under the inferred parent
	if parent != parent_guess {
		prefix, ok := strings.CutSuffix(child, "."+parent)
		if !ok {
			return prrs, fmt.Errorf("Misidentified parent for %s: %v", child, parent)
		}
		name = prefix + "._dsync." + parent
		fmt.Printf("Trying %s ...\n", name)
		prrs, _, err = DsyncQuery(name, imr)
		if err != nil {
			log.Printf("Error: during DsyncQuery: %v\n", err)
		}
		if len(prrs) > 0 {
			return prrs, err
		}
	}

	// Step 3: At the parent apex
	name = "_dsync." + parent
	fmt.Printf("Trying %s ...\n", name)
	prrs, _, err = DsyncQuery(name, imr)
	if err != nil {
		log.Printf("Error: during DsyncQuery: %v\n", err)
	}

	return prrs, err
}

func DsyncQuery(z, imr string) ([]*dns.PrivateRR, string, error) {
	m := new(dns.Msg)
	m.SetQuestion(z, TypeDSYNC)

	var prrs []*dns.PrivateRR
	var parent string

	if Globals.Debug {
		fmt.Printf("TypeDSYNC=%d\n", TypeDSYNC)
		fmt.Printf("DEBUG: Sending to server %s query:\n%s\n", imr, m.String())
	}

	res, err := dns.Exchange(m, imr)

	if err != nil {
		return prrs, "", fmt.Errorf("Error from dns.Exchange(%s, DSYNC): %v", z, err)
	}

	if res == nil {
		return prrs, "", fmt.Errorf("Error: nil response to DSYNC query")
	}

	if res.Rcode == dns.RcodeSuccess {
		for _, rr := range res.Answer {
			if prr, ok := rr.(*dns.PrivateRR); ok {
				if Globals.Debug {
					fmt.Printf("%s\n", rr.String())
				}

				if _, ok := prr.Data.(*DSYNC); ok {
					prrs = append(prrs, prr)
				} else {
					log.Printf("Error: answer is not a DSYNC RR: %s", rr.String())
				}
			} else if _, ok = rr.(*dns.RRSIG); ok {
				// ignore RRSIGs for the moment
			} else {
				log.Printf("Error: answer is not a DSYNC RR: %s", rr.String())
			}
		}
		if len(prrs) > 0 {
			return prrs, "", nil
		}
	}

	for _, rr := range res.Ns {
		if _, ok := rr.(*dns.SOA); ok {
			parent = rr.Header().Name
			return nil, parent, nil
		} else {
			fmt.Printf("ignoring authority record: %s", rr.String())
		}
	}

	if res.Rcode != dns.RcodeSuccess {
		return prrs, "", fmt.Errorf("Error: Query for %s DSYNC received rcode: %s",
			z, dns.RcodeToString[res.Rcode])
	}

	return prrs, "", nil
}

func AuthQuery(qname, ns string, rrtype uint16) ([]dns.RR, error) {
	m := new(dns.Msg)
	m.SetQuestion(qname, rrtype)

	if Globals.Debug {
		// fmt.Printf("DEBUG: Query:\n%s\n", m.String())
		fmt.Printf("Sending query %s %s to nameserver %s\n", qname,
			dns.TypeToString[rrtype], ns)
	}

	res, err := dns.Exchange(m, ns)

	if err != nil && !Globals.Debug {
		log.Fatalf("Error from dns.Exchange(%s, %s, %s): %v", qname, dns.TypeToString[rrtype], ns, err)
	}

	if res.Rcode != dns.RcodeSuccess {
		log.Fatalf("Error: Query for %s %s received rcode: %s",
			qname, dns.TypeToString[rrtype], dns.RcodeToString[res.Rcode])
	}

	var rrs []dns.RR

	if len(res.Answer) > 0 {
		if Globals.Debug {
			fmt.Printf("Looking up %s %s RRset:\n", qname, dns.TypeToString[rrtype])
		}
		for _, rr := range res.Answer {
			if rr.Header().Rrtype == rrtype {
				if Globals.Debug {
					fmt.Printf("%s\n", rr.String())
				}

				rrs = append(rrs, rr)

			} else if _, ok := rr.(*dns.RRSIG); ok {
				// ignore RRSIGs for the moment
			} else {
				log.Fatalf("Error: answer is not an %s RR: %s", dns.TypeToString[rrtype], rr.String())
			}
		}
		return rrs, nil
	}

	if len(res.Ns) > 0 {
		if Globals.Debug {
			fmt.Printf("Looking up %s %s RRset:\n", qname, dns.TypeToString[rrtype])
		}
		for _, rr := range res.Ns {
			if rr.Header().Rrtype == rrtype && rr.Header().Name == qname {
				if Globals.Debug {
					fmt.Printf("%s\n", rr.String())
				}

				rrs = append(rrs, rr)

			} else if _, ok := rr.(*dns.RRSIG); ok {
				// ignore RRSIGs for the moment
			} else {
				// Should not be fatal. Happens when querying parent for glue
				// log.Fatalf("Error: answer is not an %s RR: %s", dns.TypeToString[rrtype], rr.String())
			}
		}
		if len(rrs) > 0 { // found something
			return rrs, nil
		}
	}

	if len(res.Extra) > 0 {
		if Globals.Debug {
			fmt.Printf("Looking up %s %s RRset:\n", qname, dns.TypeToString[rrtype])
		}
		for _, rr := range res.Extra {
			if rr.Header().Rrtype == rrtype && rr.Header().Name == qname {
				if Globals.Debug {
					fmt.Printf("%s\n", rr.String())
				}

				rrs = append(rrs, rr)

			} else if _, ok := rr.(*dns.RRSIG); ok {
				// ignore RRSIGs for the moment
			} else {
				// Should not be fatal.
				// log.Fatalf("Error: answer is not an %s RR: %s", dns.TypeToString[rrtype], rr.String())
			}
		}
		return rrs, nil
	}

	return rrs, nil
}

func RRsetDiffer(zone string, newrrs, oldrrs []dns.RR, rrtype uint16, lg *log.Logger) (bool, []dns.RR, []dns.RR) {
	var match, rrsets_differ bool
	typestr := dns.TypeToString[rrtype]
	adds := []dns.RR{}
	removes := []dns.RR{}

	if Globals.Debug {
		lg.Printf("*** RRD: Comparing %s RRsets for %s:", typestr, zone)
		lg.Printf("-------- Old set for %s %s:", zone, typestr)
		for _, rr := range oldrrs {
			lg.Printf("%s", rr.String())
		}
		lg.Printf("-------- New set for %s %s:", zone, typestr)
		for _, rr := range newrrs {
			lg.Printf("%s", rr.String())
		}
	}
	// compare oldrrs to newrrs
	for _, orr := range oldrrs {
		if dns.TypeToString[orr.Header().Rrtype] == "RRSIG" {
			continue
		}
		match = false
		for _, nrr := range newrrs {
			if dns.IsDuplicate(orr, nrr) {
				match = true
				break
			}
		}
		// if we get here w/o match then this orr has no equal nrr
		if !match {
			rrsets_differ = true
			removes = append(removes, orr)
		}
	}

	// compare newrrs to oldrrs
	for _, nrr := range newrrs {
		if dns.TypeToString[nrr.Header().Rrtype] == "RRSIG" {
			continue
		}
		match = false
		for _, orr := range oldrrs {
			if dns.IsDuplicate(nrr, orr) {
				match = true
				break
			}
		}
		// if we get here w/o match then this nrr has no equal orr
		if !match {
			rrsets_differ = true
			adds = append(adds, nrr)
		}
	}
	return rrsets_differ, adds, removes
}

type DDNSTarget struct {
	Name      string
	Addresses []string
	Port      uint16
}

type DSYNCTarget struct {
	Name      string
	Addresses []string
	Port      uint16
}

func LookupDDNSTarget(parentzone, parentprimary string) (DDNSTarget, error) {
	var addrs []string
	var ddnstarget DDNSTarget

	prrs, _, err := DsyncQuery(parentzone, parentprimary)
	if err != nil {
		return ddnstarget, err
	}

	const update_scheme = 2

	if Globals.Debug {
		fmt.Printf("Found %d DSYNC RRs\n", len(prrs))
	}

	found := false
	var dsync_rr *dns.PrivateRR

	for _, prr := range prrs {
		if prr.Data.(*DSYNC).Scheme == update_scheme {
			found = true
			dsync_rr = prr
			break
		}
	}
	if !found {
		return ddnstarget, fmt.Errorf("No DDNS update destination found for for zone %s\n", parentzone)
	}

	dsync, _ := dsync_rr.Data.(*DSYNC)

	if Globals.Verbose {
		fmt.Printf("Looked up published DDNS update target for zone %s:\n\n%s\n\n",
			parentzone, dsync_rr.String())
	}

	addrs, err = net.LookupHost(dsync.Target)
	if err != nil {
		return ddnstarget, fmt.Errorf("Error: %v", err)
	}

	if Globals.Verbose {
		fmt.Printf("%s has the IP addresses: %v\n", dsync.Target, addrs)
	}
	ddnstarget.Port = dsync.Port
	ddnstarget.Addresses = addrs
	ddnstarget.Name = dsync.Target

	return ddnstarget, nil
}

func LookupDSYNCTarget(parentzone, parentprimary string, dtype uint16, scheme uint8) (DSYNCTarget, error) {
	var addrs []string
	var dsynctarget DSYNCTarget

	prrs, err := DsyncDiscovery(parentzone, parentprimary)
	if err != nil {
		return dsynctarget, err
	}

	if Globals.Debug {
		fmt.Printf("Found %d DSYNC RRs\n", len(prrs))
	}

	found := false
	var dsync *DSYNC

	for _, rr := range prrs {
		dsyncrr := rr.Data.(*DSYNC)
		if dsyncrr.Scheme == scheme && dsyncrr.Type == dtype {
			found = true
			dsync = dsyncrr
			break
		}
	}
	if !found {
		return dsynctarget, fmt.Errorf("No DSYNC type %s scheme %d destination found for for zone %s",
			dns.TypeToString, scheme, parentzone)
	}

	if Globals.Verbose {
		fmt.Printf("Looked up published DSYNC update target for zone %s:\n\n%s\tIN\tDSYNC\t%s\n\n",
			parentzone, parentzone, dsync.String())
	}

	addrs, err = net.LookupHost(dsync.Target)
	if err != nil {
		return dsynctarget, fmt.Errorf("Error: %v", err)
	}

	if Globals.Verbose {
		fmt.Printf("%s has the IP addresses: %v\n", dsync.Target, addrs)
	}
	dsynctarget.Port = dsync.Port
	dsynctarget.Addresses = addrs
	dsynctarget.Name = dsync.Target

	return dsynctarget, nil
}
