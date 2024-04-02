/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type DsyncResult struct {
     Qname	 string	
     Rdata	 []*DSYNC
     Parent	 string
     Error	 error
}

// func DsyncDiscovery(child, imr string, verbose bool) ([]*DSYNC, string, error) {
func DsyncDiscovery(child, imr string, verbose bool) (DsyncResult, error) {
     var dr DsyncResult
//     if verbose {
	log.Printf("Discovering DSYNC for %s ...\n", child)
//	}

	// Step 1: One level up
	labels := dns.SplitDomainName(child)
	prefix := labels[0]
	parent_guess := dns.Fqdn(strings.Join(labels[1:], "."))
	name := prefix + "._dsync." + parent_guess

//	if verbose {
	   	   log.Printf("Trying %s ...\n", name)
//	}
	prrs, parent, err := DsyncQuery(name, imr, verbose)
	if err != nil {
		log.Printf("Error: during DsyncQuery: %v\n", err)
		// return prrs, "", err
		return dr, err
	}
	if len(prrs) > 0 {
		// return prrs, parent_guess, err
		return DsyncResult{ Qname: name, Rdata: prrs, Parent: parent_guess }, nil
	}

	// Step 2: Under the inferred parent
	if parent != parent_guess {
		prefix, ok := strings.CutSuffix(child, "."+parent)
		if !ok {
			// return prrs, "", fmt.Errorf("Misidentified parent for %s: %v", child, parent)
			return dr, fmt.Errorf("Misidentified parent for %s: %v", child, parent)
		}
		name = prefix + "._dsync." + parent
//		if verbose {
		   log.Printf("Trying %s ...\n", name)
//		}
		prrs, _, err = DsyncQuery(name, imr, verbose)
		if err != nil {
			log.Printf("Error: during DsyncQuery: %v\n", err)
			// return prrs, "", err
			return dr, err
		}
		if len(prrs) > 0 {
			return DsyncResult{ Qname: name, Rdata: prrs, Parent: parent }, err
		}
	}

	// Step 3: At the parent apex
	name = "_dsync." + parent

//	if verbose {
	   log.Printf("Trying %s ...\n", name)
//	}
	
	prrs, _, err = DsyncQuery(name, imr, verbose)
	if err != nil {
		log.Printf("Error: during DsyncQuery: %v\n", err)
		// return prrs, "", err
		return dr, err
	}

	return DsyncResult{ Qname: name, Rdata: prrs, Parent: parent }, err
}

func DsyncQuery(qname, imr string, verbose bool) ([]*DSYNC, string, error) {
	m := new(dns.Msg)
	m.SetQuestion(qname, TypeDSYNC)

	var dsyncrrs []*DSYNC
	var parent string

//	if Globals.Debug {
		log.Printf("DsyncQuery: TypeDSYNC=%d\n", TypeDSYNC)
		log.Printf("DEBUG: Sending to server %s query:\n%s\n", imr, m.String())
//	}

	c := new(dns.Client)
	c.Timeout = 5 * time.Second
	res, _, err := c.Exchange(m, imr)

	if err != nil {
		return dsyncrrs, "", fmt.Errorf("Error from dns.Exchange(%s, DSYNC): %v", qname, err)
	}

	if res == nil {
		return dsyncrrs, "", fmt.Errorf("Error: nil response to DSYNC query")
	}

	if res.Rcode == dns.RcodeSuccess {
		for _, rr := range res.Answer {
			if prr, ok := rr.(*dns.PrivateRR); ok {
				if Globals.Debug {
					log.Printf("%s\n", rr.String())
				}

				if dsyncrr, ok := prr.Data.(*DSYNC); ok {
					dsyncrrs = append(dsyncrrs, dsyncrr)
				} else {
					log.Printf("Error: answer is not a DSYNC RR: %s", rr.String())
				}
			} else if _, ok = rr.(*dns.RRSIG); ok {
				// ignore RRSIGs for the moment
			} else {
				log.Printf("Error: answer is not a DSYNC RR: %s", rr.String())
			}
		}
		if len(dsyncrrs) > 0 {
			return dsyncrrs, "", nil
		}
	}

	for _, rr := range res.Ns {
		if _, ok := rr.(*dns.SOA); ok {
			parent = rr.Header().Name
			return nil, parent, nil
		} else {
		        if verbose {
			   log.Printf("ignoring authority record: %s", rr.String())
			}
		}
	}

	if res.Rcode != dns.RcodeSuccess {
		return dsyncrrs, "", fmt.Errorf("Error: Query for %s DSYNC received rcode: %s",
			qname, dns.RcodeToString[res.Rcode])
	}

	log.Printf("DsyncQuery: Found: %v\n", dsyncrrs)

	return dsyncrrs, "", nil
}

func AuthQuery(qname, ns string, rrtype uint16) ([]dns.RR, error) {
	m := new(dns.Msg)
	m.SetQuestion(qname, rrtype)

	if Globals.Debug {
		// fmt.Printf("DEBUG: Query:\n%s\n", m.String())
		fmt.Printf("Sending query %s %s to nameserver \"%s\"\n", qname,
			dns.TypeToString[rrtype], ns)
	}

	res, err := dns.Exchange(m, ns)

	if err != nil {
//	       	  log.Fatalf("AuthQuery: Error from dns.Exchange(%s, %s, %s): %v",
//				       qname, dns.TypeToString[rrtype], ns, err)
	   return []dns.RR{}, err
	}

	if res.Rcode != dns.RcodeSuccess {
//		log.Fatalf("Error: Query for %s %s received rcode: %s",
//			qname, dns.TypeToString[rrtype], dns.RcodeToString[res.Rcode])
		return []dns.RR{}, fmt.Errorf("Query for %s %s received rcode: %s",
		       		   		     qname, dns.TypeToString[rrtype],
						     dns.RcodeToString[res.Rcode])
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

type xxxDDNSTarget struct {
	Name      string
	Addresses []string
	Port      uint16
}

type DSYNCTarget struct {
	Name      string
	Addresses []string
	Port      uint16
}

func xxxLookupDSYNCTarget(parentzone, parentprimary string) (DSYNCTarget, error) {
	var addrs []string
	var dsynctarget DSYNCTarget

	dsyncrrs, _, err := DsyncQuery(parentzone, parentprimary, Globals.Verbose)
	if err != nil {
		return dsynctarget, err
	}

	const update_scheme = 2

	if Globals.Debug {
		fmt.Printf("Found %d DSYNC RRs\n", len(dsyncrrs))
	}

	found := false
	var dsync *DSYNC

	for _, dsyncrr := range dsyncrrs {
		if dsyncrr.Scheme == update_scheme {
			found = true
			dsync = dsyncrr
			break
		}
	}
	if !found {
		return dsynctarget,
		       fmt.Errorf("No DNS UPDATE destination found for for zone %s\n", parentzone)
	}

	if Globals.Verbose {
		fmt.Printf("Looked up published DNS UPDATE target for zone %s:\n\n%s\n\n",
			parentzone, dsync.String())
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

func LookupDSYNCTarget(childzone, imr string, dtype uint16, scheme uint8) (DSYNCTarget, error) {
	var addrs []string
	var dsynctarget DSYNCTarget

	// dsyncrrs, _, err := DsyncDiscovery(parentzone, parentprimary, Globals.Verbose)
	dsync_res, err := DsyncDiscovery(childzone, imr, Globals.Verbose)
	if err != nil {
		return dsynctarget, err
	}

	if Globals.Debug {
		fmt.Printf("Found %d DSYNC RRs\n", len(dsync_res.Rdata))
	}

	found := false
	var dsync *DSYNC

	for _, dsyncrr := range dsync_res.Rdata {
		if dsyncrr.Scheme == scheme && dsyncrr.Type == dtype {
			found = true
			dsync = dsyncrr
			break
		}
	}
	if !found {
		return dsynctarget, fmt.Errorf("No DSYNC type %s scheme %d destination found for for zone %s",
			dns.TypeToString[dtype], scheme, childzone)
	}

	if Globals.Verbose {
		fmt.Printf("Looked up published DSYNC update target for zone %s:\n\n%s\tIN\tDSYNC\t%s\n\n",
			childzone, dsync_res.Qname, dsync.String())
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
