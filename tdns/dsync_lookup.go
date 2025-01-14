/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type DsyncResult struct {
	Qname  string
	Rdata  []*DSYNC
	Parent string
	Error  error
}

// func DsyncDiscovery(child, imr string, verbose bool) ([]*DSYNC, string, error) {
func DsyncDiscovery(child, imr string, verbose bool) (DsyncResult, error) {
	var dr DsyncResult
	//     if verbose {
	log.Printf("Discovering DSYNC for parent of child zone %s ...\n", child)
	//	}

	// Step 1: One level up
	labels := dns.SplitDomainName(child)
	prefix := labels[0]
	parent_guess := dns.Fqdn(strings.Join(labels[1:], "."))
	name := prefix + "._dsync." + parent_guess

	//	if verbose {
	log.Printf("Looking up %s DSYNC...\n", name)
	//	}
	prrs, parent, err := DsyncQuery(name, imr, verbose)
	if err != nil {
		log.Printf("Error: during DsyncQuery: %v\n", err)
		// return prrs, "", err
		return dr, err
	}
	if len(prrs) > 0 {
		// return prrs, parent_guess, err
		dr = DsyncResult{Qname: name, Rdata: prrs, Parent: parent_guess}
		log.Printf("Found %d DSYNC RRs at %s:\n%v", len(prrs), name, prrs)
		return dr, nil
	}

	// Step 2: Under the inferred parent
	if parent != parent_guess {
		prefix, ok := strings.CutSuffix(child, "."+parent)
		if !ok {
			// return prrs, "", fmt.Errorf("Misidentified parent for %s: %v", child, parent)
			return dr, fmt.Errorf("misidentified parent for %s: %v", child, parent)
		}
		name = prefix + "._dsync." + parent
		//		if verbose {
		log.Printf("Looking up %s DSYNC...\n", name)
		//		}
		prrs, _, err = DsyncQuery(name, imr, verbose)
		if err != nil {
			log.Printf("Error: during DsyncQuery: %v\n", err)
			// return prrs, "", err
			return dr, err
		}
		if len(prrs) > 0 {
			return DsyncResult{Qname: name, Rdata: prrs, Parent: parent}, nil
		}
	}

	// Step 3: At the parent apex
	name = "_dsync." + parent

	//	if verbose {
	log.Printf("Looking up %s DSYNC...\n", name)
	//	}

	prrs, _, err = DsyncQuery(name, imr, verbose)
	if err != nil {
		log.Printf("Error: during DsyncQuery: %v\n", err)
		// return prrs, "", err
		return dr, err
	}

	return DsyncResult{Qname: name, Rdata: prrs, Parent: parent}, nil
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

	if verbose {
		log.Printf("DsyncQuery: Response from %s:\n%s\n", imr, res.String())
	}

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

type DsyncTarget struct {
	Name      string
	Scheme    DsyncScheme
	Port      uint16
	Addresses []string // in addr:port format
	RR        *DSYNC
}

// dtype = the type of DSYNC RR to look for (dns.TypeCDS, dns.TypeCSYNC, dns.TypeANY, ...)
// scheme = the DSYNC scheme (SchemeNotify | SchemeUpdate)
func LookupDSYNCTarget(childzone, imr string, dtype uint16, scheme DsyncScheme) (*DsyncTarget, error) {
	var addrs []string
	var dsynctarget DsyncTarget

	// dsyncrrs, _, err := DsyncDiscovery(parentzone, parentprimary, Globals.Verbose)
	dsync_res, err := DsyncDiscovery(childzone, imr, Globals.Verbose)
	if err != nil {
		return nil, err
	}

	if Globals.Debug {
		fmt.Printf("Zone %s: Found %d DSYNC RRs in parent zone %s\n", childzone, len(dsync_res.Rdata), dsync_res.Parent)
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
		return nil, fmt.Errorf("no DSYNC type %s scheme %d destination found for for zone %s",
			dns.TypeToString[dtype], scheme, childzone)
	}

	if Globals.Verbose {
		fmt.Printf("Looked up published DSYNC update target for zone %s:\n\n%s\tIN\tDSYNC\t%s\n\n",
			childzone, dsync_res.Qname, dsync.String())
	}

	addrs, err = net.LookupHost(dsync.Target)
	if err != nil {
		return nil, fmt.Errorf("Error: %v", err)
	}

	if Globals.Verbose {
		fmt.Printf("%s has the IP addresses: %v\n", dsync.Target, addrs)
	}

	for _, a := range addrs {
		dsynctarget.Addresses = append(dsynctarget.Addresses, net.JoinHostPort(a, strconv.Itoa(int(dsync.Port))))
	}

	dsynctarget.Port = dsync.Port
	dsynctarget.Name = dsync.Target
	dsynctarget.RR = dsync

	return &dsynctarget, nil
}
