/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"

	core "github.com/johanix/tdns/v0.x/core"
	"github.com/miekg/dns"
)

type DsyncResult struct {
	Qname  string
	Rdata  []*core.DSYNC
	Parent string
	Error  error
}

// extractDsyncFromResponse extracts DSYNC records and parent zone name from ImrQuery response
func (imr *Imr) extractDsyncFromResponse(qname string, resp *ImrResponse, verbose bool) ([]*core.DSYNC, string, error) {
	var dsyncrrs []*core.DSYNC
	var parent string

	// If we got an answer with DSYNC records in Answer section
	if resp.RRset != nil && len(resp.RRset.RRs) > 0 {
		for _, rr := range resp.RRset.RRs {
			if prr, ok := rr.(*dns.PrivateRR); ok {
				if Globals.Debug {
					log.Printf("%s\n", rr.String())
				}
				if dsyncrr, ok := prr.Data.(*core.DSYNC); ok {
					dsyncrrs = append(dsyncrrs, dsyncrr)
				} else {
					log.Printf("Error: answer is not a DSYNC RR: %s", rr.String())
				}
			} else if _, ok := rr.(*dns.RRSIG); ok {
				// ignore RRSIGs
			} else {
				log.Printf("Error: answer is not a DSYNC RR: %s", rr.String())
			}
		}
		if len(dsyncrrs) > 0 {
			return dsyncrrs, "", nil
		}
	}

	// If Answer is empty, this is a negative response
	// Check the cache for negative response data - extract SOA from NegAuthority
	// The SOA owner name in the Authority section tells us the parent zone
	cached := imr.Cache.Get(qname, core.TypeDSYNC)
	if cached != nil && len(cached.NegAuthority) > 0 {
		// Look for SOA RRset in NegAuthority
		for _, negRRset := range cached.NegAuthority {
			if negRRset != nil && negRRset.RRtype == dns.TypeSOA && len(negRRset.RRs) > 0 {
				// Found SOA in negative authority
				for _, rr := range negRRset.RRs {
					if soa, ok := rr.(*dns.SOA); ok {
						parent = soa.Header().Name
						return nil, parent, nil
					}
				}
				// Use the RRset name if SOA type assertion fails
				if negRRset.Name != "" {
					parent = negRRset.Name
					return nil, parent, nil
				}
			}
		}
	}

	// Check if there was an error
	if resp.Error {
		return dsyncrrs, "", fmt.Errorf("error querying %s DSYNC: %s", qname, resp.ErrorMsg)
	}

	// If we get here and have no records, return empty result
	return dsyncrrs, "", nil
}

func (imr *Imr) DsyncDiscovery(ctx context.Context, child string, verbose bool) (DsyncResult, error) {
	var dr DsyncResult
	if !imr.Quiet {
		log.Printf("Discovering DSYNC for parent of child zone %q ...\n", child)
	}

	// Step 1: One level up
	labels := dns.SplitDomainName(child)
	prefix := labels[0]
	parent_guess := dns.Fqdn(strings.Join(labels[1:], "."))
	name := prefix + "._dsync." + parent_guess

	if !imr.Quiet {
		log.Printf("Looking up %s DSYNC...\n", name)
	}
	resp, err := imr.ImrQuery(ctx, name, core.TypeDSYNC, dns.ClassINET, nil)
	if err != nil {
		log.Printf("Error: during ImrQuery: %v\n", err)
		return dr, err
	}

	prrs, parent, err := imr.extractDsyncFromResponse(name, resp, verbose)
	if err != nil {
		log.Printf("Error: extracting DSYNC from response: %v\n", err)
		return dr, err
	}
	if len(prrs) > 0 {
		dr = DsyncResult{Qname: name, Rdata: prrs, Parent: parent_guess}
		if !imr.Quiet {
			log.Printf("Found %d DSYNC RRs at %s:\n%v", len(prrs), name, prrs)
		}
		return dr, nil
	}

	// Step 2: Under the inferred parent
	if parent != "" && parent != parent_guess {
		prefix, ok := strings.CutSuffix(child, "."+parent)
		if !ok {
			return dr, fmt.Errorf("misidentified parent for %s: %v", child, parent)
		}
		name = prefix + "._dsync." + parent
		if !imr.Quiet {
			log.Printf("Looking up %s DSYNC...\n", name)
		}
		resp, err = imr.ImrQuery(ctx, name, core.TypeDSYNC, dns.ClassINET, nil)
		if err != nil {
			log.Printf("Error: during ImrQuery: %v\n", err)
			return dr, err
		}
		prrs, _, err = imr.extractDsyncFromResponse(name, resp, verbose)
		if err != nil {
			log.Printf("Error: extracting DSYNC from response: %v\n", err)
			return dr, err
		}
		if len(prrs) > 0 {
			return DsyncResult{Qname: name, Rdata: prrs, Parent: parent}, nil
		}
	}

	// Step 3: At the parent apex
	if parent == "" {
		parent = parent_guess
	}
	name = "_dsync." + parent

	if !imr.Quiet {
		log.Printf("Looking up %s DSYNC...\n", name)
	}
	resp, err = imr.ImrQuery(ctx, name, core.TypeDSYNC, dns.ClassINET, nil)
	if err != nil {
		log.Printf("Error: during ImrQuery: %v\n", err)
		return dr, err
	}

	prrs, _, err = imr.extractDsyncFromResponse(name, resp, verbose)
	if err != nil {
		log.Printf("Error: extracting DSYNC from response: %v\n", err)
		return dr, err
	}

	return DsyncResult{Qname: name, Rdata: prrs, Parent: parent}, nil
}

/*
// DsyncDiscovery is the standalone function that uses external IMR (fallback)
func xxxDsyncDiscovery(child, imr string, verbose bool) (DsyncResult, error) {
	var dr DsyncResult
	log.Printf("Discovering DSYNC for parent of child zone %s ...\n", child)

	// Step 1: One level up
	labels := dns.SplitDomainName(child)
	prefix := labels[0]
	parent_guess := dns.Fqdn(strings.Join(labels[1:], "."))
	name := prefix + "._dsync." + parent_guess

	log.Printf("Looking up %s DSYNC...\n", name)
	prrs, parent, err := DsyncQuery(name, imr, verbose)
	if err != nil {
		log.Printf("Error: during DsyncQuery: %v\n", err)
		return dr, err
	}
	if len(prrs) > 0 {
		dr = DsyncResult{Qname: name, Rdata: prrs, Parent: parent_guess}
		log.Printf("Found %d DSYNC RRs at %s:\n%v", len(prrs), name, prrs)
		return dr, nil
	}

	// Step 2: Under the inferred parent
	if parent != "" && parent != parent_guess {
		prefix, ok := strings.CutSuffix(child, "."+parent)
		if !ok {
			return dr, fmt.Errorf("misidentified parent for %s: %v", child, parent)
		}
		name = prefix + "._dsync." + parent
		log.Printf("Looking up %s DSYNC...\n", name)
		prrs, _, err = DsyncQuery(name, imr, verbose)
		if err != nil {
			log.Printf("Error: during DsyncQuery: %v\n", err)
			return dr, err
		}
		if len(prrs) > 0 {
			return DsyncResult{Qname: name, Rdata: prrs, Parent: parent}, nil
		}
	}

	// Step 3: At the parent apex
	if parent == "" {
		parent = parent_guess
	}
	name = "_dsync." + parent

	log.Printf("Looking up %s DSYNC...\n", name)
	prrs, _, err = DsyncQuery(name, imr, verbose)
	if err != nil {
		log.Printf("Error: during DsyncQuery: %v\n", err)
		return dr, err
	}

	return DsyncResult{Qname: name, Rdata: prrs, Parent: parent}, nil
}
*/

/*
func xxxDsyncQuery(qname, imr string, verbose bool) ([]*core.DSYNC, string, error) {
	m := new(dns.Msg)
	m.SetQuestion(qname, core.TypeDSYNC)

	var dsyncrrs []*core.DSYNC
	var parent string

	//	if Globals.Debug {
	log.Printf("DsyncQuery: TypeDSYNC=%d\n", core.TypeDSYNC)
	log.Printf("DEBUG: Sending to server %s query:\n%s\n", imr, m.String())
	//	}

	c := new(dns.Client)
	c.Timeout = 5 * time.Second
	res, _, err := c.Exchange(m, imr)

	if verbose {
		log.Printf("DsyncQuery: Response from %s:\n%s\n", imr, res.String())
	}

	if err != nil {
		return dsyncrrs, "", fmt.Errorf("error from dns.Exchange(%s, DSYNC): %v", qname, err)
	}

	if res == nil {
		return dsyncrrs, "", fmt.Errorf("error: nil response to DSYNC query")
	}

	if res.Rcode == dns.RcodeSuccess {
		for _, rr := range res.Answer {
			if prr, ok := rr.(*dns.PrivateRR); ok {
				if Globals.Debug {
					log.Printf("%s\n", rr.String())
				}

				if dsyncrr, ok := prr.Data.(*core.DSYNC); ok {
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
*/

type DsyncTarget struct {
	Name      string
	Scheme    core.DsyncScheme
	Port      uint16
	Addresses []string // in addr:port format
	RR        *core.DSYNC
}

// dtype = the type of DSYNC RR to look for (dns.TypeCDS, dns.TypeCSYNC, dns.TypeANY, ...)
// scheme = the DSYNC scheme (SchemeNotify | SchemeUpdate)
func (imr *Imr) LookupDSYNCTarget(ctx context.Context, childzone string, dtype uint16, scheme core.DsyncScheme) (*DsyncTarget, error) {
	var addrs []string
	var dsynctarget DsyncTarget

	// Use internal IMR to discover DSYNC records
	dsync_res, err := imr.DsyncDiscovery(ctx, childzone, Globals.Verbose)
	if err != nil {
		return nil, err
	}

	if Globals.Debug {
		fmt.Printf("Zone %s: Found %d DSYNC RRs in parent zone %s\n", childzone, len(dsync_res.Rdata), dsync_res.Parent)
	}

	found := false
	var dsync *core.DSYNC

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
		return nil, fmt.Errorf("error: %v", err)
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

/*
// LookupDSYNCTarget is the standalone function that uses external IMR (fallback)
func xxxLookupDSYNCTarget(childzone, imr string, dtype uint16, scheme core.DsyncScheme) (*DsyncTarget, error) {
	var addrs []string
	var dsynctarget DsyncTarget

	// dsyncrrs, _, err := DsyncDiscovery(parentzone, parentprimary, Globals.Verbose)
	dsync_res, err := xxxDsyncDiscovery(childzone, imr, Globals.Verbose)
	if err != nil {
		return nil, err
	}

	if Globals.Debug {
		fmt.Printf("Zone %s: Found %d DSYNC RRs in parent zone %s\n", childzone, len(dsync_res.Rdata), dsync_res.Parent)
	}

	found := false
	var dsync *core.DSYNC

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
		return nil, fmt.Errorf("error: %v", err)
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
*/
