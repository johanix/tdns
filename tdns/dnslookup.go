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
	"github.com/spf13/viper"
)

// 1. Is the RRset in a zone that we're auth for? If so we claim that the data is valid
// 2. Is the RRset in a child zone? If so, start by fetching and validating the child DNSKEYs.

// 1. Find the child NS RRset
// 2. Find the address of each NS
// 3. Query child NS for <qname, qtype>

func (zd *ZoneData) LookupAndValidateRRset(qname string, qtype uint16,
	verbose bool) (*RRset, bool, error) {

	cdd := zd.FindDelegation(qname, true)
	switch {
	case cdd != nil:
		// Ok, the rrset is below a zone cut. Is the delegations signed?
		if cdd.DS_rrset == nil {
			zd.Logger.Printf("LookupAndValidateRRset: No DS RRset found for child zone %s. Unsigned delegation.", cdd.ChildName)
		} else {
			zd.Logger.Printf("LookupAndValidateRRset: DS RRset found for child zone %s. Signed delegation.", cdd.ChildName)
			// Time to fetch and validate the child DNSKEYs
			valid, err := zd.ValidateChildDnskeys(cdd, verbose)
			if err != nil {
				zd.Logger.Printf("LookupAndValidateRRset: Error from ValidateChildDnskeys: %v", err)
				return nil, false, err
			}
			if !valid {
				zd.Logger.Printf("LookupAndValidateRRset: Failed to validate child DNSKEYs")
				return nil, false, fmt.Errorf("LookupAndValidateRRset: Failed to validate child DNSKEYs")
			}
		}
		addrs, err := ChildGlueRRsToAddrs(cdd.A_glue, cdd.AAAA_glue)
		if err != nil {
			zd.Logger.Printf("LookupAndValidateRRset: Error from ChildGlueRRsetsToAddrs: %v", err)
			return nil, false, err
		}
		zd.Logger.Printf("LookupAndValidateRRset: child zone %s has NS addresses: %v", cdd.ChildName, addrs)
		rrset, err := zd.LookupChildRRsetNG(qname, qtype, addrs, verbose)
		if err != nil {
			zd.Logger.Printf("LookupAndValidateRRset: Error from LookupChildRRsetNG: %v", err)
			return nil, false, err
		}
		valid, err := zd.ValidateRRset(rrset, verbose)
		if err != nil {
			zd.Logger.Printf("LookupAndValidateRRset: Error from ValidateRRset: %v", err)
			return nil, false, err
		}
		return rrset, valid, nil

	case cdd == nil:
		// This is the normal case, i.e. the RRset is in the zone we're authoritative for.
		rrset, err := zd.LookupRRset(qname, qtype, verbose)
		if err != nil {
			zd.Logger.Printf("LookupAndValidateRRset: Error from LookupRRset: %v", err)
			return nil, false, err
		}

		if rrset == nil {
			zd.Logger.Printf("LookupAndValidateRRset: No RRset returned from LookupRRset(%s, %s)", qname, dns.TypeToString[qtype])
			return nil, false, nil
		}

		valid, err := zd.ValidateRRset(rrset, verbose)
		if err != nil {
			zd.Logger.Printf("LookupAndValidateRRset: Error from ValidateRRset: %v", err)
			return nil, false, err
		}

		return rrset, valid, nil
	}

	return nil, false, fmt.Errorf("LookupAndValidateRRset: Internal error, should not be reached")
}

// This is mostly used for debugging of the DNSSEC validation code
// func (zd *ZoneData) LookupAndValidateRRset(qname string, qtype uint16) (string, error) {
//	zd.Logger.Printf("LookupAndValidateRRset: Looking up %s %s in DNS", qname, dns.TypeToString[qtype])
//	rrset, err := zd.LookupRRset(qname, qtype, true)
//	if err != nil {
//		return fmt.Sprintf("error from LookupRRset(%s, %s): %v", qname, dns.TypeToString[qtype], err), err
//	}
//	if rrset == nil {
//		return fmt.Sprintf("LookupRRset(%s, %s) returned nil", qname, dns.TypeToString[qtype]), fmt.Errorf("LookupRRset(%s, %s) returned nil", qname, dns.TypeToString[qtype])
//	}
//	valid, err := zd.ValidateRRset(rrset, true)
//	if err != nil {
//		return fmt.Sprintf("error from ValidateRRset(%s, %s): %v", qname, dns.TypeToString[qtype], err), err
//	}

//	msg := fmt.Sprintf("LookupAndValidateRRset: Found %s %s RRset (validated: %v)", qname, dns.TypeToString[qtype], valid)
//	zd.Logger.Printf(msg)
//	return msg, nil
//}

// XXX: This should not be a method of ZoneData, but rather a function.

func (zd *ZoneData) LookupRRset(qname string, qtype uint16, verbose bool) (*RRset, error) {
	zd.Logger.Printf("LookupRRset: looking up %s %s", qname, dns.TypeToString[qtype])
	var rrset *RRset
	var wildqname string
	origqname := qname

	// Is answer in this zone or further down?
	if !zd.NameExists(qname) {
		// Here we should do wildcard expansion like in QueryResponder()
		wildqname = "*." + strings.Join(strings.Split(qname, ".")[1:], ".")
		log.Printf("---> Checking for existence of wildcard %s", wildqname)
		if !zd.NameExists(wildqname) {
			// no, nothing
			zd.Logger.Printf("*** No data for %s in %s", wildqname, zd.ZoneName)
			return nil, nil
		}
		origqname = qname
		qname = wildqname
		zd.Logger.Printf("*** %s is a wildcard expansion from %s", origqname, wildqname)
	}

	owner, err := zd.GetOwner(qname)

	if owner.RRtypes.Count() == 0 {
		// No, nothing.
		zd.Logger.Printf("*** No data for %s in %s", qname, zd.ZoneName)
		return nil, nil // nothing found, but this is not an error
	}

	// Check for qname + CNAME: defer this to later.

	// Check for child delegation
	cdd := zd.FindDelegation(qname, true)
	// if childns != nil {
	if cdd != nil && cdd.NS_rrset != nil {
		zd.Logger.Printf("LRRset: found a delegation for %s in known zone %s",
			qname, zd.ZoneName)

		addrs, err := ChildGlueRRsToAddrs(cdd.A_glue, cdd.AAAA_glue)
		if err != nil {
			zd.Logger.Printf("LookupRRset: Error from ChildGlueRRsToAddrs: %v", err)
			return nil, err
		}
		rrset, err = zd.LookupChildRRsetNG(qname, qtype, addrs, verbose)
		if err != nil {
			zd.Logger.Printf("LookupRRset: Error from LookupChildRRset: %v", err)
		}
		return rrset, err
	} else {
		zd.Logger.Printf("*** %s is not a child delegation from %s", qname, zd.ZoneName)
	}

	zd.Logger.Printf("*** Current data for owner name=%s: RRtypes: ", owner.Name)
	for _, k := range owner.RRtypes.Keys() {
		v, _ := owner.RRtypes.Get(uint16(k))
		zd.Logger.Printf("%s: %d RRs ", dns.TypeToString[uint16(k)], len(v.RRs))
	}

	// Must instantiate the rrset if not found above
	if rrset == nil {
		rrset = &RRset{}
	}

	// Check for exact match qname + qtype
	if _, ok := owner.RRtypes.Get(qtype); ok && len(owner.RRtypes.GetOnlyRRSet(qtype).RRs) > 0 {
		zd.Logger.Printf("*** %d RRs: %v", len(owner.RRtypes.GetOnlyRRSet(qtype).RRs), owner.RRtypes.GetOnlyRRSet(qtype).RRs)
		// XXX: Dont forget that we also need to deal with CNAMEs in here
		if qname == origqname {
			rrset.RRs = owner.RRtypes.GetOnlyRRSet(qtype).RRs
			rrset.RRSIGs = owner.RRtypes.GetOnlyRRSet(qtype).RRSIGs
		} else {
			tmp := WildcardReplace(owner.RRtypes.GetOnlyRRSet(qtype).RRs, qname, origqname)
			rrset.RRs = tmp
			tmp = WildcardReplace(owner.RRtypes.GetOnlyRRSet(qtype).RRSIGs, qname, origqname)
			rrset.RRSIGs = tmp
		}
	}

	for _, rr := range rrset.RRs {
		zd.Logger.Printf("%s", rr.String())
	}
	for _, rr := range rrset.RRSIGs {
		zd.Logger.Printf("%s", rr.String())
	}

	log.Printf("LookupRRset: done. rrset=%v", rrset)
	return rrset, err
}

// XXX: This should die in favor of LookupChildRRsetNG
func (zd *ZoneData) LookupChildRRset(qname string, qtype uint16,
	v4glue, v6glue *RRset, verbose bool) (*RRset, error) {

	var servers []string

	for _, glue := range v4glue.RRs {
		servers = append(servers, net.JoinHostPort(glue.(*dns.A).A.String(), "53"))
	}
	for _, glue := range v6glue.RRs {
		servers = append(servers, net.JoinHostPort(glue.(*dns.AAAA).AAAA.String(), "53"))
	}

	rrset, _, err := AuthDNSQuery(qname, zd.Logger, servers, qtype, verbose)
	if err != nil {
		zd.Logger.Printf("LCRRset: Error from AuthDNSQuery: %v", err)
	}
	zd.Logger.Printf("LCRRset: looked up %s %s (%d RRs):", qname, dns.TypeToString[qtype], len(rrset.RRs))
	// log.Printf("LookupChildRRset: done. rrset=%v", rrset)
	return rrset, err
}

func (zd *ZoneData) LookupChildRRsetNG(qname string, qtype uint16,
	addrs []string, verbose bool) (*RRset, error) {

	rrset, _, err := AuthDNSQuery(qname, zd.Logger, addrs, qtype, verbose)
	if err != nil {
		zd.Logger.Printf("LCRRsetNG: Error from AuthDNSQuery: %v", err)
	}
	zd.Logger.Printf("LCRRsetNG: looked up %s %s (%d RRs):", qname, dns.TypeToString[qtype], len(rrset.RRs))
	// log.Printf("LookupChildRRsetNG: done. rrset=%v", rrset)
	return rrset, err
}

func ChildGlueRRsetsToAddrs(v4glue, v6glue []*RRset) ([]string, error) {
	var addrs []string
	for _, nsname := range v4glue {
		for _, glue := range nsname.RRs {
			addrs = append(addrs, net.JoinHostPort(glue.(*dns.A).A.String(), "53"))
		}
	}

	for _, nsname := range v6glue {
		for _, glue := range nsname.RRs {
			addrs = append(addrs, net.JoinHostPort(glue.(*dns.AAAA).AAAA.String(), "53"))
		}
	}
	log.Printf("ChildGlueRRsetsToAddrs: addrs=%v", addrs)
	return addrs, nil
}

func ChildGlueRRsToAddrs(v4glue, v6glue []dns.RR) ([]string, error) {
	var addrs []string
	for _, glue := range v4glue {
		addrs = append(addrs, net.JoinHostPort(glue.(*dns.A).A.String(), "53"))
	}
	for _, glue := range v6glue {
		addrs = append(addrs, net.JoinHostPort(glue.(*dns.AAAA).AAAA.String(), "53"))
	}

	log.Printf("ChildGlueRRsToAddrs: addrs=%v", addrs)
	return addrs, nil
}

func AuthDNSQuery(qname string, lg *log.Logger, nameservers []string,
	rrtype uint16, verbose bool) (*RRset, int, error) {

	crrset := RRsetCache.Get(qname, rrtype)
	if crrset != nil {
		lg.Printf("AuthDNSQuery: found %s %s in cache", qname, dns.TypeToString[rrtype])
		return crrset.RRset, int(crrset.Rcode), nil
	}
	var rrset RRset
	var rcode int

	// c := dns.Client{Net: "tcp"}

	m := new(dns.Msg)
	m.SetQuestion(qname, rrtype)
	m.SetEdns0(4096, true)
	for _, ns := range nameservers {
		if ns[len(ns)-3:] != ":53" {
			ns = net.JoinHostPort(ns, "53")
		}
		if verbose {
			// lg.Printf("AuthDNSQuery: using nameserver %s for <%s, %s> query\n",
			// 	ns, qname, dns.TypeToString[rrtype])
		}
		r, err := dns.Exchange(m, ns)
		// r, _, err := c.Exchange(m, ns)
		if err != nil && verbose {
			lg.Printf("AuthDNSQuery: Error from dns.Exchange: %v", err)
			continue // go to next server
		}

		if r == nil {
			continue
		}
		rcode = r.MsgHdr.Rcode
		if len(r.Answer) != 0 {
			for _, rr := range r.Answer {
				switch t := rr.Header().Rrtype; t {
				case rrtype:
					rrset.RRs = append(rrset.RRs, rr)
				case dns.TypeRRSIG:
					rrset.RRSIGs = append(rrset.RRSIGs, rr)
				default:
					lg.Printf("Got a %s RR when looking for %s %s",
						dns.TypeToString[t], qname,
						dns.TypeToString[rrtype])
				}
			}

			RRsetCache.Set(qname, rrtype, &CachedRRset{
				Name:       qname,
				RRtype:     rrtype,
				Rcode:      uint8(rcode),
				RRset:      &rrset,
				Expiration: time.Now().Add(getMinTTL(rrset.RRs)),
			})
			return &rrset, rcode, nil
		} else {
			if rcode == dns.RcodeSuccess {
				return &rrset, rcode, nil // no point in continuing
			}
			continue // go to next server
		}
	}
	return &rrset, rcode, fmt.Errorf("no Answers found from any auth server looking up '%s %s'", qname, dns.TypeToString[rrtype])
}

func getMinTTL(rrs []dns.RR) time.Duration {
	if len(rrs) == 0 {
		return 0
	}
	min := rrs[0].Header().Ttl
	for _, rr := range rrs[1:] {
		if rr.Header().Ttl < min {
			min = rr.Header().Ttl
		}
	}
	return time.Duration(min) * time.Second
}

func RecursiveDNSQueryWithConfig(qname string, qtype uint16, timeout time.Duration, retries int) (*RRset, error) {
	resolvers := viper.GetStringSlice("dns.resolvers")
	if len(resolvers) == 0 {
		return nil, fmt.Errorf("no DNS servers found in client configuration")
	}

	rrset, err := RecursiveDNSQueryWithServers(qname, qtype, timeout, retries, resolvers)
	if err != nil {
		return nil, err
	}
	return rrset, nil
}

func RecursiveDNSQueryWithServers(qname string, qtype uint16, timeout time.Duration,
	retries int, resolvers []string) (*RRset, error) {
	if len(resolvers) == 0 {
		return nil, fmt.Errorf("no DNS resolvers provided")
	}

	for _, server := range resolvers {
		rrset, err := RecursiveDNSQuery(server, qname, qtype, timeout, retries)
		if err == nil {
			return rrset, nil
		}
		log.Printf("failed to lookup %s record using server %s after %d attempts to %d resolvers: %v",
			qname, server, retries, len(resolvers), err)
	}

	return nil, fmt.Errorf("failed to find any %s records after trying all resolvers", qname)
}

func RecursiveDNSQueryWithResolvConf(qname string, qtype uint16, timeout time.Duration, retries int) (*RRset, error) {
	clientConfig, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("failed to load DNS client configuration: %v", err)
	}
	if len(clientConfig.Servers) == 0 {
		return nil, fmt.Errorf("no DNS servers found in client configuration")
	}

	rrset, err := RecursiveDNSQueryWithServers(qname, qtype, timeout, retries, clientConfig.Servers)
	if err != nil {
		return nil, err
	}
	return rrset, nil
}

func RecursiveDNSQuery(server, qname string, qtype uint16, timeout time.Duration, retries int) (*RRset, error) {
	m := new(dns.Msg)
	m.SetQuestion(qname, qtype)
	c := &dns.Client{
		Timeout: timeout,
	}

	host, port, err := net.SplitHostPort(server)
	if err != nil {
		// No port specified, use default DNS port
		host = server
		port = "53"
	}
	server = net.JoinHostPort(host, port)

	var rrset RRset
	var lastErr error
	for attempt := 0; attempt < retries; attempt++ {
		backoff := time.Duration(attempt) * 100 * time.Millisecond
		time.Sleep(backoff)
		r, _, err := c.Exchange(m, server)
		if err != nil {
			lastErr = err
			log.Printf("attempt %d/%d: failed to lookup %s %s record using server %s: %v",
				attempt+1, retries, qname, dns.TypeToString[qtype], server, err)
			continue
		}
		if len(r.Answer) == 0 {
			log.Printf("attempt %d/%d: no %s %s records found using server %s",
				attempt+1, retries, qname, dns.TypeToString[qtype], server)
			continue
		}

		for _, ans := range r.Answer {
			if ans.Header().Rrtype == qtype {
				rrset.RRs = append(rrset.RRs, ans)
				continue
			}
			if rrsig, ok := ans.(*dns.RRSIG); ok {
				if rrsig.TypeCovered == qtype {
					rrset.RRSIGs = append(rrset.RRSIGs, rrsig)
				}
				continue
			}
		}

		if len(rrset.RRs) > 0 {
			return &rrset, nil
		}
	}
	return nil, lastErr
}
