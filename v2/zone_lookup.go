/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"log"
	"maps"
	mrand "math/rand/v2"
	"net"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	edns0 "github.com/johanix/tdns/v2/edns0"
	// "github.com/johanix/tdns/v2/transport"
	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func (zd *ZoneData) LookupAndValidateRRset(qname string, qtype uint16,
	verbose bool) (*core.RRset, bool, error) {

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

func (zd *ZoneData) LookupRRset(qname string, qtype uint16, verbose bool) (*core.RRset, error) {
	return zd.lookupRRset(qname, qtype, verbose, true)
}

// lookupRRset is LookupRRset with wildcard synthesis optional. SIG(0) key
// discovery turns it off: a signer's KEY is the one published at the signer's
// name, not one a wildcard would synthesise for any name beneath it.
func (zd *ZoneData) lookupRRset(qname string, qtype uint16, verbose, wildcards bool) (*core.RRset, error) {
	zd.Logger.Printf("LookupRRset: looking up %s %s", qname, dns.TypeToString[qtype])
	var rrset *core.RRset
	var wildqname string
	origqname := qname

	// Is answer in this zone or further down?
	if !zd.NameExists(qname) {
		// A name that does not exist may be answered by the wildcard at its
		// closest encloser, as in QueryResponder. An empty non-terminal
		// exists, so no wildcard answers for it.
		snap := zd.publishedSnapshot()
		if !wildcards || isEmptyNonTerminal(snap, qname) {
			zd.Logger.Printf("*** No data for %s in %s", qname, zd.ZoneName)
			return nil, nil
		}
		wildqname = wildcardSourceFrom(snap, zd.ZoneName, qname)
		lgDns.Debug("---> Checking for existence of wildcard", "wildcard", wildqname)
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
		zd.Logger.Printf("RRset: found a delegation for %s in known zone %s",
			qname, zd.ZoneName)

		addrs, err := ChildGlueRRsToAddrs(cdd.A_glue, cdd.AAAA_glue)
		if err != nil {
			zd.Logger.Printf("LookupRRset: Error from ChildGlueRRsToAddrs: %v", err)
			return nil, err
		}
		rrset, err = lookupChildRRset(zd, qname, qtype, addrs, verbose)
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
		rrset = &core.RRset{}
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

	zd.Logger.Printf("LookupRRset: rrset:\n%s", rrset.String(130))

	lgDns.Debug("LookupRRset: done", "rrset", rrset)
	return rrset, err
}

// XXX: This should die in favor of LookupChildRRsetNG
func (zd *ZoneData) LookupChildRRset(qname string, qtype uint16,
	v4glue, v6glue *core.RRset, verbose bool) (*core.RRset, error) {

	var servers []string

	for _, glue := range v4glue.RRs {
		servers = append(servers, net.JoinHostPort(glue.(*dns.A).A.String(), "53"))
	}
	for _, glue := range v6glue.RRs {
		servers = append(servers, net.JoinHostPort(glue.(*dns.AAAA).AAAA.String(), "53"))
	}

	rrset, _, err := AuthDNSQuery(qname, zd.Logger, servers, qtype, verbose)
	if err != nil {
		zd.Logger.Printf("CRRset: Error from AuthDNSQuery: %v", err)
	}
	zd.Logger.Printf("CRRset: looked up %s %s (%d RRs):", qname, dns.TypeToString[qtype], len(rrset.RRs))
	// log.Printf("LookupChildRRset: done. rrset=%v", rrset)
	return rrset, err
}

func (zd *ZoneData) LookupChildRRsetNG(qname string, qtype uint16,
	addrs []string, verbose bool) (*core.RRset, error) {

	rrset, _, err := AuthDNSQuery(qname, zd.Logger, addrs, qtype, verbose)
	if err != nil {
		zd.Logger.Printf("CRRsetNG: Error from AuthDNSQuery: %v", err)
	}
	zd.Logger.Printf("CRRsetNG: looked up %s %s (%d RRs):", qname, dns.TypeToString[qtype], len(rrset.RRs))
	// log.Printf("LookupChildRRsetNG: done. rrset=%v", rrset)
	return rrset, err
}

func ChildGlueRRsetsToAddrs(v4glue, v6glue []*core.RRset) ([]string, error) {
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
	lgDns.Debug("ChildGlueRRsetsToAddrs", "addrs", addrs)
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

	lgDns.Debug("ChildGlueRRsToAddrs", "addrs", addrs)
	return addrs, nil
}

func RecursiveDNSQueryWithConfig(qname string, qtype uint16, timeout time.Duration, retries int) (*core.RRset, error) {
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
	retries int, resolvers []string) (*core.RRset, error) {
	if len(resolvers) == 0 {
		return nil, fmt.Errorf("no DNS resolvers provided")
	}

	for _, server := range resolvers {
		rrset, err := RecursiveDNSQuery(server, qname, qtype, timeout, retries)
		if err == nil {
			return rrset, nil
		}
		lgDns.Error("failed to lookup record using server after attempts to resolvers",
			"lookup", qname,
			"server", server,
			"after", retries,
			"len", len(resolvers),
			"resolvers", err)
	}

	return nil, fmt.Errorf("failed to find any %s records after trying all resolvers", qname)
}

func RecursiveDNSQueryWithResolvConf(qname string, qtype uint16, timeout time.Duration, retries int) (*core.RRset, error) {
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

func RecursiveDNSQuery(server, qname string, qtype uint16, timeout time.Duration, retries int) (*core.RRset, error) {
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

	var rrset core.RRset
	var lastErr error
	for attempt := 0; attempt < retries; attempt++ {
		backoff := time.Duration(attempt) * 100 * time.Millisecond
		time.Sleep(backoff)
		r, _, err := c.Exchange(m, server)
		if err != nil {
			lastErr = err
			lgDns.Error("attempt /: failed to lookup record using server",
				"attempt", attempt+1,
				"retries", retries,
				"lookup", qname,
				"s", dns.TypeToString[qtype],
				"server", server,
				"s", err)
			continue
		}
		if len(r.Answer) == 0 {
			lastErr = fmt.Errorf("no answers for %s %s from %s", qname, dns.TypeToString[qtype], server)
			lgDns.Debug("attempt /: no records found using server",
				"attempt", attempt+1,
				"retries", retries,
				"qname", qname,
				"s", dns.TypeToString[qtype],
				"server", server)
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
