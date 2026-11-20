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

var lgDns = Logger("dns")

// ErrPrivacyUnavailable is returned when the client asked for strict privacy
// (PRIVACY option, level 2) and no encrypted transport was available to carry
// the query. ImrResponder turns it into SERVFAIL + EDE
// EDEPrivacyRequestedUnavailable.
//
// It is a sentinel, matched with errors.Is, precisely so the message text is
// not load-bearing: the responder used to strings.Contains() on "PR flag
// requires encrypted transport", which meant every error string on this path
// was part of the interface and could not be reworded without silently losing
// the EDE.
var ErrPrivacyUnavailable = errors.New("strict privacy requested but no encrypted transport available")

// PrivacyUnavailableError is a strict-privacy dead end together with the zone
// it happened in: the zone whose servers offered no encrypted transport, or
// none that answered. It matches ErrPrivacyUnavailable, so errors.Is still
// finds the sentinel, and errors.As finds the zone for the EDE.
//
// The zone has to travel with the error because the responder does not know
// it. It knows the zone it started from, and the walk follows referrals on its
// own: the EDE named the parent of the zone that had actually failed (#776).
type PrivacyUnavailableError struct {
	Zone   string
	Detail string
}

func (e *PrivacyUnavailableError) Error() string {
	return fmt.Sprintf("%s: %s", ErrPrivacyUnavailable, e.Detail)
}

func (e *PrivacyUnavailableError) Unwrap() error { return ErrPrivacyUnavailable }

// privacyUnavailable builds the strict-privacy error for zone.
func privacyUnavailable(zone, format string, args ...any) error {
	return &PrivacyUnavailableError{Zone: zone, Detail: fmt.Sprintf(format, args...)}
}

// 1. Is the RRset in a zone that we're auth for? If so we claim that the data is valid
// 2. Is the RRset in a child zone? If so, start by fetching and validating the child DNSKEYs.

// 1. Find the child NS RRset
// 2. Find the address of each NS
// 3. Query child NS for <qname, qtype>

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

// authServerAddr is ns as AuthDNSQuery dials it: ns itself when it carries a
// port, with port 53 added when it does not. The port is told from the address
// by its form (net.SplitHostPort), not by how it ends: an address that ends in
// ":53" is not for that reason one with a port (an IPv6 address can end so),
// and one with another port has one.
func authServerAddr(ns string) string {
	if _, _, err := net.SplitHostPort(ns); err == nil {
		return ns
	}
	return net.JoinHostPort(ns, "53")
}

// authExchange asks the server at ns, a host and a port, for m over UDP, and
// over TCP when the UDP reply has TC set (RFC 1035 section 4.2.1, RFC 7766
// section 3). A truncated reply is not an answer: what it leaves out says
// nothing of what the server serves, and a large RRset, a post-quantum DNSKEY
// RRset above all, goes past the buffer m advertises. Nothing of it is used:
// not the records it may carry, and not the lack of them.
//
// The result is a whole reply or an error, never both. A reply that did not
// unpack comes back from the library as far as it did, and that part is no
// answer. An error means the server has not answered: nothing came back, what
// came did not read, there was no TCP to ask over, or the reply was truncated
// over TCP as well, where TC has no meaning.
func authExchange(m *dns.Msg, ns string) (*dns.Msg, error) {
	r, err := dns.Exchange(m, ns)
	if r != nil && r.Truncated {
		r, _, err = (&dns.Client{Net: "tcp"}).Exchange(m, ns)
		switch {
		case err != nil:
			return nil, fmt.Errorf("reply truncated, and over TCP: %w", err)
		case r == nil || r.Truncated:
			return nil, errors.New("reply truncated, over TCP as well")
		}
		return r, nil
	}
	if err != nil {
		return nil, err
	}
	return r, nil
}

// XXX: Do we still use this anywhere?
func AuthDNSQuery(qname string, lg *log.Logger, nameservers []string,
	rrtype uint16, verbose bool) (*core.RRset, int, error) {

	// crrset := RRsetCache.Get(qname, rrtype)
	// if crrset != nil {
	//	lg.Printf("AuthDNSQuery: found %s %s in cache", qname, dns.TypeToString[rrtype])
	//	return crrset.RRset, int(crrset.Rcode), nil
	// }
	var rrset core.RRset
	var rcode int

	// c := dns.Client{Net: "tcp"}

	m := authQueryMsg(qname, rrtype)
	for _, ns := range nameservers {
		ns = authServerAddr(ns)
		if verbose {
			// lg.Printf("AuthDNSQuery: using nameserver %s for <%s, %s> query\n",
			// 	ns, qname, dns.TypeToString[rrtype])
		}
		r, err := authExchange(m, ns)
		if err != nil {
			if verbose {
				lg.Printf("AuthDNSQuery: no reply from %s: %v", ns, err)
			}
			continue // go to next server
		}

		if r == nil {
			continue
		}
		if qerr := replyMatchesQuery(r, m); qerr != nil {
			lg.Printf("AuthDNSQuery: discarding a reply from %s: %v", ns, qerr)
			continue
		}
		rcode = r.MsgHdr.Rcode
		if len(r.Answer) != 0 {
			lg.Printf("*** AuthDNSQuery: there is stuff in Answer section:")
			// for _, rr := range r.Answer {
			//	lg.Printf("*** AuthDNSQuery: Answer: %s", rr.String())
			//}
			lg.Printf("*** AuthDNSQuery:\n%s", PrintMsgSection("Answer", r.Answer, 130))
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

			// RRsetCache.Set(qname, rrtype, &CachedRRset{
			//	Name:       qname,
			//	RRtype:     rrtype,
			//	Rcode:      uint8(rcode),
			//	RRset:      &rrset,
			//	Expiration: time.Now().Add(getMinTTL(rrset.RRs)),
			// })
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

func (imr *Imr) AuthDNSQuery(ctx context.Context, qname string, qtype uint16, nameservers []string,
	lg *log.Logger, verbose bool) (*core.RRset, int, cache.CacheContext, error) {
	var rrset core.RRset
	var rcode int

	// c := dns.Client{Net: "tcp"}

	m := authQueryMsg(qname, qtype)
	for _, ns := range nameservers {
		ns = authServerAddr(ns)
		if verbose {
			lg.Printf("AuthDNSQuery: using nameserver %s for <%s, %s> query\n",
				ns, qname, dns.TypeToString[qtype])
		}
		r, err := authExchange(m, ns)
		if err != nil {
			if verbose {
				lg.Printf("AuthDNSQuery: no reply from %s: %v", ns, err)
			}
			continue // go to next server
		}

		if r == nil {
			continue
		}
		if qerr := replyMatchesQuery(r, m); qerr != nil {
			lg.Printf("AuthDNSQuery: discarding a reply from %s: %v", ns, qerr)
			continue
		}
		rcode = r.MsgHdr.Rcode
		if len(r.Answer) != 0 {
			if Globals.Debug {
				lg.Printf("*** AuthDNSQuery: there is stuff in Answer section")
			}
			for _, rr := range r.Answer {
				switch t := rr.Header().Rrtype; t {
				case qtype:
					rrset.RRs = append(rrset.RRs, rr)
				case dns.TypeRRSIG:
					rrset.RRSIGs = append(rrset.RRSIGs, rr)
				case dns.TypeCNAME:
					rrset.RRs = append(rrset.RRs, rr)
					// This is a CNAME RR, we need to look up the target of the CNAME
					target := rr.(*dns.CNAME).Target
					maxchase := 10
					for i := 0; i < maxchase; i++ {
						select {
						case <-ctx.Done():
							return nil, 0, cache.ContextFailure, ctx.Err()
						default:
						}
						lg.Printf("*** AuthDNSQuery: found CNAME for %s: %s. Chasing it.", qname, target)
						// We need to look up the target of the CNAME
						tmprrset, rcode, context, err := imr.AuthDNSQuery(ctx, target, qtype, nameservers, lg, verbose)
						if err != nil {
							lg.Printf("*** AuthDNSQuery: Error from AuthDNSQuery: %v", err)
							return nil, rcode, context, err
						}
						switch {
						case tmprrset != nil && len(tmprrset.RRs) != 0:
							rrset.RRs = append(rrset.RRs, tmprrset.RRs...)
							if tmprrset.RRs[0].Header().Rrtype == dns.TypeCNAME {
								// Another CNAME; continue chasing
								target = tmprrset.RRs[0].(*dns.CNAME).Target
								continue
							} else {
								// seems that we have found the answer; cache it and return.
								// State explicitly None here (we have raw answer
								// data but have not validated it). Callers that
								// care about validation are expected to invoke
								// the validator and update the cache entry's
								// State on completion.
								imr.Cache.Set(qname, qtype, &cache.CachedRRset{
									Name:       qname,
									RRtype:     qtype,
									Rcode:      uint8(rcode),
									RRset:      &rrset,
									Context:    cache.ContextAnswer,
									State:      cache.ValidationStateNone,
									Expiration: cache.Now().Add(cache.GetMinTTL(rrset.RRs)),
									Transport:  core.TransportDo53, // AuthDNSQuery path - default to Do53
								})
								return &rrset, rcode, cache.ContextAnswer, nil
							}

						case rcode == dns.RcodeNameError:
							// This is a negative response, and <target, qtype> has already been cached
							// now we only need to cache <qname, qtype>
							imr.Cache.Set(qname, qtype, &cache.CachedRRset{
								Name:      qname,
								RRtype:    qtype,
								Rcode:     uint8(dns.RcodeNameError),
								RRset:     nil,
								Context:   cache.ContextNXDOMAIN,
								State:     cache.ValidationStateNone,
								Transport: core.TransportDo53, // AuthDNSQuery path - default to Do53
							})
							return nil, rcode, context, nil

						default:
							// XXX: Here we should also deal with ContextReferral and ContextNoErrNoAns
							continue
						}
					}
				default:
					lg.Printf("Got a %s RR when looking for %s %s",
						dns.TypeToString[t], qname,
						dns.TypeToString[qtype])
				}
			}

			// If rrset is empty (no matching records) and rcode is NOERROR, this is NODATA, not an answer
			if len(rrset.RRs) == 0 && rcode == dns.RcodeSuccess {
				// This is a negative response (NODATA), not a positive answer
				// Don't cache it here - let it fall through to be handled as negative response
				return nil, rcode, cache.ContextNoErrNoAns, nil
			}
			imr.Cache.Set(qname, qtype, &cache.CachedRRset{
				Name:       qname,
				RRtype:     qtype,
				Rcode:      uint8(rcode),
				RRset:      &rrset,
				Context:    cache.ContextAnswer,
				State:      cache.ValidationStateNone,
				Expiration: cache.Now().Add(cache.GetMinTTL(rrset.RRs)),
				Transport:  core.TransportDo53, // AuthDNSQuery path - default to Do53
			})
			return &rrset, rcode, cache.ContextAnswer, nil
		} else if len(r.Ns) != 0 {
			// This is likely either a negative response or a referral
			if Globals.Debug {
				lg.Printf("*** AuthDNSQuery: there is stuff in Authority section")
			}
			switch rcode {
			case dns.RcodeSuccess:
				// this is either a referral or a negative response
				var rrset core.RRset
				var zonename string

				// 1. Collect the NS RRset from the Authority section
				lg.Printf("*** AuthDNSQ: rcode=NOERROR, this is a referral or neg resp")
				nsMap := map[string]bool{}
				for _, rr := range r.Ns {
					switch rr := rr.(type) {
					case *dns.NS:
						// this is a referral
						rrset.RRs = append(rrset.RRs, rr)
						nsMap[rr.Ns] = true
					case *dns.SOA:
						// this is a negative response, but is the SOA right?
						// Inside the SOA's zone, as a DNS name. A byte suffix
						// accepted an SOA for "ample." as authorising a denial
						// for "example." and missed the mis-cased owner an
						// upstream returns under 0x20 randomisation.
						if dns.IsSubDomain(rr.Header().Name, qname) {
							// Yes, this SOA may auth a negative response for qname
							lgDns.Debug("*** AuthDNSQ: found SOA in Auth, it was a neg resp")
							imr.Cache.Set(qname, qtype, &cache.CachedRRset{
								Name:   qname,
								RRtype: qtype,
								Rcode:  uint8(rcode),
								RRset: &core.RRset{
									Name:   rr.Header().Name,
									Class:  dns.ClassINET,
									RRtype: dns.TypeSOA,
									RRs:    []dns.RR{dns.Copy(rr)},
								},
								Context:    cache.ContextNoErrNoAns,
								State:      cache.ValidationStateNone,
								Transport:  core.TransportDo53, // AuthDNSQuery path - default to Do53
								Expiration: cache.Now().Add(time.Duration(rr.Header().Ttl) * time.Second),
							})
							return nil, rcode, cache.ContextNoErrNoAns, nil
						} else {
							lgDns.Debug("*** The SOA is not correct to speak for qname", "soa", rr.Header().Name, "qname", qname)
							lgDns.Debug("should never get here")
						}
					default:
					}
				}
				if len(rrset.RRs) != 0 {
					zonename = rrset.RRs[0].Header().Name
					rrset.Name = zonename
					rrset.Class = dns.ClassINET
					rrset.RRtype = dns.TypeNS
					imr.Cache.Set(zonename, dns.TypeNS, &cache.CachedRRset{
						Name:       zonename,
						RRtype:     dns.TypeNS,
						Rcode:      uint8(rcode),
						RRset:      &rrset,
						Context:    cache.ContextReferral,
						State:      cache.ValidationStateIndeterminate,
						Expiration: cache.Now().Add(cache.GetMinTTL(rrset.RRs)),
						Transport:  core.TransportDo53, // AuthDNSQuery path - default to Do53
					})
				}

				// 2. Collect any glue from Additional
				glue4Map := map[string]core.RRset{}
				glue6Map := map[string]core.RRset{}
				var servers []string
				serverMap := map[string]*cache.AuthServer{}
				for _, rr := range r.Extra {
					name := rr.Header().Name
					if _, exist := nsMap[name]; !exist {
						lgDns.Debug("*** AuthDNSQuery: non-glue record in Additional", "additional", rr.String())
						continue
					}
					// The zone of the servers asked is not known here, so
					// only in-domain glue is used (imr_referral_glue.go).
					if !withinGlueZone(name, referralGlueZone("", zonename)) {
						lgDns.Debug("AuthDNSQuery: record outside the delegated zone not used", "additional", rr.String(), "zone", zonename)
						continue
					}
					switch rr := rr.(type) {
					case *dns.A:
						addr := rr.A.String()
						servers = append(servers, net.JoinHostPort(addr, "53"))
						// Use shared AuthServer instance across all zones
						server := imr.Cache.GetOrCreateAuthServer(name)
						server.AddAddr(addr)
						server.SetSrc("answer")
						if imr.Debug {
							server.PromoteDebug()
						}
						serverMap[cache.ServerKey(name)] = server
						tmp := glue4Map[name]
						tmp.RRs = append(tmp.RRs, rr)
						glue4Map[name] = tmp

					case *dns.AAAA:
						addr := rr.AAAA.String()
						servers = append(servers, net.JoinHostPort(addr, "53"))
						// Use shared AuthServer instance across all zones
						server := imr.Cache.GetOrCreateAuthServer(name)
						server.AddAddr(addr)
						server.SetSrc("answer")
						if imr.Debug {
							server.PromoteDebug()
						}
						serverMap[cache.ServerKey(name)] = server
						tmp := glue6Map[name]
						tmp.RRs = append(tmp.RRs, rr)
						glue6Map[name] = tmp

					case *dns.SVCB:
						lgDns.Debug("Additional contains an SVCB, here we should collect the ALPN")
						svcb := rr
						// Ensure we have a shared AuthServer instance for this NS
						server := imr.Cache.GetOrCreateAuthServer(name)
						serverMap[cache.ServerKey(name)] = server
						for _, kv := range svcb.Value {
							if kv.Key() == dns.SVCB_ALPN {
								if alpn, ok := kv.(*dns.SVCBAlpn); ok {
									var transports []core.Transport
									for _, t := range alpn.Alpn {
										switch t {
										case "dot":
											transports = append(transports, core.TransportDoT)
										case "doh":
											transports = append(transports, core.TransportDoH)
										case "doq":
											transports = append(transports, core.TransportDoQ)
										}
									}
									if alpn, ok := kv.(*dns.SVCBAlpn); ok {
										server.SetAlpn(alpn.Alpn)
										server.SetTransports(transports)
										lgDns.Debug("Found ALPN values for", "name", name, "s", alpn.Alpn)
									}
								}
							}
						}
					default:
					}
				}

				lgDns.Debug("AuthDNSQuery: adding servers for zone to cache", "count", len(servers), "zone", zonename)
				imr.Cache.Servers.Set(zonename, servers)

				for nsname, rrset := range glue4Map {
					if len(rrset.RRs) == 0 {
						continue
					}
					rr := rrset.RRs[0]
					imr.Cache.SetUnless(nsname, dns.TypeA, &cache.CachedRRset{
						Name:       nsname,
						RRtype:     dns.TypeA,
						RRset:      &rrset,
						Context:    cache.ContextGlue,
						State:      cache.ValidationStateIndeterminate,
						Expiration: cache.Now().Add(time.Duration(rr.Header().Ttl) * time.Second),
						Transport:  core.TransportDo53, // AuthDNSQuery path - default to Do53
					}, glueKeeps) // not over a live answer (glueMayReplace)
				}

				for nsname, rrset := range glue6Map {
					if len(rrset.RRs) == 0 {
						continue
					}
					rr := rrset.RRs[0]
					imr.Cache.SetUnless(nsname, dns.TypeAAAA, &cache.CachedRRset{
						Name:       nsname,
						RRtype:     dns.TypeAAAA,
						RRset:      &rrset,
						Context:    cache.ContextGlue,
						State:      cache.ValidationStateIndeterminate,
						Expiration: cache.Now().Add(time.Duration(rr.Header().Ttl) * time.Second),
						Transport:  core.TransportDo53, // AuthDNSQuery path - default to Do53
					}, glueKeeps) // not over a live answer (glueMayReplace)
				}

				return nil, rcode, cache.ContextReferral, nil

			case dns.RcodeNameError:
				// this is a negative response
				// For NXDOMAIN, verify SOA exists in authority section
				var foundSOA bool
				var ttl uint32
				for _, rr := range r.Ns {
					if rr.Header().Rrtype == dns.TypeSOA {
						foundSOA = true
						ttl = rr.Header().Ttl
						break
					}
				}
				if !foundSOA {
					// Invalid NXDOMAIN response without SOA
					continue // try next server
				}
				// Now we know this is an NXDOMAIN
				imr.Cache.Set(qname, qtype, &cache.CachedRRset{
					Name:       qname,
					RRtype:     qtype,
					Rcode:      uint8(dns.RcodeNameError),
					RRset:      nil,
					Context:    cache.ContextNXDOMAIN,
					Expiration: cache.Now().Add(time.Duration(ttl) * time.Second),
					Transport:  core.TransportDo53, // AuthDNSQuery path - default to Do53
				})

				return nil, rcode, cache.ContextNXDOMAIN, nil
			default:
				lgDns.Debug("*** AuthDNSQuery: surprising rcode", "rcode", dns.RcodeToString[rcode])
			}
		} else {
			if rcode == dns.RcodeSuccess {
				return &rrset, rcode, cache.ContextFailure, nil // no point in continuing
			}
			continue // go to next server
		}
	}
	return &rrset, rcode, cache.ContextNoErrNoAns, fmt.Errorf("no Answers found from any auth server looking up '%s %s'", qname, dns.TypeToString[qtype])
}

// ServerAddrXportTuple represents one prioritized query candidate: a server,
// one of its addresses, and the transport to use for the attempt.
// Rank is the index of Transport in candidateTransports for this
// (qname, server) — 0 is the OOTS share-weighted winner. Family is the
// address family selection decided on: that of the address the attempt
// would dial then (attemptKey), a redirect target's or the server's own.
// FamilyUnknown for a tuple made elsewhere. Probe is whether selection let
// the tuple through as that family's recovery probe (ShouldProbe), the
// family being suspect.
type ServerAddrXportTuple struct {
	Server    *cache.AuthServer
	Addr      string
	NSName    string
	Transport core.Transport
	Rank      int
	Family    cache.AddressFamily
	Probe     bool
}

// hostLocalAddr reports whether addr, a bare IP literal, reaches this host: a
// loopback address (127.0.0.0/8, ::1), or an unspecified one (0.0.0.0, ::),
// which the kernel also delivers locally.
func hostLocalAddr(addr string) bool {
	if i := strings.IndexByte(addr, '%'); i >= 0 {
		addr = addr[:i] // an IPv6 zone
	}
	ip := net.ParseIP(addr)
	return ip != nil && (ip.IsLoopback() || ip.IsUnspecified())
}

// mayQueryAddr reports whether a query may go to server at addr. An address on
// this host is used only if the operator configured it for the server (a
// stub's, RRsetCacheT.AddStub), or with the allow-loopback-nameservers option:
// a referral, glue or an address lookup must not be able to point the resolver
// at services on its own host (#831). The test is the address, not the server:
// glue can add addresses to a stub's server too.
func mayQueryAddr(server *cache.AuthServer, addr string, allowHostLocal bool) bool {
	return allowHostLocal || !hostLocalAddr(addr) || server.IsConfiguredAddr(addr)
}

// allowHostLocalServers reports whether allow-loopback-nameservers is set.
func (imr *Imr) allowHostLocalServers() bool {
	return imr.Options[ImrOptAllowLoopbackNameservers] == "true"
}

// prioritizeServers returns a flat, prioritized list of
// (server, addr, transport) tuples for the IMR to try in order.
//
// For each (server, addr):
//   - Skip an address on this host, unless mayQueryAddr allows it.
//   - Emit one tuple per available transport, filtered against the
//     per-(addr, transport) backoff on both the server and the
//     enclosing zone (lame-delegation tracking).
//   - Rank mirrors candidateTransports order (OOTS share winner = 0).
//   - Final order: ascending Rank, then ascending RTT within the same
//     Rank, so a faster fallback cannot leapfrog the share-picked winner.
//
// privacy is passed through to candidateTransports: PrivacyStrict excludes
// Do53 tuples, and a server with no encrypted transport then contributes no
// tuples at all.
//
// qtype picks the zone whose backoff applies: the zone holding the data, which
// for a DS is the parent's, the zone of the servers the DS query goes to.
func (imr *Imr) prioritizeServers(qname string, qtype uint16, serverMap map[string]*cache.AuthServer, privacy edns0.PrivacyLevel) (string, *cache.Zone, []ServerAddrXportTuple) {
	return imr.prioritizeServersFor(context.Background(), qname, qtype, serverMap, privacy)
}

// prioritizeServersFor is prioritizeServers for the query ctx belongs to. The
// server's backoff and the zone's lameness are those of the address and port
// an attempt would dial (attemptKey), which depends on ctx: a context marked
// withDefaultEndpoints dials the server's own address whatever its signal
// says.
func (imr *Imr) prioritizeServersFor(ctx context.Context, qname string, qtype uint16, serverMap map[string]*cache.AuthServer, privacy edns0.PrivacyLevel) (string, *cache.Zone, []ServerAddrXportTuple) {
	return imr.selectServerTuples(ctx, qname, qtype, serverMap, privacy, true, nil)
}

// tupleSkip, when given to selectServerTuples, leaves out a tuple whose
// attempt would dial addr at port over t at server, the instance dialed (the
// nameserver's own, or a redirect target's): an endpoint a pass has already
// tried (anotherPassAfter). It is asked after the backoff tests and
// before the family test, so that a suspect family's probe is not reserved
// for a tuple that is left out.
type tupleSkip func(server *cache.AuthServer, addr string, port uint16, t core.Transport) bool

// selectServerTuples is prioritizeServersFor, which it is with warn set and
// no skip. Without warn it says nothing when no tuple is left: the query loop
// asks first, and waits for its servers' transport signals before it gives up
// on them (awaitUsableTuples).
func (imr *Imr) selectServerTuples(ctx context.Context, qname string, qtype uint16, serverMap map[string]*cache.AuthServer, privacy edns0.PrivacyLevel, warn bool, skip tupleSkip) (string, *cache.Zone, []ServerAddrXportTuple) {
	zoneName, _, _ := imr.Cache.FindClosestKnownZoneFor(qname, qtype)
	var zone *cache.Zone
	if zoneName != "" {
		if z, ok := imr.Cache.ZoneMap.Get(zoneName); ok {
			zone = z
		}
	}

	allowHostLocal := imr.allowHostLocalServers()
	var tuples []ServerAddrXportTuple
	var suspectTuples []ServerAddrXportTuple
	for nsname, server := range serverMap {
		transports := candidateTransports(server, qname, privacy)
		if len(transports) == 0 {
			continue
		}
		if server == nil {
			// GetAddrs is nil-safe, so this does not crash -- but a nil entry
			// and a server with no addresses are different faults, and saying
			// "no addresses" about a nil entry sends the reader looking for a
			// nameserver that was never there.
			noteServerProblem(zoneName, nsname, "nil server entry in the server map")
			continue
		}
		addrs := server.GetAddrs()
		if len(addrs) == 0 {
			// A server in the map with no addresses contributes nothing and,
			// until now, said nothing either -- indistinguishable in the logs
			// from a server that was tried and failed. It is never normal: it
			// is either a defect in how the map was populated, or a delegation
			// whose nameserver has no address records. Worth a line even when
			// other servers carry the query, because nothing else will ever
			// mention it.
			noteServerProblem(zoneName, nsname, "no addresses")
			continue
		}
		for _, addr := range addrs {
			if !mayQueryAddr(server, addr, allowHostLocal) {
				noteServerProblem(zoneName, nsname, "address "+addr+" is on this host (allow-loopback-nameservers is not set)")
				continue
			}
			for rank, t := range transports {
				// What the attempt would dial (attemptKey): the endpoint's
				// address and port, where both the backoff of the instance
				// dialed (the server's own, or a redirect target's) and the
				// zone's lameness are read. A target whose addresses are not
				// known is looked up from here, so that the default
				// endpoint's backoff does not keep it from being found.
				d, ok := imr.attemptKey(ctx, server, zone, addr, t, true)
				if !ok || !d.server.IsEndpointAddrAvailable(d.addr, d.keyPort, t) {
					if Globals.Debug {
						lgDns.Debug("prioritizeServers: skipping (addr,transport) due to server backoff",
							"addr", addr, "dial", cache.JoinDialAddr(d.addr, d.keyPort), "transport", core.TransportToString[t], "ns", nsname)
					}
					continue
				}
				if zone != nil && !zone.IsZoneEndpointAvailable(d.addr, d.keyPort, t) {
					if Globals.Debug {
						lgDns.Debug("prioritizeServers: skipping (addr,transport) due to zone backoff",
							"addr", addr, "dial", cache.JoinDialAddr(d.addr, d.keyPort), "transport", core.TransportToString[t], "ns", nsname, "zone", zoneName)
					}
					continue
				}
				if skip != nil && skip(d.server, d.addr, d.keyPort, t) {
					continue
				}
				// Address-family deprioritization (W8). If the local host's
				// v4 or v6 path is currently suspect, suppress those tuples
				// — but let one through per ProbeInterval as a recovery
				// probe, appended after the healthy bucket. The family is
				// that of the address dialed: a redirect target's may not be
				// the glue's.
				fam := cache.FamilyOf(d.addr)
				tup := ServerAddrXportTuple{
					Server: server, Addr: addr, NSName: nsname, Transport: t, Rank: rank, Family: fam,
				}
				if imr.FamilyTracker.IsSuspect(fam) {
					if imr.FamilyTracker.ShouldProbe(fam) {
						tup.Probe = true
						suspectTuples = append(suspectTuples, tup)
					} else if Globals.Debug {
						lgDns.Debug("prioritizeServers: skipping suspect-family (addr,transport)",
							"addr", addr, "transport", core.TransportToString[t], "family", int(fam))
					}
					continue
				}
				tuples = append(tuples, tup)
			}
		}
	}

	// A zero-tuple result is always a dead end: the query loop below never
	// runs, the caller sees attempts==0, and the only trace is a phrase inside
	// an error string. It is never normal and never recoverable, so say why --
	// at WARN, and not gated on debug, because this is exactly the state that
	// is impossible to diagnose after the fact.
	if warn && len(tuples) == 0 && len(suspectTuples) == 0 {
		lgDns.Warn("prioritizeServers: no usable (server, addr, transport) tuples; the query cannot be sent",
			"qname", qname, "zone", zoneName, "servers", len(serverMap),
			"privacy", privacy.String(), "why", imr.explainNoTuplesFor(ctx, serverMap, zone, qname, privacy, allowHostLocal))
	}

	sortTuplesByRankThenRTT(tuples, func(tup ServerAddrXportTuple) (time.Duration, bool) {
		return imr.tupleRTT(ctx, zone, tup)
	})
	// Suspect-family tuples (if any) follow the healthy ones — they're
	// reachable in principle, just deprioritized while the family is suspect.
	tuples = append(tuples, suspectTuples...)
	return zoneName, zone, tuples
}

// awaitUsableTuples is prioritizeServersFor for the query loop. When no
// (server, addr, transport) tuple is left, a server may only be waiting for
// its transport signal: its one transport so far, Do53, is in backoff, and
// the lookup that would give it others is running, or has not been made. The
// query then starts or joins those lookups and waits for them, as a strict
// query does (awaitTransportSignalsUntil), and selects again.
//
// Without it a query that a referral had just brought to a server with no
// Do53 failed while that server's signal was being validated: both had tried
// the server over Do53 first and been refused, and the referral was followed
// before the signal could be installed (#1065).
//
// Before it selects, it waits for the signal lookups of the servers that are
// still looking theirs up (awaitRunningSignalLookups), so that the query goes
// out over what the signal offers rather than over Do53 first.
func (imr *Imr) awaitUsableTuples(ctx context.Context, budget *signalWaitBudget, qname string, qtype uint16, serverMap map[string]*cache.AuthServer, privacy edns0.PrivacyLevel) (string, *cache.Zone, []ServerAddrXportTuple) {
	imr.awaitRunningSignalLookups(ctx, budget, qtype, serverMap)
	zoneName, zone, tuples := imr.selectServerTuples(ctx, qname, qtype, serverMap, privacy, false, nil)
	if len(tuples) > 0 {
		return zoneName, zone, tuples
	}
	// Only a server with an address can be made usable by its signal. One
	// without is the address fallback's to resolve, after this pass, and
	// waiting for its signal first only held that up.
	withAddrs := make(map[string]*cache.AuthServer, len(serverMap))
	for key, server := range serverMap {
		if server != nil && len(server.GetAddrs()) > 0 {
			withAddrs[key] = server
		}
	}
	if len(withAddrs) == 0 {
		return imr.prioritizeServersFor(ctx, qname, qtype, serverMap, privacy)
	}
	// The selection that ends the wait is the one used: selecting again could
	// lose a suspect family's probe tuple, which is let through once per
	// probe interval.
	budget.run(ctx, imr.strictWait(), func(wctx context.Context) bool {
		return imr.awaitTransportSignalsUntil(wctx, withAddrs, transportQueryReasonNoUsableTransport, func() bool {
			zoneName, zone, tuples = imr.selectServerTuples(ctx, qname, qtype, serverMap, privacy, false, nil)
			return len(tuples) > 0
		})
	})
	if len(tuples) > 0 {
		return zoneName, zone, tuples
	}
	return imr.prioritizeServersFor(ctx, qname, qtype, serverMap, privacy)
}

// awaitRunningSignalLookups waits, within the query's budget, for the
// transport-signal lookups of the servers in serverMap that have an address
// and no signal yet: until one of the servers has a signal, or every lookup
// has ended. A server with a signal already ends it at once, and whichever
// lookup ends first is looked at first, so a lookup that never ends does not
// hold up a server whose signal has come in. A lookup is waited for when it
// is running, typically the one the referral that brought the query here
// started (always-query-for-transport), and with always-query-for-transport
// it is started when it is not. A server whose signal is denied, or whose
// lookup failed and is cooling down, is not waited for.
//
// The query then goes out over what the signal offers. Without the wait it
// went to the server over Do53 first, before the signal was in. A server
// that refuses queries over Do53 answered REFUSED, and the refusal put Do53
// to it in the zone's backoff. A nameserver named inside its own zone has
// its signal in that zone, so the signal lookup was left with nothing to
// send if it had not sent its query yet, and every query to the zone failed
// until the backoff ran out, then failed the same way again (#1116).
//
// A transport-signal lookup, and what it asks on the way, never waits
// (awaitTransportSignalsUntil). Nor do DNSKEY and DS queries: they validate
// signals, and a lookup validates a denial with a context of its own, so its
// DNSKEY query would otherwise wait for the very lookup it serves until the
// budget ran out.
func (imr *Imr) awaitRunningSignalLookups(ctx context.Context, budget *signalWaitBudget, qtype uint16, serverMap map[string]*cache.AuthServer) {
	if qtype == dns.TypeDNSKEY || qtype == dns.TypeDS || inTransportSignalLookup(ctx) {
		return
	}
	withAddrs := make(map[string]*cache.AuthServer, len(serverMap))
	for key, server := range serverMap {
		if server != nil && len(server.GetAddrs()) > 0 {
			withAddrs[key] = server
		}
	}
	signalled := func() bool {
		for _, server := range withAddrs {
			if len(server.GetTransportWeights()) > 0 {
				return true
			}
		}
		return false
	}
	if len(withAddrs) == 0 || signalled() {
		return
	}
	budget.run(ctx, imr.strictWait(), func(wctx context.Context) bool {
		return imr.awaitTransportSignalsUntil(wctx, withAddrs, transportQueryReasonNewServer, signalled)
	})
}

// tupleSelection is one selection of a query's (server, addr, transport)
// tuples, with the zone whose backoff applied (selectServerTuples).
type tupleSelection struct {
	zoneName string
	zone     *cache.Zone
	tuples   []ServerAddrXportTuple
	// tried is the endpoints the pass before tried, which the selection
	// left out (anotherPassAfter): the next pass's attempts do not dial
	// them either (attemptSelection).
	tried map[passTuple]bool
}

// signalWaitBudget is what a query may spend waiting for transport signals:
// discovery.strict-wait in all, however many times it waits (the strict
// precheck, awaitUsableTuples, anotherPassAfter). Only the time spent
// waiting counts. Without it a query whose servers' lookups never ended
// waited strict-wait at the start of its pass and again after it.
//
// One query is the whole lookup, referrals and the lookups nested in it
// included: the budget travels on the context (signalWaitBudgetFor).
// Several of them may wait at once, hence the lock.
type signalWaitBudget struct {
	mu    sync.Mutex
	spent time.Duration
}

// signalWaitBudgetKey carries a query's signalWaitBudget on its context.
type signalWaitBudgetKey struct{}

// signalWaitBudgetFor returns the budget ctx carries, or a new one and a
// context carrying it.
func signalWaitBudgetFor(ctx context.Context) (context.Context, *signalWaitBudget) {
	if b, ok := ctx.Value(signalWaitBudgetKey{}).(*signalWaitBudget); ok && b != nil {
		return ctx, b
	}
	b := &signalWaitBudget{}
	return context.WithValue(ctx, signalWaitBudgetKey{}, b), b
}

// run calls wait with a context that ends when the budget is spent, or with
// ctx, and counts the time it took against the budget. Once the budget is
// spent, wait still runs, and starts its lookups, but does not wait.
func (b *signalWaitBudget) run(ctx context.Context, total time.Duration, wait func(context.Context) bool) bool {
	b.mu.Lock()
	left := total - b.spent
	b.mu.Unlock()
	if left < 0 {
		left = 0
	}
	wctx, cancel := context.WithTimeout(ctx, left)
	defer cancel()
	start := time.Now()
	ok := wait(wctx)
	b.mu.Lock()
	b.spent += time.Since(start)
	b.mu.Unlock()
	return ok
}

// strictWait is the tuning's discovery.strict-wait, or its default.
func (imr *Imr) strictWait() time.Duration {
	if imr.Tuning.Discovery.StrictWait > 0 {
		return imr.Tuning.Discovery.StrictWait
	}
	return defaultDiscoveryStrictWait
}

// passTuple is an endpoint a pass of the query loop has tried
// (anotherPassAfter): the instance the attempt went to, the nameserver or a
// redirect target, and the address and port it dialed (endpointDial) over the
// tuple's transport. A tuple whose attempt would now dial elsewhere, as a udp
// endpoint on 5353 that failed gives way to port 53 at the nameserver, is not
// one the pass tried.
type passTuple struct {
	server    *cache.AuthServer
	addr      string
	port      uint16
	transport core.Transport
}

// anotherPassSelectedHook, when set, runs in anotherPassAfter after the pass's
// first selection, before the target lookups are looked at again: tests end
// or allow a lookup there.
var anotherPassSelectedHook func()

// anotherPassWaitHook, when set, runs in anotherPassAfter when its wait
// begins, once the running target lookups are collected and no tuple is
// usable: tests end a lookup there, so that the wait is what sees it.
var anotherPassWaitHook func()

// anotherPassAfter decides whether a pass of the query loop that ran out of
// tuples without an answer is worth another, given the tuples it tried, and
// returns the selection the next pass is to use, or nil.
//
// It is when a tuple the pass did not try is available now. Typically a
// server's transport signal came in during the pass, while the query's own
// Do53 attempt to it was being refused: the server has transports the pass
// never had (#1065). Only tried tuples left: they failed without a backoff,
// and another pass would repeat them, unless a redirect target's lookup is
// running, whose addresses are tuples the pass never had. No tuple left at
// all: every one it tried went into backoff, and a server without a signal
// may have nothing else yet. It then waits, within the query's budget, until
// an untried tuple appears: for the running lookups of the redirect targets
// the servers' signals send a transport the query may use to
// (targetLookupWatch), and, unless tried tuples are left, for the signals of
// the servers that have an address and none, the two side by side
// (awaitTargetsAndSignals). A query held to the default
// endpoints (withDefaultEndpoints), as a target's own address lookup is,
// never dials a target, and waits for none. A transport
// redirected to a target whose addresses are still being looked up goes to
// its default endpoint, the nameserver's own address, which may not serve
// it; once that attempt has failed, the target is the one thing left, and the
// first strict query to a cold target used to fail although its addresses
// came in a moment later.
//
// The next pass uses the selection made here rather than selecting again:
// selecting reserves a suspect family's probe tuple (ShouldProbe), and a
// second selection within the probe interval would leave it out. The
// selection leaves out the endpoints the pass tried before it reserves a
// probe, so the next pass holds only the tuples it did not try, and a probe
// is not used up on a tuple that would be left out.
func (imr *Imr) anotherPassAfter(ctx context.Context, budget *signalWaitBudget, qname string, qtype uint16, serverMap map[string]*cache.AuthServer, privacy edns0.PrivacyLevel, tried map[passTuple]bool) *tupleSelection {
	sel := tupleSelection{tried: tried}
	triedLeft := false
	skip := func(server *cache.AuthServer, addr string, port uint16, t core.Transport) bool {
		if tried[passTuple{server, addr, port, t}] {
			triedLeft = true
			return true
		}
		return false
	}
	untried := func() bool {
		triedLeft = false
		sel.zoneName, sel.zone, sel.tuples = imr.selectServerTuples(ctx, qname, qtype, serverMap, privacy, false, skip)
		return len(sel.tuples) > 0
	}
	// Where the target lookups stand is read before the first selection,
	// so that one ending after it shows (targetLookupWatch).
	var watch func() (map[string]<-chan struct{}, bool)
	if !defaultEndpointsOnly(ctx) {
		watch = imr.targetLookupWatch(serverMap, qname, privacy)
		watch()
	}
	if untried() {
		return &sel
	}
	if anotherPassSelectedHook != nil {
		anotherPassSelectedHook()
	}
	// The running target lookups are collected, to be waited for, and the
	// selection made again: a target's retry mark may have run out since the
	// last one, and a selection starts the lookup of such a target itself.
	// It is made again for as long as a lookup has ended since the selection
	// before, whose tuples that selection may not have seen.
	targets := map[string]<-chan struct{}{}
	for reselected := false; watch != nil; reselected = true {
		running, ended := watch()
		maps.Copy(targets, running)
		if reselected && !ended {
			break
		}
		if untried() {
			return &sel
		}
	}
	if triedLeft && len(targets) == 0 {
		return nil
	}
	unsignalled := map[string]*cache.AuthServer{}
	if !triedLeft {
		for key, server := range serverMap {
			if server != nil && len(server.GetAddrs()) > 0 && len(server.GetTransportWeights()) == 0 {
				unsignalled[key] = server
			}
		}
	}
	if len(unsignalled) == 0 && len(targets) == 0 {
		return nil
	}
	if budget.run(ctx, imr.strictWait(), func(wctx context.Context) bool {
		if anotherPassWaitHook != nil {
			anotherPassWaitHook()
		}
		switch {
		case len(targets) > 0 && len(unsignalled) > 0:
			return imr.awaitTargetsAndSignals(wctx, targets, watch, unsignalled, untried)
		case len(targets) > 0:
			return awaitTargetLookups(wctx, targets, watch, untried)
		default:
			return imr.awaitTransportSignalsUntil(wctx, unsignalled, transportQueryReasonNoUsableTransport, untried)
		}
	}) {
		return &sel
	}
	return nil
}

// awaitTargetsAndSignals waits for the target lookups in targets
// (awaitTargetLookups) and the signals of the servers in unsignalled
// (awaitTransportSignalsUntil) side by side, both within ctx, so that neither
// spends the other's time: a target lookup that runs to its own deadline
// would otherwise leave a signal wait made after it no time at all, and a
// signal lookup it starts would never be waited for. The first wait that
// ready says yes to ends the other. ready is asked by one wait at a time, and
// once it has said yes it is not asked again: the selection it made stands.
func (imr *Imr) awaitTargetsAndSignals(ctx context.Context, targets map[string]<-chan struct{}, watch func() (map[string]<-chan struct{}, bool), unsignalled map[string]*cache.AuthServer, ready func() bool) bool {
	var mu sync.Mutex
	found := false
	readyOnce := func() bool {
		mu.Lock()
		defer mu.Unlock()
		if !found {
			found = ready()
		}
		return found
	}
	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if awaitTargetLookups(wctx, targets, watch, readyOnce) {
			cancel()
		}
	}()
	go func() {
		defer wg.Done()
		if imr.awaitTransportSignalsUntil(wctx, unsignalled, transportQueryReasonNoUsableTransport, readyOnce) {
			cancel()
		}
	}()
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	return found
}

// attemptSelection is what selection decided for an attempt, which tryServer
// holds the attempt to: the address family it decided on and whether it
// reserved that family's probe (ServerAddrXportTuple.Family and Probe;
// FamilyUnknown for no decision), and the endpoints the pass before tried,
// which an extra pass's selection left out (tupleSelection.tried). The zero
// value holds the attempt to nothing.
type attemptSelection struct {
	family cache.AddressFamily
	probe  bool
	tried  map[passTuple]bool
}

// suspectWithoutProbe reports whether addr, the address an attempt is about
// to dial, is of a family held suspect that selection reserved no probe for:
// it decided on another family, or on this one while it was healthy.
// FamilyUnknown is no decision, and holds nothing back.
func (imr *Imr) suspectWithoutProbe(sel attemptSelection, addr string) bool {
	fam := cache.FamilyOf(addr)
	if sel.family == cache.FamilyUnknown || !imr.FamilyTracker.IsSuspect(fam) {
		return false
	}
	return !sel.probe || fam != sel.family
}

// passTried is the endpoint a pass's attempt counts as tried, which
// anotherPassAfter leaves out of the next selection: the one tryServer
// dialed, or the server's own address when it did not get as far as choosing
// one, under the tuple's transport t. An attempt refused because the address
// it would dial is of a suspect family with no probe reserved
// (errEndpointSuspectFamily) counts as none: nothing was sent, and the next
// selection decides on that family afresh, letting the tuple through as its
// probe when one is due and leaving it out otherwise.
func passTried(server *cache.AuthServer, addr string, t core.Transport, ep endpointDial, err error) (passTuple, bool) {
	if ep.addr != "" {
		return passTuple{ep.server, ep.addr, ep.keyPort, t}, true
	}
	var suspect errEndpointSuspectFamily
	if errors.As(err, &suspect) {
		return passTuple{}, false
	}
	return passTuple{server, addr, 0, t}, true
}

// unprobedRTTSentinel is the RTT used for sort when no usable sample exists
// for a tuple. A midpoint value keeps unprobed tuples between known-fast and
// known-slow ones, so they get tried at a reasonable priority and acquire a
// real sample.
const unprobedRTTSentinel = 200 * time.Millisecond

// sortTuplesByRankThenRTT stable-sorts by OOTS candidate Rank ascending
// (share winner first), then by RTT ascending within the same Rank, the RTT
// of each tuple as rttOf reads it (tupleRTT: that of what the attempt would
// dial). unprobedRTTSentinel is used when no usable RTT sample exists.
func sortTuplesByRankThenRTT(tuples []ServerAddrXportTuple, rttOf func(ServerAddrXportTuple) (time.Duration, bool)) {
	if len(tuples) < 2 {
		return
	}
	rtts := make([]time.Duration, len(tuples))
	for i, tup := range tuples {
		if r, ok := rttOf(tup); ok {
			rtts[i] = r
		} else {
			rtts[i] = unprobedRTTSentinel
		}
	}
	indices := make([]int, len(tuples))
	for i := range indices {
		indices[i] = i
	}
	sort.SliceStable(indices, func(i, j int) bool {
		a, b := indices[i], indices[j]
		if tuples[a].Rank != tuples[b].Rank {
			return tuples[a].Rank < tuples[b].Rank
		}
		return rtts[a] < rtts[b]
	})
	sorted := make([]ServerAddrXportTuple, len(tuples))
	for newIdx, oldIdx := range indices {
		sorted[newIdx] = tuples[oldIdx]
	}
	copy(tuples, sorted)
}

// explainNoTuples says, per server, why it contributed no (addr, transport)
// tuple. Written for the case that produced #344: a server that is present in
// the map and named in the logs, but yields nothing -- which until now looked
// identical to having no server at all.
func explainNoTuples(serverMap map[string]*cache.AuthServer, zone *cache.Zone,
	ft *cache.FamilyTracker, qname string, privacy edns0.PrivacyLevel, allowHostLocal bool) string {
	serverAllows := func(server *cache.AuthServer, addr string, t core.Transport) bool {
		return server.IsEndpointAddrAvailable(addr, server.SelfPort(t), t)
	}
	zoneAllows := func(server *cache.AuthServer, addr string, t core.Transport) bool {
		return zone.IsZoneEndpointAvailable(addr, server.SelfPort(t), t)
	}
	return explainNoTuplesWith(serverMap, zone, ft, qname, privacy, allowHostLocal, serverAllows, zoneAllows)
}

// explainNoTuplesFor is explainNoTuples with the backoff tests
// prioritizeServersFor applies for ctx.
func (imr *Imr) explainNoTuplesFor(ctx context.Context, serverMap map[string]*cache.AuthServer, zone *cache.Zone,
	qname string, privacy edns0.PrivacyLevel, allowHostLocal bool) string {
	serverAllows := func(server *cache.AuthServer, addr string, t core.Transport) bool {
		d, ok := imr.attemptKey(ctx, server, zone, addr, t, false)
		return ok && d.server.IsEndpointAddrAvailable(d.addr, d.keyPort, t)
	}
	zoneAllows := func(server *cache.AuthServer, addr string, t core.Transport) bool {
		d, ok := imr.attemptKey(ctx, server, zone, addr, t, false)
		return ok && zone.IsZoneEndpointAvailable(d.addr, d.keyPort, t)
	}
	return explainNoTuplesWith(serverMap, zone, imr.FamilyTracker, qname, privacy, allowHostLocal, serverAllows, zoneAllows)
}

// explainNoTuplesWith is explainNoTuples with the server's backoff test and
// the zone's given.
func explainNoTuplesWith(serverMap map[string]*cache.AuthServer, zone *cache.Zone,
	ft *cache.FamilyTracker, qname string, privacy edns0.PrivacyLevel, allowHostLocal bool,
	serverAllows func(*cache.AuthServer, string, core.Transport) bool,
	zoneAllows func(*cache.AuthServer, string, core.Transport) bool) string {

	if len(serverMap) == 0 {
		return "no servers in the map for this zone"
	}
	reasons := make([]string, 0, len(serverMap))
	for nsname, server := range serverMap {
		switch {
		case server == nil:
			reasons = append(reasons, fmt.Sprintf("%s: nil server entry", nsname))
			continue
		case len(candidateTransports(server, qname, privacy)) == 0:
			reasons = append(reasons, fmt.Sprintf("%s: no usable transport (privacy=%s, no encrypted transport available)", nsname, privacy))
			continue
		}
		addrs := server.GetAddrs()
		if len(addrs) == 0 {
			// The silent case: present, named in every log line, and unusable.
			reasons = append(reasons, fmt.Sprintf("%s: no addresses", nsname))
			continue
		}
		// Each tuple is counted under the first reason prioritizeServers would
		// skip it for, so the counts add up. The family count used to be
		// missing: "2 addr(s), 1 in server backoff" read as a contradiction when
		// the other address was on a family the tracker held suspect (#703).
		var hostLocal, serverBackoff, zoneBackoff, familySuspect int
		for _, addr := range addrs {
			for _, t := range candidateTransports(server, qname, privacy) {
				if !mayQueryAddr(server, addr, allowHostLocal) {
					hostLocal++
					continue
				}
				if !serverAllows(server, addr, t) {
					serverBackoff++
					continue
				}
				if zone != nil && !zoneAllows(server, addr, t) {
					zoneBackoff++
					continue
				}
				if ft.IsSuspect(cache.FamilyOf(addr)) {
					familySuspect++
				}
			}
		}
		reasons = append(reasons, fmt.Sprintf("%s: %d addr(s), %d on this host, %d in server backoff, %d in zone backoff, %d on a suspect address family",
			nsname, len(addrs), hostLocal, serverBackoff, zoneBackoff, familySuspect))
	}
	sort.Strings(reasons)
	return strings.Join(reasons, "; ")
}

// Unusable-server reports are deduplicated: the condition is a standing state,
// not an event, so repeating it per query would bury the log without adding
// information. The state is bounded in both directions -- entries expire so a
// problem that persists is re-reported eventually, and the table is capped so a
// resolver meeting an unbounded number of broken delegations cannot grow it
// without limit.
const (
	unusableServerRepeat  = time.Hour
	unusableServerMaxKeys = 1024
)

var (
	unusableServersMu sync.Mutex
	unusableServers   = map[string]time.Time{}
)

// noteServerProblem reports, once per zone/server per repeat interval, that a
// server in the map cannot be queried and why.
func noteServerProblem(zoneName, nsname, reason string) {
	key := zoneName + "|" + nsname + "|" + reason

	unusableServersMu.Lock()
	now := time.Now()
	if last, seen := unusableServers[key]; seen && now.Sub(last) < unusableServerRepeat {
		unusableServersMu.Unlock()
		return
	}
	unusableServers[key] = now
	if len(unusableServers) > unusableServerMaxKeys {
		// Drop what has aged out first; if that is not enough, drop arbitrary
		// entries until the table is back under the cap. Go randomises map
		// iteration, so this is effectively random eviction -- the worst it
		// costs is a repeated warning, which is much cheaper than unbounded
		// growth in an error path.
		for k, t := range unusableServers {
			if now.Sub(t) >= unusableServerRepeat {
				delete(unusableServers, k)
			}
		}
		for k := range unusableServers {
			if len(unusableServers) <= unusableServerMaxKeys {
				break
			}
			delete(unusableServers, k)
		}
	}
	unusableServersMu.Unlock()

	lgDns.Warn("prioritizeServers: server cannot be queried",
		"ns", nsname, "zone", zoneName, "reason", reason,
		"note", "reported once per zone/server/reason per hour")
}

// refusalIndicatesLameness reports whether a refusal rcode is evidence that the
// answering server is lame for the zone, and should therefore be put into a
// backoff.
//
// A DS is PARENT-side data. A server authoritative for the child answers
// REFUSED or NOTAUTH to a DS query for that child -- correctly, and it says
// nothing about whether that server is lame for the zone it does serve. It
// should not be queried for a DS in the first place, but a stray query must not
// be able to disable the server either.
func refusalIndicatesLameness(qtype uint16, rcode int) bool {
	if qtype == dns.TypeDS && (rcode == dns.RcodeRefused || rcode == dns.RcodeNotAuth) {
		return false
	}
	return true
}

// candidateTransports returns the ordered list of transports to try for a
// query to this (qname, server), honoring OOTS query-load shares (-03 /
// svcb-oots-00): each encrypted transport with weight > 1 gets that share of
// the load; do53_share = max(0, 100−Σ encrypted). The deterministic
// fnv(qname|server) bucket picks the winner from that pool so Do53 usually
// wins when its share dominates. With privacy == PrivacyNone and do53_share
// 0, Do53 is still appended last as a reliability fallback.
//
// The client's PRIVACY level changes the pool rather than the selection:
//
//   - PrivacyNone: the OOTS shares as described above.
//   - PrivacyOpportunistic: only encrypted transports enter the weighted
//     draw, and Do53 is appended last as the fallback the client said it
//     would accept. That is "prefer encrypted", not "encrypted only".
//   - PrivacyStrict: encrypted transports only, no Do53 at any position. A
//     server advertising none contributes no transports at all.
func candidateTransports(server *cache.AuthServer, qname string, privacy edns0.PrivacyLevel) []core.Transport {
	if server == nil {
		if privacy == edns0.PrivacyStrict {
			return nil
		}
		return []core.Transport{core.TransportDo53}
	}

	// Read under the server's lock: the transport-signal lookups write these
	// in the background while queries read them.
	transports, weights := server.GetTransportSignal()
	pool := transportPool(transports, weights, privacy)

	if len(pool) == 0 {
		if privacy == edns0.PrivacyStrict {
			return nil
		}
		return []core.Transport{core.TransportDo53}
	}

	total := 0
	for _, c := range pool {
		total += c.w
	}

	h := fnv.New32a()
	_, _ = h.Write([]byte(qname))
	_, _ = h.Write([]byte("|"))
	_, _ = h.Write([]byte(server.Name))
	bucket := int(h.Sum32() % uint32(maxInt(total, 1)))

	winnerIdx := len(pool) - 1
	acc := 0
	for i, c := range pool {
		acc += c.w
		if bucket < acc {
			winnerIdx = i
			break
		}
	}

	rest := make([]poolEntry, 0, len(pool)-1)
	for i, c := range pool {
		if i == winnerIdx {
			continue
		}
		rest = append(rest, c)
	}
	sort.SliceStable(rest, func(i, j int) bool {
		if rest[i].w != rest[j].w {
			return rest[i].w > rest[j].w
		}
		return rest[i].t < rest[j].t
	})

	out := make([]core.Transport, 0, len(pool)+1)
	out = append(out, pool[winnerIdx].t)
	for _, c := range rest {
		out = append(out, c.t)
	}

	if privacy != edns0.PrivacyStrict {
		hasDo53 := false
		for _, t := range out {
			if t == core.TransportDo53 {
				hasDo53 = true
				break
			}
		}
		if !hasDo53 {
			out = append(out, core.TransportDo53)
		}
	}
	return out
}

// poolScale is the factor transportPool scales its weights by without
// privacy, so that a Do53 weight cut to the udp cap keeps its precision.
const poolScale = 100

// poolEntry is a transport and its weight in the draw candidateTransports
// makes.
type poolEntry struct {
	t core.Transport
	w int
}

// transportPool is the weighted pool candidateTransports draws a server's
// first transport from, given the server's signal (transports and weights,
// absence defaults included) and the client's privacy level. It is shared with
// the transport stats, which show the shares it implies, so that the two
// cannot drift apart.
//
// Each encrypted transport with a weight above 1 is in the pool with its
// weight. Without privacy, Do53 is in it with what the encrypted weights leave
// of 100, cut so that its share of the draw is no more than the signal's udp
// weight: a udp weight caps the share of queries the resolver sends over UDP
// by its own choice (design 2026-11-14, sections 2 and 3). The cap is on the
// share, not the weight: udp:20,dot:60 gives UDP 20% of first picks and DoT
// 80%, not 20 parts in 80. udp:0 sends none that way. A signal that names no
// udp weight has 100 by the absence default (core.ApplyTransportDefaults),
// which caps nothing. Do53 stays the last resort all the same
// (candidateTransports). With privacy (opportunistic or strict) only the
// encrypted transports are.
//
// Without privacy the weights are scaled by poolScale, so that a Do53 weight
// cut to a share rounds down, never above the cap.
func transportPool(transports []core.Transport, weights map[core.Transport]uint8, privacy edns0.PrivacyLevel) []poolEntry {
	seen := map[core.Transport]bool{}
	var encrypted []poolEntry
	encSum := 0
	consider := func(t core.Transport) {
		if seen[t] || !core.IsEncryptedTransport(t) {
			return
		}
		seen[t] = true
		w := weights[t]
		// -03: MAY attempt connections over any transport with weight > 1.
		if w <= 1 {
			return
		}
		encrypted = append(encrypted, poolEntry{t: t, w: int(w)})
		encSum += int(w)
	}
	for _, t := range transports {
		consider(t)
	}
	for t := range weights {
		consider(t)
	}
	sort.SliceStable(encrypted, func(i, j int) bool {
		return encrypted[i].t < encrypted[j].t
	})

	if privacy != edns0.PrivacyNone {
		// Opportunistic and strict both draw only from the encrypted
		// transports; they part company over whether Do53 may be appended
		// after them (candidateTransports).
		return encrypted
	}
	var pool []poolEntry
	do53Share := (100 - encSum) * poolScale
	if c, ok := weights[core.TransportDo53]; ok && c < 100 {
		// Do53's share of the draw is do53/(do53+encSum); at most c/100
		// means do53 <= c*encSum/(100-c).
		if capped := int(c) * encSum * poolScale / (100 - int(c)); capped < do53Share {
			do53Share = capped
		}
	}
	for i := range encrypted {
		encrypted[i].w *= poolScale
	}
	if do53Share < 0 {
		do53Share = 0
	}
	if do53Share > 0 {
		pool = append(pool, poolEntry{t: core.TransportDo53, w: do53Share})
	}
	return append(pool, encrypted...)
}

// expectedShares is the share of first picks, in percent, that
// candidateTransports gives each transport of a server with this signal under
// privacy: the pool's weights, normalised. With an empty pool the pick is Do53
// (100) unless privacy is strict, where the server is not used at all (nil).
func expectedShares(transports []core.Transport, weights map[core.Transport]uint8, privacy edns0.PrivacyLevel) map[core.Transport]uint8 {
	pool := transportPool(transports, weights, privacy)
	if len(pool) == 0 {
		if privacy == edns0.PrivacyStrict {
			return nil
		}
		return map[core.Transport]uint8{core.TransportDo53: 100}
	}
	total := 0
	for _, e := range pool {
		total += e.w
	}
	out := make(map[core.Transport]uint8, len(pool))
	for _, e := range pool {
		out[e.t] = uint8((e.w*100 + total/2) / total)
	}
	return out
}

// hasStrictCandidate reports whether any server in serverMap can carry a
// strict-privacy query for qname: whether it has an encrypted transport that
// candidateTransports would pick.
func hasStrictCandidate(serverMap map[string]*cache.AuthServer, qname string) bool {
	for _, server := range serverMap {
		if len(candidateTransports(server, qname, edns0.PrivacyStrict)) > 0 {
			return true
		}
	}
	return false
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// expandServerMapWithMissingNS resolves A/AAAA records for any NS names in
// the qname's closest known zone that are missing from serverMap (or
// present but with no addresses). Returns the number of servers that now
// have addresses in serverMap and had none there before.
//
// Servers are counted, not addresses. AuthServer instances are shared across
// zones, so a nameserver can already carry addresses when it is put into this
// map. Counting new addresses reported 0 for exactly that server, the caller
// gave up without retrying, and the query ended with no auth-server attempts
// although the map now held a usable server (#675).
//
// This is the fallback path for the case where the parent zone provided
// glue only for in-bailiwick NS names but every in-bailiwick server is
// unreachable: we then have to do explicit A/AAAA lookups for the
// out-of-bailiwick names that the parent could not legally glue. Without
// this fallback, the IMR returns "no Answers found" even though there are
// other authoritative servers that would have answered, simply because
// the parent's referral didn't include their addresses.
//
// Synchronous on purpose: only called after the optimistic try-all-known-
// addresses pass has failed. It waits, bounded by ctx, for the address
// lookups of every missing name, which run at once (nsLookup). A name whose
// lookup is already running, typically started by the referral that brought
// the query here, is joined rather than looked up a second time. A name whose
// shared server already has addresses needs no lookup at all.
//
// qtype picks the zone whose NS set is expanded, the same zone the query was
// sent to: for a DS, the parent's. Expanding the child's instead would add the
// servers that do not hold the DS to a map of servers that do.
//
// The servers that get addresses are also stored in that zone's cached server
// map (storeZoneServers).
//
// This form has no first pass to compare with: a server already in serverMap
// with addresses counts 0. IterativeDNSQuery uses
// expandServerMapWithMissingNSSince.
func (imr *Imr) expandServerMapWithMissingNS(ctx context.Context, qname string, qtype uint16, serverMap map[string]*cache.AuthServer) int {
	return imr.expandServerMapWithMissingNSSince(ctx, qname, qtype, serverMap, nil)
}

// expandServerMapWithMissingNSSince is expandServerMapWithMissingNS for a
// query whose first pass has already run: addresslessAtStart holds the keys
// of the servers that had no address when it did.
//
// Such a server can be in serverMap with addresses by now. The map holds
// shared AuthServer instances, and another lookup may have filled this one in
// while the first pass ran. It was never tried, so it counts like a server
// the fallback resolved itself; skipped as "already have addresses", it left
// the count at 0 and the query gave up beside a usable server. A server that
// had its addresses at the start was tried, and counts 0.
func (imr *Imr) expandServerMapWithMissingNSSince(ctx context.Context, qname string, qtype uint16, serverMap map[string]*cache.AuthServer, addresslessAtStart map[string]bool) int {
	if imr == nil || imr.Cache == nil || serverMap == nil {
		return 0
	}
	zonename, _, _ := imr.Cache.FindClosestKnownZoneFor(qname, qtype)
	if zonename == "" {
		return 0
	}
	crrset := imr.Cache.Get(zonename, dns.TypeNS)
	if crrset == nil || crrset.RRset == nil || len(crrset.RRset.RRs) == 0 {
		return 0
	}
	type pending struct {
		nsname string
		srv    *cache.AuthServer
		done   <-chan struct{}
	}
	var lookups []pending
	added := 0
	usable := map[string]*cache.AuthServer{}
	for _, rr := range crrset.RRset.RRs {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		nsname := dns.Fqdn(ns.Ns)
		srv, present := serverMap[cache.ServerKey(nsname)]
		if present && len(srv.GetAddrs()) > 0 && !addresslessAtStart[cache.ServerKey(nsname)] {
			continue // had its addresses at the start, and was tried
		}
		if srv == nil {
			srv = imr.Cache.GetOrCreateAuthServer(nsname)
			serverMap[cache.ServerKey(nsname)] = srv
		}
		if len(srv.GetAddrs()) > 0 {
			// The shared server has addresses by now -- from another zone's
			// glue, an earlier lookup, or one that finished while the first
			// pass ran: usable, not tried, and no query needed.
			added++
			usable[cache.ServerKey(nsname)] = srv
			continue
		}
		lookups = append(lookups, pending{nsname, srv, imr.nsLookup(ctx, nsname, zonename)})
	}
	for _, l := range lookups {
		select {
		case <-l.done:
		case <-ctx.Done():
			// The lookups go on, and store what they find in the zone's map.
			imr.storeZoneServers(zonename, usable)
			return added
		}
		if addrs := l.srv.GetAddrs(); len(addrs) > 0 {
			added++
			usable[cache.ServerKey(l.nsname)] = l.srv
			if Globals.Debug {
				lgDns.Debug("expandServerMapWithMissingNS: resolved addresses for previously-unresolved NS",
					"ns", l.nsname, "zone", zonename, "addresses", addrs)
			}
		}
	}
	// The caller's map is a copy; the zone's cached map gets them too, or the
	// next query into the zone would repeat these lookups (#682).
	imr.storeZoneServers(zonename, usable)
	return added
}

// force is true if we should force a lookup even if the answer is in the cache
// visitedZones tracks which zones we've been referred to for this qname to prevent referral loops
// privacy is the client's PRIVACY EDNS(0) level: none, opportunistic (prefer
// an encrypted transport, cleartext accepted) or strict (encrypted or fail).
// Returns: rrset, rcode, context, transport, error
func (imr *Imr) IterativeDNSQuery(ctx context.Context, qname string, qtype uint16, serverMap map[string]*cache.AuthServer, force bool, privacy edns0.PrivacyLevel) (*core.RRset, int, cache.CacheContext, core.Transport, error) {
	return imr.IterativeDNSQueryInZone(ctx, qname, qtype, serverMap, "", force, privacy)
}

// IterativeDNSQueryInZone is IterativeDNSQuery for a caller that knows the zone
// serverMap serves (serversZone). A referral in a reply is judged against that
// zone (referralLeavesZone). With serversZone "", as from IterativeDNSQuery,
// it is found from the servers when the lookup starts (zoneOfServers).
func (imr *Imr) IterativeDNSQueryInZone(ctx context.Context, qname string, qtype uint16, serverMap map[string]*cache.AuthServer, serversZone string, force bool, privacy edns0.PrivacyLevel) (*core.RRset, int, cache.CacheContext, core.Transport, error) {
	return imr.IterativeDNSQueryWithLoopDetection(ctx, qname, qtype, serverMap, serversZone, force, make(map[string]bool), privacy)
}

// zoneOfServers returns the zone serverMap serves, for a caller that did not
// say: the closest zone at or above the closest known zone for the question
// whose cached server map holds every server in serverMap. The closest known
// zone alone is not enough. ServersFor hands out the root's servers for a zone
// cut whose map is empty, and judged against that cut the root's referral
// towards it would look lame. With no such zone the result is "", and
// referralLeavesZone then follows every referral, as before #829.
func (imr *Imr) zoneOfServers(qname string, qtype uint16, serverMap map[string]*cache.AuthServer) string {
	zone, _, _ := imr.Cache.FindClosestKnownZoneFor(qname, qtype)
	if zone == "" || len(serverMap) == 0 {
		return zone
	}
	for {
		if held, ok := imr.Cache.ServerMap.Get(zone); ok && holdsServers(held, serverMap) {
			return zone
		}
		labels := dns.Split(zone)
		if len(labels) <= 1 {
			if zone == "." {
				return ""
			}
			zone = "."
			continue
		}
		zone = zone[labels[1]:]
	}
}

// holdsServers reports whether held has every server that servers has.
func holdsServers(held, servers map[string]*cache.AuthServer) bool {
	for key := range servers {
		if _, ok := held[key]; !ok {
			return false
		}
	}
	return true
}

// IterativeDNSQueryWithLoopDetection is the internal implementation with loop detection
// serversZone is the zone serverMap serves, or "" (see IterativeDNSQueryInZone)
// visitedZones tracks which zones we've been referred to for this qname (format: "qname:zone")
// privacy is the client's PRIVACY EDNS(0) level (see IterativeDNSQuery)
// Returns: rrset, rcode, context, transport, error
func (imr *Imr) IterativeDNSQueryWithLoopDetection(ctx context.Context, qname string, qtype uint16, serverMap map[string]*cache.AuthServer, serversZone string, force bool, visitedZones map[string]bool, privacy edns0.PrivacyLevel) (*core.RRset, int, cache.CacheContext, core.Transport, error) {
	lg := imr.Cache.Logger

	// Apply per-query wall-time budget. context.WithTimeout takes
	// min(parent.Deadline, now+budget), so recursive calls inherit
	// the outermost deadline rather than each getting a fresh budget.
	if budget := imr.Tuning.QueryBudget; budget > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, budget)
		defer cancel()
	}

	if Globals.Debug {
		lg.Printf("IterativeDNSQuery: looking up <%s, %s> using %d servers", qname, dns.TypeToString[qtype], len(serverMap))
	}

	// The resolver's own DS or DNSKEY question at the owner of a CNAME link
	// that is being validated (cnameValidationKey): the name is a CNAME, and
	// holds neither. Answered without asking, and nothing is cached. Asking
	// returned the link, which was then validated again, without end (#717).
	if cnameDeniesType(ctx, qtype) && validatingCNAME(ctx, qname) {
		lgDns.Debug("IterativeDNSQuery: the name is a CNAME being validated; not asking for its "+dns.TypeToString[qtype], "qname", qname)
		return nil, dns.RcodeSuccess, cache.ContextNoErrNoAns, core.TransportDo53, nil
	}
	var servernames []string
	for k := range serverMap {
		servernames = append(servernames, k)
	}
	if Globals.Debug {
		lg.Printf("IterativeDNSQuery: servers for %q: %+v", qname, servernames)
	}

	if !force {
		crrset := imr.Cache.Get(qname, qtype)
		if crrset != nil {
			// Only use cached answer if it's a direct answer or negative response.
			// Don't use referrals, glue, hints, priming, or failures - issue a direct query instead
			// to get DNSSEC signatures and upgrade the quality of the data.
			switch crrset.Context {
			case cache.ContextAnswer, cache.ContextNoErrNoAns, cache.ContextNXDOMAIN:
				// These are direct answers or negative responses - safe to use
				// Strict privacy: cached data that arrived over an
				// unencrypted transport is not usable, so re-query. An
				// opportunistic client accepted cleartext, so it keeps the
				// cache hit rather than paying for a re-query it did not ask
				// for.
				if privacy == edns0.PrivacyStrict && !core.IsEncryptedTransport(crrset.Transport) {
					if Globals.Debug {
						lg.Printf("IterativeDNSQuery: strict privacy requested but cached data for %s %s came over unencrypted transport (%s), skipping cache", qname, dns.TypeToString[qtype], core.TransportToString[crrset.Transport])
					}
					crrset = nil // Force query over encrypted transport
				} else {
					if Globals.Debug {
						lg.Printf("IterativeDNSQuery: found answer to <%s, %s> in cache (result=%s)", qname, dns.TypeToString[qtype], cache.CacheContextToString[crrset.Context])
					}
					// A NEGATIVE entry's RRset is the SOA that PROVES the
					// denial, not an answer to the question. Returning it as
					// the answer RRset is how a cached NODATA came back with
					// the zone apex SOA in the ANSWER section, under a qname
					// that SOA does not even own: every caller tests the
					// RRset first (ProcessAuthDNSResponse: `if rrset != nil {
					// m.Answer = rrset.RRs }`) and never reaches the context
					// switch that would have called serveNegativeResponse and
					// put the SOA in AUTHORITY where it belongs.
					//
					// The cold resolution was correct and every cache hit
					// afterwards was wrong, which is the signature of a defect
					// on this path rather than in the negative proof itself.
					//
					// The context is what carries the meaning of a negative
					// entry; the caller re-reads the proof from the cache
					// through serveNegativeResponse, which also restores the
					// AD bit from the entry's validation state.
					if crrset.Context == cache.ContextNoErrNoAns || crrset.Context == cache.ContextNXDOMAIN {
						return nil, int(crrset.Rcode), crrset.Context, crrset.Transport, nil
					}
					return crrset.RRset, int(crrset.Rcode), crrset.Context, crrset.Transport, nil
				}
			case cache.ContextReferral, cache.ContextGlue, cache.ContextHint:
				// Indirect contexts. By default re-query to upgrade
				// quality (get DNSSEC signatures). With the
				// UpgradeIndirectCacheHits=false toggle, return the
				// cached data if it matches qtype.
				if !imr.upgradeIndirectCacheHits() && crrset.RRset != nil && crrset.RRset.RRtype == qtype {
					if privacy == edns0.PrivacyStrict && !core.IsEncryptedTransport(crrset.Transport) {
						// Strict privacy still wins -- need encrypted transport
						crrset = nil
					} else {
						if Globals.Debug {
							lg.Printf("IterativeDNSQuery: returning cached indirect data for <%s, %s> (UpgradeIndirectCacheHits=false, context=%s)", qname, dns.TypeToString[qtype], cache.CacheContextToString[crrset.Context])
						}
						return crrset.RRset, int(crrset.Rcode), crrset.Context, crrset.Transport, nil
					}
				} else if Globals.Debug {
					lg.Printf("IterativeDNSQuery: found <%s, %s> in cache with context=%s, but issuing direct query to upgrade quality and get DNSSEC signatures", qname, dns.TypeToString[qtype], cache.CacheContextToString[crrset.Context])
				}
				// Fall through to issue query
			case cache.ContextPriming, cache.ContextFailure:
				if Globals.Debug {
					lg.Printf("IterativeDNSQuery: found <%s, %s> in cache with context=%s, issuing direct query", qname, dns.TypeToString[qtype], cache.CacheContextToString[crrset.Context])
				}
				// Fall through to issue query
			default:
				// Unknown context - be safe and issue query
				if Globals.Debug {
					lg.Printf("IterativeDNSQuery: found <%s, %s> in cache with unknown context=%s, issuing query", qname, dns.TypeToString[qtype], cache.CacheContextToString[crrset.Context])
				}
				// Fall through to issue query
			}
		} else {
			if Globals.Debug {
				lg.Printf("IterativeDNSQuery: answer to <%s, %s> not present in cache", qname, dns.TypeToString[qtype])
			}
		}
	} else {
		if Globals.Debug {
			lg.Printf("IterativeDNSQuery: forcing re-query of <%s, %s>, bypassing cache", qname, dns.TypeToString[qtype])
		}
	}

	// qname is a CNAME we hold: follow it from the cache rather than asking
	// qname's servers for it again. A chain is cached link by link, never as
	// one entry under <qname, qtype> (serveChain). For the resolver's own DS
	// or DNSKEY question the link is the answer: there is none at qname
	// (cnameDeniesType).
	if !force {
		if link, target, ok := imr.cachedLink(qname, privacy); ok {
			switch {
			case followsCNAME(ctx, qtype):
				recordChainLink(ctx, qname, target, link.Expiration)
				return imr.chaseCNAME(ctx, qname, target, qtype, force, privacy)
			case cnameDeniesType(ctx, qtype):
				return nil, dns.RcodeSuccess, cache.ContextNoErrNoAns, link.Transport, nil
			}
		}
	}

	// A question about a zone this server is authoritative for is answered
	// from that zone, in process: it is neither forwarded nor iterated
	// (imr_own_zone.go, #842). Ahead of the forward hook below, and here for
	// the same reason it is: every internal consumer comes through this entry
	// point.
	if rrset, rcode, cacheCtx, transport, err, ok := imr.answerFromOwnZone(ctx, qname, qtype, force, privacy); ok {
		return rrset, rcode, cacheCtx, transport, err
	}

	// Forwarding: when qname falls under a configured forward zone, hand the
	// query to that zone's upstream resolver(s) instead of iterating. Placed
	// after the cache check so cached answers still short-circuit, and inside
	// this entry point so every internal consumer (responder, ImrQuery, CNAME
	// chase, NS-address resolution, the validator's fetcher) forwards
	// consistently. The serverMap argument is deliberately ignored here: a
	// forward zone outranks whatever zone cut the caller had found. The callers
	// that pick servers decide the same way before they look for a cut, and
	// send a forwarded question with none (forwardZoneForQuestion).
	if fz := imr.forwardZoneForQuestion(qname, qtype); fz != nil {
		return imr.forwardQuery(ctx, qname, qtype, fz, force, privacy)
	}
	// A caller that found the question forwarded sent it with no servers. A
	// reload that has removed the forward since leaves it to be iterated after
	// all, from the closest cached zone cut, as it would be if asked now: with
	// no servers, the walk below would have nothing to try.
	if len(serverMap) == 0 {
		serversZone, serverMap, _ = imr.Cache.FindClosestKnownZoneFor(qname, qtype)
	}
	// The zone of serverMap, for the referral checks below. The zoneName that
	// prioritizeServers returns is looked up again on each pass: a zone below
	// the servers' own, learned meanwhile by another lookup, would make a
	// referral into it from these servers look like a lame answer.
	if serversZone == "" {
		serversZone = imr.zoneOfServers(qname, qtype, serverMap)
	}

	var rrset core.RRset
	var rcode int

	withOOTS := imr.Options[ImrOptUseTransportSignals] != "false"
	m, err := buildQuery(qname, qtype, withOOTS)
	if err != nil {
		lg.Printf("IterativeDNSQuery: Error building query: %v", err)
		return nil, 0, cache.ContextFailure, core.TransportDo53, err
	}

	dnskeyBypass := imr.dnskeyTransportBypass(qname, qtype, privacy)
	if qtype == dns.TypeDNSKEY {
		imr.noteDNSKEYLookup(dnskeyBypass)
	}

	// Under strict privacy, verify up front that at least one server has an
	// encrypted transport available: failing here names the actual reason,
	// rather than letting the walk below run out of tuples and report a
	// generic dead end. Opportunistic privacy has no such precondition --
	// falling back to cleartext is exactly what it asked for.
	//
	// Availability is asked of candidateTransports (hasStrictCandidate) rather
	// than computed here, so the precheck and the tuple selection below cannot
	// disagree. A hand-rolled scan did disagree in two ways: it read
	// server.Transports without a nil check, where candidateTransports handles
	// a nil entry (as prioritizeServers does), and it counted an encrypted
	// transport of weight 0 or 1 as available, where candidateTransports
	// excludes it.
	//
	// A server may also have no encrypted transport only because it has not
	// told us yet: the zone was met a moment ago, through the referral that
	// brought us here. Its transports are learned before the query gives up on
	// it, or the first strict query to every new zone failed (#776).
	// One signal-wait budget for the whole query: a referral followed below
	// recurses with this context, and waits within the same budget.
	ctx, budget := signalWaitBudgetFor(ctx)
	if privacy == edns0.PrivacyStrict && !hasStrictCandidate(serverMap, qname) &&
		!budget.run(ctx, imr.strictWait(), func(wctx context.Context) bool {
			return imr.awaitTransportSignals(wctx, qname, serverMap)
		}) {
		zoneName, _, _ := imr.Cache.FindClosestKnownZoneFor(qname, qtype)
		return nil, dns.RcodeServerFailure, cache.ContextFailure, core.TransportDo53,
			privacyUnavailable(zoneName, "no servers have encrypted transports available (zone=%s)", zoneName)
	}

	// Prioritize (server, addr, transport) tuples. The privacy level is
	// applied here so tryServer no longer needs to filter.
	//
	// Two-attempt outer loop: if the first pass exhausts every tuple
	// without an answer, try resolving any NS names in the zone whose
	// addresses were not provided as glue (typical for out-of-bailiwick
	// NS where the parent legally cannot glue them), then re-prioritize
	// with the expanded serverMap. Hard cap at 2 attempts to prevent
	// loops if resolution keeps producing nothing.
	var zoneName string
	var zone *cache.Zone
	var prioritized []ServerAddrXportTuple
	// Diagnostic accumulator: track the last (server, addr, transport)
	// we attempted so error returns can tell the operator WHERE the
	// chain walk got stuck instead of just "no Answers found" or
	// "context deadline exceeded". Updated on every tuple attempt.
	var (
		lastNS, lastAddr string
		lastTransport    core.Transport
		lastErr          error
		attempts         int
	)
	// When the DNSKEY transport policy bypasses probabilistic selection, every
	// tuple for a given (server, addr) resolves to the SAME preferred transport.
	// prioritizeServers still emits one tuple per advertised transport, so dedup
	// by resolved (addr, transport) to avoid re-querying an identical path that
	// just failed.
	dnskeyAttempted := map[cache.AddrXport]bool{}
	// The servers that have no address as the first pass starts. Should one
	// gain an address before the fallback runs (another lookup filling in the
	// shared server), the fallback counts it: it was never tried
	// (expandServerMapWithMissingNSSince).
	addresslessAtStart := map[string]bool{}
	for key, srv := range serverMap {
		if len(srv.GetAddrs()) == 0 {
			addresslessAtStart[key] = true
		}
	}
	// Two passes, and one more when a pass has run out and a tuple it did
	// not have is available, or comes with a transport signal
	// (anotherPassAfter).
	maxPasses := 2
	extraPassAdded := false
	var nextPass *tupleSelection
	for attempt := 0; attempt < maxPasses; attempt++ {
		var triedBefore map[passTuple]bool
		if nextPass != nil {
			zoneName, zone, prioritized = nextPass.zoneName, nextPass.zone, nextPass.tuples
			triedBefore = nextPass.tried
			nextPass = nil
		} else {
			zoneName, zone, prioritized = imr.awaitUsableTuples(ctx, budget, qname, qtype, serverMap, privacy)
		}
		tried := map[passTuple]bool{}
		if Globals.Debug {
			lg.Printf("IterativeDNSQuery: prioritized %d (server,addr,transport) tuples (from %d servers) attempt=%d", len(prioritized), len(serverMap), attempt+1)
		}

		for _, tuple := range prioritized {
			select {
			case <-ctx.Done():
				return nil, 0, cache.ContextFailure, core.TransportDo53, walkErr(zoneName, lastNS, lastAddr, lastTransport, attempts, lastErr, ctx.Err())
			default:
			}
			server := tuple.Server
			addr := tuple.Addr
			nsname := tuple.NSName
			transport := tuple.Transport

			// effTransport is what tryServer will actually attempt: the
			// tuple's probabilistic pick, or the policy-preferred transport
			// under dnskeyBypass.
			effTransport := transport
			var dnskeyKey cache.AddrXport
			if dnskeyBypass {
				// All tuples for this (server, addr) collapse to the same
				// preferred transport; skip the ones we've already tried.
				// The attempt is recorded once made, under the endpoint
				// tryServer dialed (dnskeyTried).
				eff := imr.preferredDNSKEYTransport(server)
				dnskeyKey = imr.dnskeyAttemptKey(ctx, server, zone, addr, eff)
				if dnskeyAttempted[dnskeyKey] {
					continue
				}
				effTransport = eff
			}

			lastNS, lastAddr, lastTransport = nsname, addr, transport
			attempts++

			if Globals.Debug {
				lg.Printf("IterativeDNSQuery: using nameserver %s@%s over %s (ALPN: %v) for <%s, %s> query\n",
					addr, nsname, core.TransportToString[effTransport], server.GetAlpn(), qname, dns.TypeToString[qtype])
			}

			r, _, wireTransport, ep, err := imr.tryServer(ctx, server, zone, addr, transport, m, qname, qtype, dnskeyBypass, trafficClass(ctx, privacy), attemptSelection{family: tuple.Family, probe: tuple.Probe, tried: triedBefore})
			if dnskeyBypass {
				// Under the transport tryServer dialed: it reads the
				// preference again, and a signal update in between may
				// have changed it from effTransport.
				dnskeyAttempted[dnskeyTried(dnskeyKey, ep, wireTransport)] = true
			}
			// The endpoint tried: the one tryServer dialed, or the server's
			// own address when it did not get as far as choosing one, kept
			// under the tuple's transport. anotherPassAfter compares it with
			// what an attempt for that transport would dial, so the two agree
			// when the tuple dialed itself. Under the DNSKEY bypass the
			// endpoint is the preferred transport's, which anotherPassAfter
			// may not see as tried; dnskeyAttempted, which lasts the whole
			// query, is what keeps the extra pass from dialing it again. An
			// attempt refused for its suspect family is none (passTried).
			if key, ok := passTried(server, addr, transport, ep, err); ok {
				tried[key] = true
			}
			lastTransport = wireTransport
			if err != nil {
				lastErr = err
				if imr.Cache.Verbose {
					// lg.Printf("IterativeDNSQuery: Error from dns.Exchange: %v (rtt: %v)", err, rtt)
				}
				continue // go to next tuple
			}

			if r == nil {
				if Globals.Debug {
					lg.Printf("IterativeDNSQuery: nil response from tryServer(dns.Exchange) qname=%s, qtype=%s", qname, dns.TypeToString[qtype])
				}
				continue
			}

			if Globals.Debug {
				lg.Printf("IterativeDNSQuery: response from tryServer(dns.Exchange) qname=%s, qtype=%s:\n%s", qname, dns.TypeToString[qtype], PrintMsgFull(r, imr.LineWidth))
			}

			for _, hook := range getImrResponseHooks() {
				hook(ctx, qname, qtype, server.Name, addr, wireTransport, r, r.MsgHdr.Rcode)
			}

			rcode = r.MsgHdr.Rcode

			// Lame-delegation rcodes: zone-scoped backoff for this (addr, transport).
			// Other servers / other transports stay available.
			switch rcode {
			case dns.RcodeRefused, dns.RcodeNotAuth, dns.RcodeServerFailure, dns.RcodeNotImplemented:
				// A DS is PARENT-side data. A server authoritative for the child
				// answers REFUSED or NOTAUTH to a DS query for that child --
				// correctly, and it says nothing whatever about whether that
				// server is lame for the zone it does serve.
				//
				// Booking it as a lame delegation was fatal for any zone reached
				// through a single server: the backoff removed the only address
				// there was, prioritizeServers then had nothing to offer, and
				// every later query for the zone ended with no auth-server
				// attempt at all. A stub zone with a trust anchor hit this during
				// startup, because validating the anchor's NS RRset backfills the
				// DS before the first ordinary query arrives.
				//
				// Genuine lameness still gets recorded: a server that is really
				// lame refuses the other qtypes too, and those take the branch
				// below.
				if !refusalIndicatesLameness(qtype, rcode) {
					if Globals.Debug {
						lg.Printf("IterativeDNSQuery: %s from %s@%s for a DS query (%s) — parent-side data, not evidence of lameness; not recording a backoff",
							dns.RcodeToString[rcode], addr, nsname, qname)
					}
					continue
				}
				if Globals.Debug {
					lg.Printf("IterativeDNSQuery: %s response from %s@%s over %s for %s %s (likely lame delegation for zone %q)",
						dns.RcodeToString[rcode], addr, nsname, core.TransportToString[wireTransport], qname, dns.TypeToString[qtype], zoneName)
				}
				// Booked at the address and port tryServer dialed: the
				// server's own address, or the address of the target the
				// signal sent the transport to. A lame endpoint holds back
				// only itself: one on 5353 not port 53, a target address
				// not the target's others nor the nameserver's own address
				// (design 2026-11-14, section 3). The endpoint is the one
				// tried, not a fresh reading, which a signal update during
				// the exchange may have moved.
				if zone != nil {
					zone.RecordZoneEndpointFailureForRcode(ep.addr, ep.keyPort, wireTransport, uint8(rcode), Globals.Debug)
				} else {
					ep.server.RecordEndpointAddrFailureForRcode(ep.addr, ep.keyPort, wireTransport, uint8(rcode))
				}
				continue
			case dns.RcodeSuccess:
				if zone != nil {
					zone.RecordZoneEndpointSuccess(ep.addr, ep.keyPort, wireTransport)
				}
			default:
				if zone != nil {
					zone.RecordZoneEndpointSuccess(ep.addr, ep.keyPort, wireTransport)
				}
			}

			if len(r.Answer) != 0 {
				// Parse any transport signal for this specific server even on final answers
				// Note: server is a shared instance across all zones, so modifications are automatically visible everywhere
				imr.parseTransportForServerFromAdditional(ctx, server, r)
				tmprrset, rcode2, ctx2, transport2, err, done := imr.handleAnswer(ctx, qname, qtype, r, force, wireTransport, privacy)
				if err != nil || done {
					return tmprrset, rcode2, ctx2, transport2, err
				}
				// If not done, fall-through to process referral glue embedded with answers
				nsRRs, zonename, nsMap := extractReferral(r, qname, qtype)
				if len(nsRRs.RRs) > 0 && referralLeavesZone(zonename, serversZone) {
					serverMap, err := imr.ParseAdditionalForNSAddrs(ctx, "authority", nsRRs, zonename, serversZone, nsMap, r)
					if err != nil {
						lgDns.Error("*** IterativeDNSQuery: Error from CollectNSAddressesFromAdditional",
							"collectnsaddressesfromadditional", err)
						return nil, rcode, cache.ContextFailure, wireTransport, err
					}
					if len(serverMap) == 0 {
						return nil, rcode, cache.ContextReferral, wireTransport, nil
					}
					rrset, rcode, cacheCtx, transport, err := imr.IterativeDNSQueryWithLoopDetection(ctx, qname, qtype, serverMap, zonename, force, visitedZones, privacy)
					return rrset, rcode, cacheCtx, transport, err
				}
				continue
			}

			// A negative answer with an empty authority section (RFC 2308
			// types 3, and the NODATA form of it) is classified too when it is
			// authoritative (#830); anything else without an authority section
			// falls through as before.
			if len(r.Ns) != 0 || (r.Authoritative && (rcode == dns.RcodeNameError || rcode == dns.RcodeSuccess)) {
				kind := classifyResponse(qname, qtype, r)
				lgDns.Debug("IterativeDNSQuery: classified response",
					"qname", qname, "qtype", dns.TypeToString[qtype],
					"kind", responseKindToString(kind), "rcode", dns.RcodeToString[rcode],
					"answerCount", len(r.Answer), "authorityCount", len(r.Ns))

				switch kind {
				case responseKindNegativeNoData, responseKindNegativeNXDOMAIN:
					if ctxNeg, rcodeNeg, handled := imr.handleNegative(qname, qtype, r, wireTransport, serversZone); handled {
						return nil, rcodeNeg, ctxNeg, wireTransport, nil
					}
					// If not handled, fall through to try next server
					if rcode == dns.RcodeNameError {
						lgDns.Debug("IterativeDNSQuery: NXDOMAIN response lacked usable SOA",
							"qname", qname, "qtype", dns.TypeToString[qtype])
					}
					continue
				case responseKindReferral:
					// A referral hands the lookup to a zone below the one these
					// servers serve. An NS RRset for that zone itself, or for
					// one above it, is not a referral. Following it would reach
					// the loop check in handleReferral, which aborts the whole
					// lookup (#829).
					if _, refZone, _ := extractReferral(r, qname, qtype); !referralLeavesZone(refZone, serversZone) {
						// With AA set and the zone's own NS RRset, the server is
						// answering NODATA without an SOA (#830). A referral
						// below the zone keeps its meaning even with AA set, as
						// some servers set it on referrals; NS for a zone above
						// is an upward referral, and lame whatever the AA bit.
						if r.Authoritative && rcode == dns.RcodeSuccess && core.EqualNames(refZone, serversZone) {
							if ctxNeg, rcodeNeg, handled := imr.handleNegative(qname, qtype, r, wireTransport, serversZone); handled {
								return nil, rcodeNeg, ctxNeg, wireTransport, nil
							}
						}
						// Otherwise the server is lame for the zone: try the
						// next one. The fallback below still resolves the
						// zone's glue-less nameservers.
						lgDns.Debug("IterativeDNSQuery: NS RRset does not lead below the zone being queried;"+
							" treating the server as lame and trying the next one",
							"qname", qname, "qtype", dns.TypeToString[qtype],
							"zone", serversZone, "ns_owner", refZone, "server", nsname, "addr", addr,
							"aa", r.Authoritative)
						continue
					}
					return imr.handleReferral(ctx, qname, qtype, r, force, visitedZones, serversZone, wireTransport, privacy)
				case responseKindError:
					lgDns.Debug("IterativeDNSQuery: treating response as error",
						"qname", qname, "qtype", dns.TypeToString[qtype],
						"rcode", dns.RcodeToString[rcode])
					continue
				case responseKindUnknown:
					lgDns.Debug("IterativeDNSQuery: responseKindUnknown, trying next server",
						"qname", qname, "qtype", dns.TypeToString[qtype])
					continue
				default:
					// Should not reach here, but be defensive
					lgDns.Debug("IterativeDNSQuery: unexpected response kind, trying next server",
						"kind", kind, "qname", qname, "qtype", dns.TypeToString[qtype])
					continue
				}
			}

			if rcode == dns.RcodeSuccess {
				return &rrset, rcode, cache.ContextFailure, wireTransport, nil // no point in continuing
			}
			continue
		}
		// Tuple loop exhausted without an answer. On the first attempt,
		// try to resolve any NS names in this zone whose addresses are
		// missing (typical for out-of-bailiwick NS that the parent could
		// not glue) and retry. If nothing new was added, give up.
		if attempt == 0 {
			added := imr.expandServerMapWithMissingNSSince(ctx, qname, qtype, serverMap, addresslessAtStart)
			if added > 0 {
				if Globals.Debug {
					lg.Printf("IterativeDNSQuery: expanded serverMap with %d previously-unresolved NS addresses; retrying", added)
				}
				continue
			}
		}
		// The pass's own attempts may have put the servers' one transport
		// so far in backoff: Do53 to a server that refuses it, or has
		// nothing on port 53, before its signal is in (#1065). A server
		// whose signal came in during the pass, or comes in now, has
		// transports this pass did not: go again, once per query.
		if !extraPassAdded {
			nextPass = imr.anotherPassAfter(ctx, budget, qname, qtype, serverMap, privacy, tried)
		}
		if nextPass != nil {
			extraPassAdded = true
			maxPasses++
			if Globals.Debug {
				lg.Printf("IterativeDNSQuery: tuples the pass did not try are available after it ran out; retrying qname=%s", qname)
			}
			continue
		}
		break
	}
	// If we get here, we tried all servers but none succeeded.
	// Enrich the error with diagnostic info so operators don't see a
	// bare "no Answers found" / "context deadline exceeded" and have to
	// dig through the IMR log to find out what happened.
	if privacy == edns0.PrivacyStrict {
		base := privacyUnavailable(zoneName, "no answers found from any server with encrypted transport for '%s %s'", qname, dns.TypeToString[qtype])
		return nil, dns.RcodeServerFailure, cache.ContextFailure, core.TransportDo53, walkErr(zoneName, lastNS, lastAddr, lastTransport, attempts, lastErr, base)
	}
	base := fmt.Errorf("IterativeDNSQuery: no Answers found from any auth server looking up '%s %s'", qname, dns.TypeToString[qtype])
	return &rrset, rcode, cache.ContextNoErrNoAns, core.TransportDo53, walkErr(zoneName, lastNS, lastAddr, lastTransport, attempts, lastErr, base)
}

// walkErr wraps the underlying error with the diagnostic state of the
// IterativeDNSQuery walk at the point of failure. Use the operator's
// last-attempted (server, addr, transport) and the most recent per-tuple
// error so a CLI showing the returned error tells the operator WHERE
// the chain walk got stuck.
//
// Format kept compact since this string ends up in user-facing CLI
// output ("Error: ...") rather than only in logs.
func walkErr(zoneName, lastNS, lastAddr string, lastTransport core.Transport, attempts int, lastErr, base error) error {
	if attempts == 0 {
		// Never tried anything — no point listing a last-attempt that
		// doesn't exist. Keep the base error.
		return fmt.Errorf("%w (zone=%s, no auth-server attempts made)", base, zoneName)
	}
	parts := []string{
		fmt.Sprintf("zone=%s", zoneName),
		fmt.Sprintf("attempts=%d", attempts),
		fmt.Sprintf("last=%s@%s/%s", lastNS, lastAddr, core.TransportToString[lastTransport]),
	}
	if lastErr != nil {
		parts = append(parts, fmt.Sprintf("lastErr=%s", lastErr))
	}
	return fmt.Errorf("%w (%s)", base, strings.Join(parts, " "))
}

// parseOwnerName extracts the base server name from an owner name, handling both
// direct nameserver names and OOTS transport signal owners (_dns.{nsname}).
// oobTransportPrefix is the owner-name prefix an out-of-bailiwick transport
// signal lives under (draft-ietf-dnsop-oots). Named so the test and the strip
// cannot drift apart -- they did.
const oobTransportPrefix = "_dns."

// Returns: baseName, isOOTSOwner, originalOwner
func parseOwnerName(owner string) (baseName string, isOOTSOwner bool, originalOwner string) {
	originalOwner = owner
	// Fold to TEST the prefix, then slice the ORIGINAL by the prefix's length.
	// strings.TrimPrefix would compare bytes again and strip nothing from
	// _DNS.ns1.example. -- the name would clear the test and then keep its
	// prefix, so baseName stayed the whole owner and every lookup on it missed.
	// Slicing preserves the leftover case, which is the point: the base name is
	// a nameserver name, and we serve back what arrived.
	if strings.HasPrefix(core.CanonicalizeName(owner), oobTransportPrefix) {
		isOOTSOwner = true
		baseName = owner[len(oobTransportPrefix):]
	} else {
		baseName = owner
	}
	return baseName, isOOTSOwner, originalOwner
}

// ootsRecord is one SVCB the resolver acts on: the weights its oots SvcParam
// names (for an ALPN-only record, 100 for each ALPN it lists, kept in order),
// the port key on the same RR (0 when the key is absent), and what the
// tie-break compares, its SvcPriority and its RDATA in wire form.
type ootsRecord struct {
	raw      map[string]uint8
	alpn     []string
	port     uint16
	target   string // the TargetName, "" for "." (the nameserver itself)
	priority uint16
	rdata    []byte
}

// svcbSignalSet collects the SVCB transport signals for one nameserver, from
// one message's Additional section or from one answer RRset. Its oots records
// are combined into one signal. Its ALPN-only records are combined the same
// way and used only when no record carried oots. alias records that the set
// held an AliasMode record, and then the whole set is ignored: RFC 9460
// section 2.4.1 has a client ignore the ServiceMode records of an RRset that
// holds an AliasMode one.
//
// owner and rrs are the RRset as received, which an in-place validation
// needs. via and path are where the set arrived and the validation state of
// each RRset on its path (oots_signal_state.go). They are stored with the
// signal and change nothing that is installed.
type svcbSignalSet struct {
	recs  []ootsRecord
	alpn  []ootsRecord
	alias bool
	owner string
	rrs   []dns.RR
	via   string
	path  []cache.SignalHop
	// awaitsLookup records that installing the set ignored a record with a
	// target whose path was not decided, or that its alias path ran into a
	// target the Additional section did not hold: the verifying lookup may
	// give either.
	awaitsLookup bool
	// final is the set an AliasMode record leads to, at the end of path,
	// when it was read (decideAdditionalPath, followLookupAlias). It is what
	// the alias delegates the signal to.
	final *svcbSignalSet
}

// add collects one SVCB of the set's RRset. All three paths a signal arrives
// by (two Additional parsers and the answer path) collect through here.
func (set *svcbSignalSet) add(rr *dns.SVCB) {
	if set == nil || rr == nil {
		return
	}
	if set.owner == "" {
		set.owner = dns.Fqdn(rr.Hdr.Name)
	}
	set.rrs = append(set.rrs, rr)
	if rr.Priority == 0 {
		set.alias = true
		return
	}
	if rec, ok := ootsRecordFromSVCB(rr); ok {
		set.recs = append(set.recs, rec)
		return
	}
	if rec, ok := alpnRecordFromSVCB(rr); ok {
		set.alpn = append(set.alpn, rec)
	}
}

// svcbUsable reports whether rr is about the nameserver itself: rr is in
// ServiceMode (SvcPriority above 0) and its TargetName is ".". SvcParams in
// AliasMode are to be ignored (RFC 9460 section 2.4.2). The TLSA SvcParam is
// read only from such a record.
func svcbUsable(rr *dns.SVCB) bool {
	return svcbServiceMode(rr) && rr.Target == "."
}

// svcbServiceMode reports whether rr is a ServiceMode record, whose SvcParams
// a signal is read from. One with a TargetName other than "." names another
// endpoint: it is collected with its target and honoured only when its path
// validated Secure (honouredRecords). Its port is never joined onto the
// nameserver's own address.
func svcbServiceMode(rr *dns.SVCB) bool {
	return rr != nil && rr.Priority != 0
}

// svcbTarget is rr's TargetName, "" for ".".
func svcbTarget(rr *dns.SVCB) string {
	if rr == nil || rr.Target == "." || rr.Target == "" {
		return ""
	}
	return dns.Fqdn(rr.Target)
}

func svcbPortValue(rr *dns.SVCB) uint16 {
	if rr == nil {
		return 0
	}
	for _, kv := range rr.Value {
		if p, ok := kv.(*dns.SVCBPort); ok {
			return p.Port
		}
	}
	return 0
}

// svcbAlpnCSV is rr's ALPN list, comma-separated. "" when rr has none, is
// not in ServiceMode, or carries an oots SvcParam: a record with oots is read
// by its oots alone, and one whose oots names no signal token is ignored, its
// alpn not read in its place (hasOotsParam).
func svcbAlpnCSV(rr *dns.SVCB) string {
	if !svcbServiceMode(rr) || hasOotsParam(rr) {
		return ""
	}
	for _, kv := range rr.Value {
		if a, ok := kv.(*dns.SVCBAlpn); ok && len(a.Alpn) > 0 {
			return strings.Join(a.Alpn, ",")
		}
	}
	return ""
}

// ootsRecordFromSVCB is rr's oots SvcParam as a record, when rr carries one
// and is in ServiceMode. A record with a target keeps it (ootsRecord.target).
func ootsRecordFromSVCB(rr *dns.SVCB) (ootsRecord, bool) {
	if !svcbServiceMode(rr) {
		return ootsRecord{}, false
	}
	m, ok, err := GetTransportParamRaw(rr)
	if !ok || err != nil {
		return ootsRecord{}, false
	}
	if !dropDo53WithEndpoint(m, svcbPortValue(rr), svcbTarget(rr)) {
		return ootsRecord{}, false
	}
	return newOOTSRecord(rr, m, nil), true
}

// dropDo53WithEndpoint deletes do53 from the tokens of a record with a port
// key or a target, and reports whether any token is left; a record left with
// none is ignored whole. do53 is the receive-only shorthand for udp and tcp on
// the nameserver's own port 53: it carries no port and no target, and is
// ignored in a record that has one (the alternative-endpoint design, section
// 2). udp and tcp, which do take them, are kept. tdns-auth never published
// do53 beside a port.
func dropDo53WithEndpoint(raw map[string]uint8, port uint16, target string) bool {
	if port != 0 || target != "" {
		delete(raw, "do53")
	}
	return len(raw) > 0
}

// alpnRecordFromSVCB is an ALPN-only SVCB as a record. Its port applies to
// the transports it lists: RFC 9461 section 4.2 makes the port key
// automatically mandatory for SVCB-DNS, so a client may not use the record
// and drop the port.
func alpnRecordFromSVCB(rr *dns.SVCB) (ootsRecord, bool) {
	csv := svcbAlpnCSV(rr)
	if csv == "" {
		return ootsRecord{}, false
	}
	raw := map[string]uint8{}
	var order []string
	// do53 in a record with a port or a target is skipped, as in oots
	// (dropDo53WithEndpoint).
	withEndpoint := svcbPortValue(rr) != 0 || svcbTarget(rr) != ""
	for _, tok := range strings.Split(csv, ",") {
		tok = strings.ToLower(strings.TrimSpace(tok))
		if _, dup := raw[tok]; tok == "" || dup || (withEndpoint && tok == "do53") {
			continue
		}
		raw[tok] = 100
		order = append(order, tok)
	}
	if len(order) == 0 {
		return ootsRecord{}, false
	}
	return newOOTSRecord(rr, raw, order), true
}

func newOOTSRecord(rr *dns.SVCB, raw map[string]uint8, alpn []string) ootsRecord {
	return ootsRecord{raw: raw, alpn: alpn, port: svcbPortValue(rr), target: svcbTarget(rr), priority: rr.Priority, rdata: svcbRdata(rr)}
}

// svcbRdata is rr's RDATA in wire form, which is also its canonical form:
// RFC 4034 section 6.2 lowercases no SVCB field, and the SvcParams are packed
// in key order. nil when rr does not pack.
func svcbRdata(rr *dns.SVCB) []byte {
	bare := &dns.SVCB{
		Hdr:      dns.RR_Header{Name: ".", Rrtype: dns.TypeSVCB, Class: dns.ClassINET},
		Priority: rr.Priority,
		Target:   rr.Target,
		Value:    rr.Value,
	}
	buf := make([]byte, dns.Len(bare))
	off, err := dns.PackRR(bare, buf, 0, nil, false)
	if err != nil {
		return nil
	}
	// The root owner is one octet; type, class, TTL and RDLENGTH are ten.
	return buf[11:off]
}

// compareOOTSRecords orders records for the tie-break: the lower SvcPriority
// first, then the lower RDATA in DNSSEC canonical order (RFC 4034 section
// 6.3). The priority octets lead the RDATA and the root name sorts before any
// label, so on equal priority a record with TargetName "." comes before one
// that names another host. A record whose RDATA did not pack comes last.
func compareOOTSRecords(a, b ootsRecord) int {
	if a.priority != b.priority {
		return cmp.Compare(a.priority, b.priority)
	}
	if (a.rdata == nil) != (b.rdata == nil) {
		if a.rdata == nil {
			return 1
		}
		return -1
	}
	return bytes.Compare(a.rdata, b.rdata)
}

// rankOOTSRecords returns a copy of recs, the tie-break's winner first.
func rankOOTSRecords(recs []ootsRecord) []ootsRecord {
	ranked := slices.Clone(recs)
	slices.SortStableFunc(ranked, compareOOTSRecords)
	return ranked
}

// portsFromOOTSRecord applies the port key of one record. The port applies to
// every transport the record names, as RFC 9461 has it for SVCB-DNS, udp and
// tcp included: cleartext is not special (the alternative-endpoint design,
// section 2). The do53 shorthand never carries a port; a record with a port
// has it dropped (dropDo53WithEndpoint). A port of 0 means the key is absent.
func portsFromOOTSRecord(raw map[string]uint8, port uint16) map[core.Transport]uint16 {
	if port == 0 {
		return nil
	}
	var out map[core.Transport]uint16
	for k := range raw {
		t, err := core.StringToTransport(k)
		if err != nil || k == "do53" {
			continue
		}
		if out == nil {
			out = map[core.Transport]uint16{}
		}
		out[t] = port
	}
	return out
}

// combineOOTSRecords is combineOOTSEndpoints without the targets: the raw
// weights and the ports.
func combineOOTSRecords(recs []ootsRecord) (map[string]uint8, map[core.Transport]uint16) {
	raw, ports, _ := combineOOTSEndpoints(recs)
	return raw, ports
}

// combineOOTSEndpoints merges one server's records into one signal: the raw
// weights they name, and the ports and targets of the endpoints their port
// keys and TargetNames assign. A transport named in several records takes its
// weight and endpoint from the one that wins the tie-break
// (compareOOTSRecords), on equal priority "." before a target. A record that
// loses a transport still supplies the others it names. The result does not
// depend on the order the records arrived in. Absence defaults are not
// applied here; the caller applies them once to the combined set.
//
// A record with a target names only the tokens it may carry there
// (targetMayCarry): udp and tcp go to a target like the encrypted
// transports, the do53 shorthand never does. recs holds a record with a
// target only once its path has validated (honouredRecords).
func combineOOTSEndpoints(recs []ootsRecord) (map[string]uint8, map[core.Transport]uint16, map[core.Transport]string) {
	raw := map[string]uint8{}
	var ports map[core.Transport]uint16
	var targets map[core.Transport]string
	for _, rec := range rankOOTSRecords(recs) {
		assigned := portsFromOOTSRecord(rec.raw, rec.port)
		for k, w := range rec.raw {
			if _, taken := raw[k]; taken {
				continue
			}
			if rec.target != "" && !targetMayCarry(k) {
				continue
			}
			t, err := core.StringToTransport(k)
			raw[k] = w
			if err != nil {
				continue
			}
			if p := assigned[t]; p != 0 {
				if ports == nil {
					ports = map[core.Transport]uint16{}
				}
				ports[t] = p
			}
			if rec.target != "" {
				if targets == nil {
					targets = map[core.Transport]string{}
				}
				targets[t] = rec.target
			}
		}
	}
	return raw, ports, targets
}

// targetMayCarry reports whether a record with a target may name transport
// token k there: a signal token other than the do53 shorthand, which carries
// no target (dropDo53WithEndpoint). udp and tcp go to a target like any
// transport (the design, section 2).
func targetMayCarry(k string) bool {
	k = strings.ToLower(strings.TrimSpace(k))
	return k != "do53" && core.IsSignalToken(k)
}

// alpnOrder lists the ALPN tokens of recs once each: the tie-break's winner
// first, each record's tokens as written. A record with a target gives only
// the tokens it may carry (targetMayCarry), as in combineOOTSEndpoints; do53
// comes only from a record with TargetName ".".
func alpnOrder(recs []ootsRecord) []string {
	seen := map[string]bool{}
	var order []string
	for _, rec := range rankOOTSRecords(recs) {
		for _, tok := range rec.alpn {
			if rec.target != "" && !targetMayCarry(tok) {
				continue
			}
			if !seen[tok] {
				seen[tok] = true
				order = append(order, tok)
			}
		}
	}
	return order
}

func (imr *Imr) collectSVCBSignal(pending map[string]*svcbSignalSet, serverName string, rr *dns.SVCB) {
	if pending == nil || rr == nil {
		return
	}
	key := cache.ServerKey(serverName)
	set := pending[key]
	if set == nil {
		set = &svcbSignalSet{}
		pending[key] = set
	}
	set.add(rr)
}

// installSVCBSignal installs one server's collected SVCB signal, which
// replaces the whole previous signal, ports included: the combined oots
// records, or the combined ALPN-only records when no record carried oots. A
// set that held an AliasMode record installs nothing. It reports whether a
// signal was installed and whether the set had oots records. Promotion and
// the follow-up lookups are the caller's.
func (imr *Imr) installSVCBSignal(server *cache.AuthServer, set *svcbSignalSet) (installed, oots bool) {
	if server == nil || set == nil {
		return false, false
	}
	pathState := cache.SignalStateString(cache.SignalPathState(set.path))
	pathText := cache.FormatSignalPath(set.path)
	if set.alias {
		// RFC 9460 section 2.4.1: the ServiceMode records beside an AliasMode
		// one are ignored. The signal is the one the alias leads to, read with
		// the whole path.
		if set.final != nil && !set.final.alias {
			if !imr.Quiet {
				lgDns.Debug("SVCB signal through an AliasMode record", "servername", server.Name,
					"via", set.via, "state", pathState, "path", pathText)
			}
			installed, oots = imr.installSVCBSignal(server, set.final)
			if set.final.awaitsLookup {
				set.awaitsLookup = true
			}
			return installed, oots
		}
		if !imr.Quiet {
			lgDns.Debug("SVCB signal ignored: the RRset holds an AliasMode record that leads to no signal", "servername", server.Name,
				"via", set.via, "state", pathState, "path", pathText)
		}
		return false, false
	}
	recs := imr.honouredRecords(server, set, set.recs)
	alpnRecs := imr.honouredRecords(server, set, set.alpn)
	if len(recs) > 0 {
		raw, ports, targets := combineOOTSEndpoints(recs)
		if !imr.Quiet {
			lgDns.Debug("SVCB oots for", "servername", server.Name, "value", MarshalTransport(raw), "ports", ports,
				"targets", targets, "via", set.via, "state", pathState, "path", pathText)
		}
		return installTransportMap(server, raw, ports, targets, set.via, set.pathCopy()), true
	}
	if len(alpnRecs) > 0 {
		_, ports, targets := combineOOTSEndpoints(alpnRecs)
		order := alpnOrder(alpnRecs)
		if !imr.Quiet {
			lgDns.Debug("SVCB ALPN for", "servername", server.Name, "alpn", strings.Join(order, ","), "ports", ports,
				"targets", targets, "via", set.via, "state", pathState, "path", pathText)
		}
		return installAlpnSignal(server, order, ports, targets, set.via, set.pathCopy()), false
	}
	return false, false
}

// applySVCBSignalSet installs one server's SVCB signal from an Additional
// section. After an oots signal it promotes the server to opportunistic and
// repeats the observation lookups.
func (imr *Imr) applySVCBSignalSet(ctx context.Context, server *cache.AuthServer, set *svcbSignalSet) {
	installed, oots := imr.installSVCBSignal(server, set)
	if set != nil && set.awaitsLookup && server != nil {
		if owner := transportOwnerForNS(server.Name); owner != "" {
			imr.maybeQueryTransportSignal(ctx, owner, transportQueryReasonVerify)
		}
	}
	if !oots {
		return
	}
	if installed {
		server.PromoteConnMode(cache.ConnModeOpportunistic)
	}
	if owner := transportOwnerForNS(server.Name); owner != "" {
		imr.maybeQueryTransportSignal(ctx, owner, transportQueryReasonObservation)
	}
	imr.maybeQueryTLSA(ctx, server.Name)
}

// parseTSYNCTransportSignal extracts and applies transport signals from a TSYNC record.
// Returns true if a transport signal was successfully applied.
func (imr *Imr) parseTSYNCTransportSignal(rr *dns.PrivateRR, serverName string, serverMap map[string]*cache.AuthServer, ctx context.Context) bool {
	if rr == nil {
		return false
	}
	ts, ok := rr.Data.(*core.TSYNC)
	if !ok || ts == nil || ts.Transports == "" {
		return false
	}
	server, ok := serverMap[cache.ServerKey(serverName)]
	if !ok {
		return false
	}

	val := strings.TrimPrefix(ts.Transports, "transport=")
	if !imr.Quiet {
		lgDns.Debug("TSYNC transport value for", "servername", serverName, "value", val)
	}
	if imr.applyTransportSignalToServer(server, val) {
		server.PromoteConnMode(cache.ConnModeOpportunistic)
	}
	if owner := transportOwnerForNS(serverName); owner != "" {
		imr.maybeQueryTransportSignal(ctx, owner, transportQueryReasonObservation)
	}
	imr.maybeQueryTLSA(ctx, serverName)
	return true
}

// ParseAdditionalForNSAddrs reads the additional section of r, a referral to
// zonename whose NS RRset is nsrrset (the nameserver names in nsMap), for the
// nameservers' addresses (glue) and transport signals, and stores what it uses
// in zonename's cached server map, which it returns. referringZone is the zone
// of the servers that sent r, or "" when it is not known: a record is used only
// when its owner lies within that zone (imr_referral_glue.go).
func (imr *Imr) ParseAdditionalForNSAddrs(ctx context.Context, src string, nsrrset *core.RRset, zonename, referringZone string,
	nsMap map[string]bool, r *dns.Msg) (map[string]*cache.AuthServer, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if r == nil {
		return nil, fmt.Errorf("message is nil")
	}
	// If we don't know the zone name (no NS owner found), don't mutate ServerMap with an empty key
	if zonename == "" {
		if imr.Cache.Debug && !imr.Quiet {
			lgDns.Debug("ParseAdditionalForNSAddrs: empty zonename; skipping glue collection")
		}
		return map[string]*cache.AuthServer{}, nil
	}
	// A stub's servers are configuration: the glue and transport signals in a
	// response do not change them, and the lookup goes on to the configured
	// servers. The map's entries are the stub's own AuthServer instances, so
	// the processing below would add to them in place.
	if imr.Cache.IsStubZone(zonename) {
		serverMap, _ := imr.Cache.ServerMapCopy(zonename)
		return serverMap, nil
	}

	if Globals.Debug && !imr.Quiet {
		lgDns.Debug("*** ParseAdditionalForNSAddrs: zonename: \nnsMap", "zonename", zonename, "nnsmap", nsMap)
	}

	// Collect any glue from Additional
	glue4Map := map[string]core.RRset{}
	glue6Map := map[string]core.RRset{}
	// ServerMapCopy, not ServerMap.Get: this map is edited below and handed on.
	serverMap, exist := imr.Cache.ServerMapCopy(zonename)
	if !exist {
		serverMap = map[string]*cache.AuthServer{}
	}

	// Prune expired auth servers for this zone before updating. The servers are
	// the shared instances, which other queries and the background address
	// lookups read and write concurrently: every access goes through the
	// accessors, which hold the server's lock.
	now := cache.Now()
	for name, srv := range serverMap {
		if expire := srv.GetExpire(); !expire.IsZero() && expire.Before(now) {
			delete(serverMap, name)
			if Globals.Debug && !imr.Quiet {
				lgDns.Debug("ParseAdditionalForNSAddrs: pruned expired server for zone", "server", name, "zone", zonename)
			}
		}
	}

	// Single pass through Additional section: handle glue records and transport signals.
	// oots SVCB records for one nameserver are collected and applied once after
	// the pass. Applying each as it arrives would let the second replace the first.
	glueZone := referralGlueZone(referringZone, zonename)
	pendingSVCB := map[string]*svcbSignalSet{}
	for _, rr := range r.Extra {
		owner := rr.Header().Name
		baseName, isOOTSOwner, _ := parseOwnerName(owner)

		// Determine which server name to use and whether to process this record
		var serverName string
		var isGlueRecord bool
		var shouldProcessTransportSignal bool

		switch rr.(type) {
		case *dns.A, *dns.AAAA:
			// Glue records must match an NS name directly (not _dns.*)
			if !isOOTSOwner {
				if _, exist := nsMap[baseName]; exist {
					serverName = baseName
					isGlueRecord = true
				} else {
					if !imr.Quiet {
						lgDns.Debug("*** IterativeDNSQuery: non-glue record in Additional", "additional", rr.String())
					}
					continue
				}
			} else {
				// A/AAAA with _dns. prefix is not glue, skip
				continue
			}
		case *dns.SVCB, *dns.PrivateRR:
			// -03: ignore Additional OOTS unless we set the OOTS option (use-transport-signals).
			if imr.Options[ImrOptUseTransportSignals] == "false" {
				continue
			}
			// Transport signals: process if:
			// 1. First pass equivalent: isOOTSOwner AND baseName in nsMap (will create server entry)
			// 2. Second pass equivalent: isOOTSOwner AND baseName in serverMap (server already exists)
			if isOOTSOwner {
				_, inNsMap := nsMap[baseName]
				_, inServerMap := serverMap[cache.ServerKey(baseName)]
				if inNsMap || inServerMap {
					serverName = baseName
					shouldProcessTransportSignal = true
				} else {
					// OOTS owner but server not in nsMap or serverMap, skip
					continue
				}
			} else {
				// Not OOTS owner, skip transport signals (they should be _dns.*)
				if !imr.Quiet {
					lgDns.Debug("*** IterativeDNSQuery: non-glue record in Additional", "additional", rr.String())
				}
				continue
			}
		default:
			// Unknown record type, skip
			continue
		}

		// Only for a name within the referring zone (imr_referral_glue.go).
		// For a nameserver outside it the record is not used, and its
		// addresses are looked up as for a referral without glue.
		if !withinGlueZone(owner, glueZone) {
			if !imr.Quiet {
				lgDns.Debug("ParseAdditionalForNSAddrs: record outside the referring zone not used",
					"rr", rr.String(), "zone", zonename, "referring_zone", referringZone)
			}
			continue
		}

		// Create server entry if it doesn't exist (for glue records or transport signals with nsMap match)
		_, exist := serverMap[cache.ServerKey(serverName)]
		justCreated := false
		if !exist && (isGlueRecord || shouldProcessTransportSignal) {
			serversrc := ""
			switch src {
			case "answer":
				serversrc = "answer"
			case "authority":
				serversrc = "referral"
			}
			// Use shared AuthServer instance across all zones
			serverMap[cache.ServerKey(serverName)] = imr.Cache.GetOrCreateAuthServer(serverName)
			// Update fields for this specific context
			serverMap[cache.ServerKey(serverName)].SetSrc(serversrc)
			if imr.Debug {
				serverMap[cache.ServerKey(serverName)].PromoteDebug()
			}
			justCreated = true
		}

		if justCreated {
			if owner := transportOwnerForNS(serverName); owner != "" {
				imr.maybeQueryTransportSignal(ctx, owner, transportQueryReasonNewServer)
			}
			imr.maybeQueryTLSA(ctx, serverName)
		}

		// Process the record based on type
		switch rr := rr.(type) {
		case *dns.A:
			srv := serverMap[cache.ServerKey(serverName)]
			srv.AddAddr(rr.A.String())
			// set expiry for this server mapping from glue TTL
			srv.SetExpire(cache.Now().Add(time.Duration(rr.Header().Ttl) * time.Second))
			tmp := glue4Map[serverName]
			tmp.RRs = append(tmp.RRs, rr)
			glue4Map[serverName] = tmp

		case *dns.AAAA:
			srv := serverMap[cache.ServerKey(serverName)]
			srv.AddAddr(rr.AAAA.String())
			// set expiry for this server mapping from glue TTL
			srv.SetExpire(cache.Now().Add(time.Duration(rr.Header().Ttl) * time.Second))
			tmp := glue6Map[serverName]
			tmp.RRs = append(tmp.RRs, rr)
			glue6Map[serverName] = tmp

		case *dns.SVCB:
			if shouldProcessTransportSignal {
				if !imr.Quiet {
					lgDns.Debug("Additional contains an SVCB; rr", "rr", rr.String())
				}
				imr.collectSVCBSignal(pendingSVCB, serverName, rr)
			}

		case *dns.PrivateRR:
			if shouldProcessTransportSignal {
				if !imr.Quiet {
					lgDns.Debug("Additional contains TSYNC; rr", "rr", rr.String())
				}
				imr.parseTSYNCTransportSignal(rr, serverName, serverMap, ctx)
			}
		}
	}

	for key, set := range pendingSVCB {
		imr.decideAdditionalPath(set, r.Extra, cache.SignalViaReferral)
		imr.applySVCBSignalSet(ctx, serverMap[key], set)
	}

	for nsname, rrset := range glue4Map {
		if len(rrset.RRs) == 0 {
			continue
		}
		rr := rrset.RRs[0]
		if Globals.Debug && !imr.Quiet {
			fmt.Printf("ParseAdditionalForNSAddrs: Calling rrcache.Set for <%s, A> (adding glue unless a live answer is cached)\n", nsname)
		}
		imr.Cache.SetUnless(nsname, dns.TypeA, &cache.CachedRRset{
			Name:       nsname,
			RRtype:     dns.TypeA,
			RRset:      &rrset,
			Context:    cache.ContextGlue,
			State:      cache.ValidationStateIndeterminate,
			Expiration: cache.Now().Add(time.Duration(rr.Header().Ttl) * time.Second),
			Transport:  core.TransportDo53, // Glue records from Additional - default to Do53
		}, glueKeeps) // not over a live answer (glueMayReplace)
	}

	for nsname, rrset := range glue6Map {
		if len(rrset.RRs) == 0 {
			continue
		}
		rr := rrset.RRs[0]
		if Globals.Debug && !imr.Quiet {
			fmt.Printf("ParseAdditionalForNSAddrs: Calling rrcache.Set for <%s, AAAA> (adding glue unless a live answer is cached)\n", nsname)
		}
		imr.Cache.SetUnless(nsname, dns.TypeAAAA, &cache.CachedRRset{
			Name:       nsname,
			RRtype:     dns.TypeAAAA,
			RRset:      &rrset,
			Context:    cache.ContextGlue,
			State:      cache.ValidationStateIndeterminate,
			Expiration: cache.Now().Add(time.Duration(rr.Header().Ttl) * time.Second),
			Transport:  core.TransportDo53, // Glue records from Additional - default to Do53
		}, glueKeeps) // not over a live answer (glueMayReplace)
	}

	if Globals.Debug && !imr.Quiet {
		lgDns.Debug("*** ParseAdditionalForNSAddrs: adding servers for zone to cache",
			"adding", len(serverMap),
			"zone", zonename)
	}
	// rrcache.Servers.Set(zonename, servers)
	imr.Cache.AddServers(zonename, serverMap)

	if Globals.Debug && !imr.Quiet {
		lgDns.Debug("ParseAdditionalForNSAddrs: serverMap:")
		for n, as := range serverMap {
			lgDns.Debug("server: : (addrs: )", "server", n, "s", as.Name, "addrs", as.GetAddrs())
		}
	}

	return serverMap, nil
}

// parseTransportString removed; use transport.ParseTransportString
// pickTransport removed in W6 cleanup; its logic was absorbed into
// candidateTransports + the prioritizeServers tuple-expansion loop.

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

// Helpers

// authQueryMsg is a query for an authoritative server: the resolver's own
// iterative traffic, including priming, trust-anchor and DNSKEY fetches, and
// nameserver address lookups. RD is cleared. miekg's SetQuestion sets it, and
// a server that also recurses answers an RD=1 query from its recursive side,
// handing back something other than its own data and referrals (#817). The
// forwarding paths ask a server to recurse; they build their own messages and
// keep RD set.
func authQueryMsg(qname string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(qname, qtype)
	m.RecursionDesired = false
	m.SetEdns0(4096, true)
	return m
}

// referralLeavesZone reports whether an NS RRset owned by refZone, returned by
// a server of zone, is a referral: whether refZone lies strictly below zone.
// With either name unknown it says yes, which is how every NS RRset was read
// before the zone was compared.
func referralLeavesZone(refZone, zone string) bool {
	if refZone == "" || zone == "" {
		return true
	}
	ref, cur := dns.CanonicalName(refZone), dns.CanonicalName(zone)
	return ref != cur && dns.IsSubDomain(cur, ref)
}

// replyMatchesQuery reports why r is not an answer to query's question, or nil
// when it is: r must carry exactly one question, with the query's name
// (compared case-insensitively), type and class (RFC 1035 section 7.3, RFC 5452
// section 3). A reply that fails this says nothing about the name that was
// asked, and is not used: taking its records for the queried name is how a
// server answering some other question -- or none -- would reach the cache.
func replyMatchesQuery(r, query *dns.Msg) error {
	if len(r.Question) != 1 {
		return fmt.Errorf("reply carries %d questions, want 1", len(r.Question))
	}
	if len(query.Question) != 1 {
		return nil
	}
	rq, q := r.Question[0], query.Question[0]
	if !strings.EqualFold(rq.Name, q.Name) || rq.Qtype != q.Qtype || rq.Qclass != q.Qclass {
		return fmt.Errorf("reply is for %s %s %s, the query was for %s %s %s",
			rq.Name, dns.ClassToString[rq.Qclass], dns.TypeToString[rq.Qtype],
			q.Name, dns.ClassToString[q.Qclass], dns.TypeToString[q.Qtype])
	}
	return nil
}

// dnskeyAttemptKey is what a DNSKEY bypass attempt is deduplicated by: the
// address and port the attempt would dial (attemptKey) and the transport. Two
// servers that share an address but signal different ports or targets for
// the transport are two endpoints, and a failure on one must not skip the
// other.
func (imr *Imr) dnskeyAttemptKey(ctx context.Context, server *cache.AuthServer, zone *cache.Zone, addr string, t core.Transport) cache.AddrXport {
	d, ok := imr.attemptKey(ctx, server, zone, addr, t, false)
	if !ok {
		return cache.AddrXport{Addr: addr, Transport: t}
	}
	return cache.AddrXport{Addr: d.addr, Port: d.keyPort, Transport: t}
}

// dnskeyTried is the key a DNSKEY bypass attempt is recorded under once it
// has been made: the endpoint tryServer dialed, at its address and key port
// over the effective transport eff, or pre, the key the attempt was checked
// against, when tryServer chose no endpoint. Recording pre for an attempt
// that dialed elsewhere, as a target whose addresses came in between the two
// readings, would skip a later attempt at an endpoint never dialed.
func dnskeyTried(pre cache.AddrXport, ep endpointDial, eff core.Transport) cache.AddrXport {
	if ep.addr == "" {
		return pre
	}
	return cache.AddrXport{Addr: ep.addr, Port: ep.keyPort, Transport: eff}
}

func buildQuery(qname string, qtype uint16, withOOTS bool) (*dns.Msg, error) {
	m := authQueryMsg(qname, qtype)
	if withOOTS {
		if err := edns0.AddOOTSToMessage(m); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// tryServer executes one query attempt for an explicit (server, addr,
// transport) tuple selected upstream by prioritizeServers. It records the
// outcome against the per-(addr, port, transport) backoff map of the instance
// it dialed: the server's own, or a redirect target's (endpointDial.server).
//
// It returns the transport it attempted and the endpoint it tried, whose
// address and port its backoff and RTT went under (the zero endpointDial
// when it never got as far as choosing one). The caller books the rcode
// outcome by the same endpoint, not a fresh reading: a signal update during
// the exchange may have moved the port, and the answer came from the
// endpoint tried. zone is the zone the query is for (nil when none is
// known): an endpoint lame for it is not chosen (endpointFor).
//
// class is whose query it is, for the per-class answer counters. sel is
// what selection decided for the attempt (attemptSelection).
func (imr *Imr) tryServer(ctx context.Context, server *cache.AuthServer, zone *cache.Zone, addr string, t core.Transport, m *dns.Msg, qname string, qtype uint16, dnskeyBypass bool, class cache.TrafficClass, sel attemptSelection) (*dns.Msg, time.Duration, core.Transport, endpointDial, error) {
	eff := t
	if dnskeyBypass {
		// DNSKEY transport policy bypasses this server's probabilistic
		// transport weights and picks the best advertised transport instead.
		// Returns 0 only under force_encrypted when the server has no
		// encrypted transport; in that case we must fail rather than fall
		// back to cleartext.
		pref := imr.preferredDNSKEYTransport(server)
		if pref == 0 {
			return nil, 0, t, endpointDial{}, fmt.Errorf("dnssec.dnskey-query-transport=force_encrypted but server %s advertises no encrypted transport", server.Name)
		}
		eff = pref
	}

	select {
	case <-ctx.Done():
		return nil, 0, eff, endpointDial{}, ctx.Err()
	default:
	}

	c, exist := imr.Cache.DNSClient[eff]
	if !exist {
		return nil, 0, eff, endpointDial{}, fmt.Errorf("no DNS client for transport %d exists", eff)
	}
	// Where the attempt goes: the server's own address, at a port the signal
	// gave it, or an address of the target the signal sent the transport to
	// (oots_endpoints.go). At the server's own address backoff, RTT and the
	// family tracker stay on the bare IP, as they always were; at a target
	// they are kept under the target's address and the endpoint's port, on
	// the target's own instance (ep.server), as are the attempt's counters.
	// The server keeps the count of answers its targets carried for it.
	ep, eerr := imr.endpointFor(ctx, server, zone, addr, eff)
	// The endpoint chosen now is checked again: selection checked the one
	// an attempt would have dialed then, and an attempt earlier in the pass
	// may since have made it, or the fallback it gives way to, lame or
	// backed off, as a target that refused does for the next tuple sent to
	// it. So is its address family: one held suspect is dialed only as the
	// probe selection reserved for it, whether the family turned suspect
	// since, or the endpoint moved to another family, as a udp or tcp
	// endpoint at a target whose address has gone out of use gives way to
	// the server's own address. And an extra pass does not dial an endpoint
	// the pass before tried: a signal that changed since the selection may
	// send the tuple there. None of this applies under the DNSKEY bypass,
	// which dials the preferred transport whatever selection said, except
	// that it dials a target's address of a suspect family only for a probe
	// selection reserved: such an address is picked only when no other is
	// left (chooseEndpointAddr).
	if eerr == nil {
		target := cache.JoinDialAddr(ep.addr, ep.port)
		switch {
		case (!dnskeyBypass || ep.redirect) && imr.suspectWithoutProbe(sel, ep.addr):
			eerr = errEndpointSuspectFamily{server: server.Name, target: target, transport: eff}
		case dnskeyBypass:
		case !endpointUsable(ep.server, zone, ep.addr, ep.keyPort, eff):
			eerr = errEndpointUnavailable{server: server.Name, target: target, transport: eff}
		case sel.tried[passTuple{ep.server, ep.addr, ep.keyPort, eff}]:
			eerr = errEndpointTried{server: server.Name, target: target, transport: eff}
		}
	}
	if eerr != nil {
		if Globals.Debug {
			lgDns.Debug("tryServer: no attempt", "server", server.Name, "addr", addr, "transport", core.TransportToString[eff], "error", eerr)
		}
		return nil, 0, eff, endpointDial{}, eerr
	}
	ep.server.IncrementTransportCounter(eff)
	dial := ep.dialAddr()
	if Globals.Debug {
		lgDns.Debug("*** tryServer: calling c.Exchange",
			"transport", core.TransportToString[eff],
			"server", server.Name,
			"addrs", server.GetAddrs(),
			"addr", addr,
			"dial", dial,
			"redirect", ep.redirect,
			"target", redirectTargetName(ep),
			"qname", qname,
			"qtype", dns.TypeToString[qtype])
	}
	if !imr.Quiet {
		weights := server.GetTransportWeights()
		lgDns.Debug("IMR: query",
			"query", qname,
			"rrtype", dns.TypeToString[qtype],
			"name", server.Name,
			"transport", core.TransportToString[eff],
			"doq", weights[core.TransportDoQ],
			"dot", weights[core.TransportDoT],
			"doh", weights[core.TransportDoH],
			"do53", weights[core.TransportDo53])
	}
	for _, hook := range getImrOutboundQueryHooks() {
		if err := hook(ctx, qname, qtype, server.Name, ep.addr, eff); err != nil {
			return nil, 0, eff, ep, err
		}
	}

	// Single Exchange call: ExchangeCtxWithResult handles TC=1 and
	// UDP-transient-error TCP fallback internally for Do53 (DoT/DoH/DoQ have no
	// fallback path) and additionally reports the actual wire transport used and
	// whether a TC=1 truncation drove a UDP->TCP upgrade — used below for the
	// per-server transport-usage / truncation stats. The Exchange timeout bounds
	// wall time per call; the overall query budget (W2) bounds the iterative loop.
	//
	// Through ExchangeCtxWithResult rather than ExchangeWithResult so ctx
	// interrupts the exchange itself (#435): the ctx.Done() check above only
	// stops us BETWEEN servers, which left a hung server costing the full
	// client timeout even after the budget had expired or the daemon had
	// begun shutting down.
	//
	// We measure wall-clock RTT ourselves instead of trusting the rtt returned
	// by Exchange, because Exchange's TCP fallback path returns only the TCP
	// rtt and hides any preceding UDP-timeout cost. The wall-clock value is
	// what we actually care about for prioritization.
	start := time.Now()
	r, _, xres, err := core.ExchangeCtxWithResult(ctx, c, m, dial, Globals.Debug && !imr.Quiet)
	rtt := time.Since(start)
	// A TC=1 truncation upgrade is a size-driven fact about this exchange (not a
	// failure); record it regardless of the subsequent TCP outcome.
	if xres.Truncated {
		ep.server.IncrementTruncated()
	}
	// An abandoned exchange is not evidence about this server (#435). Since a
	// cancel now interrupts a query already on the wire, recording one would
	// let a shutdown — or an expired query budget — book a backoff against
	// every server that happened to be mid-exchange, and the address-family
	// tracker would read the same event as a network-level failure.
	if cerr := ctx.Err(); cerr != nil && err != nil {
		return nil, rtt, eff, ep, err
	}
	// A refused connection is an answer from the host: the path to it works,
	// whatever the server does. Counted as a family failure, a few servers
	// restarting at once (in different zones, on a family with little other
	// traffic) marked the whole family suspect, and every zone whose servers
	// were left with only addresses in it answered SERVFAIL until the suspect
	// window ran out (#703).
	imr.FamilyTracker.RecordResult(ep.addr, (err == nil && r != nil) || isConnRefused(err))
	if err != nil {
		lgDns.Error("*** tryServer: query returned error",
			"qname", qname,
			"qtype", dns.TypeToString[qtype],
			"addr", addr,
			"dial", dial,
			"transport", core.TransportToString[eff],
			"error", err)
		ep.server.RecordEndpointAddrFailure(ep.addr, ep.keyPort, eff, err)
		// Stats: key failed on the ACTUAL wire transport (symmetric with used on
		// success). A TC=1-then-TCP failure is thus attributed to Do53TCP, and
		// failed[Do53] stays 0 — preserving "failed[Do53]=0 => size upgrade".
		// (The backoff and RTT stay on eff: they are keyed by the attempted
		// address, port and transport, a separate concern from usage stats.)
		ep.server.IncrementFailedCounter(xres.WireTransport)
		// Penalty RTT: record the full elapsed time so a slow-failing path
		// naturally sorts to the bottom of prioritizeServers even after the
		// backoff lifts.
		ep.server.RecordEndpointAddrRTT(ep.addr, ep.keyPort, eff, rtt)
		return nil, rtt, eff, ep, err
	}
	if r != nil {
		// A reply to some other question, or to none, is a failed attempt at
		// this server: nothing below may read it as an answer to ours.
		if qerr := replyMatchesQuery(r, m); qerr != nil {
			lgDns.Warn("tryServer: discarding a reply that does not answer the query",
				"qname", qname,
				"qtype", dns.TypeToString[qtype],
				"addr", addr,
				"transport", core.TransportToString[eff],
				"error", qerr)
			ep.server.RecordEndpointAddrFailure(ep.addr, ep.keyPort, eff, qerr)
			ep.server.IncrementFailedCounter(xres.WireTransport)
			return nil, rtt, eff, ep, qerr
		}
		ep.server.RecordEndpointAddrSuccess(ep.addr, ep.keyPort, eff)
		ep.server.IncrementUsedCounter(xres.WireTransport, class)
		if ep.redirect {
			server.IncrementRedirectedCounter(xres.WireTransport)
		}
		ep.server.RecordEndpointAddrRTT(ep.addr, ep.keyPort, eff, rtt)
	} else if Globals.Debug {
		lgDns.Debug("*** tryServer: query returned no response",
			"qname", qname,
			"qtype", dns.TypeToString[qtype],
			"addr", addr,
			"transport", core.TransportToString[eff])
	}
	return r, rtt, eff, ep, nil
}

// applyTransportSignalToServer parses a received transport string (the
// transport= value of a TSYNC) and applies it to the given server. Only signal
// tokens count (core.ParseReceivedTransportString); a string naming none of
// them is not applied. Returns true if at least one transport entry was
// applied.
func (imr *Imr) applyTransportSignalToServer(server *cache.AuthServer, s string) bool {
	if server == nil || s == "" {
		return false
	}
	kvMap, err := core.ParseReceivedTransportString(s)
	if err != nil {
		lgDns.Debug("applyTransportSignalToServer: invalid transport string for :", "name", server.Name, "s", s, "q", err)
		return false
	}
	return applyTransportMapToServer(server, kvMap)
}

// applyTransportMapToServer installs a decoded weight map on server, keeping
// all weights (including do53). The do53 share and the per-query transport
// pick are computed later, at selection time, by candidateTransports — this
// just records the decoded weights and the set of transports (any order).
//
// kvMap is the signal as received: only the transports it names. The absence
// defaults (do53 100, the others 0) are applied here, to a copy, for
// selection; the signal itself is kept beside the weights, so that the stats
// can show what the server said rather than what the defaults made of it.
//
// Every oots and TSYNC path reaches selection through here, so the
// signal-token filter is applied here too, whatever the caller did: a key that
// is not a signal token (core.IsSignalToken) is dropped before it can be mapped
// by core.StringToTransport, whose operator aliases (do53-tcp, DoT, ...) are
// not tokens a server sends. A map with no signal token left is not applied:
// it is no signal, not one that gets the absence defaults. The ALPN fallback
// does not come through here; applyAlpnSignalToServer applies the same filter
// itself.
//
// The do53 shorthand is expanded into udp and tcp (core.ExpandDo53Shorthand)
// before the signal is recorded, so the stats show what it means. udp maps to
// TransportDo53 and tcp to TransportDo53TCP. The tcp weight is kept, but
// TransportDo53TCP is not entered among the transports selection draws from
// (core.SelectableTransport): the weight caps optional TCP, and tdns chooses
// none.
func applyTransportMapToServer(server *cache.AuthServer, kvMap map[string]uint8) bool {
	return applyTransportMapWithPorts(server, kvMap, nil)
}

// applyTransportMapWithPorts is applyTransportMapToServer with the ports the
// oots rule assigned. A nil or empty ports map clears any port the previous
// signal had stored: the new signal replaces the whole set.
func applyTransportMapWithPorts(server *cache.AuthServer, kvMap map[string]uint8, ports map[core.Transport]uint16) bool {
	return installTransportMap(server, kvMap, ports, nil, "", nil)
}

// installTransportMap is applyTransportMapWithPorts for a signal read from an
// SVCB RRset, with the targets its validated records assigned, where it
// arrived and the validation state of its path, which are stored with it
// (ReceivedSignal.Targets, ReceivedSignal.Via, ReceivedSignal.Path).
func installTransportMap(server *cache.AuthServer, kvMap map[string]uint8, ports map[core.Transport]uint16, targets map[core.Transport]string,
	via string, path []cache.SignalHop) bool {
	if server == nil || kvMap == nil {
		return false
	}
	named := core.FilterSignalTokens(kvMap)
	if len(named) == 0 {
		return false
	}
	core.ExpandDo53Shorthand(named)
	received := &cache.ReceivedSignal{Source: "oots", Weights: map[core.Transport]uint8{}, Ports: cache.DialPorts(ports), Targets: targets,
		Via: via, Path: path}
	for k, v := range named {
		if t, err := core.StringToTransport(k); err == nil {
			received.Weights[t] = v
		}
	}
	full := maps.Clone(named)
	core.ApplyTransportDefaults(full)
	weights, transports, alpnOrder := signalSelection(full)
	if len(weights) == 0 {
		return false
	}
	server.SetTransportSignal(transports, alpnOrder, weights, received)
	return true
}

// signalSelection maps a signal's weights, the do53 shorthand expanded, to
// what a server holds for selection: the weight of each transport, and the
// transports selection may choose with their names, in transport order. A
// transport selection does not choose on its own (core.SelectableTransport)
// keeps its weight but is not entered among the transports.
func signalSelection(m map[string]uint8) (map[core.Transport]uint8, []core.Transport, []string) {
	weights := make(map[core.Transport]uint8, len(m))
	for k, v := range m {
		t, err := core.StringToTransport(k)
		if err != nil {
			continue
		}
		weights[t] = v
	}
	transports := slices.Sorted(maps.Keys(weights))
	transports = slices.DeleteFunc(transports, func(t core.Transport) bool { return !core.SelectableTransport(t) })
	names := make([]string, 0, len(transports))
	for _, t := range transports {
		names = append(names, core.TransportToString[t])
	}
	return weights, transports, names
}

func transportOwnerForNS(nsname string) string {
	base := strings.TrimSpace(nsname)
	if base == "" {
		return ""
	}
	base = strings.TrimSuffix(base, ".")
	return dns.Fqdn("_dns." + base)
}

// applyAlpnSignalToServer applies 100-weight transports from a comma-separated
// ALPN list to a specific server pointer.
func applyAlpnSignalToServer(server *cache.AuthServer, alpnCSV string) bool {
	return applyAlpnSignalWithPorts(server, strings.Split(alpnCSV, ","), nil)
}

// applyAlpnSignalWithPorts is applyAlpnSignalToServer for a list already
// split, with the ports the ALPN records assigned. A received ALPN list is a
// received signal too, so only signal tokens count (core.IsSignalToken, after
// lower-casing): an `alpn=do53-tcp` or `alpn=h2` installs nothing through
// core.StringToTransport's operator aliases. Each token listed weighs 100, and
// do53 is the shorthand for udp and tcp, as in oots. It reports whether a
// signal was applied.
func applyAlpnSignalWithPorts(server *cache.AuthServer, tokens []string, ports map[core.Transport]uint16) bool {
	return installAlpnSignal(server, tokens, ports, nil, "", nil)
}

// installAlpnSignal is applyAlpnSignalWithPorts with the targets, where the
// signal arrived and the validation state of its path, as installTransportMap
// stores them.
func installAlpnSignal(server *cache.AuthServer, tokens []string, ports map[core.Transport]uint16, targets map[core.Transport]string,
	via string, path []cache.SignalHop) bool {
	if server == nil {
		return false
	}
	// The list's order is kept: it is the order the server gave.
	weights := map[core.Transport]uint8{}
	var transports []core.Transport
	var order []string
	add := func(tok string) {
		t, err := core.StringToTransport(tok)
		if _, dup := weights[t]; err != nil || dup {
			return
		}
		weights[t] = 100
		if core.SelectableTransport(t) {
			transports = append(transports, t)
			order = append(order, core.TransportToString[t])
		}
	}
	for _, tok := range tokens {
		k := strings.ToLower(strings.TrimSpace(tok))
		switch {
		case !core.IsSignalToken(k):
		case k == "do53":
			add("udp")
			add("tcp")
		default:
			add(k)
		}
	}
	if len(weights) == 0 {
		return false
	}
	received := &cache.ReceivedSignal{Source: "alpn", Weights: maps.Clone(weights), Ports: cache.DialPorts(ports),
		Targets: targets, Via: via, Path: path}
	server.SetTransportSignal(transports, order, weights, received)
	return true
}

// parseTransportForServerFromAdditional looks for a transport signal for the specific server in the Additional section.
// -03: ignore Additional OOTS unless we set the OOTS option on the query (coupled to use-transport-signals).
func (imr *Imr) parseTransportForServerFromAdditional(ctx context.Context, server *cache.AuthServer, r *dns.Msg) {
	if imr.Options[ImrOptUseTransportSignals] == "false" {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if server == nil || r == nil {
		lgDns.Debug("*** parseTransportForServerFromAdditional: server or r is nil")
		return
	}
	lgDns.Debug("parseTransportForServerFromAdditional: inspecting server", "server", server.Name, "addrs", server.GetAddrs())
	if len(r.Question) > 0 {
		lgDns.Debug("pTFSA: looking for transport signal in response", "qname", r.Question[0].Name, "qtype", dns.TypeToString[r.Question[0].Qtype], "additionalRRs", len(r.Extra))
	}
	if len(r.Extra) == 0 {
		lgDns.Debug("*** parseTransportForServerFromAdditional: no Additional section in response")
		return
	}
	// Canonicalize target owner to FQDN and lower-case for case-insensitive compare
	base := strings.TrimSuffix(server.Name, ".")
	targetOwner := dns.Fqdn("_dns." + base)
	// SVCBs are combined and applied after the section, so a second oots
	// record adds to the first instead of replacing it. A TSYNC in the same
	// section is applied where it stands and then replaced if any oots SVCB
	// is present: one message carries one signal, and oots is that signal.
	set := &svcbSignalSet{}
	for _, rr := range r.Extra {
		owner := dns.Fqdn(rr.Header().Name)
		if !core.EqualNames(owner, targetOwner) {
			lgDns.Debug("parseTransportForServerFromAdditional: owner != target", "owner", owner, "target", targetOwner)
			continue
		}
		lgDns.Debug("parseTransportForServerFromAdditional: owner matches target", "owner", owner, "target", targetOwner)
		switch x := rr.(type) {
		case *dns.SVCB:
			lgDns.Debug("**** parseTransportForServerFromAdditional: x", "x", x)
			set.add(x)
		case *dns.PrivateRR:
			lgDns.Debug("parseTransportForServerFromAdditional: TSYNC RR", "rr", x)
			if ts, ok := x.Data.(*core.TSYNC); ok && ts != nil {
				lgDns.Debug("parseTransportForServerFromAdditional: TSYNC data", "tsync", ts)
				lgDns.Debug("parseTransportForServerFromAdditional: TSYNC transports", "transports", ts.Transports)
				if ts.Transports != "" {
					val := strings.TrimPrefix(ts.Transports, "transport=")
					lgDns.Debug("parseTransportForServerFromAdditional: parsing TSYNC transport value", "value", val)
					if imr.applyTransportSignalToServer(server, val) {
						server.PromoteConnMode(cache.ConnModeOpportunistic)
					}
					if owner := transportOwnerForNS(server.Name); owner != "" {
						imr.maybeQueryTransportSignal(ctx, owner, transportQueryReasonObservation)
					}
					imr.maybeQueryTLSA(ctx, server.Name)
				}
			}
		}
	}
	imr.decideAdditionalPath(set, r.Extra, cache.SignalViaResponse)
	imr.applySVCBSignalSet(ctx, server, set)
}

// applyTransportRRsetFromAnswer applies the transport signal rrset, an answer
// for qname (_dns.<nameserver>), to that nameserver's servers in the cache's
// zone server maps. also names servers to apply it to besides those: a
// server a query holds that is in none of them yet
// (applyCachedTransportSignal).
func (imr *Imr) applyTransportRRsetFromAnswer(qname string, rrset *core.RRset, vstate cache.ValidationState, also ...*cache.AuthServer) {
	imr.applyTransportRRsetWalk(aliasWalk{}, qname, rrset, vstate, also...)
}

// applyTransportRRsetWalk is applyTransportRRsetFromAnswer, with walk for how
// an AliasMode record in rrset is followed (followLookupAlias).
func (imr *Imr) applyTransportRRsetWalk(walk aliasWalk, qname string, rrset *core.RRset, vstate cache.ValidationState, also ...*cache.AuthServer) {
	if imr.Cache == nil || rrset == nil || len(rrset.RRs) == 0 {
		return
	}
	owner := dns.Fqdn(qname)
	if !strings.HasPrefix(core.CanonicalizeName(owner), oobTransportPrefix) {
		return
	}
	// Sliced, not TrimPrefix'd: see parseOwnerName.
	base := owner[len(oobTransportPrefix):]
	if base == "" {
		return
	}
	targetMode := cache.ConnModeOpportunistic
	if vstate == cache.ValidationStateSecure {
		targetMode = cache.ConnModeValidated
	}
	set := &svcbSignalSet{}
	if rrset.RRtype == dns.TypeSVCB {
		for _, rr := range rrset.RRs {
			if svcb, ok := rr.(*dns.SVCB); ok {
				set.add(svcb)
			}
		}
		set.decideLookupPath(vstate)
		imr.followLookupAlias(set, walk)
	}
	// The shared instance of a nameserver is listed under every zone it
	// serves: it takes the signal once, and its ignored redirects count once.
	var servers []*cache.AuthServer
	for _, sm := range imr.Cache.ServerMap.Items() {
		if server, ok := sm[cache.ServerKey(base)]; ok {
			servers = append(servers, server)
		}
	}
	for _, server := range also {
		if server != nil && cache.ServerKey(server.Name) == cache.ServerKey(base) {
			servers = append(servers, server)
		}
	}
	done := map[*cache.AuthServer]bool{}
	for _, server := range servers {
		if done[server] {
			continue
		}
		done[server] = true
		applied := false
		switch rrset.RRtype {
		case dns.TypeSVCB:
			// The TLSA SvcParam follows the same rule as the signal: only
			// from a record the resolver acts on, and from none in an RRset
			// that holds an AliasMode record.
			if owners := tlsaOwnersForServer(base, server); len(owners) > 0 && !set.alias {
				for _, rr := range rrset.RRs {
					if svcb, ok := rr.(*dns.SVCB); ok && svcbUsable(svcb) {
						imr.storeTLSAFromSVCB(base, owners, svcb, vstate)
					}
				}
			}
			applied, _ = imr.installSVCBSignal(server, set)
		case core.TypeTSYNC:
			for _, rr := range rrset.RRs {
				if priv, ok := rr.(*dns.PrivateRR); ok {
					if ts, ok := priv.Data.(*core.TSYNC); ok && ts != nil && ts.Transports != "" {
						val := strings.TrimPrefix(ts.Transports, "transport=")
						if imr.applyTransportSignalToServer(server, val) {
							applied = true
						}
					}
				}
			}
		default:
			continue
		}
		if applied {
			// server is the shared instance, updated in place. Storing sm
			// again changed nothing, and could put back a map another writer
			// had just replaced.
			server.PromoteConnMode(targetMode)
		}
	}
}

// storeTLSAFromSVCB stores the TLSA SvcParam of one SVCB, if it has one, for
// each of the server's TLSA owners.
func (imr *Imr) storeTLSAFromSVCB(base string, owners []string, svcb *dns.SVCB, vstate cache.ValidationState) {
	for _, kv := range svcb.Value {
		local, ok := kv.(*dns.SVCBLocal)
		if !ok || uint16(local.Key()) != SvcbTLSAKey {
			continue
		}
		tlsaRR, err := ParseTLSAString(string(local.Data))
		if err != nil {
			lgDns.Error("applyTransportRRsetFromAnswer: failed to parse TLSA from SVCB", "svcb", err)
			continue
		}
		for _, ownerName := range owners {
			tlsa := &dns.TLSA{
				Hdr: dns.RR_Header{
					Name:   ownerName,
					Rrtype: dns.TypeTLSA,
					Class:  dns.ClassINET,
					Ttl:    svcb.Hdr.Ttl,
				},
				Usage:        tlsaRR.Usage,
				Selector:     tlsaRR.Selector,
				MatchingType: tlsaRR.MatchingType,
				Certificate:  tlsaRR.Certificate,
			}
			imr.Cache.StoreTLSAForServer(base, ownerName, &core.RRset{
				Name:   ownerName,
				Class:  dns.ClassINET,
				RRtype: dns.TypeTLSA,
				RRs:    []dns.RR{tlsa},
			}, vstate)
		}
	}
}

func (imr *Imr) handleAnswer(ctx context.Context, qname string, qtype uint16, r *dns.Msg, force bool, transport core.Transport, privacy edns0.PrivacyLevel) (*core.RRset, int, cache.CacheContext, core.Transport, error, bool) {
	if r == nil {
		if Globals.Debug {
			imr.Cache.Logger.Printf("*** handleAnswer: nil response for qname=%s, qtype=%s", qname, dns.TypeToString[qtype])
		}
		return nil, dns.RcodeServerFailure, cache.ContextFailure, transport, fmt.Errorf("nil response in handleAnswer"), false
	}

	if Globals.Debug {
		imr.Cache.Logger.Printf("*** handleAnswer: qname=%s, qtype=%s, rcode=%s, r: %s", qname, dns.TypeToString[qtype], dns.RcodeToString[r.MsgHdr.Rcode], PrintMsgFull(r, imr.LineWidth))
	}
	// qname is a CNAME: cache the link and follow the chain. Decided before
	// anything is collected, so that the link's RRSIG -- which follows it in
	// the section -- and a DNAME that synthesized it are both still there
	// (answerViaCNAME). The resolver's own DS or DNSKEY question is answered
	// by the CNAME itself: there is none at qname (cnameAsNoData).
	if cn := cnameAt(r, qname); cn != nil {
		switch {
		case followsCNAME(ctx, qtype):
			return imr.answerViaCNAME(ctx, qname, qtype, r, cn, force, transport, privacy)
		case cnameDeniesType(ctx, qtype):
			return imr.cnameAsNoData(ctx, qname, qtype, r, cn, transport)
		}
	}
	// The answer is built only from the records owned by qname, the name asked
	// for: its records of qtype, and its RRSIGs that cover qtype. Records of
	// qtype owned by another name are not part of it, nor are signatures over
	// another RRset. The RRset is validated, cached and served as qname's.
	var rrset core.RRset
	owner := dns.Fqdn(qname)
	for _, rr := range r.Answer {
		t := rr.Header().Rrtype
		owned := core.EqualNames(rr.Header().Name, owner)
		switch {
		case t == qtype && owned:
			rrset.RRs = append(rrset.RRs, rr)
		case t == qtype:
			imr.Cache.Logger.Printf("handleAnswer: a %s RR owned by %s is not part of the answer for %s %s",
				dns.TypeToString[t], rr.Header().Name, qname, dns.TypeToString[qtype])
		case t == dns.TypeRRSIG:
			if sig, ok := rr.(*dns.RRSIG); ok && owned && sig.TypeCovered == qtype {
				rrset.RRSIGs = append(rrset.RRSIGs, rr)
			}
		default:
			imr.Cache.Logger.Printf("Got a %s RR when looking for %s %s", dns.TypeToString[t], qname, dns.TypeToString[qtype])
		}
	}
	if len(rrset.RRs) > 0 {
		// Fill RRset metadata
		rrset.Name = qname
		rrset.Class = dns.ClassINET
		rrset.RRtype = qtype
		// Validate the RRset (if possible) using DnskeyCache
		// Always call ValidateRRset - it will check zone state even when there are no RRSIGs
		var vstate cache.ValidationState
		if Globals.Debug {
			imr.Cache.Logger.Printf("*** handleAnswer: validating RRset for %s %s:\n%s", qname, dns.TypeToString[qtype], rrset.String(imr.LineWidth))
		}
		// With the authority section: an answer synthesized from a wildcard
		// is validated with the proof that came with it, which is kept.
		verdict, err := imr.Cache.ValidateAnswer(ctx, &rrset, authorityRRsets(r.Ns), imr.IterativeDNSQueryFetcher())
		vstate = verdict.State
		if err != nil {
			lgDns.Error("handleAnswer: failed to validate RRset", "rrset", err)
			return nil, r.MsgHdr.Rcode, cache.ContextFailure, transport, err, false
		}
		if Globals.Debug {
			imr.Cache.Logger.Printf("*** handleAnswer: validated RRset for %s %s:\n%s", qname, dns.TypeToString[qtype], rrset.String(imr.LineWidth))
		}
		cr := &cache.CachedRRset{
			Name:          qname,
			RRtype:        qtype,
			Rcode:         uint8(r.MsgHdr.Rcode),
			RRset:         &rrset,
			Context:       cache.ContextAnswer,
			State:         vstate,
			EDECode:       verdict.EDECode,
			EDEText:       verdict.EDEText,
			WildcardProof: verdict.Proof,
			Expiration:    cache.Now().Add(cache.GetMinTTL(rrset.RRs)),
			Transport:     transport,
		}
		imr.Cache.Set(qname, qtype, cr)
		if qtype == dns.TypeSVCB || qtype == core.TypeTSYNC {
			imr.applyTransportRRsetWalk(aliasWalkFor(ctx), qname, &rrset, vstate)
		} else if qtype == dns.TypeTLSA {
			base := baseFromTLSAOwner(qname)
			if base != "" {
				imr.Cache.StoreTLSAForServer(base, qname, &rrset, vstate)
			}
		}
		// Note: DNSKEYs are added to DnskeyCache by ValidateDNSKEYs() upon successful validation,
		// so we don't need to add them here. This ensures keys are available immediately for
		// validating subsequent RRsets (e.g., A records signed by ZSKs).
		return &rrset, r.MsgHdr.Rcode, cache.ContextAnswer, transport, nil, true
	}
	return nil, r.MsgHdr.Rcode, cache.ContextFailure, transport, nil, false
}

// extractReferral builds an RRset of NS records (and any RRSIGs that cover NS) from a DNS message
// and returns that RRset, the zone name for the NS records, and a map of NS hostnames found.
// When qtype is NS the function inspects the Answer section; otherwise it inspects the Authority section.
// The returned RRset contains the collected NS RRs and any RRSIGs whose TypeCovered is NS.
// extractReferral extracts the NS RRset and any RRSIGs that cover NS from a DNS message for the given query.
// It returns a pointer to a core.RRset containing the collected NS records and their RRSIGs, the owner name of the NS RRset (empty if none found), and a map whose keys are the NS hostnames.
func extractReferral(r *dns.Msg, qname string, qtype uint16) (*core.RRset, string, map[string]bool) {
	nsMap := map[string]bool{}
	zonename := ""
	// A referral always carries its NS RRset in the AUTHORITY section, regardless
	// of the query type — including a QTYPE=NS query whose parent delegation puts
	// the child NS in Authority with an empty Answer. (The apex-NS *answer* case,
	// NS in the ANSWER section with aa=1, is handled earlier by handleAnswer;
	// extractReferral is only ever reached to extract a referral/delegation.)
	// Previously this read r.Answer for QTYPE=NS, so a QTYPE=NS query would find
	// no NS in the parent's referral and loop until "max iterations reached".
	nsrrs := r.Ns
	var rrset core.RRset
	for _, rr := range nsrrs {
		switch rr.Header().Rrtype {
		case dns.TypeNS:
			if ns, ok := rr.(*dns.NS); ok {
				rrset.RRs = append(rrset.RRs, rr)
				nsMap[ns.Ns] = true
				zonename = rr.Header().Name
			}
		case dns.TypeRRSIG:
			if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeNS {
				rrset.RRSIGs = append(rrset.RRSIGs, rr)
			}
		}
	}
	return &rrset, zonename, nsMap
}

// collectDSFromAuthority picks the DS RRset for zonename, and its signatures,
// out of a referral's authority section.
//
// The owner names come from another server's response, so their spelling is
// that server's choice -- and under 0x20 query-name randomisation it is
// whatever we happened to send. Compared byte-wise, the DS records were
// dropped and the child looked unsigned; worse, the two comparisons could
// disagree, keeping the DS RRset while discarding the RRSIGs that prove it.
//
// Pulled out of handleReferral so it can be tested without a network.
func collectDSFromAuthority(authority []dns.RR, zonename string) (dsRRs, dsSigs []dns.RR) {
	for _, rr := range authority {
		switch rr.Header().Rrtype {
		case dns.TypeDS:
			if core.EqualNames(rr.Header().Name, zonename) {
				dsRRs = append(dsRRs, rr)
			}
		case dns.TypeRRSIG:
			sig, ok := rr.(*dns.RRSIG)
			if ok && sig.TypeCovered == dns.TypeDS && core.EqualNames(rr.Header().Name, zonename) {
				dsSigs = append(dsSigs, rr)
			}
		}
	}
	return dsRRs, dsSigs
}

// zoneHasVerdict reports whether a ZoneMap entry holds a validation verdict. An
// entry made before its zone was judged holds none, and an Indeterminate state
// reads as none once it has stood for cache.ZoneStateRecheck.
func zoneHasVerdict(z *cache.Zone) bool {
	switch z.GetState() {
	case cache.ValidationStateSecure, cache.ValidationStateInsecure,
		cache.ValidationStateIndeterminate, cache.ValidationStateBogus:
		return true
	}
	return false
}

// handleReferral follows r, a referral for qname from servers of serversZone
// ("" when that is not known), and caches what it carries: the delegated zone's
// NS RRset, its DS, and the glue and transport signals that may be used
// (ParseAdditionalForNSAddrs).
func (imr *Imr) handleReferral(ctx context.Context, qname string, qtype uint16, r *dns.Msg, force bool, visitedZones map[string]bool, serversZone string, transport core.Transport, privacy edns0.PrivacyLevel) (*core.RRset, int, cache.CacheContext, core.Transport, error) {
	if Globals.Debug && !imr.Quiet {
		imr.Cache.Logger.Printf("*** handleReferral: rcode=NOERROR, this is a referral or neg resp")
	}
	nsRRset, zonename, nsMap := extractReferral(r, qname, qtype)

	// Check for referral loop: have we already been referred to this zone for this qname?
	if zonename != "" {
		referralKey := fmt.Sprintf("%s:%s", qname, zonename)
		if visitedZones[referralKey] {
			if Globals.Debug {
				imr.Cache.Logger.Printf("handleReferral: detected referral loop - already referred to zone %q for qname %q, aborting", zonename, qname)
			}
			return nil, r.MsgHdr.Rcode, cache.ContextFailure, transport, fmt.Errorf("referral loop detected: already referred to zone %q for qname %q", zonename, qname)
		}
		visitedZones[referralKey] = true
		if Globals.Debug {
			imr.Cache.Logger.Printf("handleReferral: tracking referral to zone %q for qname %q", zonename, qname)
		}
	}

	if Globals.Debug && !imr.Quiet {
		imr.Cache.Logger.Printf("*** handleReferral: zone name is %q, nsRRset: %+v", zonename, nsRRset)
	}
	if len(nsRRset.RRs) != 0 {
		nsRRset.Name = zonename
		nsRRset.Class = dns.ClassINET
		nsRRset.RRtype = dns.TypeNS
		if Globals.Debug && !imr.Quiet {
			fmt.Printf("handleReferral: Calling rrcache.Set for <%s, NS>\n", zonename)
		}
		// Validate NS RRset if signatures are present
		vstate := cache.ValidationStateNone
		var err error
		if len(nsRRset.RRSIGs) > 0 {
			vstate, err = imr.Cache.ValidateRRsetWithParentZone(ctx, nsRRset, imr.IterativeDNSQueryFetcher(), imr.ParentZone)
			if err != nil {
				lgDns.Error("handleReferral: failed to validate NS RRset", "rrset", err)
				return nil, r.MsgHdr.Rcode, cache.ContextFailure, transport, err
			}
		}
		// If validation state is None (not validated), set to Indeterminate for referral data
		if vstate == cache.ValidationStateNone {
			vstate = cache.ValidationStateIndeterminate
		}
		imr.Cache.Set(zonename, dns.TypeNS, &cache.CachedRRset{
			Name:       zonename,
			RRtype:     dns.TypeNS,
			Rcode:      uint8(r.MsgHdr.Rcode),
			RRset:      nsRRset,
			Context:    cache.ContextReferral,
			State:      vstate,
			Expiration: cache.Now().Add(cache.GetMinTTL(nsRRset.RRs)),
			Transport:  transport,
		})
	}
	// Also collect and cache DS RRset (signed) when present in referral
	dsRRs, dsSigs := collectDSFromAuthority(r.Ns, zonename)
	if len(dsRRs) > 0 {
		dsRRset := &core.RRset{
			Name:   zonename,
			Class:  dns.ClassINET,
			RRtype: dns.TypeDS,
			RRs:    dsRRs,
			RRSIGs: dsSigs,
		}
		vstate := cache.ValidationStateNone
		var err error
		if len(dsSigs) > 0 {
			vstate, err = imr.Cache.ValidateRRsetWithParentZone(ctx, dsRRset, imr.IterativeDNSQueryFetcher(), imr.ParentZone)
			if err != nil {
				lgDns.Error("handleReferral: failed to validate DS RRset", "rrset", err)
				return nil, r.MsgHdr.Rcode, cache.ContextFailure, transport, err
			}
		}
		// A signed DS validates Secure or Indeterminate, or Insecure when the
		// parent is insecure: a DS is the parent's data. An unsigned one stays
		// None.
		imr.noteDSEncountered(dsRRs)
		imr.Cache.Set(zonename, dns.TypeDS, &cache.CachedRRset{
			Name:       zonename,
			RRtype:     dns.TypeDS,
			Rcode:      uint8(r.MsgHdr.Rcode),
			RRset:      dsRRset,
			Context:    cache.ContextReferral,
			State:      vstate,
			Expiration: cache.Now().Add(cache.GetMinTTL(dsRRs)),
			Transport:  transport,
		})
		// A DS that validated makes the child Secure. Any other verdict proves
		// nothing about the child by itself, and ReferralChildState below
		// decides, knowing whether the parent's DS had to validate. This used to
		// enter the child as Indeterminate, so a DS altered on the path, or
		// stripped of its RRSIG, left a signed child whose unsigned answers were
		// served.
		if vstate == cache.ValidationStateSecure {
			z, ok := imr.Cache.ZoneMap.Get(zonename)
			if !ok {
				z = &cache.Zone{ZoneName: zonename}
			}
			z.SetState(vstate)
			imr.Cache.ZoneMap.Set(zonename, z)
		}
	}
	// A child the referral has not made Secure is entered as its parent proves
	// it (ReferralChildState), and so is one whose entry holds no verdict: an
	// Indeterminate state reads as none once it has stood for ZoneStateRecheck.
	// This used to be Insecure whenever the resolver held any trust anchor, so a
	// referral with its DS stripped turned DNSSEC off for the child. A DS that
	// validated Insecure is decided the same way, by the parent's own state:
	// that verdict alone comes as easily from an RRSIG that merely names a zone
	// held Insecure as its signer.
	if nsRRset != nil && zonename != "" && len(nsRRset.RRs) > 0 {
		if z, exists := imr.Cache.ZoneMap.Get(zonename); !exists || !zoneHasVerdict(z) {
			if state, ok := imr.Cache.ReferralChildState(ctx, zonename, r.Ns, imr.IterativeDNSQueryFetcher()); ok {
				if exists {
					z.SetState(state)
				} else {
					imr.Cache.ZoneMap.SetIfAbsent(zonename, &cache.Zone{ZoneName: zonename, State: state})
				}
			}
		}
	}
	serverMap, err := imr.ParseAdditionalForNSAddrs(ctx, "authority", nsRRset, zonename, serversZone, nsMap, r)
	if err != nil {
		lgDns.Error("*** handleReferral: Error from CollectNSAddressesFromAdditional",
			"collectnsaddressesfromadditional", err)
		return nil, r.MsgHdr.Rcode, cache.ContextFailure, transport, err
	}

	// For out-of-bailiwick nameservers, we still need their addresses if they
	// are not already present in cache. In-bailiwick NS should primarily use
	// glue (and, when ImrOptRevalidateNS is enabled, will later be
	// revalidated by scheduleReferralNSRevalidation / revalidateInBailiwickGlue).
	// Not for a stub: its servers are the configured ones, whatever the
	// referral names.
	if nsRRset != nil && zonename != "" && len(nsRRset.RRs) > 0 && !imr.Cache.IsStubZone(zonename) {
		inBailiwick := func(host, zone string) bool {
			return dns.IsSubDomain(dns.Fqdn(zone), dns.Fqdn(host))
		}

		var oobRRset core.RRset
		// Initialize oobRRset with proper fields from nsRRset
		oobRRset.Name = zonename
		oobRRset.Class = dns.ClassINET
		oobRRset.RRtype = dns.TypeNS
		oobKnown := map[string]*cache.AuthServer{}
		for _, rr := range nsRRset.RRs {
			ns, ok := rr.(*dns.NS)
			if !ok {
				continue
			}
			// Ensure RR header matches the RRset
			if rr.Header().Rrtype != dns.TypeNS {
				continue
			}
			if inBailiwick(ns.Ns, zonename) {
				// in-bailiwick: prefer glue; any needed revalidation is handled
				// by scheduleReferralNSRevalidation below.
				continue
			}
			// Out-of-bailiwick, outside the delegated zone. The referral's
			// glue for such a name is used only when the name lies within the
			// referring zone (sibling glue, RFC 9471); ParseAdditionalForNSAddrs
			// cached it, and it is found below. For a name outside the
			// referring zone the glue is not used (imr_referral_glue.go), and
			// the addresses come from the cache or a lookup. We have two cases:
			//
			//   1. Addresses already cached (from glue or a prior query) -
			//      seed serverMap so prioritizeServers can try this NS.
			//      Previously this was a `continue` that silently dropped
			//      the known-good address on the floor, leading to "no
			//      Answers found" when the in-bailiwick NS happened to be
			//      down even though we knew of a working alternate.
			//
			//   2. No cached addresses - resolve them in the background
			//      (resolveZoneServersInBackground, further down), which adds
			//      each server to the zone's cached server map once it has an
			//      address. The current foreground query may not see the
			//      result, but the next one will, and
			//      expandServerMapWithMissingNS handles the "we need this
			//      address right now" case as a fallback.
			//
			// Case 1 servers are stored in the zone's cached map too:
			// ParseAdditionalForNSAddrs stored it before they were added here,
			// and serverMap is this query's copy (#682).
			cachedA := imr.Cache.Get(ns.Ns, dns.TypeA)
			cachedAAAA := imr.Cache.Get(ns.Ns, dns.TypeAAAA)
			haveA := cachedA != nil && cachedA.RRset != nil && len(cachedA.RRset.RRs) > 0
			haveAAAA := cachedAAAA != nil && cachedAAAA.RRset != nil && len(cachedAAAA.RRset.RRs) > 0
			if haveA || haveAAAA {
				srv, present := serverMap[cache.ServerKey(ns.Ns)]
				if !present {
					srv = imr.Cache.GetOrCreateAuthServer(ns.Ns)
					srv.SetSrc("referral-oob-cached")
					serverMap[cache.ServerKey(ns.Ns)] = srv
				}
				// AuthServer.Addrs stores BARE IPs (no port). Exchange adds
				// the port via JoinHostPort when dialing.
				if haveA {
					for _, addrRR := range cachedA.RRset.RRs {
						if a, ok := addrRR.(*dns.A); ok {
							srv.AddAddr(a.A.String())
						}
					}
				}
				if haveAAAA {
					for _, addrRR := range cachedAAAA.RRset.RRs {
						if a, ok := addrRR.(*dns.AAAA); ok {
							srv.AddAddr(a.AAAA.String())
						}
					}
				}
				oobKnown[cache.ServerKey(ns.Ns)] = srv
				continue
			}
			oobRRset.RRs = append(oobRRset.RRs, rr)
		}
		imr.storeZoneServers(zonename, oobKnown)
		// Depth-aware resolution budget: it matters more to find good
		// addresses near the root because each TLD / SLD NS is reused
		// across millions of downstream queries; a name deep in the
		// long tail benefits only the few queries that touch it. So
		// resolve more aggressively at shallow depths and back off as
		// we descend.
		//
		//   depth(child) ≤ nsLookupShallowDepth → nsLookupBudgetShallow
		//                 lookups per pass (default 3, applies to TLDs
		//                 like net. and SLDs like axfr.net.)
		//   depth(child) >  nsLookupShallowDepth → nsLookupBudgetDeep
		//                 lookups per pass (default 1, applies from
		//                 the third label down)
		//
		// "Per pass" = once per referral that delegates into this zone.
		// Frequently-visited zones converge to full coverage quickly;
		// rarely-visited deep zones converge slowly. Backwaters that
		// never get visited stay sparsely resolved — that's correct,
		// the cost wouldn't be amortized over anything.
		if len(oobRRset.RRs) > 0 {
			budget := nsLookupBudgetDeep
			if zoneDepth(zonename) <= nsLookupShallowDepth {
				budget = nsLookupBudgetShallow
			}
			if len(oobRRset.RRs) > budget {
				// Pick `budget` of them at random. Random spreads the
				// resolution load across an IMR population that all
				// hit the same parent.
				mrand.Shuffle(len(oobRRset.RRs), func(i, j int) {
					oobRRset.RRs[i], oobRRset.RRs[j] = oobRRset.RRs[j], oobRRset.RRs[i]
				})
				oobRRset.RRs = oobRRset.RRs[:budget]
			}
			picked := make([]string, 0, len(oobRRset.RRs))
			for _, rr := range oobRRset.RRs {
				if ns, ok := rr.(*dns.NS); ok {
					picked = append(picked, ns.Ns)
				}
			}
			if Globals.Debug {
				lgDns.Debug("handleReferral: OOB resolution budget",
					"zone", zonename, "depth", zoneDepth(zonename),
					"budget", budget, "picked", picked)
			}
			imr.resolveZoneServersInBackground(ctx, zonename, picked)
		}
	}

	if len(serverMap) == 0 {
		return nil, r.MsgHdr.Rcode, cache.ContextReferral, transport, nil
	}
	// rrcache.Logger.Printf("*** handleReferral: calling revalidateReferralNS for zone %s, serverMap: %+v", zonename, serverMap)
	imr.scheduleReferralNSRevalidation(zonename, serverMap)
	//rrcache.Logger.Printf("*** handleReferral: revalidateReferralNS returned, calling IterativeDNSQuery for zone %s, serverMap: %+v", zonename, serverMap)
	rrset, rcode, cacheCtx, transport, err := imr.IterativeDNSQueryWithLoopDetection(ctx, qname, qtype, serverMap, zonename, force, visitedZones, privacy)
	return rrset, rcode, cacheCtx, transport, err
}

const maxNSRevalidateServers = 3

// Depth-aware OOB NS lookup budget. See handleReferral for the rationale.
const (
	nsLookupShallowDepth  = 2 // TLD (depth 1) and SLD (depth 2)
	nsLookupBudgetShallow = 3
	nsLookupBudgetDeep    = 1
)

// zoneDepth returns the label depth of a zone name: 0 for root ".",
// 1 for a TLD ("net."), 2 for an SLD ("axfr.net."), etc.
func zoneDepth(zone string) int {
	if zone == "" || zone == "." {
		return 0
	}
	return len(dns.SplitDomainName(zone))
}

func (imr *Imr) scheduleReferralNSRevalidation(zonename string, serverMap map[string]*cache.AuthServer) {
	if imr.Cache == nil || zonename == "" || len(serverMap) == 0 {
		return
	}
	if imr.Options[ImrOptRevalidateNS] != "true" {
		return
	}
	if !imr.Cache.MarkNSRevalidation(zonename) {
		return
	}
	snapshot := cloneServerMap(serverMap)
	if len(snapshot) == 0 {
		imr.Cache.ClearNSRevalidation(zonename)
		return
	}
	go func() {
		defer imr.Cache.ClearNSRevalidation(zonename)
		// Detached (detachedContext): the foreground IterativeDNSQuery returns
		// long before this background chain walk completes, and its deferred
		// cancel would otherwise kill every in-flight DNSKEY fetch this
		// goroutine makes.
		asyncCtx, cancel := detachedContext(60 * time.Second)
		defer cancel()
		imr.revalidateReferralNS(asyncCtx, zonename, snapshot)
	}()
}

func cloneServerMap(src map[string]*cache.AuthServer) map[string]*cache.AuthServer {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]*cache.AuthServer, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func (imr *Imr) revalidateReferralNS(ctx context.Context, zonename string, serverMap map[string]*cache.AuthServer) {
	imr.Cache.Logger.Printf("*** revalidateReferralNS: revalidating NS for zone %s", zonename)
	if imr.Cache == nil || imr.Options[ImrOptRevalidateNS] != "true" || zonename == "" || len(serverMap) == 0 {
		return
	}
	var existing *cache.CachedRRset
	if existing = imr.Cache.Get(zonename, dns.TypeNS); existing != nil && existing.Context == cache.ContextAnswer {
		return
	}
	// rrcache.Logger.Printf("*** revalidateReferralNS: existing context is %s, collecting server addresses for revalidation", CacheContextToString[existing.Context])
	addrs := collectServerAddressesForRevalidation(serverMap, imr.allowHostLocalServers())
	if len(addrs) == 0 {
		return
	}
	if len(addrs) > maxNSRevalidateServers {
		addrs = addrs[:maxNSRevalidateServers]
	}

	select {
	case <-ctx.Done():
		return
	default:
	}

	rrset, rcode, _, err := imr.AuthDNSQuery(ctx, zonename, dns.TypeNS, addrs, imr.Cache.Logger, imr.Cache.Verbose)
	if err != nil || rrset == nil || len(rrset.RRs) == 0 {
		if imr.Cache.Debug && err != nil {
			lgDns.Error("NS revalidation for failed", "zonename", zonename, "failed", err)
		}
		return
	}
	rrset.Name = zonename
	rrset.Class = dns.ClassINET
	rrset.RRtype = dns.TypeNS
	vstate := cache.ValidationStateNone
	if len(rrset.RRSIGs) > 0 {
		vstate, err = imr.Cache.ValidateRRsetWithParentZone(ctx, rrset, imr.IterativeDNSQueryFetcher(), imr.ParentZone)
		if err != nil {
			imr.Cache.Logger.Printf("*** revalidateReferralNS: Error from ValidateRRset: %v", err)
		}
	}

	if err == nil {
		imr.Cache.Set(zonename, dns.TypeNS, &cache.CachedRRset{
			Name:       zonename,
			RRtype:     dns.TypeNS,
			Rcode:      uint8(rcode),
			RRset:      rrset,
			Context:    cache.ContextAnswer,
			State:      vstate,
			Expiration: cache.Now().Add(cache.GetMinTTL(rrset.RRs)),
			Transport:  core.TransportDo53, // revalidateReferralNS - default to Do53
		})
	}

	imr.revalidateInBailiwickGlue(ctx, zonename, serverMap, true)
}

// collectServerAddressesForRevalidation returns the host:port of each address
// in serverMap that mayQueryAddr allows.
func collectServerAddressesForRevalidation(serverMap map[string]*cache.AuthServer, allowHostLocal bool) []string {
	if len(serverMap) == 0 {
		return nil
	}
	seen := make(map[string]struct{})
	var out []string
	for _, server := range serverMap {
		for _, raw := range server.Addrs {
			if raw == "" {
				continue
			}
			host, hostPort := raw, raw
			if h, _, err := net.SplitHostPort(raw); err == nil {
				host = h
			} else {
				hostPort = net.JoinHostPort(raw, "53")
			}
			if !mayQueryAddr(server, host, allowHostLocal) {
				continue
			}
			if _, ok := seen[hostPort]; ok {
				continue
			}
			out = append(out, hostPort)
			seen[hostPort] = struct{}{}
		}
	}
	return out
}

func collectInBailiwickNS(serverMap map[string]*cache.AuthServer, zonename string) []string {
	if len(serverMap) == 0 || zonename == "" {
		return nil
	}
	zone := dns.Fqdn(zonename)
	var hosts []string
	for name := range serverMap {
		fq := dns.Fqdn(name)
		if dns.IsSubDomain(zone, fq) {
			// Canonical, matching cache.ServerKey, which is what every
			// subscript of the per-zone server map goes through.
			hosts = append(hosts, core.CanonicalizeName(fq))
		}
	}
	return hosts
}

func (imr *Imr) revalidateInBailiwickGlue(ctx context.Context, zonename string, serverMap map[string]*cache.AuthServer, force bool) {
	if imr.Cache == nil || imr.Options[ImrOptRevalidateNS] != "true" {
		return
	}
	hosts := collectInBailiwickNS(serverMap, zonename)
	if len(hosts) == 0 {
		return
	}
	for _, host := range hosts {
		server := serverMap[cache.ServerKey(host)]
		for _, atype := range imr.Cache.AddressTypes() {
			imr.revalidateGlueRR(ctx, zonename, host, atype, server, force)
		}
	}
}

func (imr *Imr) revalidateGlueRR(ctx context.Context, zonename, host string, rrtype uint16, server *cache.AuthServer, force bool) {
	select {
	case <-ctx.Done():
		return
	default:
	}
	if server == nil || len(server.Addrs) == 0 {
		return
	}
	hostServerMap := map[string]*cache.AuthServer{
		server.Name: server,
	}
	rrset, _, _, _, err := imr.IterativeDNSQueryInZone(withOwnTraffic(ctx), host, rrtype, hostServerMap, zonename, force, edns0.PrivacyNone) // privacy is a client signal; glue revalidation is our own traffic
	if err != nil || rrset == nil || len(rrset.RRs) == 0 {
		return
	}

	// The entry replaced is the one the lookup just made or read; an answer
	// synthesized from a wildcard keeps the proof that came with it. Read
	// before validation: its Get drops an entry stored already expired (a
	// proof with TTL 0), and the proof with it.
	var proof []*core.RRset
	if c := imr.Cache.Peek(host, rrtype); c != nil && c.RRset == rrset {
		proof = c.WildcardProof
	}
	// Always call ValidateRRset - it will check zone state even when there are no RRSIGs
	var vstate cache.ValidationState
	vstate, err = imr.Cache.ValidateRRsetWithParentZone(ctx, rrset, imr.IterativeDNSQueryFetcher(), imr.ParentZone)
	if err != nil {
		imr.Cache.Logger.Printf("*** revalidateGlueRR: Error from ValidateRRset: %v", err)
	}
	imr.Cache.Set(host, rrtype, &cache.CachedRRset{
		Name:          host,
		RRtype:        rrtype,
		Rcode:         uint8(dns.RcodeSuccess),
		RRset:         rrset,
		Context:       cache.ContextAnswer,
		State:         vstate,
		WildcardProof: proof,
		Expiration:    cache.Now().Add(cache.GetMinTTL(rrset.RRs)), // XXX: This will be overridden by imr.Cache.Set(). TODO: Fix this.
		Transport:     core.TransportDo53,                          // revalidateGlueRR - default to Do53
	})
}

// responseKind describes the high-level semantics of a DNS response
// as seen by the iterative resolver.
type responseKind int

const (
	responseKindUnknown responseKind = iota
	responseKindAnswer
	responseKindReferral
	responseKindNegativeNoData
	responseKindNegativeNXDOMAIN
	responseKindError
)

func responseKindToString(k responseKind) string {
	switch k {
	case responseKindAnswer:
		return "answer"
	case responseKindReferral:
		return "referral"
	case responseKindNegativeNoData:
		return "negative-noerror-nodata"
	case responseKindNegativeNXDOMAIN:
		return "negative-nxdomain"
	case responseKindError:
		return "error"
	case responseKindUnknown:
		fallthrough
	default:
		return "unknown"
	}
}

// classifyResponse inspects a DNS message and classifies it into one of a small
// set of semantic categories. This is used to decide whether to treat
// an empty-answer response with Authority data as a negative response
// (NXDOMAIN / NOERROR-NODATA) or as a referral.
//
// The rules are intentionally conservative:
//   - Any non-empty Answer -> responseKindAnswer
//   - NXDOMAIN + SOA in authority that can speak for qname -> NegativeNXDOMAIN
//   - NOERROR + SOA in authority that can speak for qname -> NegativeNoData
//   - Otherwise, if there is at least one NS in authority -> Referral
//   - All other shapes are classified as Unknown/Error and left to callers.
func classifyResponse(qname string, qtype uint16, r *dns.Msg) responseKind {
	if r == nil {
		return responseKindError
	}
	// Any non-empty Answer is considered an "answer" here, even if it also
	// contains referral-ish NS in Authority; the caller is responsible for
	// deciding whether to also treat embedded NS as a referral.
	if len(r.Answer) > 0 {
		return responseKindAnswer
	}

	rcode := r.MsgHdr.Rcode

	// No Authority section: not a referral. An authoritative NXDOMAIN or
	// NODATA with nothing in authority is still a denial (RFC 2308 section 2.1
	// type 3, and the NODATA form of it); handleNegative serves it uncached
	// (#830). Without AA it says nothing.
	if len(r.Ns) == 0 {
		switch {
		case r.Authoritative && rcode == dns.RcodeNameError:
			return responseKindNegativeNXDOMAIN
		case r.Authoritative && rcode == dns.RcodeSuccess:
			return responseKindNegativeNoData
		case rcode == dns.RcodeSuccess:
			return responseKindUnknown
		}
		return responseKindError
	}

	hasSOA := false
	hasNS := false
	var soaOwner string

	for _, rr := range r.Ns {
		if rr == nil {
			continue
		}
		switch rr.Header().Rrtype {
		case dns.TypeSOA:
			hasSOA = true
			if soaOwner == "" {
				soaOwner = rr.Header().Name
			}
		case dns.TypeNS:
			hasNS = true
		}
	}

	// Helper: does this SOA plausibly speak for qname?
	soaSpeaksForQname := func() bool {
		if !hasSOA || soaOwner == "" {
			return false
		}
		return dns.IsSubDomain(dns.Fqdn(soaOwner), dns.Fqdn(qname))
	}

	switch rcode {
	case dns.RcodeNameError:
		// For NXDOMAIN, we require a SOA to be present, but we're more lenient
		// about whether it "speaks for" qname. If there's a SOA present, we
		// accept it as a valid NXDOMAIN response even if the SOA owner doesn't
		// exactly match qname (some servers may return SOA for parent zone).
		if soaSpeaksForQname() {
			return responseKindNegativeNXDOMAIN
		}
		// An authoritative NXDOMAIN without an SOA is still a denial: RFC 2308
		// section 2.1 lists it with an empty authority section (type 3) and
		// with NS records only (type 4). handleNegative serves it without
		// caching it (#830). Without AA it says nothing, and the caller tries
		// the next server.
		if r.Authoritative {
			return responseKindNegativeNXDOMAIN
		}
		return responseKindError

	case dns.RcodeSuccess:
		// Prefer interpreting SOA as a negative response when it can
		// plausibly speak for qname, per RFC 2308 (NOERROR/NODATA).
		if soaSpeaksForQname() {
			return responseKindNegativeNoData
		}
		// Otherwise, if there are NS records, this looks like a referral.
		if hasNS {
			return responseKindReferral
		}
		// Anything else is ambiguous / unexpected.
		return responseKindUnknown

	default:
		return responseKindError
	}
}

// authorityRRsets groups the records of an authority section into RRsets, in
// the order each owner and type first appears, each with the RRSIGs that cover
// it. A negative answer's proof is read this way: the SOA, the NSEC or NSEC3
// records, and their signatures, as cache.ValidateNegativeResponse takes them.
func authorityRRsets(rrs []dns.RR) []*core.RRset {
	sets := make(map[string]*core.RRset)
	var out []*core.RRset
	setFor := func(name string, rrtype uint16) *core.RRset {
		key := fmt.Sprintf("%s::%d", name, rrtype)
		if rs, ok := sets[key]; ok {
			return rs
		}
		rs := &core.RRset{Name: name, Class: dns.ClassINET, RRtype: rrtype}
		sets[key] = rs
		out = append(out, rs)
		return rs
	}
	for _, rr := range rrs {
		if rr == nil {
			continue
		}
		if sig, ok := rr.(*dns.RRSIG); ok {
			set := setFor(sig.Header().Name, sig.TypeCovered)
			set.RRSIGs = append(set.RRSIGs, dns.Copy(sig))
			continue
		}
		set := setFor(rr.Header().Name, rr.Header().Rrtype)
		set.RRs = append(set.RRs, dns.Copy(rr))
	}
	return out
}

// handleNegative caches a negative answer and reports how it was read.
//
// zone is the zone the answering servers serve, when the caller knows it. It is
// what judges an authoritative denial that carries no SOA (negativeWithoutSOA);
// without it such a denial is not used. And a denial whose SOA names a zone
// above it is not used either (soaAboveServersZone).
func (imr *Imr) handleNegative(qname string, qtype uint16, r *dns.Msg, transport core.Transport, zone string) (cache.CacheContext, int, bool) {
	if r == nil {
		return cache.ContextFailure, dns.RcodeServerFailure, false
	}
	if len(r.Ns) == 0 && !r.Authoritative {
		return cache.ContextFailure, r.MsgHdr.Rcode, false
	}

	var negContext cache.CacheContext
	switch r.MsgHdr.Rcode {
	case dns.RcodeNameError:
		negContext = cache.ContextNXDOMAIN
	case dns.RcodeSuccess:
		if len(r.Answer) != 0 {
			// We should not get here, but if we do, it's a failure
			return cache.ContextFailure, r.MsgHdr.Rcode, false
		}
		negContext = cache.ContextNoErrNoAns
	default:
		return cache.ContextFailure, r.MsgHdr.Rcode, false
	}

	// The authority section is the proof of the denial. Its first SOA names
	// the zone that denies. How long the denial is cached, the cache decides
	// from the SOA and the proof (RFC 2308 section 5; cache entryLifetime).
	negAuthority := authorityRRsets(r.Ns)
	var (
		soaOwner string
		soarrset *core.RRset
	)
	for _, set := range negAuthority {
		for _, rr := range set.RRs {
			if soa, ok := rr.(*dns.SOA); ok && soarrset == nil {
				soarrset = set
				soaOwner = soa.Header().Name
			}
		}
	}

	if soarrset == nil || len(soarrset.RRs) == 0 {
		if r.Authoritative && zone != "" {
			return imr.negativeWithoutSOA(qname, qtype, r, negContext, zone, transport)
		}
		lgDns.Debug("handleNegative: no SOA found in authority for \" \" ()",
			"qname", qname,
			"s", dns.TypeToString[qtype],
			"rcode", dns.RcodeToString[r.MsgHdr.Rcode])
		return cache.ContextFailure, r.MsgHdr.Rcode, false
	}
	if soaAboveServersZone(soaOwner, zone) && !imr.configuredZone(zone) {
		lgDns.Debug("handleNegative: the denial's SOA is from a zone above the one the servers serve; not used",
			"qname", qname, "qtype", dns.TypeToString[qtype], "soa", soaOwner, "zone", zone,
			"rcode", dns.RcodeToString[r.MsgHdr.Rcode])
		return cache.ContextFailure, r.MsgHdr.Rcode, false
	}

	skipDNSKEYValidation := qtype == dns.TypeDNSKEY
	hasValidatedDS := false
	if skipDNSKEYValidation {
		if ds := imr.Cache.Get(qname, dns.TypeDS); ds != nil && ds.RRset != nil && len(ds.RRset.RRs) > 0 && ds.State == cache.ValidationStateSecure {
			hasValidatedDS = true
		}
	}

	soaVstate := cache.ValidationStateNone
	var err error
	if !skipDNSKEYValidation && len(soarrset.RRSIGs) > 0 {
		soaVstate, err = imr.Cache.ValidateRRset(context.Background(), soarrset, imr.IterativeDNSQueryFetcher())
		if err != nil {
			lgDns.Error("handleNegative: failed to validate SOA RRset", "rrset", err)
			return cache.ContextFailure, r.MsgHdr.Rcode, false
		}
	}

	// RFC 9824: a compact denial of existence proves that qname does not
	// exist with an NSEC owned by qname itself, and the authoritative server
	// sends it with rcode NOERROR unless the query set CO (this resolver does
	// not). That rcode describes how the NSEC reads to a validator without
	// NXNAME support; the bitmap says what it proves. Cache what it proves,
	// NXDOMAIN, marked compact so the responder can pick the rcode each
	// client can cope with (negativeRcode).
	//
	// Decided on the shape of the proof, before validation. Whether the proof
	// validates decides the AD bit, not which name it denies: behind
	// validation, as this once was, a zone without a trust anchor was cached
	// as NODATA and every client was told the name existed.
	compactDenial := cache.CompactDenialNXDOMAIN(qname, negAuthority)
	if compactDenial {
		negContext = cache.ContextNXDOMAIN
	}

	var edeCode uint16
	var edeText string
	if skipDNSKEYValidation && hasValidatedDS && soaOwner != "" {
		edeCode = 9
		zone := strings.TrimSuffix(soaOwner, ".")
		if zone == "" {
			zone = "."
		}
		edeText = fmt.Sprintf("no DNSKEY matches DS for zone %s", zone)
	}

	vstate := cache.ValidationStateNone
	negRcode := uint8(r.MsgHdr.Rcode)
	if !skipDNSKEYValidation && len(negAuthority) > 0 {
		var verdict cache.DenialVerdict
		verdict, err = imr.Cache.ValidateDenial(context.Background(), qname, qtype, negRcode, negAuthority, imr.IterativeDNSQueryFetcher())
		vstate, negRcode = verdict.State, verdict.Rcode
		// An NSEC3 proof over the iteration limit is served, Insecure, with
		// EDE 27 beside it (RFC 9276).
		if verdict.EDECode != 0 {
			edeCode, edeText = verdict.EDECode, verdict.EDEText
		}
		if err != nil {
			// If validation returns ValidationStateIndeterminate (e.g., no trust anchors),
			// we should still cache and return the response, not treat it as a failure.
			if vstate == cache.ValidationStateIndeterminate {
				lgDns.Debug("handleNegative: validation returned indeterminate state (likely no trust anchors)", "err", err)
				// Continue to cache with indeterminate state
			} else {
				lgDns.Error("handleNegative: failed to validate negative response", "response", err)
				return cache.ContextFailure, r.MsgHdr.Rcode, false
			}
		}
	}

	cachedRcode := uint8(r.MsgHdr.Rcode)
	if compactDenial {
		cachedRcode = uint8(dns.RcodeNameError)
	}
	// In the specific case where ValidateNegativeResponse has modified the rcode from NOERROR to NXDOMAIN we propagate this change.
	if negRcode != uint8(r.MsgHdr.Rcode) && negRcode == dns.RcodeNameError && uint8(r.MsgHdr.Rcode) == dns.RcodeSuccess {
		lgDns.Debug("handleNegative: ValidateNegativeResponse has modified the rcode from NOERROR to NXDOMAIN")
		cachedRcode = uint8(dns.RcodeNameError)
		negContext = cache.ContextNXDOMAIN
	}

	// A Secure proof supports one rcode, and the denial is cached with that one
	// or not at all. The compact denial reading above is made from the shape
	// of every NSEC in the section before validation, and an NSEC that did not
	// count there -- unsigned, or another zone's -- must not set the rcode of a
	// proof that validated. ValidateDenial reads the RFC 9824 form from the
	// records that count.
	if vstate == cache.ValidationStateSecure && negRcode != cachedRcode {
		lgDns.Debug("handleNegative: the proof that validated does not support the rcode; not used",
			"qname", qname, "qtype", dns.TypeToString[qtype],
			"proof", dns.RcodeToString[int(negRcode)], "rcode", dns.RcodeToString[int(cachedRcode)])
		return cache.ContextFailure, r.MsgHdr.Rcode, false
	}

	// Ensure RCODE matches the context we're caching
	// If we're caching as NXDOMAIN, the RCODE must be NXDOMAIN
	// If we're caching as NODATA, the RCODE must be NOERROR
	if negContext == cache.ContextNXDOMAIN && cachedRcode != uint8(dns.RcodeNameError) {
		lgDns.Warn("*** handleNegative: WARNING - caching as NXDOMAIN but RCODE is (expected NXDOMAIN)",
			"rcode", dns.RcodeToString[r.MsgHdr.Rcode])
		// cachedRcode = uint8(dns.RcodeNameError)
		return cache.ContextFailure, r.MsgHdr.Rcode, false
	} else if negContext == cache.ContextNoErrNoAns && cachedRcode != uint8(dns.RcodeSuccess) {
		lgDns.Warn("*** handleNegative: WARNING - caching as NODATA but RCODE is (expected NOERROR)",
			"rcode", dns.RcodeToString[r.MsgHdr.Rcode])
		// cachedRcode = uint8(dns.RcodeSuccess)
		return cache.ContextFailure, r.MsgHdr.Rcode, false
	}

	imr.Cache.Set(qname, qtype, &cache.CachedRRset{
		Name:          qname,
		RRtype:        qtype,
		Rcode:         cachedRcode,
		RRset:         soarrset,
		NegAuthority:  negAuthority,
		CompactDenial: compactDenial,
		Context:       negContext,
		State:         vstate,
		EDECode:       edeCode,
		EDEText:       edeText,
		Transport:     transport,
	})

	// Also cache the SOA RRset itself for future direct lookups, for its own
	// TTL: the negative TTL is the denial's.
	imr.Cache.Set(soaOwner, dns.TypeSOA, &cache.CachedRRset{
		Name:      soaOwner,
		RRtype:    dns.TypeSOA,
		Rcode:     uint8(dns.RcodeSuccess),
		RRset:     soarrset,
		Context:   cache.ContextAnswer,
		State:     soaVstate,
		Transport: transport,
	})

	return negContext, int(cachedRcode), true
}

// soaAboveServersZone reports whether soaOwner, the SOA of a denial, names a
// zone above zone, the one the servers that sent it serve. Those servers
// answer for zone, and for any zone below it they also serve; a denial from a
// zone above is not theirs to give. It comes from a server that also serves
// that zone and answers from it for a cut it no longer holds, or it is a reply
// that does not belong to the question. The caller asks the next server. With
// zone unknown ("") nothing is judged.
//
// A configured stub zone's servers are the operator's, and may serve the zone
// above the stub's apex; handleNegative does not ask this of them.
func soaAboveServersZone(soaOwner, zone string) bool {
	if zone == "" || soaOwner == "" {
		return false
	}
	return dns.IsSubDomain(soaOwner, zone) && !core.EqualNames(soaOwner, zone)
}

// negativeWithoutSOA serves an authoritative NXDOMAIN or NODATA that carries no
// SOA (RFC 2308 section 2.1 types 3 and 4, and the NODATA forms of the same).
//
// It is not cached: without an SOA there is no negative TTL, and section 5 says
// such an answer should not be cached. It is stored already expired, which is
// what lets this query -- and a CNAME chain it ends -- be answered from it
// (freshChainGrace), while no later query sees it. Its authority section is not
// kept: there is no proof in it to serve.
//
// With nothing to validate, it gets the verdict unsigned data from zone gets:
// Insecure outside a zone held Secure, Bogus below one unless an insecure
// delegation is proven on the way down. A Bogus one is not used, and the caller
// tries the next server.
func (imr *Imr) negativeWithoutSOA(qname string, qtype uint16, r *dns.Msg, negContext cache.CacheContext, zone string, transport core.Transport) (cache.CacheContext, int, bool) {
	vstate := imr.Cache.UnsignedDenialState(context.Background(), zone, qname, qtype, imr.IterativeDNSQueryFetcher())
	if vstate == cache.ValidationStateBogus {
		lgDns.Debug("handleNegative: denial without an SOA from a zone that must sign its denials; not used",
			"qname", qname, "qtype", dns.TypeToString[qtype], "zone", zone,
			"rcode", dns.RcodeToString[r.MsgHdr.Rcode])
		return cache.ContextFailure, r.MsgHdr.Rcode, false
	}
	imr.Cache.Set(qname, qtype, &cache.CachedRRset{
		Name:       qname,
		RRtype:     qtype,
		Rcode:      uint8(r.MsgHdr.Rcode),
		Context:    negContext,
		State:      vstate,
		Expiration: cache.Now(),
		Transport:  transport,
	})
	lgDns.Debug("handleNegative: serving a denial without an SOA, uncached",
		"qname", qname, "qtype", dns.TypeToString[qtype], "zone", zone,
		"rcode", dns.RcodeToString[r.MsgHdr.Rcode], "state", cache.ValidationStateToString[vstate])
	return negContext, r.MsgHdr.Rcode, true
}

// maxCNAMEChain is the most CNAMEs one answer follows, as BIND's default
// max-query-restarts.
const maxCNAMEChain = 11

// cnameChainKey carries, on the context of a CNAME chase, the chain it is
// following: canonical names, the query name first and the current target
// last.
type cnameChainKey struct{}

// extendCNAMEChain returns the chain with target appended, continuing the
// chain on ctx when owner is its last name. Any other chase -- say, the lookup
// of a nameserver's address made while resolving one link -- is a chain of its
// own and starts from owner. It fails on a name the chain has already visited,
// and on a chain of more than maxCNAMEChain CNAMEs.
//
// The chain has to be carried on the context because the chase nests: the
// query for each target goes through IterativeDNSQuery and handleAnswer, which
// chase that target's own CNAME. Counted per call, a loop never ended: every
// link was answered from the cache and the stack overflowed.
func extendCNAMEChain(ctx context.Context, owner, target string) ([]string, error) {
	chain, _ := ctx.Value(cnameChainKey{}).([]string)
	if len(chain) == 0 || chain[len(chain)-1] != core.CanonicalizeName(owner) {
		chain = []string{core.CanonicalizeName(owner)}
	}
	t := core.CanonicalizeName(target)
	if slices.Contains(chain, t) {
		return nil, fmt.Errorf("CNAME loop: %s leads back to %s", owner, target)
	}
	if len(chain) > maxCNAMEChain {
		return nil, fmt.Errorf("CNAME chain from %s is longer than %d", chain[0], maxCNAMEChain)
	}
	return append(slices.Clone(chain), t), nil
}

// chaseCNAME resolves <target, qtype>, where target is the CNAME target of
// owner. It returns what the chain ends in: the data at its last name (when
// target is itself a CNAME, IterativeDNSQuery has followed it that far), or a
// negative end -- no RRset, and the rcode and context of the name that does
// not exist (NXDOMAIN) or has no qtype (NODATA). Each link is cached on the
// way (cacheCNAMELink); the client's answer is built from them (serveChain).
func (imr *Imr) chaseCNAME(ctx context.Context, owner, target string, qtype uint16, force bool, privacy edns0.PrivacyLevel) (*core.RRset, int, cache.CacheContext, core.Transport, error) {
	chain, err := extendCNAMEChain(ctx, owner, target)
	if err != nil {
		return nil, dns.RcodeServerFailure, cache.ContextFailure, core.TransportDo53, err
	}
	ctx = context.WithValue(ctx, cnameChainKey{}, chain)
	// A referral IterativeDNSQuery could not follow yet is retried; nothing
	// else is.
	const maxAttempts = 10
	var combinedTransport core.Transport = core.TransportDoQ // Start with encrypted, will downgrade if needed
	hasUnencryptedHop := false
	for i := 0; i < maxAttempts; i++ {
		select {
		case <-ctx.Done():
			return nil, 0, cache.ContextFailure, core.TransportDo53, ctx.Err()
		default:
		}
		imr.Cache.Logger.Printf("*** IterativeDNSQuery: found CNAME target: %s, chasing.", target)
		bestmatch, tmpservers, err := imr.Cache.FindClosestKnownZoneFor(target, qtype)
		if err != nil {
			imr.Cache.Logger.Printf("*** IterativeDNSQuery: Error from FindClosestKnownZoneFor: %v", err)
			return nil, dns.RcodeServerFailure, cache.ContextFailure, core.TransportDo53, err
		}
		imr.Cache.Logger.Printf("*** IterativeDNSQuery: best match for target %s is %s", target, bestmatch)
		tmprrset, rcode, context, hopTransport, err := imr.IterativeDNSQueryInZone(ctx, target, qtype, tmpservers, bestmatch, force, privacy)
		if err != nil {
			imr.Cache.Logger.Printf("*** IterativeDNSQuery: Error from IterativeDNSQuery: %v", err)
			return nil, rcode, context, core.TransportDo53, err
		}
		// Track if any hop used unencrypted transport
		if !core.IsEncryptedTransport(hopTransport) {
			hasUnencryptedHop = true
			combinedTransport = core.TransportDo53
		} else if !hasUnencryptedHop {
			// Only update if we haven't seen an unencrypted hop yet
			combinedTransport = hopTransport
		}
		if tmprrset != nil && len(tmprrset.RRs) != 0 {
			// The data at the chain's last name. When target is itself a
			// CNAME, IterativeDNSQuery has already followed the rest of the
			// chain; chasing it again repeated every later link.
			return tmprrset, rcode, context, combinedTransport, nil
		}
		// A chain that ends in a name that does not exist, or in a name
		// without data of this type. Only NXDOMAIN ended the chase before:
		// NODATA sent it back to the same name until the attempts ran out,
		// and the client got a SERVFAIL.
		if rcode == dns.RcodeNameError || context == cache.ContextNXDOMAIN || context == cache.ContextNoErrNoAns {
			return nil, rcode, context, combinedTransport, nil
		}
	}
	return nil, dns.RcodeServerFailure, cache.ContextFailure, core.TransportDo53,
		fmt.Errorf("CNAME target %s: no answer after %d attempts", target, maxAttempts)
}

func (imr *Imr) DefaultDNSKEYFetcher(ctx context.Context, name string) (*core.RRset, error) {
	// A forwarded name is fetched without servers (ServersFor).
	servers, ok := imr.Cache.ServersFor(name, dns.TypeDNSKEY)
	if !ok {
		return nil, fmt.Errorf("no servers for %s", name)
	}
	rr, _, _, _, err := imr.IterativeDNSQuery(withOwnTraffic(ctx), name, dns.TypeDNSKEY, servers, false, edns0.PrivacyNone) // privacy is a client signal; DNSKEY fetches are our own traffic
	if err != nil || rr == nil || len(rr.RRs) == 0 {
		return nil, fmt.Errorf("dnskey fetch failed for %s: %v", name, err)
	}
	return rr, nil
}

func (imr *Imr) DefaultRRsetFetcher(ctx context.Context, qname string, qtype uint16) (*core.RRset, error) {
	// A forwarded question is fetched without servers (ServersFor).
	servers, ok := imr.Cache.ServersFor(qname, qtype)
	if !ok {
		return nil, fmt.Errorf("no servers for %s", qname)
	}
	rr, _, _, _, err := imr.IterativeDNSQuery(withOwnTraffic(ctx), qname, qtype, servers, false, edns0.PrivacyNone) // privacy is a client signal; the fetcher is our own traffic
	if err != nil || rr == nil || len(rr.RRs) == 0 {
		return nil, fmt.Errorf("fetch failed for %s %s: %v", qname, dns.TypeToString[qtype], err)
	}
	return rr, nil
}

// IterativeDNSQueryFetcher adapts IterativeDNSQuery to the RRsetFetcher interface.
// It discards the rcode and CacheContext return values, only returning the RRset and error.
func (imr *Imr) IterativeDNSQueryFetcher() cache.RRsetFetcher {
	return func(ctx context.Context, qname string, qtype uint16, servers map[string]*cache.AuthServer) (*core.RRset, error) {
		rrset, _, _, _, err := imr.IterativeDNSQuery(withOwnTraffic(ctx), qname, qtype, servers, false, edns0.PrivacyNone) // privacy is a client signal; RRsetFetcher is our own traffic
		return rrset, err
	}
}

// isConnRefused reports whether err is a refused connection: TCP RST, or ICMP
// port unreachable read back on a UDP socket. Either way the host itself
// answered, so the network path to it is fine.
func isConnRefused(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	return strings.Contains(err.Error(), "connection refused")
}
