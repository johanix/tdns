/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"fmt"
	"hash/fnv"
	"log"
	"net"
	"slices"
	"sort"
	"strings"
	"time"

	edns0 "github.com/johanix/tdns/tdns/edns0"
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

	// crrset := RRsetCache.Get(qname, rrtype)
	// if crrset != nil {
	//	lg.Printf("AuthDNSQuery: found %s %s in cache", qname, dns.TypeToString[rrtype])
	//	return crrset.RRset, int(crrset.Rcode), nil
	// }
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

func (rrcache *RRsetCacheT) AuthDNSQuery(ctx context.Context, qname string, qtype uint16, nameservers []string,
	lg *log.Logger, verbose bool) (*RRset, int, CacheContext, error) {

	crrset := rrcache.Get(qname, qtype)
	if crrset != nil {
		lg.Printf("AuthDNSQuery: found answer to <%s, %s> in cache (result=%s)", qname, dns.TypeToString[qtype], CacheContextToString[crrset.Context])
		return crrset.RRset, int(crrset.Rcode), crrset.Context, nil
	}
	lg.Printf("AuthDNSQuery: answer to <%s, %s> not present in cache", qname, dns.TypeToString[qtype])
	var rrset RRset
	var rcode int

	// c := dns.Client{Net: "tcp"}

	m := new(dns.Msg)
	m.SetQuestion(qname, qtype)
	m.SetEdns0(4096, true)
	for _, ns := range nameservers {
		if ns[len(ns)-3:] != ":53" {
			ns = net.JoinHostPort(ns, "53")
		}
		if verbose {
			lg.Printf("AuthDNSQuery: using nameserver %s for <%s, %s> query\n",
				ns, qname, dns.TypeToString[qtype])
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
			lg.Printf("*** AuthDNSQuery: there is stuff in Answer section")
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
							return nil, 0, ContextFailure, ctx.Err()
						default:
						}
						lg.Printf("*** AuthDNSQuery: found CNAME for %s: %s. Chasing it.", qname, target)
						// We need to look up the target of the CNAME
						tmprrset, rcode, context, err := rrcache.AuthDNSQuery(ctx, target, qtype, nameservers, lg, verbose)
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
								// seems that we have found the answer; cache it and return
								rrcache.Set(qname, qtype, &CachedRRset{
									Name:       qname,
									RRtype:     qtype,
									Rcode:      uint8(rcode),
									RRset:      &rrset,
									Context:    ContextAnswer,
									Expiration: time.Now().Add(getMinTTL(rrset.RRs)),
								})
								return &rrset, rcode, ContextAnswer, nil
							}

						case rcode == dns.RcodeNameError:
							// This is a negative response, and <target, qtype> has already been cached
							// now we only need to cache <qname, qtype>
							rrcache.Set(qname, qtype, &CachedRRset{
								Name:    qname,
								RRtype:  qtype,
								RRset:   nil,
								Context: ContextNXDOMAIN,
							})
							return nil, rcode, context, nil

						default:
							// XXX: Here we should also deal with ContextReferral and ContextNoErrNoAns
							break
						}
					}
				default:
					lg.Printf("Got a %s RR when looking for %s %s",
						dns.TypeToString[t], qname,
						dns.TypeToString[qtype])
				}
			}

			rrcache.Set(qname, qtype, &CachedRRset{
				Name:       qname,
				RRtype:     qtype,
				Rcode:      uint8(rcode),
				RRset:      &rrset,
				Context:    ContextAnswer,
				Expiration: time.Now().Add(getMinTTL(rrset.RRs)),
			})
			return &rrset, rcode, ContextAnswer, nil
		} else if len(r.Ns) != 0 {
			// This is likely either a negative response or a referral
			lg.Printf("*** AuthDNSQuery: there is stuff in Authority section")
			switch rcode {
			case dns.RcodeSuccess:
				// this is either a referral or a negative response
				var rrset RRset
				var zonename string

				// 1. Collect the NS RRset from the Authority section
				lg.Printf("*** AuthDNSQ: rcode=NOERROR, this is a referral or neg resp")
				nsMap := map[string]bool{}
				for _, rr := range r.Ns {
					switch rr.(type) {
					case *dns.NS:
						// this is a referral
						rrset.RRs = append(rrset.RRs, rr)
						nsMap[rr.(*dns.NS).Ns] = true
					case *dns.SOA:
						// this is a negative response, but is the SOA right?
						if strings.HasSuffix(qname, rr.Header().Name) {
							// Yes, this SOA may auth a negative response for qname
							log.Printf("*** AuthDNSQ: found SOA in Auth, it was a neg resp")
							rrcache.Set(qname, qtype, &CachedRRset{
								Name:       qname,
								RRtype:     qtype,
								Rcode:      uint8(rcode),
								RRset:      nil,
								Context:    ContextNoErrNoAns,
								Expiration: time.Now().Add(time.Duration(rr.Header().Ttl) * time.Second),
							})
							return nil, rcode, ContextNoErrNoAns, nil
						} else {
							log.Printf("*** The SOA %q is not correct to speak for qname %q", rr.Header().Name, qname)
							log.Printf("should never get here")
						}
					default:
					}
				}
				if len(rrset.RRs) != 0 {
					zonename = rrset.RRs[0].Header().Name
					rrset.Name = zonename
					rrset.Class = dns.ClassINET
					rrset.RRtype = dns.TypeNS
					rrcache.Set(zonename, dns.TypeNS, &CachedRRset{
						Name:       zonename,
						RRtype:     dns.TypeNS,
						Rcode:      uint8(rcode),
						RRset:      &rrset,
						Context:    ContextReferral,
						Expiration: time.Now().Add(getMinTTL(rrset.RRs)),
					})
				}

				// 2. Collect any glue from Additional
				glue4Map := map[string]RRset{}
				glue6Map := map[string]RRset{}
				var servers []string
				serverMap := map[string]*AuthServer{}
				for _, rr := range r.Extra {
					name := rr.Header().Name
					if _, exist := nsMap[name]; !exist {
						log.Printf("*** AuthDNSQuery: non-glue record in Additional: %q", rr.String())
						continue
					}
					switch rr.(type) {
					case *dns.A:
						addr := rr.(*dns.A).A.String()
						servers = append(servers, net.JoinHostPort(addr, "53"))
						serverMap[name] = &AuthServer{
							Name:       name,
							Alpn:       []string{"do53"},
							Transports: []Transport{TransportDo53},
							Src:        "answer",
						}
						tmp := glue4Map[name]
						tmp.RRs = append(tmp.RRs, rr)
						glue4Map[name] = tmp

					case *dns.AAAA:
						addr := rr.(*dns.AAAA).AAAA.String()
						servers = append(servers, net.JoinHostPort(addr, "53"))
						serverMap[name] = &AuthServer{
							Name:       name,
							Alpn:       []string{"do53"},
							Transports: []Transport{TransportDo53},
							Src:        "answer",
						}
						tmp := glue6Map[name]
						tmp.RRs = append(tmp.RRs, rr)
						glue6Map[name] = tmp

					case *dns.SVCB:
						log.Printf("Additional contains an SVCB, here we should collect the ALPN")
						svcb := rr.(*dns.SVCB)
						for _, kv := range svcb.Value {
							if kv.Key() == dns.SVCB_ALPN {
								if alpn, ok := kv.(*dns.SVCBAlpn); ok {
									var transports []Transport
									for _, t := range alpn.Alpn {
										switch t {
										case "dot":
											transports = append(transports, TransportDoT)
										case "doh":
											transports = append(transports, TransportDoH)
										case "doq":
											transports = append(transports, TransportDoQ)
										}
									}
									if alpn, ok := kv.(*dns.SVCBAlpn); ok {
										serverMap[name].Alpn = alpn.Alpn
										serverMap[name].Transports = transports
										log.Printf("Found ALPN values for %s: %v", name, alpn.Alpn)
									}
								}
							}
						}
					default:
					}
				}

				log.Printf("*** AuthDNSQuery: adding %d servers for zone %q to cache", len(servers), zonename)
				rrcache.Servers.Set(zonename, servers)

				for nsname, rrset := range glue4Map {
					if len(rrset.RRs) == 0 {
						continue
					}
					rr := rrset.RRs[0]
					rrcache.Set(nsname, dns.TypeA, &CachedRRset{
						Name:       nsname,
						RRtype:     dns.TypeA,
						RRset:      &rrset,
						Context:    ContextGlue,
						Expiration: time.Now().Add(time.Duration(rr.Header().Ttl) * time.Second),
					})
				}

				for nsname, rrset := range glue6Map {
					if len(rrset.RRs) == 0 {
						continue
					}
					rr := rrset.RRs[0]
					rrcache.Set(nsname, dns.TypeAAAA, &CachedRRset{
						Name:       nsname,
						RRtype:     dns.TypeAAAA,
						RRset:      &rrset,
						Context:    ContextGlue,
						Expiration: time.Now().Add(time.Duration(rr.Header().Ttl) * time.Second),
					})
				}

				return nil, rcode, ContextReferral, nil

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
				rrcache.Set(qname, qtype, &CachedRRset{
					Name:       qname,
					RRtype:     qtype,
					RRset:      nil,
					Context:    ContextNXDOMAIN,
					Expiration: time.Now().Add(time.Duration(ttl) * time.Second),
				})

				return nil, rcode, ContextNXDOMAIN, nil
			default:
				log.Printf("*** AuthDNSQuery: surprising rcode: %s", dns.RcodeToString[rcode])
			}
		} else {
			if rcode == dns.RcodeSuccess {
				return &rrset, rcode, ContextFailure, nil // no point in continuing
			}
			continue // go to next server
		}
	}
	return &rrset, rcode, ContextNoErrNoAns, fmt.Errorf("no Answers found from any auth server looking up '%s %s'", qname, dns.TypeToString[qtype])
}

// force is true if we should force a lookup even if the answer is in the cache
func (rrcache *RRsetCacheT) IterativeDNSQuery(ctx context.Context, qname string, qtype uint16, serverMap map[string]*AuthServer, force bool) (*RRset, int, CacheContext, error) {
	lg := rrcache.Logger

	if Globals.Debug {
		lg.Printf("IterativeDNSQuery: looking up <%s, %s> using %d servers", qname, dns.TypeToString[qtype], len(serverMap))
		fmt.Printf("IterativeDNSQuery: looking up <%s, %s> using %d servers\n", qname, dns.TypeToString[qtype], len(serverMap))
	}
	var servernames []string
	for k, _ := range serverMap {
		servernames = append(servernames, k)
	}
	if Globals.Debug {
		lg.Printf("IterativeDNSQuery: servers for %q: %+v", qname, servernames)
		fmt.Printf("IterativeDNSQuery: servers for %q: %+v\n", qname, servernames)
	}

	if !force {
		crrset := rrcache.Get(qname, qtype)
		if crrset != nil {
			lg.Printf("IterativeDNSQuery: found answer to <%s, %s> in cache (result=%s)", qname, dns.TypeToString[qtype], CacheContextToString[crrset.Context])
			return crrset.RRset, int(crrset.Rcode), crrset.Context, nil
		} else {
			lg.Printf("IterativeDNSQuery: answer to <%s, %s> not present in cache", qname, dns.TypeToString[qtype])
		}
	} else {
		lg.Printf("IterativeDNSQuery: forcing re-query of <%s, %s>, bypassing cache", qname, dns.TypeToString[qtype])
	}
	var rrset RRset
	var rcode int

	m, err := rrcache.buildQuery(qname, qtype)
	if err != nil {
		lg.Printf("IterativeDNSQuery: Error building query: %v", err)
		return nil, 0, ContextFailure, err
	}
	// if Globals.Debug { fmt.Printf("IterativeDNSQuery: message after AddOTSToMessage: %s", m.String()) }

	// Try each server in the map
	for nsname, server := range serverMap {
		select {
		case <-ctx.Done():
			return nil, 0, ContextFailure, ctx.Err()
		default:
		}
		lg.Printf("IterativeDNSQuery: trying server %q: %+v", nsname, server)
		// Try each address for this server
		for _, addr := range server.Addrs {
			select {
			case <-ctx.Done():
				return nil, 0, ContextFailure, ctx.Err()
			default:
			}
			if rrcache.Verbose {
				lg.Printf("IterativeDNSQuery: using nameserver %s (ALPN: %v) for <%s, %s> query\n",
					addr, server.Alpn, qname, dns.TypeToString[qtype])
			}

			r, rtt, err := rrcache.tryServer(ctx, server, addr, m, qname, qtype)
			if err != nil && rrcache.Verbose {
				lg.Printf("IterativeDNSQuery: Error from dns.Exchange: %v (rtt: %v)", err, rtt)
				continue // go to next server
			}

			if r == nil {
				continue
			}
			rcode = r.MsgHdr.Rcode

			if len(r.Answer) != 0 {
				// Parse any transport signal for this specific server even on final answers
				parseTransportForServerFromAdditional(server, r)
				rrcache.persistServerTransportUpdate(server)
				tmprrset, rcode2, ctx2, err, done := rrcache.handleAnswer(ctx, qname, qtype, r)
				if err != nil || done {
					return tmprrset, rcode2, ctx2, err
				}
				// If not done, fall-through to process referral glue embedded with answers
				nsRRs, zonename, nsMap := extractReferral(r, qname, qtype)
				if len(nsRRs.RRs) > 0 {
					serverMap, err := rrcache.ParseAdditionalForNSAddrs("authority", nsRRs, zonename, nsMap, r)
					if err != nil {
						log.Printf("*** IterativeDNSQuery: Error from CollectNSAddressesFromAdditional: %v", err)
						return nil, rcode, ContextFailure, err
					}
					if len(serverMap) == 0 {
						return nil, rcode, ContextReferral, nil
					}
					return rrcache.IterativeDNSQuery(ctx, qname, qtype, serverMap, false)
				}
				continue
			}

			if len(r.Ns) != 0 {
				if rcode == dns.RcodeSuccess {
					return rrcache.handleReferral(ctx, qname, qtype, r, false)
				}
				if rcode == dns.RcodeNameError {
					ctxn, rcode3, handled := rrcache.handleNegative(qname, qtype, r)
					if handled {
						return nil, rcode3, ctxn, nil
					}
					continue
				}
				log.Printf("*** IterativeDNSQuery: surprising rcode: %s", dns.RcodeToString[rcode])
				continue
			}

			if rcode == dns.RcodeSuccess {
				return &rrset, rcode, ContextFailure, nil // no point in continuing
			}
			continue
		}
	}
	return &rrset, rcode, ContextNoErrNoAns, fmt.Errorf("no Answers found from any auth server looking up '%s %s'", qname, dns.TypeToString[qtype])
}

// CollectNSAddresses - given an NS RRset, chase down the A and AAAA records corresponding to each nsname
func (rrcache *RRsetCacheT) CollectNSAddresses(ctx context.Context, rrset *RRset, respch chan *ImrResponse) error {
	if rrset == nil || len(rrset.RRs) == 0 {
		return fmt.Errorf("rrset is nil or empty")
	}

	for _, rr := range rrset.RRs {
		nsname := rr.(*dns.NS).Ns
		// Query for A records
		go func(nsname string) {
			log.Printf("CollectNSAddresses: querying for %s A records", nsname)
			_, err := rrcache.ImrQuery(ctx, nsname, dns.TypeA, dns.ClassINET, respch)
			if err != nil {
				log.Printf("Error querying A for %s: %v", nsname, err)
			}
		}(nsname)

		// Query for AAAA records
		go func(nsname string) {
			log.Printf("CollectNSAddresses: querying for %s AAAA records", nsname)
			_, err := rrcache.ImrQuery(ctx, nsname, dns.TypeAAAA, dns.ClassINET, respch)
			if err != nil {
				log.Printf("Error querying AAAA for %s: %v", nsname, err)
			}
		}(nsname)
	}
	return nil
}

func (rrcache *RRsetCacheT) ParseAdditionalForNSAddrs(src string, nsrrset *RRset, zonename string,
	nsMap map[string]bool, r *dns.Msg) (map[string]*AuthServer, error) {
	if r == nil {
		return nil, fmt.Errorf("message is nil")
	}
	// If we don't know the zone name (no NS owner found), don't mutate ServerMap with an empty key
	if zonename == "" {
		if rrcache.Debug {
			log.Printf("ParseAdditionalForNSAddrs: empty zonename; skipping glue collection")
		}
		return map[string]*AuthServer{}, nil
	}

	if Globals.Debug {
		log.Printf("*** ParseAdditionalForNSAddrs: zonename: %q", zonename)
		log.Printf("*** ParseAdditionalForNSAddrs: nsMap: %+v", nsMap)
		fmt.Printf("*** ParseAdditionalForNSAddrs: zonename: %q\n", zonename)
		fmt.Printf("*** ParseAdditionalForNSAddrs: nsMap: %+v\n", nsMap)
	}

	// 2. Collect any glue from Additional
	glue4Map := map[string]RRset{}
	glue6Map := map[string]RRset{}
	// var servers []string
	serverMap, exist := rrcache.ServerMap.Get(zonename)
	if !exist {
		log.Printf("ParseAdditionalForNSAddrs: *** warning: serverMap entry for zone %q not found, creating new", zonename)
		serverMap = map[string]*AuthServer{}
	}
	// Prune expired auth servers for this zone before updating
	now := time.Now()
	for name, srv := range serverMap {
		if !srv.Expire.IsZero() && srv.Expire.Before(now) {
			delete(serverMap, name)
			if Globals.Debug {
				log.Printf("ParseAdditionalForNSAddrs: pruned expired server %s for zone %s", name, zonename)
			}
		}
	}

	// Helper to parse and apply transport signal (common for SVCB local key and TSYNC)
	applyTransportSignal := func(owner string, s string) {
		kvMap, err := parseTransportString(s)
		if err != nil {
			log.Printf("Invalid transport string for %s: %q: %v", owner, s, err)
			return
		}
		// Build weights and ordered transports by descending weight
		type pair struct {
			k string
			w uint8
		}
		var pairs []pair
		weights := map[Transport]uint8{}
		for k, v := range kvMap {
			t, err := StringToTransport(k)
			if err != nil {
				log.Printf("Unknown transport in transport weights for %s: %q", owner, k)
				continue
			}
			pairs = append(pairs, pair{k: k, w: v})
			weights[t] = v
		}
		// sort by weight desc, stable on key
		sort.SliceStable(pairs, func(i, j int) bool {
			return pairs[i].w > pairs[j].w || (pairs[i].w == pairs[j].w && pairs[i].k < pairs[j].k)
		})
		var transports []Transport
		var alpnOrder []string
		for _, p := range pairs {
			t, err := StringToTransport(p.k)
			if err != nil {
				continue
			}
			transports = append(transports, t)
			alpnOrder = append(alpnOrder, p.k)
		}
		serverMap[owner].Transports = transports
		if len(transports) > 0 {
			serverMap[owner].PrefTransport = transports[0]
		}
		// keep textual order for display/debug
		serverMap[owner].Alpn = alpnOrder
		serverMap[owner].TransportWeights = weights
	}

	for _, rr := range r.Extra {
		name := rr.Header().Name
		isOTSOwner := false
		if strings.HasPrefix(name, "_dns.") {
			isOTSOwner = true
			name = strings.TrimPrefix(name, "_dns.")
		}
		if _, exist := nsMap[name]; !exist {
			log.Printf("*** IterativeDNSQuery: non-glue record in Additional: %q", rr.String())
			continue
		}
		serversrc := ""
		_, exist := serverMap[name]
		if !exist {
			switch src {
			case "answer":
				serversrc = "answer"
			case "authority":
				serversrc = "referral"
			}
			serverMap[name] = &AuthServer{
				Name: name,
				Alpn: []string{"do53"},
				Src:  serversrc,
			}
		}

		if strings.HasSuffix(rr.Header().Name, "p.axfr.net.") {
			log.Printf("ParseAdditionalForNSAddrs: processing rr: %s", rr.String())
		}
		// log.Printf("ParseAdditionalForNSAddrs: processing rr: %s", rr.String())
		switch rr.(type) {
		case *dns.A:
			addr := rr.(*dns.A).A.String()
			// servers = append(servers, net.JoinHostPort(addr, "53"))
			if !slices.Contains(serverMap[name].Addrs, addr) {
				serverMap[name].Addrs = append(serverMap[name].Addrs, addr)
			}
			// set expiry for this server mapping from glue TTL
			serverMap[name].Expire = time.Now().Add(time.Duration(rr.Header().Ttl) * time.Second)
			tmp := glue4Map[name]
			tmp.RRs = append(tmp.RRs, rr)
			glue4Map[name] = tmp

		case *dns.AAAA:
			addr := rr.(*dns.AAAA).AAAA.String()
			// servers = append(servers, net.JoinHostPort(addr, "53"))
			if !slices.Contains(serverMap[name].Addrs, addr) {
				serverMap[name].Addrs = append(serverMap[name].Addrs, addr)
			}
			// set expiry for this server mapping from glue TTL
			serverMap[name].Expire = time.Now().Add(time.Duration(rr.Header().Ttl) * time.Second)
			tmp := glue6Map[name]
			tmp.RRs = append(tmp.RRs, rr)
			glue6Map[name] = tmp

		case *dns.SVCB:
			if !isOTSOwner {
				log.Printf("Additional contains an SVCB, but owner is not _dns.{nsname}, skipping")
				continue
			}
			log.Printf("Additional contains an SVCB; rr: %s", rr.String())
			svcb := rr.(*dns.SVCB)
			haveLocal := false
			for _, kv := range svcb.Value {
				if local, ok := kv.(*dns.SVCBLocal); ok && local.KeyCode == dns.SVCBKey(SvcbTransportKey) {
					log.Printf("SVCB transport key for %s: %q", name, string(local.Data))
					applyTransportSignal(name, string(local.Data))
					haveLocal = true
					break
				}
			}
			if !haveLocal {
				for _, kv := range svcb.Value {
					if a, ok := kv.(*dns.SVCBAlpn); ok && len(a.Alpn) > 0 {
						log.Printf("SVCB ALPN for %s: %v", name, a.Alpn)
						applyAlpnSignal(name, strings.Join(a.Alpn, ","), serverMap)
						break
					}
				}
			}
		case *dns.PrivateRR:
			// TSYNC transport signal
			if !isOTSOwner {
				log.Printf("Additional contains a Private RR (TSYNC?), but owner is not _dns.{nsname}, skipping")
				continue
			}
			if ts, ok := rr.(*dns.PrivateRR).Data.(*TSYNC); ok && ts != nil {
				if ts.Transports != "" {
					val := ts.Transports
					if strings.HasPrefix(val, "transport=") {
						val = strings.TrimPrefix(val, "transport=")
					}
					log.Printf("Additional contains TSYNC; rr: %s", rr.String())
					log.Printf("TSYNC transport value for %s: %q", name, val)
					log.Printf("Additional contains TSYNC; collecting transport weights from TSYNC")
					applyTransportSignal(name, val)
				}
			}
		default:
		}
	}

	// Second pass: parse transport signals irrespective of earlier non-glue filtering,
	// but only apply to known NS owners for this zone (present in serverMap).
	for _, rr := range r.Extra {
		if strings.HasSuffix(rr.Header().Name, "p.axfr.net.") {
			log.Printf("ParseAdditionalForNSAddrs: second-pass processing rr: %s", rr.String())
		}

		// log.Printf("ParseAdditionalForNSAddrs: second-pass processing rr: %s", rr.String())
		owner := rr.Header().Name
		if !strings.HasPrefix(owner, "_dns.") {
			continue
		}
		base := strings.TrimPrefix(owner, "_dns.")
		// Only apply to owners we track for this zone
		if _, ok := serverMap[base]; !ok {
			continue
		}
		switch rr.(type) {
		case *dns.SVCB:
			svcb := rr.(*dns.SVCB)
			haveLocal := false
			for _, kv := range svcb.Value {
				if local, ok := kv.(*dns.SVCBLocal); ok && local.KeyCode == dns.SVCBKey(SvcbTransportKey) {
					log.Printf("Transport(second-pass): SVCB key for %s: %q", base, string(local.Data))
					applyTransportSignal(base, string(local.Data))
					haveLocal = true
					break
				}
			}
			if !haveLocal {
				for _, kv := range svcb.Value {
					if a, ok := kv.(*dns.SVCBAlpn); ok && len(a.Alpn) > 0 {
						log.Printf("Transport(second-pass): SVCB ALPN for %s: %v", base, a.Alpn)
						applyAlpnSignal(base, strings.Join(a.Alpn, ","), serverMap)
						break
					}
				}
			}
		case *dns.PrivateRR:
			if ts, ok := rr.(*dns.PrivateRR).Data.(*TSYNC); ok && ts != nil && ts.Transports != "" {
				val := ts.Transports
				if strings.HasPrefix(val, "transport=") {
					val = strings.TrimPrefix(val, "transport=")
				}
				log.Printf("Transport(second-pass): TSYNC value for %s: %q", base, val)
				applyTransportSignal(base, val)
			}
		}
	}

	for nsname, rrset := range glue4Map {
		if len(rrset.RRs) == 0 {
			continue
		}
		rr := rrset.RRs[0]
		if Globals.Debug {
			fmt.Printf("ParseAdditionalForNSAddrs: Calling rrcache.Set for <%s, A> (adding glue)\n", nsname)
		}
		rrcache.Set(nsname, dns.TypeA, &CachedRRset{
			Name:       nsname,
			RRtype:     dns.TypeA,
			RRset:      &rrset,
			Context:    ContextGlue,
			Expiration: time.Now().Add(time.Duration(rr.Header().Ttl) * time.Second),
		})
	}

	for nsname, rrset := range glue6Map {
		if len(rrset.RRs) == 0 {
			continue
		}
		rr := rrset.RRs[0]
		if Globals.Debug {
			fmt.Printf("ParseAdditionalForNSAddrs: Calling rrcache.Set for <%s, AAAA> (adding glue)\n", nsname)
		}
		rrcache.Set(nsname, dns.TypeAAAA, &CachedRRset{
			Name:       nsname,
			RRtype:     dns.TypeAAAA,
			RRset:      &rrset,
			Context:    ContextGlue,
			Expiration: time.Now().Add(time.Duration(rr.Header().Ttl) * time.Second),
		})
	}

	log.Printf("*** ParseAdditionalForNSAddrs: adding %d servers for zone %q to cache", len(serverMap), zonename)
	// rrcache.Servers.Set(zonename, servers)
	rrcache.AddServers(zonename, serverMap)
	// log.Printf("ParseAdditionalForNSAddrs: serverMap:")
	for n, as := range serverMap {
		log.Printf("server: %s: %+v", n, as)
	}

	return serverMap, nil
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

// parseTransportString parses strings like "doq:30,dot:20" into a map[string]uint8
func parseTransportString(s string) (map[string]uint8, error) {
	res := map[string]uint8{}
	s = strings.TrimSpace(s)
	if s == "" {
		return res, nil
	}
	var sum int
	parts := strings.Split(s, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		kv := strings.SplitN(p, ":", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("invalid transport item: %q", p)
		}
		k := strings.ToLower(strings.TrimSpace(kv[0]))
		vstr := strings.TrimSpace(kv[1])
		// simple atoi
		var v int
		for i := 0; i < len(vstr); i++ {
			if vstr[i] < '0' || vstr[i] > '9' {
				return nil, fmt.Errorf("invalid pct number: %q", vstr)
			}
			v = v*10 + int(vstr[i]-'0')
			if v > 100 {
				return nil, fmt.Errorf("pct value > 100: %d", v)
			}
		}
		if v < 0 || v > 100 {
			return nil, fmt.Errorf("pct out of range: %d", v)
		}
		res[k] = uint8(v)
		sum += v
		if sum > 100 {
			return nil, fmt.Errorf("pct sum > 100: %d", sum)
		}
	}
	return res, nil
}

// pickTransport chooses a transport based on configured weights, falling back sensibly
func pickTransport(server *AuthServer, qname string) Transport {
	if server == nil {
		return TransportDo53
	}
	if len(server.TransportWeights) == 0 {
		if server.PrefTransport != 0 {
			return server.PrefTransport
		}
		if len(server.Transports) > 0 {
			return server.Transports[0]
		}
		return TransportDo53
	}
	// Build weighted list honoring server.Transports order
	var total int
	type pair struct {
		t Transport
		w int
	}
	var candidates []pair
	for _, t := range server.Transports {
		if w, ok := server.TransportWeights[t]; ok && w > 0 {
			candidates = append(candidates, pair{t: t, w: int(w)})
			total += int(w)
		}
	}
	// remainder goes to Do53
	if total < 100 {
		candidates = append(candidates, pair{t: TransportDo53, w: 100 - total})
		total = 100
	}
	if total == 0 {
		if server.PrefTransport != 0 {
			return server.PrefTransport
		}
		if len(server.Transports) > 0 {
			return server.Transports[0]
		}
		return TransportDo53
	}
	// stable hash on (qname, server.Name)
	h := fnv.New32a()
	_, _ = h.Write([]byte(qname))
	_, _ = h.Write([]byte{"|"[0]})
	_, _ = h.Write([]byte(server.Name))
	bucket := int(h.Sum32() % 100)
	acc := 0
	for _, c := range candidates {
		acc += c.w
		if bucket < acc {
			return c.t
		}
	}
	return candidates[len(candidates)-1].t
}

func incrementTransportCounter(server *AuthServer, t Transport) {
	if server == nil {
		return
	}
	server.mu.Lock()
	if server.TransportCounters == nil {
		server.TransportCounters = make(map[Transport]uint64)
	}
	server.TransportCounters[t]++
	server.mu.Unlock()
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

// Helpers
func (rrcache *RRsetCacheT) buildQuery(qname string, qtype uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(qname, qtype)
	m.SetEdns0(4096, true)
	if err := edns0.AddOTSToMessage(m, edns0.OTS_OPT_IN); err != nil {
		return nil, err
	}
	return m, nil
}

func (rrcache *RRsetCacheT) tryServer(ctx context.Context, server *AuthServer, addr string, m *dns.Msg, qname string, qtype uint16) (*dns.Msg, time.Duration, error) {
	t := pickTransport(server, qname)
	c, exist := rrcache.DNSClient[t]
	if !exist {
		return nil, 0, fmt.Errorf("no DNS client for transport %d exists", t)
	}
	incrementTransportCounter(server, t)
	log.Printf("calling c.Exchange with Transport=%q, server=%+v, addr=%q, qname=%q, qtype=%q", TransportToString[t], server, addr,
		qname, dns.TypeToString[qtype])
	// return c.Exchange(m, addr)
	r, _, err := c.Exchange(m, addr)
	if Globals.Verbose {
		log.Printf("tryServer: r: %s, err: %v", r.String(), err)
	}
	return r, 0, err
}

// applyTransportSignalToServer parses a colon-separated transport string and applies it to the given server
func applyTransportSignalToServer(server *AuthServer, s string) {
	if server == nil || s == "" {
		return
	}
	kvMap, err := parseTransportString(s)
	if err != nil {
		log.Printf("applyTransportSignalToServer: invalid transport string for %s: %q: %v", server.Name, s, err)
		return
	}
	type pair struct {
		k string
		w uint8
	}
	var pairs []pair
	weights := map[Transport]uint8{}
	for k, v := range kvMap {
		t, err := StringToTransport(k)
		if err != nil {
			log.Printf("applyTransportSignalToServer: unknown transport for %s: %q", server.Name, k)
			continue
		}
		pairs = append(pairs, pair{k: k, w: v})
		weights[t] = v
	}
	sort.SliceStable(pairs, func(i, j int) bool {
		return pairs[i].w > pairs[j].w || (pairs[i].w == pairs[j].w && pairs[i].k < pairs[j].k)
	})
	var transports []Transport
	var alpnOrder []string
	for _, p := range pairs {
		t, err := StringToTransport(p.k)
		if err != nil {
			continue
		}
		transports = append(transports, t)
		alpnOrder = append(alpnOrder, p.k)
	}
	server.Transports = transports
	if len(transports) > 0 {
		server.PrefTransport = transports[0]
	}
	server.Alpn = alpnOrder
	server.TransportWeights = weights
}

// applyAlpnSignal applies 100-weight transports from a comma-separated ALPN list to a server in serverMap
func applyAlpnSignal(owner string, alpnCSV string, serverMap map[string]*AuthServer) {
	if owner == "" || serverMap == nil {
		return
	}
	weights := map[Transport]uint8{}
	var order []string
	tokens := strings.Split(alpnCSV, ",")
	for _, tok := range tokens {
		k := strings.TrimSpace(tok)
		if k == "" {
			continue
		}
		t, err := StringToTransport(k)
		if err != nil {
			continue
		}
		weights[t] = 100
		order = append(order, k)
	}
	if len(order) == 0 {
		return
	}
	serverMap[owner].TransportWeights = weights
	serverMap[owner].Alpn = order
	serverMap[owner].Transports = nil
	for _, k := range order {
		if t, err := StringToTransport(k); err == nil {
			serverMap[owner].Transports = append(serverMap[owner].Transports, t)
		}
	}
	if len(serverMap[owner].Transports) > 0 {
		serverMap[owner].PrefTransport = serverMap[owner].Transports[0]
	}
}

// applyAlpnSignalToServer applies 100-weight transports from a comma-separated ALPN list to a specific server pointer
func applyAlpnSignalToServer(server *AuthServer, alpnCSV string) {
	if server == nil {
		return
	}
	weights := map[Transport]uint8{}
	var order []string
	tokens := strings.Split(alpnCSV, ",")
	for _, tok := range tokens {
		k := strings.TrimSpace(tok)
		if k == "" {
			continue
		}
		t, err := StringToTransport(k)
		if err != nil {
			continue
		}
		weights[t] = 100
		order = append(order, k)
	}
	if len(order) == 0 {
		return
	}
	server.TransportWeights = weights
	server.Alpn = order
	server.Transports = nil
	for _, k := range order {
		if t, err := StringToTransport(k); err == nil {
			server.Transports = append(server.Transports, t)
		}
	}
	if len(server.Transports) > 0 {
		server.PrefTransport = server.Transports[0]
	}
}
// parseTransportForServerFromAdditional looks for a transport signal for the specific server in the Additional section
func parseTransportForServerFromAdditional(server *AuthServer, r *dns.Msg) {
	if Globals.Verbose {
		log.Printf("**** parseTransportForServerFromAdditional: server: %+v, r: %s", server, r.String())
	}
	if server == nil || r == nil {
		return
	}
	// Canonicalize target owner to FQDN and lower-case for case-insensitive compare
	base := strings.TrimSuffix(server.Name, ".")
	targetOwner := dns.Fqdn("_dns." + base)
	for _, rr := range r.Extra {
		owner := dns.Fqdn(rr.Header().Name)
		if !strings.EqualFold(owner, targetOwner) {
			log.Printf("**** parseTransportForServerFromAdditional: owner != target: %s != %s", owner, targetOwner)
			continue
		}
		log.Printf("**** parseTransportForServerFromAdditional: owner == target: %s == %s", owner, targetOwner)
		switch x := rr.(type) {
		case *dns.SVCB:
			log.Printf("**** parseTransportForServerFromAdditional: x: %+v", x)
			haveLocal := false
			for _, kv := range x.Value {
				if local, ok := kv.(*dns.SVCBLocal); ok && local.KeyCode == dns.SVCBKey(SvcbTransportKey) {
					log.Printf("**** parseTransportForServerFromAdditional: parsing SVCB transport value: %s", string(local.Data))
					applyTransportSignalToServer(server, string(local.Data))
					haveLocal = true
					break
				}
			}
			if !haveLocal {
				for _, kv := range x.Value {
					if a, ok := kv.(*dns.SVCBAlpn); ok && len(a.Alpn) > 0 {
						log.Printf("**** parseTransportForServerFromAdditional: parsing SVCB ALPN value: %v", a.Alpn)
						applyAlpnSignalToServer(server, strings.Join(a.Alpn, ","))
						break
					}
				}
			}
		case *dns.PrivateRR:
			log.Printf("**** parseTransportForServerFromAdditional: TSYNC RR: x: %+v", x)
			if ts, ok := x.Data.(*TSYNC); ok && ts != nil {
				log.Printf("**** parseTransportForServerFromAdditional: TSYNC data: %+v", ts)
				log.Printf("**** parseTransportForServerFromAdditional: TSYNC transports: \"%s\"", ts.Transports)
				if ts.Transports != "" {
					val := ts.Transports
					if strings.HasPrefix(val, "transport=") {
						val = strings.TrimPrefix(val, "transport=")
					}
					log.Printf("**** parseTransportForServerFromAdditional: parsing TSYNC transport value: %s", val)
					applyTransportSignalToServer(server, val)
				}
			}
		}
	}
}

// persistServerTransportUpdate writes the updated server transport info back into the global ServerMap
func (rrcache *RRsetCacheT) persistServerTransportUpdate(server *AuthServer) {
	if server == nil {
		return
	}
	for zone, sm := range rrcache.ServerMap.Items() {
		if _, ok := sm[server.Name]; ok {
			sm[server.Name] = server
			rrcache.ServerMap.Set(zone, sm)
		}
	}
}
func (rrcache *RRsetCacheT) handleAnswer(ctx context.Context, qname string, qtype uint16, r *dns.Msg) (*RRset, int, CacheContext, error, bool) {
	var rrset RRset
	for _, rr := range r.Answer {
		switch t := rr.Header().Rrtype; t {
		case qtype:
			rrset.RRs = append(rrset.RRs, rr)
		case dns.TypeRRSIG:
			rrset.RRSIGs = append(rrset.RRSIGs, rr)
		case dns.TypeCNAME:
			rrset.RRs = append(rrset.RRs, rr)
			target := rr.(*dns.CNAME).Target
			tmprrset, rcode, context, err := rrcache.chaseCNAME(ctx, target, qtype)
			if err != nil {
				return nil, rcode, context, err, true
			}
			if tmprrset != nil && len(tmprrset.RRs) != 0 {
				rrset.RRs = append(rrset.RRs, tmprrset.RRs...)
				if tmprrset.RRs[0].Header().Rrtype != dns.TypeCNAME {
					rrcache.Set(qname, qtype, &CachedRRset{
						Name:       qname,
						RRtype:     qtype,
						Rcode:      uint8(rcode),
						RRset:      &rrset,
						Context:    ContextAnswer,
						Expiration: time.Now().Add(getMinTTL(rrset.RRs)),
					})
					return &rrset, rcode, ContextAnswer, nil, true
				}
			}
		default:
			rrcache.Logger.Printf("Got a %s RR when looking for %s %s", dns.TypeToString[t], qname, dns.TypeToString[qtype])
		}
	}
	if len(rrset.RRs) > 0 {
		rrcache.Set(qname, qtype, &CachedRRset{
			Name:       qname,
			RRtype:     qtype,
			Rcode:      uint8(r.MsgHdr.Rcode),
			RRset:      &rrset,
			Context:    ContextAnswer,
			Expiration: time.Now().Add(getMinTTL(rrset.RRs)),
		})
		return &rrset, r.MsgHdr.Rcode, ContextAnswer, nil, true
	}
	return nil, r.MsgHdr.Rcode, ContextFailure, nil, false
}

func extractReferral(r *dns.Msg, qname string, qtype uint16) (*RRset, string, map[string]bool) {
	nsMap := map[string]bool{}
	zonename := ""
	var nsrrs []dns.RR
	switch qtype {
	case dns.TypeNS:
		nsrrs = r.Answer
	default:
		nsrrs = r.Ns
	}
	var rrset RRset
	for _, rr := range nsrrs {
		if ns, ok := rr.(*dns.NS); ok {
			rrset.RRs = append(rrset.RRs, rr)
			nsMap[ns.Ns] = true
			zonename = rr.Header().Name
		}
	}
	return &rrset, zonename, nsMap
}

func (rrcache *RRsetCacheT) handleReferral(ctx context.Context, qname string, qtype uint16, r *dns.Msg, force bool) (*RRset, int, CacheContext, error) {
	rrcache.Logger.Printf("*** IterativeDNSQuery: rcode=NOERROR, this is a referral or neg resp")
	nsRRset, zonename, nsMap := extractReferral(r, qname, qtype)
	// ensure we collect all the NS addresses
	if err := rrcache.CollectNSAddresses(ctx, nsRRset, nil); err != nil {
		log.Printf("*** IterativeDNSQuery: Error from CollectNSAddresses: %v", err)
		return nil, r.MsgHdr.Rcode, ContextFailure, err
	}
	if len(nsRRset.RRs) != 0 {
		nsRRset.Name = zonename
		nsRRset.Class = dns.ClassINET
		nsRRset.RRtype = dns.TypeNS
		if Globals.Debug {
			fmt.Printf("IterativeDNSQuery: Calling rrcache.Set for <%s, NS>\n", zonename)
		}
		rrcache.Set(zonename, dns.TypeNS, &CachedRRset{
			Name:       zonename,
			RRtype:     dns.TypeNS,
			Rcode:      uint8(r.MsgHdr.Rcode),
			RRset:      nsRRset,
			Context:    ContextReferral,
			Expiration: time.Now().Add(getMinTTL(nsRRset.RRs)),
		})
	}
	serverMap, err := rrcache.ParseAdditionalForNSAddrs("authority", nsRRset, zonename, nsMap, r)
	if err != nil {
		log.Printf("*** IterativeDNSQuery: Error from CollectNSAddressesFromAdditional: %v", err)
		return nil, r.MsgHdr.Rcode, ContextFailure, err
	}
	if len(serverMap) == 0 {
		return nil, r.MsgHdr.Rcode, ContextReferral, nil
	}
	return rrcache.IterativeDNSQuery(ctx, qname, qtype, serverMap, force)
}

func (rrcache *RRsetCacheT) handleNegative(qname string, qtype uint16, r *dns.Msg) (CacheContext, int, bool) {
	// NXDOMAIN: SOA must exist in authority section
	if r.MsgHdr.Rcode == dns.RcodeNameError {
		var ttl uint32
		var foundSOA bool
		for _, rr := range r.Ns {
			if rr.Header().Rrtype == dns.TypeSOA {
				foundSOA = true
				ttl = rr.Header().Ttl
				break
			}
		}
		if !foundSOA {
			return ContextFailure, r.MsgHdr.Rcode, false
		}
		rrcache.Set(qname, qtype, &CachedRRset{
			Name:       qname,
			RRtype:     qtype,
			RRset:      nil,
			Context:    ContextNXDOMAIN,
			Expiration: time.Now().Add(time.Duration(ttl) * time.Second),
		})
		return ContextNXDOMAIN, r.MsgHdr.Rcode, true
	}
	// NOERROR/NODATA handled earlier in referral builder when SOA present
	return ContextFailure, r.MsgHdr.Rcode, false
}

func (rrcache *RRsetCacheT) chaseCNAME(ctx context.Context, target string, qtype uint16) (*RRset, int, CacheContext, error) {
	maxchase := 10
	cur := target
	for i := 0; i < maxchase; i++ {
		select {
		case <-ctx.Done():
			return nil, 0, ContextFailure, ctx.Err()
		default:
		}
		rrcache.Logger.Printf("*** IterativeDNSQuery: found CNAME target: %s, chasing.", cur)
		bestmatch, tmpservers, err := rrcache.FindClosestKnownZone(cur)
		if err != nil {
			rrcache.Logger.Printf("*** IterativeDNSQuery: Error from FindClosestKnownZone: %v", err)
			return nil, dns.RcodeServerFailure, ContextFailure, err
		}
		rrcache.Logger.Printf("*** IterativeDNSQuery: best match for target %s is %s", cur, bestmatch)
		tmprrset, rcode, context, err := rrcache.IterativeDNSQuery(ctx, cur, qtype, tmpservers, false)
		if err != nil {
			rrcache.Logger.Printf("*** IterativeDNSQuery: Error from IterativeDNSQuery: %v", err)
			return nil, rcode, context, err
		}
		if tmprrset != nil && len(tmprrset.RRs) != 0 {
			if tmprrset.RRs[0].Header().Rrtype == dns.TypeCNAME {
				cur = tmprrset.RRs[0].(*dns.CNAME).Target
				continue
			}
			return tmprrset, rcode, context, nil
		}
		if rcode == dns.RcodeNameError {
			// Cache negative for the original qname will be handled by caller
			return nil, rcode, context, nil
		}
	}
	return nil, dns.RcodeServerFailure, ContextFailure, fmt.Errorf("CNAME chase exceeded max depth")
}
