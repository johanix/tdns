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
	// "github.com/johanix/tdns/tdns/transport"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
	core "github.com/johanix/tdns/tdns/core"
)

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
	zd.Logger.Printf("LookupRRset: looking up %s %s", qname, dns.TypeToString[qtype])
	var rrset *core.RRset
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
		zd.Logger.Printf("LCRRset: Error from AuthDNSQuery: %v", err)
	}
	zd.Logger.Printf("LCRRset: looked up %s %s (%d RRs):", qname, dns.TypeToString[qtype], len(rrset.RRs))
	// log.Printf("LookupChildRRset: done. rrset=%v", rrset)
	return rrset, err
}

func (zd *ZoneData) LookupChildRRsetNG(qname string, qtype uint16,
	addrs []string, verbose bool) (*core.RRset, error) {

	rrset, _, err := AuthDNSQuery(qname, zd.Logger, addrs, qtype, verbose)
	if err != nil {
		zd.Logger.Printf("LCRRsetNG: Error from AuthDNSQuery: %v", err)
	}
	zd.Logger.Printf("LCRRsetNG: looked up %s %s (%d RRs):", qname, dns.TypeToString[qtype], len(rrset.RRs))
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
			lg.Printf("*** AuthDNSQuery: there is stuff in Answer section:")
			for _, rr := range r.Answer {
				lg.Printf("*** AuthDNSQuery: Answer: %s", rr.String())
			}
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
	lg *log.Logger, verbose bool) (*core.RRset, int, CacheContext, error) {
	var rrset core.RRset
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
								Name:   qname,
								RRtype: qtype,
								Rcode:  uint8(rcode),
								RRset: &core.RRset{
									Name:   rr.Header().Name,
									Class:  dns.ClassINET,
									RRtype: dns.TypeSOA,
									RRs:    []dns.RR{dns.Copy(rr)},
								},
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
				glue4Map := map[string]core.RRset{}
				glue6Map := map[string]core.RRset{}
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
func (rrcache *RRsetCacheT) IterativeDNSQuery(ctx context.Context, qname string, qtype uint16, serverMap map[string]*AuthServer, force bool) (*core.RRset, int, CacheContext, error) {
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
			if Globals.Debug {
				lg.Printf("IterativeDNSQuery: found answer to <%s, %s> in cache (result=%s)", qname, dns.TypeToString[qtype], CacheContextToString[crrset.Context])
			}
			return crrset.RRset, int(crrset.Rcode), crrset.Context, nil
		} else {
			if Globals.Debug {
				lg.Printf("IterativeDNSQuery: answer to <%s, %s> not present in cache", qname, dns.TypeToString[qtype])
			}
		}
	} else {
		lg.Printf("IterativeDNSQuery: forcing re-query of <%s, %s>, bypassing cache", qname, dns.TypeToString[qtype])
	}
	var rrset core.RRset
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
		if Globals.Debug {
			lg.Printf("IterativeDNSQuery: trying server %q: (addrs: %v)", nsname, server.Addrs)
		}
		// Try each address for this server
		for _, addr := range server.Addrs {
			select {
			case <-ctx.Done():
				return nil, 0, ContextFailure, ctx.Err()
			default:
			}
			if Globals.Debug {
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
				rrcache.parseTransportForServerFromAdditional(ctx, server, r)
				rrcache.persistServerTransportUpdate(server)
				tmprrset, rcode2, ctx2, err, done := rrcache.handleAnswer(ctx, qname, qtype, r, force)
				if err != nil || done {
					return tmprrset, rcode2, ctx2, err
				}
				// If not done, fall-through to process referral glue embedded with answers
				nsRRs, zonename, nsMap := extractReferral(r, qname, qtype)
				if len(nsRRs.RRs) > 0 {
					serverMap, err := rrcache.ParseAdditionalForNSAddrs(ctx, "authority", nsRRs, zonename, nsMap, r)
					if err != nil {
						log.Printf("*** IterativeDNSQuery: Error from CollectNSAddressesFromAdditional: %v", err)
						return nil, rcode, ContextFailure, err
					}
					if len(serverMap) == 0 {
						return nil, rcode, ContextReferral, nil
					}
					return rrcache.IterativeDNSQuery(ctx, qname, qtype, serverMap, force)
				}
				continue
			}

			if Globals.Debug {
				log.Printf("IterativeDNSQuery: examining Authoritative section (%d RRs):\n", len(r.Ns))
				for _, rr := range r.Ns {
					if rr == nil {
						continue
					}
					log.Printf("  %T %s", rr, rr.String())
				}
				log.Printf("IterativeDNSQuery: ---- end of Authoritative section (%d RRs):\n", len(r.Ns))
			}

			if len(r.Ns) != 0 {
				if ctxNeg, rcodeNeg, handled := rrcache.handleNegative(qname, qtype, r); handled {
					return nil, rcodeNeg, ctxNeg, nil
				}
				if rcode == dns.RcodeSuccess {
					return rrcache.handleReferral(ctx, qname, qtype, r, force)
				}
				if rcode == dns.RcodeNameError {
					log.Printf("*** IterativeDNSQuery: NXDOMAIN response lacked usable SOA for %s %s", qname, dns.TypeToString[qtype])
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
func (rrcache *RRsetCacheT) CollectNSAddresses(ctx context.Context, rrset *core.RRset, respch chan *ImrResponse) error {
	if rrset == nil || len(rrset.RRs) == 0 {
		return fmt.Errorf("rrset is nil or empty")
	}

	for _, rr := range rrset.RRs {
		nsname := rr.(*dns.NS).Ns
		// Query for A records
		go func(nsname string) {
			// log.Printf("CollectNSAddresses: querying for %s A records", nsname)
			_, err := rrcache.ImrQuery(ctx, nsname, dns.TypeA, dns.ClassINET, respch)
			if err != nil {
				log.Printf("CollectNSAddresses: Error querying A for %s: %v", nsname, err)
			}
		}(nsname)

		// Query for AAAA records
		go func(nsname string) {
			// log.Printf("CollectNSAddresses: querying for %s AAAA records", nsname)
			_, err := rrcache.ImrQuery(ctx, nsname, dns.TypeAAAA, dns.ClassINET, respch)
			if err != nil {
				log.Printf("CollectNSAddresses: Error querying AAAA for %s: %v", nsname, err)
			}
		}(nsname)
	}
	return nil
}

func (rrcache *RRsetCacheT) ParseAdditionalForNSAddrs(ctx context.Context, src string, nsrrset *core.RRset, zonename string,
	nsMap map[string]bool, r *dns.Msg) (map[string]*AuthServer, error) {
	if ctx == nil {
		ctx = context.Background()
	}
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
		log.Printf("*** ParseAdditionalForNSAddrs: zonename: %q\nnsMap: %+v", zonename, nsMap)
	}

	// 2. Collect any glue from Additional
	glue4Map := map[string]core.RRset{}
	glue6Map := map[string]core.RRset{}
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
	applyTransportSignal := func(owner string, s string) bool {
		kvMap, err := ParseTransportString(s)
		if err != nil {
			log.Printf("Invalid transport string for %s: %q: %v", owner, s, err)
			return false
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
		return len(transports) > 0
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
		justCreated := false
		if !exist {
			switch src {
			case "answer":
				serversrc = "answer"
			case "authority":
				serversrc = "referral"
			}
			serverMap[name] = &AuthServer{
				Name:     name,
				Alpn:     []string{"do53"},
				Src:      serversrc,
				ConnMode: ConnModeLegacy,
			}
			justCreated = true
		}

		if justCreated {
			if owner := transportOwnerForNS(name); owner != "" {
				rrcache.maybeQueryTransportSignal(ctx, owner, transportQueryReasonNewServer)
			}
			rrcache.maybeQueryTLSA(ctx, name)
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
					if applyTransportSignal(name, string(local.Data)) {
						promoteConnMode(serverMap[name], ConnModeOpportunistic)
					}
					if owner := transportOwnerForNS(name); owner != "" {
						rrcache.maybeQueryTransportSignal(ctx, owner, transportQueryReasonObservation)
					}
					rrcache.maybeQueryTLSA(ctx, name)
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
					if applyTransportSignal(name, val) {
						promoteConnMode(serverMap[name], ConnModeOpportunistic)
					}
					if owner := transportOwnerForNS(name); owner != "" {
						rrcache.maybeQueryTransportSignal(ctx, owner, transportQueryReasonObservation)
					}
					rrcache.maybeQueryTLSA(ctx, name)
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
					if applyTransportSignal(base, string(local.Data)) {
						promoteConnMode(serverMap[base], ConnModeOpportunistic)
					}
					if owner := transportOwnerForNS(base); owner != "" {
						rrcache.maybeQueryTransportSignal(ctx, owner, transportQueryReasonObservation)
					}
					rrcache.maybeQueryTLSA(ctx, base)
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
				if applyTransportSignal(base, val) {
					promoteConnMode(serverMap[base], ConnModeOpportunistic)
				}
				if owner := transportOwnerForNS(base); owner != "" {
					rrcache.maybeQueryTransportSignal(ctx, owner, transportQueryReasonObservation)
				}
				rrcache.maybeQueryTLSA(ctx, base)
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

	if Globals.Debug {
		log.Printf("*** ParseAdditionalForNSAddrs: adding %d servers for zone %q to cache", len(serverMap), zonename)
	}
	// rrcache.Servers.Set(zonename, servers)
	rrcache.AddServers(zonename, serverMap)

	if Globals.Debug {
		log.Printf("ParseAdditionalForNSAddrs: serverMap:")
		for n, as := range serverMap {
			log.Printf("server: %s: %s (addrs: %v)", n, as.Name, as.Addrs)
		}
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
// parseTransportString removed; use transport.ParseTransportString

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
	if server != nil {
		server.mu.Lock()
		defer server.mu.Unlock()
		if server.TransportCounters == nil {
			server.TransportCounters = make(map[Transport]uint64)
		}
		server.TransportCounters[t]++
	}
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
		log.Printf("failed to lookup %s record using server %s after %d attempts to %d resolvers: %v",
			qname, server, retries, len(resolvers), err)
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
	if Globals.Debug {
		log.Printf("***tryServer: calling c.Exchange with Transport=%q, server=%s (addrs: %v), addr=%q, qname=%q, qtype=%q",
			TransportToString[t], server.Name, server.Addrs, addr, qname, dns.TypeToString[qtype])
	}
	// return c.Exchange(m, addr)
	r, _, err := c.Exchange(m, addr)
	if Globals.Debug {
		if r != nil {
			log.Printf("tryServer: query \"%s %s\" sent to %s returned response:\n%s", qname, dns.TypeToString[qtype], addr, r.String())
		} else {
			log.Printf("tryServer: query \"%s %s\" sent to %s returned no response", qname, dns.TypeToString[qtype], addr)
		}
	}
	if err != nil {
		log.Printf("tryServer: query \"%s %s\" sent to %s returned error: %v", qname, dns.TypeToString[qtype], addr, err)
	}
	return r, 0, err
}

// applyTransportSignalToServer parses a colon-separated transport string and applies it to the given server.
// Returns true if at least one transport entry was applied.
func applyTransportSignalToServer(server *AuthServer, s string) bool {
	if server == nil || s == "" {
		return false
	}
	kvMap, err := ParseTransportString(s)
	if err != nil {
		log.Printf("applyTransportSignalToServer: invalid transport string for %s: %q: %v", server.Name, s, err)
		return false
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
	return len(transports) > 0
}

func transportOwnerForNS(nsname string) string {
	base := strings.TrimSpace(nsname)
	if base == "" {
		return ""
	}
	base = strings.TrimSuffix(base, ".")
	return dns.Fqdn("_dns." + base)
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
func (rrcache *RRsetCacheT) parseTransportForServerFromAdditional(ctx context.Context, server *AuthServer, r *dns.Msg) {
	if ctx == nil {
		ctx = context.Background()
	}
	if server == nil || r == nil {
		if Globals.Debug {
			log.Printf("*** parseTransportForServerFromAdditional: server or r is nil")
		}
		return
	}
	if Globals.Debug {
		log.Printf("*** parseTransportForServerFromAdditional: server: %s (addrs: %v)", server.Name, server.Addrs)
		log.Printf("*** pTFSA: looking for transport signal in response to \"%s %s\" (%d RRs in Additional)", r.Question[0].Name, dns.TypeToString[r.Question[0].Qtype], len(r.Extra))
	}
	if len(r.Extra) == 0 {
		if Globals.Verbose {
			log.Printf("*** parseTransportForServerFromAdditional: no Additional section in response")
		}
		return
	}
	// Canonicalize target owner to FQDN and lower-case for case-insensitive compare
	base := strings.TrimSuffix(server.Name, ".")
	targetOwner := dns.Fqdn("_dns." + base)
	for _, rr := range r.Extra {
		owner := dns.Fqdn(rr.Header().Name)
		if !strings.EqualFold(owner, targetOwner) {
			if Globals.Debug {
				log.Printf("**** parseTransportForServerFromAdditional: owner != target: %s != %s", owner, targetOwner)
			}
			continue
		}
		if Globals.Debug {
			log.Printf("**** parseTransportForServerFromAdditional: owner == target: %s == %s", owner, targetOwner)
		}
		switch x := rr.(type) {
		case *dns.SVCB:
			log.Printf("**** parseTransportForServerFromAdditional: x: %+v", x)
			haveLocal := false
			for _, kv := range x.Value {
				if local, ok := kv.(*dns.SVCBLocal); ok && local.KeyCode == dns.SVCBKey(SvcbTransportKey) {
					if Globals.Verbose {
						log.Printf("**** parseTransportForServerFromAdditional: parsing SVCB transport value: %s", string(local.Data))
					}
					if applyTransportSignalToServer(server, string(local.Data)) {
						promoteConnMode(server, ConnModeOpportunistic)
					}
					if owner := transportOwnerForNS(server.Name); owner != "" {
						rrcache.maybeQueryTransportSignal(ctx, owner, transportQueryReasonObservation)
					}
					rrcache.maybeQueryTLSA(ctx, server.Name)
					haveLocal = true
					break
				}
			}
			if !haveLocal {
				for _, kv := range x.Value {
					if a, ok := kv.(*dns.SVCBAlpn); ok && len(a.Alpn) > 0 {
						if Globals.Verbose {
							log.Printf("**** parseTransportForServerFromAdditional: parsing SVCB ALPN value: %v", a.Alpn)
						}
						applyAlpnSignalToServer(server, strings.Join(a.Alpn, ","))
						break
					}
				}
			}
		case *dns.PrivateRR:
			if Globals.Verbose {
				log.Printf("**** parseTransportForServerFromAdditional: TSYNC RR: x: %+v", x)
			}
			if ts, ok := x.Data.(*TSYNC); ok && ts != nil {
				if Globals.Verbose {
					log.Printf("**** parseTransportForServerFromAdditional: TSYNC data: %+v", ts)
					log.Printf("**** parseTransportForServerFromAdditional: TSYNC transports: \"%s\"", ts.Transports)
				}
				if ts.Transports != "" {
					val := ts.Transports
					if strings.HasPrefix(val, "transport=") {
						val = strings.TrimPrefix(val, "transport=")
					}
					if Globals.Verbose {
						log.Printf("**** parseTransportForServerFromAdditional: parsing TSYNC transport value: %s", val)
					}
					if applyTransportSignalToServer(server, val) {
						promoteConnMode(server, ConnModeOpportunistic)
					}
					if owner := transportOwnerForNS(server.Name); owner != "" {
						rrcache.maybeQueryTransportSignal(ctx, owner, transportQueryReasonObservation)
					}
					rrcache.maybeQueryTLSA(ctx, server.Name)
				}
			}
		}
	}
}

// persistServerTransportUpdate writes the updated server transport info back into the global ServerMap
// XXX: This should be safe as ServerMap is a concurrent map.
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

func (rrcache *RRsetCacheT) applyTransportRRsetFromAnswer(qname string, rrset *core.RRset, validated bool) {
	if rrcache == nil || rrset == nil || len(rrset.RRs) == 0 {
		return
	}
	owner := dns.Fqdn(qname)
	if !strings.HasPrefix(owner, "_dns.") {
		return
	}
	base := strings.TrimPrefix(owner, "_dns.")
	if base == "" {
		return
	}
	targetMode := ConnModeOpportunistic
	if validated {
		targetMode = ConnModeValidated
	}
	for zone, sm := range rrcache.ServerMap.Items() {
		server, ok := sm[base]
		if !ok {
			continue
		}
		applied := false
		switch rrset.RRtype {
		case dns.TypeSVCB:
			for _, rr := range rrset.RRs {
				svcb, ok := rr.(*dns.SVCB)
				if !ok {
					continue
				}
				haveLocal := false
				for _, kv := range svcb.Value {
					if local, ok := kv.(*dns.SVCBLocal); ok && local.KeyCode == dns.SVCBKey(SvcbTransportKey) {
						if applyTransportSignalToServer(server, string(local.Data)) {
							applied = true
						}
						haveLocal = true
						break
					}
				}
				if !haveLocal {
					for _, kv := range svcb.Value {
						if a, ok := kv.(*dns.SVCBAlpn); ok && len(a.Alpn) > 0 {
							applyAlpnSignalToServer(server, strings.Join(a.Alpn, ","))
							applied = true
							break
						}
					}
				}
				owners := tlsaOwnersForServer(base, server)
				if len(owners) > 0 {
					for _, kv := range svcb.Value {
						local, ok := kv.(*dns.SVCBLocal)
						if !ok || uint16(local.Key()) != SvcbTLSAKey {
							continue
						}
						tlsaRR, err := ParseTLSAString(string(local.Data))
						if err != nil {
							log.Printf("applyTransportRRsetFromAnswer: failed to parse TLSA from SVCB: %v", err)
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
							rrcache.storeTLSAForServer(base, ownerName, &core.RRset{
								Name:   ownerName,
								Class:  dns.ClassINET,
								RRtype: dns.TypeTLSA,
								RRs:    []dns.RR{tlsa},
							}, validated)
						}
					}
				}
			}
		case TypeTSYNC:
			for _, rr := range rrset.RRs {
				if priv, ok := rr.(*dns.PrivateRR); ok {
					if ts, ok := priv.Data.(*TSYNC); ok && ts != nil && ts.Transports != "" {
						val := ts.Transports
						if strings.HasPrefix(val, "transport=") {
							val = strings.TrimPrefix(val, "transport=")
						}
						if applyTransportSignalToServer(server, val) {
							applied = true
						}
					}
				}
			}
		default:
			continue
		}
		if applied {
			promoteConnMode(server, targetMode)
			rrcache.ServerMap.Set(zone, sm)
		}
	}
}

func (rrcache *RRsetCacheT) handleAnswer(ctx context.Context, qname string, qtype uint16, r *dns.Msg, force bool) (*core.RRset, int, CacheContext, error, bool) {
	var rrset core.RRset
	for _, rr := range r.Answer {
		switch t := rr.Header().Rrtype; t {
		case qtype:
			rrset.RRs = append(rrset.RRs, rr)
		case dns.TypeRRSIG:
			rrset.RRSIGs = append(rrset.RRSIGs, rr)
		case dns.TypeCNAME:
			rrset.RRs = append(rrset.RRs, rr)
			target := rr.(*dns.CNAME).Target
			tmprrset, rcode, context, err := rrcache.chaseCNAME(ctx, target, qtype, force)
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
		// Fill RRset metadata
		rrset.Name = qname
		rrset.Class = dns.ClassINET
		rrset.RRtype = qtype
		// Validate the RRset (if possible) using DnskeyCache
		validated := false
		if len(rrset.RRSIGs) > 0 {
			ok, _ := rrcache.ValidateRRset(ctx, DnskeyCache, &rrset, rrcache.Debug)
			validated = ok
		}
		cr := &CachedRRset{
			Name:       qname,
			RRtype:     qtype,
			Rcode:      uint8(r.MsgHdr.Rcode),
			RRset:      &rrset,
			Context:    ContextAnswer,
			Expiration: time.Now().Add(getMinTTL(rrset.RRs)),
			Validated:  validated,
		}
		rrcache.Set(qname, qtype, cr)
		if qtype == dns.TypeSVCB || qtype == TypeTSYNC {
			rrcache.applyTransportRRsetFromAnswer(qname, &rrset, validated)
		} else if qtype == dns.TypeTLSA {
			base := baseFromTLSAOwner(qname)
			if base != "" {
				rrcache.storeTLSAForServer(base, qname, &rrset, validated)
			}
		}
		// If this is a validated DNSKEY RRset, cache its keys as trusted anchors with TTL-based expiration
		if qtype == dns.TypeDNSKEY && validated {
			// derive expiration from just-cached rrset
			exp := cr.Expiration
			for _, rr := range rrset.RRs {
				if dk, ok := rr.(*dns.DNSKEY); ok {
					DnskeyCache.Set(dns.Fqdn(dk.Hdr.Name), dk.KeyTag(), &CachedDnskeyRRset{
						Name:       dns.Fqdn(dk.Hdr.Name),
						Keyid:      dk.KeyTag(),
						Validated:  true,
						Trusted:    true,
						Dnskey:     *dk,
						Expiration: exp,
					})
				}
			}
		}
		return &rrset, r.MsgHdr.Rcode, ContextAnswer, nil, true
	}
	return nil, r.MsgHdr.Rcode, ContextFailure, nil, false
}

func extractReferral(r *dns.Msg, qname string, qtype uint16) (*core.RRset, string, map[string]bool) {
	nsMap := map[string]bool{}
	zonename := ""
	var nsrrs []dns.RR
	switch qtype {
	case dns.TypeNS:
		nsrrs = r.Answer
	default:
		nsrrs = r.Ns
	}
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

func (rrcache *RRsetCacheT) handleReferral(ctx context.Context, qname string, qtype uint16, r *dns.Msg, force bool) (*core.RRset, int, CacheContext, error) {
	if Globals.Debug {
		rrcache.Logger.Printf("*** handleReferral: rcode=NOERROR, this is a referral or neg resp")
	}
	nsRRset, zonename, nsMap := extractReferral(r, qname, qtype)

	if Globals.Debug {
		rrcache.Logger.Printf("*** handleReferral: zone name is %q, nsRRset: %+v", zonename, nsRRset)
	}
	// ensure we collect all the NS addresses
	if err := rrcache.CollectNSAddresses(ctx, nsRRset, nil); err != nil {
		log.Printf("*** handleReferral: Error from CollectNSAddresses: %v", err)
		return nil, r.MsgHdr.Rcode, ContextFailure, err
	}
	if len(nsRRset.RRs) != 0 {
		nsRRset.Name = zonename
		nsRRset.Class = dns.ClassINET
		nsRRset.RRtype = dns.TypeNS
		if Globals.Debug {
			fmt.Printf("handleReferral: Calling rrcache.Set for <%s, NS>\n", zonename)
		}
		// Validate NS RRset if signatures are present
		validated := false
		if len(nsRRset.RRSIGs) > 0 {
			if ok, _ := rrcache.ValidateRRset(ctx, DnskeyCache, nsRRset, rrcache.Debug); ok {
				validated = true
			}
		}
		rrcache.Set(zonename, dns.TypeNS, &CachedRRset{
			Name:       zonename,
			RRtype:     dns.TypeNS,
			Rcode:      uint8(r.MsgHdr.Rcode),
			RRset:      nsRRset,
			Context:    ContextReferral,
			Validated:  validated,
			Expiration: time.Now().Add(getMinTTL(nsRRset.RRs)),
		})
	}
	// Also collect and cache DS RRset (signed) when present in referral
	var dsRRs []dns.RR
	var dsSigs []dns.RR
	for _, rr := range r.Ns {
		switch rr.Header().Rrtype {
		case dns.TypeDS:
			if rr.Header().Name == zonename {
				dsRRs = append(dsRRs, rr)
			}
		case dns.TypeRRSIG:
			if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeDS && rr.Header().Name == zonename {
				dsSigs = append(dsSigs, rr)
			}
		}
	}
	if len(dsRRs) > 0 {
		dsRRset := &core.RRset{
			Name:   zonename,
			Class:  dns.ClassINET,
			RRtype: dns.TypeDS,
			RRs:    dsRRs,
			RRSIGs: dsSigs,
		}
		validated := false
		if len(dsSigs) > 0 {
			if ok, _ := rrcache.ValidateRRset(ctx, DnskeyCache, dsRRset, rrcache.Debug); ok {
				validated = true
			}
		}
		rrcache.Set(zonename, dns.TypeDS, &CachedRRset{
			Name:       zonename,
			RRtype:     dns.TypeDS,
			Rcode:      uint8(r.MsgHdr.Rcode),
			RRset:      dsRRset,
			Context:    ContextReferral,
			Validated:  validated,
			Expiration: time.Now().Add(getMinTTL(dsRRs)),
		})
	}
	serverMap, err := rrcache.ParseAdditionalForNSAddrs(ctx, "authority", nsRRset, zonename, nsMap, r)
	if err != nil {
		log.Printf("*** handleReferral: Error from CollectNSAddressesFromAdditional: %v", err)
		return nil, r.MsgHdr.Rcode, ContextFailure, err
	}
	if len(serverMap) == 0 {
		return nil, r.MsgHdr.Rcode, ContextReferral, nil
	}
	// rrcache.Logger.Printf("*** handleReferral: calling revalidateReferralNS for zone %s, serverMap: %+v", zonename, serverMap)
	rrcache.scheduleReferralNSRevalidation(ctx, zonename, serverMap)
	//rrcache.Logger.Printf("*** handleReferral: revalidateReferralNS returned, calling IterativeDNSQuery for zone %s, serverMap: %+v", zonename, serverMap)
	return rrcache.IterativeDNSQuery(ctx, qname, qtype, serverMap, force)
}

const maxNSRevalidateServers = 3

func (rrcache *RRsetCacheT) scheduleReferralNSRevalidation(ctx context.Context, zonename string, serverMap map[string]*AuthServer) {
	if ctx == nil {
		ctx = context.Background()
	}
	if rrcache == nil || zonename == "" || len(serverMap) == 0 {
		return
	}
	if !rrcache.hasOption(ImrOptRevalidateNS) {
		return
	}
	if !rrcache.markNSRevalidation(zonename) {
		return
	}
	snapshot := cloneServerMap(serverMap)
	if len(snapshot) == 0 {
		rrcache.clearNSRevalidation(zonename)
		return
	}
	go func() {
		defer rrcache.clearNSRevalidation(zonename)
		rrcache.revalidateReferralNS(ctx, zonename, snapshot)
	}()
}

func cloneServerMap(src map[string]*AuthServer) map[string]*AuthServer {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]*AuthServer, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func (rrcache *RRsetCacheT) markNSRevalidation(zone string) bool {
	rrcache.nsRevalidateMu.Lock()
	defer rrcache.nsRevalidateMu.Unlock()
	if rrcache.nsRevalidateInFlight == nil {
		rrcache.nsRevalidateInFlight = make(map[string]struct{})
	}
	if _, ok := rrcache.nsRevalidateInFlight[zone]; ok {
		return false
	}
	rrcache.nsRevalidateInFlight[zone] = struct{}{}
	return true
}

func (rrcache *RRsetCacheT) clearNSRevalidation(zone string) {
	rrcache.nsRevalidateMu.Lock()
	defer rrcache.nsRevalidateMu.Unlock()
	if rrcache.nsRevalidateInFlight == nil {
		return
	}
	delete(rrcache.nsRevalidateInFlight, zone)
}

func (rrcache *RRsetCacheT) revalidateReferralNS(ctx context.Context, zonename string, serverMap map[string]*AuthServer) {
	rrcache.Logger.Printf("*** revalidateReferralNS: revalidating NS for zone %s", zonename)
	if rrcache == nil || !rrcache.hasOption(ImrOptRevalidateNS) || zonename == "" || len(serverMap) == 0 {
		return
	}
	var existing *CachedRRset
	if existing = rrcache.Get(zonename, dns.TypeNS); existing != nil && existing.Context == ContextAnswer {
		return
	}
	// rrcache.Logger.Printf("*** revalidateReferralNS: existing context is %s, collecting server addresses for revalidation", CacheContextToString[existing.Context])
	addrs := collectServerAddressesForRevalidation(serverMap)
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
	rrset, rcode, _, err := rrcache.AuthDNSQuery(ctx, zonename, dns.TypeNS, addrs, rrcache.Logger, rrcache.Verbose)
	if err != nil || rrset == nil || len(rrset.RRs) == 0 {
		if rrcache.Debug && err != nil {
			log.Printf("NS revalidation for %s failed: %v", zonename, err)
		}
		return
	}
	rrset.Name = zonename
	rrset.Class = dns.ClassINET
	rrset.RRtype = dns.TypeNS
	validated := false
	if len(rrset.RRSIGs) > 0 {
		ok, err := rrcache.ValidateRRset(ctx, DnskeyCache, rrset, rrcache.Debug)
		if err != nil {
			rrcache.Logger.Printf("*** revalidateReferralNS: Error from ValidateRRset: %v", err)
		}
		if ok {
			validated = true
		}
	}
	rrcache.Set(zonename, dns.TypeNS, &CachedRRset{
		Name:       zonename,
		RRtype:     dns.TypeNS,
		Rcode:      uint8(rcode),
		RRset:      rrset,
		Context:    ContextAnswer,
		Validated:  validated,
		Expiration: time.Now().Add(getMinTTL(rrset.RRs)),
	})

	rrcache.revalidateInBailiwickGlue(ctx, zonename, serverMap, true)
}

func collectServerAddressesForRevalidation(serverMap map[string]*AuthServer) []string {
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
			hostPort := raw
			if _, _, err := net.SplitHostPort(raw); err != nil {
				hostPort = net.JoinHostPort(raw, "53")
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

func collectInBailiwickNS(serverMap map[string]*AuthServer, zonename string) []string {
	if len(serverMap) == 0 || zonename == "" {
		return nil
	}
	zone := strings.ToLower(dns.Fqdn(zonename))
	var hosts []string
	for name := range serverMap {
		fq := strings.ToLower(dns.Fqdn(name))
		if fq == zone || strings.HasSuffix(fq, "."+zone) {
			hosts = append(hosts, fq)
		}
	}
	return hosts
}

func (rrcache *RRsetCacheT) revalidateInBailiwickGlue(ctx context.Context, zonename string, serverMap map[string]*AuthServer, force bool) {
	if rrcache == nil || !rrcache.hasOption(ImrOptRevalidateNS) {
		return
	}
	hosts := collectInBailiwickNS(serverMap, zonename)
	if len(hosts) == 0 {
		return
	}
	for _, host := range hosts {
		server := serverMap[host]
		rrcache.revalidateGlueRR(ctx, host, dns.TypeA, server, force)
		rrcache.revalidateGlueRR(ctx, host, dns.TypeAAAA, server, force)
	}
}

func (rrcache *RRsetCacheT) revalidateGlueRR(ctx context.Context, host string, rrtype uint16, server *AuthServer, force bool) {
	select {
	case <-ctx.Done():
		return
	default:
	}
	if server == nil || len(server.Addrs) == 0 {
		return
	}
	hostServerMap := map[string]*AuthServer{
		server.Name: server,
	}
	rrset, _, _, err := rrcache.IterativeDNSQuery(ctx, host, rrtype, hostServerMap, force)
	if err != nil || rrset == nil || len(rrset.RRs) == 0 {
		return
	}

	validated := false
	if len(rrset.RRSIGs) > 0 {
		ok, err := rrcache.ValidateRRset(ctx, DnskeyCache, rrset, rrcache.Debug)
		if err != nil {
			rrcache.Logger.Printf("*** revalidateGlueRR: Error from ValidateRRset: %v", err)
		}
		if ok {
			validated = true
		}
	}
	rrcache.Set(host, rrtype, &CachedRRset{
		Name:       host,
		RRtype:     rrtype,
		Rcode:      uint8(dns.RcodeSuccess),
		RRset:      rrset,
		Context:    ContextAnswer,
		Validated:  validated,
		Expiration: time.Now().Add(getMinTTL(rrset.RRs)), // XXX: This will be overridden by rrcache.Set(). TODO: Fix this.
	})
}

func (rrcache *RRsetCacheT) handleNegative(qname string, qtype uint16, r *dns.Msg) (CacheContext, int, bool) {
	if r == nil || len(r.Ns) == 0 {
		return ContextFailure, r.MsgHdr.Rcode, false
	}

	var negContext CacheContext
	switch r.MsgHdr.Rcode {
	case dns.RcodeNameError:
		negContext = ContextNXDOMAIN
	case dns.RcodeSuccess:
		if len(r.Answer) != 0 {
			return ContextFailure, r.MsgHdr.Rcode, false
		}
		negContext = ContextNoErrNoAns
	default:
		return ContextFailure, r.MsgHdr.Rcode, false
	}

	var (
		ttl      uint32
		soaOwner string
		soaMin   uint32
		soarrset *core.RRset
		negSets  = make(map[string]*core.RRset)
		negOrder []string
	)

	getNegKey := func(name string, rrtype uint16) string {
		return fmt.Sprintf("%s::%d", name, rrtype)
	}
	getNegSet := func(name string, rrtype uint16) *core.RRset {
		key := getNegKey(name, rrtype)
		if rs, ok := negSets[key]; ok {
			return rs
		}
		rs := &core.RRset{
			Name:   name,
			Class:  dns.ClassINET,
			RRtype: rrtype,
		}
		negSets[key] = rs
		negOrder = append(negOrder, key)
		return rs
	}

	for _, rawrr := range r.Ns {
		if rawrr == nil {
			continue
		}
		switch rr := rawrr.(type) {
		case *dns.SOA:
			set := getNegSet(rr.Header().Name, dns.TypeSOA)
			set.RRs = append(set.RRs, dns.Copy(rr))
			if soarrset == nil {
				soarrset = set
				soaOwner = rr.Header().Name
				ttl = rr.Header().Ttl
			} else if rr.Header().Ttl < ttl || ttl == 0 {
				ttl = rr.Header().Ttl
			}
			if rr.Minttl != 0 {
				if soaMin == 0 || rr.Minttl < soaMin {
					soaMin = rr.Minttl
				}
			}
		case *dns.RRSIG:
			set := getNegSet(rr.Header().Name, rr.TypeCovered)
			set.RRSIGs = append(set.RRSIGs, dns.Copy(rr))
		default:
			set := getNegSet(rr.Header().Name, rr.Header().Rrtype)
			set.RRs = append(set.RRs, dns.Copy(rr))
		}
	}

	if soarrset == nil || len(soarrset.RRs) == 0 {
		log.Printf("handleNegative: no SOA found in authority for \"%s %s\" (%s)", qname, dns.TypeToString[qtype], dns.RcodeToString[r.MsgHdr.Rcode])
		return ContextFailure, r.MsgHdr.Rcode, false
	}
	if soaMin > 0 && (ttl == 0 || soaMin < ttl) {
		ttl = soaMin
	}
	if ttl == 0 {
		ttl = 60
	}

	skipDNSKEYValidation := qtype == dns.TypeDNSKEY
	hasValidatedDS := false
	if skipDNSKEYValidation {
		if ds := rrcache.Get(qname, dns.TypeDS); ds != nil && ds.RRset != nil && len(ds.RRset.RRs) > 0 && ds.Validated {
			hasValidatedDS = true
		}
	}

	soaValidated := false
	if !skipDNSKEYValidation && len(soarrset.RRSIGs) > 0 {
		if ok, _ := rrcache.ValidateRRset(context.Background(), DnskeyCache, soarrset, rrcache.Debug); ok {
			soaValidated = true
		}
	}

	expiration := time.Now().Add(time.Duration(ttl) * time.Second)

	var negAuthority []*core.RRset
	for _, key := range negOrder {
		if rs, ok := negSets[key]; ok && rs != nil {
			if len(rs.RRs) == 0 && len(rs.RRSIGs) == 0 {
				continue
			}
			negAuthority = append(negAuthority, rs)
		}
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

	negValidated := false
	if !skipDNSKEYValidation && len(negAuthority) > 0 {
		if rrcache.ValidateNegativeResponse(context.Background(), qname, qtype, negAuthority) {
			negValidated = true
		}
	}

	rrcache.Set(qname, qtype, &CachedRRset{
		Name:         qname,
		RRtype:       qtype,
		Rcode:        uint8(r.MsgHdr.Rcode),
		RRset:        soarrset,
		NegAuthority: negAuthority,
		Context:      negContext,
		Validated:    negValidated,
		Expiration:   expiration, // XXX: This will be overridden by rrcache.Set(). TODO: Fix this.
		EDECode:      edeCode,
		EDEText:      edeText,
	})

	// XXX: should do either of:
	// push the computed TTL into the SOA RR header(s) before calling Set, or
	// teach Set to respect a non-zero crrset.Ttl/Expiration for negative entries instead of recomputing it.

	// Also cache the SOA RRset itself for future direct lookups.
	rrcache.Set(soaOwner, dns.TypeSOA, &CachedRRset{
		Name:       soaOwner,
		RRtype:     dns.TypeSOA,
		Rcode:      uint8(dns.RcodeSuccess),
		RRset:      soarrset,
		Context:    ContextAnswer,
		Validated:  soaValidated,
		Expiration: expiration, // XXX: This will be overridden by rrcache.Set(). TODO: Fix this.
	})

	return negContext, r.MsgHdr.Rcode, true
}

func (rrcache *RRsetCacheT) xxxValidateNegativeResponse(ctx context.Context, qname string, qtype uint16, negAuthority []*core.RRset) bool {
	if len(negAuthority) == 0 {
		return false
	}
	if qtype == dns.TypeDNSKEY {
		// Cannot validate negative DNSKEY responses without the zone's DNSKEYs; treat as insecure/bogus
		if Globals.Debug {
			log.Printf("ValidateNegativeResponse: skipping validation for DNSKEY negative response at %q", qname)
		}
		return false
	}
	if ctx == nil {
		ctx = context.Background()
	}
	qnameCanon := dns.CanonicalName(qname)
	var (
		soarrset      *core.RRset
		hasSignatures bool
		nsecs         []*dns.NSEC
		nsec3Present  bool
	)
	for _, set := range negAuthority {
		if set == nil {
			continue
		}
		if set.RRtype == dns.TypeSOA && soarrset == nil {
			soarrset = set
		}
		if len(set.RRSIGs) > 0 {
			hasSignatures = true
		}
		switch set.RRtype {
		case dns.TypeNSEC:
			for _, rr := range set.RRs {
				if nsec, ok := rr.(*dns.NSEC); ok {
					nsecs = append(nsecs, nsec)
				}
			}
		case dns.TypeNSEC3:
			nsec3Present = true
		}
	}
	if soarrset == nil || len(soarrset.RRs) == 0 {
		return false
	}
	zoneName := dns.CanonicalName(soarrset.Name)
	if !strings.HasSuffix(qnameCanon, zoneName) {
		return false
	}
	if !hasSignatures {
		return true
	}
	for _, set := range negAuthority {
		if set == nil || len(set.RRSIGs) == 0 {
			continue
		}
		if ok, _ := rrcache.ValidateRRset(ctx, DnskeyCache, set, rrcache.Debug); !ok {
			return false
		}
	}
	if len(nsecs) > 0 {
		baseZone := strings.TrimSuffix(zoneName, ".")
		wildcard := dns.CanonicalName("*." + baseZone)
		coveredQname := false
		coveredWildcard := false
		for _, nsec := range nsecs {
			if nsecCoversName(qnameCanon, nsec) {
				coveredQname = true
			}
			if nsecCoversName(wildcard, nsec) {
				coveredWildcard = true
			}
			if coveredQname && coveredWildcard {
				break
			}
		}
		return coveredQname && coveredWildcard
	}
	if nsec3Present {
		return true
	}
	return false
}

func nsecCoversName(name string, nsec *dns.NSEC) bool {
	if nsec == nil {
		return false
	}
	owner := dns.CanonicalName(nsec.Hdr.Name)
	next := dns.CanonicalName(nsec.NextDomain)
	target := dns.CanonicalName(name)
	if owner == next {
		return true
	}
	if strings.Compare(owner, next) < 0 {
		return strings.Compare(target, owner) >= 0 && strings.Compare(target, next) < 0
	}
	return strings.Compare(target, owner) >= 0 || strings.Compare(target, next) < 0
}

func (rrcache *RRsetCacheT) chaseCNAME(ctx context.Context, target string, qtype uint16, force bool) (*core.RRset, int, CacheContext, error) {
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
		tmprrset, rcode, context, err := rrcache.IterativeDNSQuery(ctx, cur, qtype, tmpservers, force)
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

func DefaultDNSKEYFetcher(ctx context.Context, name string, rrcache *RRsetCacheT) (*core.RRset, error) {
	// implement with your IterativeDNSQuery + server selection
	best, servers, err := rrcache.FindClosestKnownZone(name)
	if err != nil {
		return nil, fmt.Errorf("FindClosestKnownZone error for %s: %v", name, err)
	}
	_ = best // could be used for logging
	if len(servers) == 0 {
		if sm, ok := rrcache.ServerMap.Get("."); ok {
			servers = sm
		}
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("no servers for %s", name)
	}
	rr, _, _, err := rrcache.IterativeDNSQuery(ctx, name, dns.TypeDNSKEY, servers, false)
	if err != nil || rr == nil || len(rr.RRs) == 0 {
		return nil, fmt.Errorf("dnskey fetch failed for %s: %v", name, err)
	}
	return rr, nil
}

func DefaultRRsetFetcher(ctx context.Context, qname string, qtype uint16, rrcache *RRsetCacheT) (*core.RRset, error) {
	// implement with your IterativeDNSQuery + server selection
	best, servers, err := rrcache.FindClosestKnownZone(qname)
	if err != nil {
		return nil, fmt.Errorf("FindClosestKnownZone error for %s: %v", qname, err)
	}
	_ = best // could be used for logging
	if len(servers) == 0 {
		if sm, ok := rrcache.ServerMap.Get("."); ok {
			servers = sm
		}
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("no servers for %s", qname)
	}
	rr, _, _, err := rrcache.IterativeDNSQuery(ctx, qname, qtype, servers, false)
	if err != nil || rr == nil || len(rr.RRs) == 0 {
		return nil, fmt.Errorf("fetch failed for %s %s: %v", qname, dns.TypeToString[qtype], err)
	}
	return rr, nil
}