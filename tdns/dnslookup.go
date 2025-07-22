/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"
	"log"
	"net"
	"slices"
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

func (rrcache *RRsetCacheT) AuthDNSQuery(qname string, qtype uint16, nameservers []string,
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
						lg.Printf("*** AuthDNSQuery: found CNAME for %s: %s. Chasing it.", qname, target)
						// We need to look up the target of the CNAME
						tmprrset, rcode, context, err := rrcache.AuthDNSQuery(target, qtype, nameservers, lg, verbose)
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
							// XXX: Is this correct? This is when we have a CNAME -> NXDOMAIN chain
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
func (rrcache *RRsetCacheT) IterativeDNSQuery(qname string, qtype uint16, serverMap map[string]*AuthServer, force bool) (*RRset, int, CacheContext, error) {
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

	m := new(dns.Msg)
	m.SetQuestion(qname, qtype)
	m.SetEdns0(4096, true)
	err := AddOTSToMessage(m, OTS_OPT_IN)
	if err != nil {
		lg.Printf("IterativeDNSQuery: Error from AddOTSToMessage: %v", err)
		return nil, 0, ContextFailure, err
	}
	if Globals.Debug {
		fmt.Printf("IterativeDNSQuery: message after AddOTSToMessage: %s", m.String())
	}

	// Try each server in the map
	for nsname, server := range serverMap {
		lg.Printf("IterativeDNSQuery: trying server %q: %+v", nsname, server)
		// Try each address for this server
		for _, addr := range server.Addrs {
			// ns := net.JoinHostPort(addr, "53")
			if rrcache.Verbose {
				lg.Printf("IterativeDNSQuery: using nameserver %s (ALPN: %v) for <%s, %s> query\n",
					addr, server.Alpn, qname, dns.TypeToString[qtype])
			}

			c, exist := rrcache.DNSClient[server.PrefTransport]
			if !exist {
				return nil, 0, ContextFailure, fmt.Errorf("no DNS client for transport %d exists", server.PrefTransport)
			}

			log.Printf("calling c.Exchange with PrefTransport=%q, server=%+v, addr=%q, qname=%q, qtype=%q", TransportToString[server.PrefTransport], server, addr,
				qname, dns.TypeToString[qtype])
			r, rtt, err := c.Exchange(m, addr)
			if err != nil && rrcache.Verbose {
				lg.Printf("IterativeDNSQuery: Error from dns.Exchange: %v (rtt: %v)", err, rtt)
				continue // go to next server
			}

			if r == nil {
				continue
			}
			rcode = r.MsgHdr.Rcode

			switch {
			case len(r.Answer) != 0:
				lg.Printf("*** IterativeDNSQuery: there is stuff in Answer section")
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
							lg.Printf("*** IterativeDNSQuery: found CNAME for %s: %s, Chasing it.", qname, target)
							// We need to look up the target of the CNAME
							bestmatch, tmpservers, err := rrcache.FindClosestKnownZone(target)
							if err != nil {
								lg.Printf("*** IterativeDNSQuery: Error from FindClosestKnownZone: %v", err)
								return nil, dns.RcodeServerFailure, ContextFailure, err
							}
							lg.Printf("*** IterativeDNSQuery: best match for target %s is %s", target, bestmatch)
							tmprrset, rcode, context, err := rrcache.IterativeDNSQuery(target, qtype, tmpservers, false)
							if err != nil {
								lg.Printf("*** IterativeDNSQuery: Error from IterativeDNSQuery: %v", err)
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
									Name:       qname,
									RRtype:     qtype,
									Rcode:      uint8(rcode),
									RRset:      nil,
									Context:    ContextNXDOMAIN,
									Expiration: time.Now().Add(time.Duration(15*60) * time.Second),
								})
								return nil, rcode, context, nil

							default:
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

				// 2. Collect the NS RRset from Authority section (if qname=NS then from Answer section)
				nsMap := map[string]bool{}
				zonename := ""
				var nsrrs []dns.RR
				switch qtype {
				case dns.TypeNS:
					nsrrs = r.Answer
				default:
					nsrrs = r.Ns
				}

				for _, rr := range nsrrs {
					switch rr.(type) {
					case *dns.NS:
						nsMap[rr.(*dns.NS).Ns] = true
						zonename = rr.Header().Name
					}
				}

				// 3. Collect the glue from Additional section
				serverMap, err := rrcache.ParseAdditionalForNSAddrs("authority", &rrset, zonename, nsMap, r)
				if err != nil {
					log.Printf("*** IterativeDNSQuery: Error from CollectNSAddressesFromAdditional: %v", err)
					return nil, rcode, ContextFailure, err
				}

				switch {
				case len(serverMap) == 0:
					// we have no servers to try
					return nil, rcode, ContextReferral, nil
				default:
					tmprrset, rcode, context, err := rrcache.IterativeDNSQuery(qname, qtype, serverMap, false)
					if err != nil {
						return nil, rcode, context, err
					}
					return tmprrset, rcode, context, nil
				}

			case len(r.Ns) != 0:
				// This is likely either a negative response or a referral
				lg.Printf("*** IterativeDNSQuery: there is stuff in Authority section")
				switch rcode {
				case dns.RcodeSuccess:
					// this is either a referral or a negative response
					var rrset RRset
					var zonename string

					// 1. Collect the NS RRset from the Authority section
					lg.Printf("*** IterativeDNSQuery: rcode=NOERROR, this is a referral or neg resp")
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
								log.Printf("*** IterativeDNSQuery: found SOA in Auth, it was a neg resp:\n%s", rr.String())
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
								log.Printf("*** should never get here ***")
							}
						default:
						}
					}

					// Now we know that this is a referral; ensure we collect all the NS addresses
					err := rrcache.CollectNSAddresses(&rrset, nil) // nil respch, we don't need the results here
					if err != nil {
						log.Printf("*** IterativeDNSQuery: Error from CollectNSAddresses: %v", err)
						return nil, rcode, ContextFailure, err
					}

					if len(rrset.RRs) != 0 {
						zonename = rrset.RRs[0].Header().Name
						rrset.Name = zonename
						rrset.Class = dns.ClassINET
						rrset.RRtype = dns.TypeNS
						if Globals.Debug {
							fmt.Printf("IterativeDNSQuery: Calling rrcache.Set for <%s, NS>\n", zonename)
						}
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
					serverMap, err := rrcache.ParseAdditionalForNSAddrs("authority", &rrset, zonename, nsMap, r)
					if err != nil {
						log.Printf("*** IterativeDNSQuery: Error from CollectNSAddressesFromAdditional: %v", err)
						return nil, rcode, ContextFailure, err
					}

					switch {
					case len(serverMap) == 0:
						// we have no servers to try
						return nil, rcode, ContextReferral, nil
					default:
						// Convert []string to map[string]*AuthServer
						// tmpServerMap := make(map[string]*AuthServer)
						//for _, addr := range servers {
						//	tmpServerMap[addr] = &AuthServer{
						//		Name:  addr,
						//		Addrs: []string{addr},
						//		Alpn:  []string{"do53"},
						//		Src:   "referral",
						//	}
						//}
						tmprrset, rcode, context, err := rrcache.IterativeDNSQuery(qname, qtype, serverMap, force)
						if err != nil {
							return nil, rcode, context, err
						}
						return tmprrset, rcode, context, nil
					}

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
					log.Printf("*** IterativeDNSQuery: surprising rcode: %s", dns.RcodeToString[rcode])
				}
			default:
				if rcode == dns.RcodeSuccess {
					return &rrset, rcode, ContextFailure, nil // no point in continuing
				}
				continue // go to next server
			}
		}
	}
	return &rrset, rcode, ContextNoErrNoAns, fmt.Errorf("no Answers found from any auth server looking up '%s %s'", qname, dns.TypeToString[qtype])
}

// CollectNSAddresses - given an NS RRset, chase down the A and AAAA records corresponding to each nsname
func (rrcache *RRsetCacheT) CollectNSAddresses(rrset *RRset, respch chan *ImrResponse) error {
	if rrset == nil || len(rrset.RRs) == 0 {
		return fmt.Errorf("rrset is nil or empty")
	}

	for _, rr := range rrset.RRs {
		nsname := rr.(*dns.NS).Ns
		// Query for A records
		go func(nsname string) {
			log.Printf("CollectNSAddresses: querying for %s A records", nsname)
			_, err := rrcache.ImrQuery(nsname, dns.TypeA, dns.ClassINET, respch)
			if err != nil {
				log.Printf("Error querying A for %s: %v", nsname, err)
			}
		}(nsname)

		// Query for AAAA records
		go func(nsname string) {
			log.Printf("CollectNSAddresses: querying for %s AAAA records", nsname)
			_, err := rrcache.ImrQuery(nsname, dns.TypeAAAA, dns.ClassINET, respch)
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
	for _, rr := range r.Extra {
		name := rr.Header().Name
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

		switch rr.(type) {
		case *dns.A:
			addr := rr.(*dns.A).A.String()
			// servers = append(servers, net.JoinHostPort(addr, "53"))
			if !slices.Contains(serverMap[name].Addrs, addr) {
				serverMap[name].Addrs = append(serverMap[name].Addrs, addr)
			}
			tmp := glue4Map[name]
			tmp.RRs = append(tmp.RRs, rr)
			glue4Map[name] = tmp

		case *dns.AAAA:
			addr := rr.(*dns.AAAA).AAAA.String()
			// servers = append(servers, net.JoinHostPort(addr, "53"))
			if !slices.Contains(serverMap[name].Addrs, addr) {
				serverMap[name].Addrs = append(serverMap[name].Addrs, addr)
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
						// Keep the server's ALPN order
						serverMap[name].Alpn = alpn.Alpn

						// Convert ALPN strings to Transport values in the same order
						var transports []Transport
						for _, t := range alpn.Alpn {
							if transport, err := StringToTransport(t); err == nil {
								transports = append(transports, transport)
							}
						}
						serverMap[name].Transports = transports

						// Set the first transport as preferred (server's preference)
						if len(transports) > 0 {
							serverMap[name].PrefTransport = transports[0]
						}

						log.Printf("Found ALPN values for %s: %v (preferred: %s)",
							name, alpn.Alpn, TransportToString[serverMap[name].PrefTransport])
					}
				}
			}
		default:
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

	log.Printf("*** CollectNSAddrsFromAdditional: adding %d servers for zone %q to cache", len(serverMap), zonename)
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
