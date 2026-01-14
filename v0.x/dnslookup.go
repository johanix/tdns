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

	edns0 "github.com/johanix/tdns/v0.x/edns0"
	// "github.com/johanix/tdns/v0.x/transport"
	cache "github.com/johanix/tdns/v0.x/cache"
	core "github.com/johanix/tdns/v0.x/core"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
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

	zd.Logger.Printf("LookupRRset: rrset:\n%s", rrset.String(130))

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
								// seems that we have found the answer; cache it and return
								imr.Cache.Set(qname, qtype, &cache.CachedRRset{
									Name:       qname,
									RRtype:     qtype,
									Rcode:      uint8(rcode),
									RRset:      &rrset,
									Context:    cache.ContextAnswer,
									Expiration: time.Now().Add(cache.GetMinTTL(rrset.RRs)),
								})
								return &rrset, rcode, cache.ContextAnswer, nil
							}

						case rcode == dns.RcodeNameError:
							// This is a negative response, and <target, qtype> has already been cached
							// now we only need to cache <qname, qtype>
							imr.Cache.Set(qname, qtype, &cache.CachedRRset{
								Name:    qname,
								RRtype:  qtype,
								RRset:   nil,
								Context: cache.ContextNXDOMAIN,
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
				Expiration: time.Now().Add(cache.GetMinTTL(rrset.RRs)),
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
						if strings.HasSuffix(qname, rr.Header().Name) {
							// Yes, this SOA may auth a negative response for qname
							log.Printf("*** AuthDNSQ: found SOA in Auth, it was a neg resp")
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
								Expiration: time.Now().Add(time.Duration(rr.Header().Ttl) * time.Second),
							})
							return nil, rcode, cache.ContextNoErrNoAns, nil
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
					imr.Cache.Set(zonename, dns.TypeNS, &cache.CachedRRset{
						Name:       zonename,
						RRtype:     dns.TypeNS,
						Rcode:      uint8(rcode),
						RRset:      &rrset,
						Context:    cache.ContextReferral,
						State:      cache.ValidationStateIndeterminate,
						Expiration: time.Now().Add(cache.GetMinTTL(rrset.RRs)),
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
						log.Printf("*** AuthDNSQuery: non-glue record in Additional: %q", rr.String())
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
						serverMap[name] = server
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
						serverMap[name] = server
						tmp := glue6Map[name]
						tmp.RRs = append(tmp.RRs, rr)
						glue6Map[name] = tmp

					case *dns.SVCB:
						log.Printf("Additional contains an SVCB, here we should collect the ALPN")
						svcb := rr
						// Ensure we have a shared AuthServer instance for this NS
						server := imr.Cache.GetOrCreateAuthServer(name)
						serverMap[name] = server
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
										log.Printf("Found ALPN values for %s: %v", name, alpn.Alpn)
									}
								}
							}
						}
					default:
					}
				}

				log.Printf("*** AuthDNSQuery: adding %d servers for zone %q to cache", len(servers), zonename)
				imr.Cache.Servers.Set(zonename, servers)

				for nsname, rrset := range glue4Map {
					if len(rrset.RRs) == 0 {
						continue
					}
					rr := rrset.RRs[0]
					imr.Cache.Set(nsname, dns.TypeA, &cache.CachedRRset{
						Name:       nsname,
						RRtype:     dns.TypeA,
						RRset:      &rrset,
						Context:    cache.ContextGlue,
						State:      cache.ValidationStateIndeterminate,
						Expiration: time.Now().Add(time.Duration(rr.Header().Ttl) * time.Second),
					})
				}

				for nsname, rrset := range glue6Map {
					if len(rrset.RRs) == 0 {
						continue
					}
					rr := rrset.RRs[0]
					imr.Cache.Set(nsname, dns.TypeAAAA, &cache.CachedRRset{
						Name:       nsname,
						RRtype:     dns.TypeAAAA,
						RRset:      &rrset,
						Context:    cache.ContextGlue,
						State:      cache.ValidationStateIndeterminate,
						Expiration: time.Now().Add(time.Duration(rr.Header().Ttl) * time.Second),
					})
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
					RRset:      nil,
					Context:    cache.ContextNXDOMAIN,
					Expiration: time.Now().Add(time.Duration(ttl) * time.Second),
				})

				return nil, rcode, cache.ContextNXDOMAIN, nil
			default:
				log.Printf("*** AuthDNSQuery: surprising rcode: %s", dns.RcodeToString[rcode])
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

// ServerAddrTuple represents a (server, address) pair for prioritization
type ServerAddrTuple struct {
	Server *cache.AuthServer
	Addr   string
	NSName string
}

// prioritizeServers returns a prioritized list of (server, addr) tuples.
// It filters out addresses that are in backoff (either zone-specific or server-wide).
// Future: This function can be extended to prioritize by RTT or other metrics.
func (imr *Imr) prioritizeServers(qname string, serverMap map[string]*cache.AuthServer) (string, *cache.Zone, []ServerAddrTuple) {
	// Find the zone for this qname to check zone-specific backoffs
	zoneName, _, _ := imr.Cache.FindClosestKnownZone(qname)
	var zone *cache.Zone
	if zoneName != "" {
		if z, ok := imr.Cache.ZoneMap.Get(zoneName); ok {
			zone = z
		}
	}

	var tuples []ServerAddrTuple
	// now := time.Now()

	for nsname, server := range serverMap {
		// Get available addresses for this server (checks server-wide backoffs)
		availableAddrs := server.GetAvailableAddresses()

		for _, addr := range availableAddrs {
			// Check zone-specific backoff if zone exists
			if zone != nil && !zone.IsZoneAddressAvailable(addr) {
				if Globals.Debug {
					log.Printf("prioritizeServers: skipping %s@%s due to zone-specific backoff for zone %q", addr, nsname, zoneName)
				}
				continue
			}

			tuples = append(tuples, ServerAddrTuple{
				Server: server,
				Addr:   addr,
				NSName: nsname,
			})
		}
	}

	// Future: Sort by RTT or other metrics here
	// For now, we keep the order as-is (which is essentially random map iteration order)

	return zoneName, zone, tuples
}

// force is true if we should force a lookup even if the answer is in the cache
// visitedZones tracks which zones we've been referred to for this qname to prevent referral loops
func (imr *Imr) IterativeDNSQuery(ctx context.Context, qname string, qtype uint16, serverMap map[string]*cache.AuthServer, force bool) (*core.RRset, int, cache.CacheContext, error) {
	return imr.IterativeDNSQueryWithLoopDetection(ctx, qname, qtype, serverMap, force, make(map[string]bool))
}

// IterativeDNSQueryWithLoopDetection is the internal implementation with loop detection
// visitedZones tracks which zones we've been referred to for this qname (format: "qname:zone")
func (imr *Imr) IterativeDNSQueryWithLoopDetection(ctx context.Context, qname string, qtype uint16, serverMap map[string]*cache.AuthServer, force bool, visitedZones map[string]bool) (*core.RRset, int, cache.CacheContext, error) {
	lg := imr.Cache.Logger

	if Globals.Debug {
		lg.Printf("IterativeDNSQuery: looking up <%s, %s> using %d servers", qname, dns.TypeToString[qtype], len(serverMap))
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
				if Globals.Debug {
					lg.Printf("IterativeDNSQuery: found answer to <%s, %s> in cache (result=%s)", qname, dns.TypeToString[qtype], cache.CacheContextToString[crrset.Context])
				}
				return crrset.RRset, int(crrset.Rcode), crrset.Context, nil
			case cache.ContextReferral, cache.ContextGlue, cache.ContextHint, cache.ContextPriming, cache.ContextFailure:
				// These are indirect - issue a direct query to upgrade quality and get DNSSEC signatures
				if Globals.Debug {
					lg.Printf("IterativeDNSQuery: found <%s, %s> in cache with context=%s, but issuing direct query to upgrade quality and get DNSSEC signatures", qname, dns.TypeToString[qtype], cache.CacheContextToString[crrset.Context])
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
	var rrset core.RRset
	var rcode int

	m, err := buildQuery(qname, qtype)
	if err != nil {
		lg.Printf("IterativeDNSQuery: Error building query: %v", err)
		return nil, 0, cache.ContextFailure, err
	}
	// if Globals.Debug { fmt.Printf("IterativeDNSQuery: message after AddOTSToMessage: %s", m.String()) }

	// Prioritize servers and addresses (filters out backoff addresses)
	zoneName, zone, prioritized := imr.prioritizeServers(qname, serverMap)
	if Globals.Debug {
		lg.Printf("IterativeDNSQuery: prioritized %d server-address tuples (from %d servers)", len(prioritized), len(serverMap))
	}

	// Iterate over prioritized server-address tuples
	for _, tuple := range prioritized {
		select {
		case <-ctx.Done():
			return nil, 0, cache.ContextFailure, ctx.Err()
		default:
		}
		server := tuple.Server
		addr := tuple.Addr
		nsname := tuple.NSName

		if Globals.Debug {
			lg.Printf("IterativeDNSQuery: using nameserver %s@%s (ALPN: %v) for <%s, %s> query\n",
				addr, nsname, server.Alpn, qname, dns.TypeToString[qtype])
		}

		r, _, err := imr.tryServer(ctx, server, addr, m, qname, qtype)
		if err != nil && imr.Cache.Verbose {
			// lg.Printf("IterativeDNSQuery: Error from dns.Exchange: %v (rtt: %v)", err, rtt)
			continue // go to next server
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
		rcode = r.MsgHdr.Rcode

		// Check for REFUSED/NOTAUTH/NOTIMP/SERVFAIL responses (lame delegations) and record as zone-specific failure
		switch rcode {
		case dns.RcodeRefused, dns.RcodeNotAuth, dns.RcodeServerFailure, dns.RcodeNotImplemented:
			if Globals.Debug {
				lg.Printf("IterativeDNSQuery: %s response from %s@%s for %s %s (likely lame delegation for zone %q)",
					dns.RcodeToString[rcode], addr, nsname, qname, dns.TypeToString[qtype], zoneName)
			}
			// Record zone-specific failure (not server-wide, as server might work for other zones)
			if zone != nil {
				zone.RecordZoneAddressFailureForRcode(addr, uint8(rcode), Globals.Debug)
			} else {
				// If zone not found, fall back to server-wide backoff
				server.RecordAddressFailureForRcode(addr, uint8(rcode))
			}
			continue // Try next server
		case dns.RcodeSuccess:
			// Successful response - clear any zone-specific backoff for this address
			// (server-wide backoff already cleared by tryServer)
			if zone != nil {
				zone.RecordZoneAddressSuccess(addr)
			}
		default:
			// Other rcodes (NXDOMAIN, etc.) - server responded successfully, clear zone-specific backoff
			// (server-wide backoff already cleared by tryServer)
			if zone != nil {
				zone.RecordZoneAddressSuccess(addr)
			}
		}

		if len(r.Answer) != 0 {
			// Parse any transport signal for this specific server even on final answers
			// Note: server is a shared instance across all zones, so modifications are automatically visible everywhere
			imr.parseTransportForServerFromAdditional(ctx, server, r)
			tmprrset, rcode2, ctx2, err, done := imr.handleAnswer(ctx, qname, qtype, r, force)
			if err != nil || done {
				return tmprrset, rcode2, ctx2, err
			}
			// If not done, fall-through to process referral glue embedded with answers
			nsRRs, zonename, nsMap := extractReferral(r, qname, qtype)
			if len(nsRRs.RRs) > 0 {
				serverMap, err := imr.ParseAdditionalForNSAddrs(ctx, "authority", nsRRs, zonename, nsMap, r)
				if err != nil {
					log.Printf("*** IterativeDNSQuery: Error from CollectNSAddressesFromAdditional: %v", err)
					return nil, rcode, cache.ContextFailure, err
				}
				if len(serverMap) == 0 {
					return nil, rcode, cache.ContextReferral, nil
				}
				return imr.IterativeDNSQueryWithLoopDetection(ctx, qname, qtype, serverMap, force, visitedZones)
			}
			continue
		}

		if len(r.Ns) != 0 {
			kind := classifyResponse(qname, qtype, r)
			if Globals.Debug {
				log.Printf("IterativeDNSQuery: classified response for %s %s as %s (rcode=%s, Answer=%d, Authority=%d)",
					qname, dns.TypeToString[qtype], responseKindToString(kind), dns.RcodeToString[rcode], len(r.Answer), len(r.Ns))
			}

			switch kind {
			case responseKindNegativeNoData, responseKindNegativeNXDOMAIN:
				if ctxNeg, rcodeNeg, handled := imr.handleNegative(qname, qtype, r); handled {
					return nil, rcodeNeg, ctxNeg, nil
				}
				// If not handled, fall through to try next server
				if rcode == dns.RcodeNameError {
					log.Printf("*** IterativeDNSQuery: NXDOMAIN response lacked usable SOA for %s %s", qname, dns.TypeToString[qtype])
				}
				continue
			case responseKindReferral:
				return imr.handleReferral(ctx, qname, qtype, r, force, visitedZones)
			case responseKindError:
				log.Printf("*** IterativeDNSQuery: treating response as error for %s %s (rcode=%s)",
					qname, dns.TypeToString[qtype], dns.RcodeToString[rcode])
				continue
			case responseKindUnknown:
				if Globals.Debug {
					log.Printf("IterativeDNSQuery: responseKindUnknown for %s %s; trying next server",
						qname, dns.TypeToString[qtype])
				}
				continue
			default:
				// Should not reach here, but be defensive
				log.Printf("*** IterativeDNSQuery: unexpected response kind %d for %s %s; trying next server",
					kind, qname, dns.TypeToString[qtype])
				continue
			}
		}

		if rcode == dns.RcodeSuccess {
			return &rrset, rcode, cache.ContextFailure, nil // no point in continuing
		}
		continue
	}
	return &rrset, rcode, cache.ContextNoErrNoAns, fmt.Errorf("IterativeDNSQuery: no Answers found from any auth server looking up '%s %s'", qname, dns.TypeToString[qtype])
}

// CollectNSAddresses - given an NS RRset, chase down the A and AAAA records corresponding to each nsname
func (imr *Imr) CollectNSAddresses(ctx context.Context, rrset *core.RRset, respch chan *ImrResponse) error {
	if rrset == nil || len(rrset.RRs) == 0 {
		return fmt.Errorf("rrset is nil or empty")
	}

	// Defensive check: ensure this is actually an NS RRset
	if rrset.RRtype != dns.TypeNS {
		return fmt.Errorf("CollectNSAddresses: expected NS RRset, got %s", dns.TypeToString[rrset.RRtype])
	}

	for _, rr := range rrset.RRs {
		// Defensive check: ensure each RR is actually an NS record
		ns, ok := rr.(*dns.NS)
		if !ok {
			// return fmt.Errorf("CollectNSAddresses: expected NS record, got %s", dns.TypeToString[rr.Header().Rrtype])
			continue
		}
		nsname := ns.Ns
		// Query for A records
		go func(nsname string) {
			// log.Printf("CollectNSAddresses: querying for %s A records", nsname)
			_, err := imr.ImrQuery(ctx, nsname, dns.TypeA, dns.ClassINET, respch)
			if err != nil {
				log.Printf("CollectNSAddresses: Error querying A for %s: %v", nsname, err)
			}
		}(nsname)

		// Query for AAAA records
		go func(nsname string) {
			// log.Printf("CollectNSAddresses: querying for %s AAAA records", nsname)
			_, err := imr.ImrQuery(ctx, nsname, dns.TypeAAAA, dns.ClassINET, respch)
			if err != nil {
				log.Printf("CollectNSAddresses: Error querying AAAA for %s: %v", nsname, err)
			}
		}(nsname)
	}
	return nil
}

// parseOwnerName extracts the base server name from an owner name, handling both
// direct nameserver names and OTS transport signal owners (_dns.{nsname}).
// Returns: baseName, isOTSOwner, originalOwner
func parseOwnerName(owner string) (baseName string, isOTSOwner bool, originalOwner string) {
	originalOwner = owner
	if strings.HasPrefix(owner, "_dns.") {
		isOTSOwner = true
		baseName = strings.TrimPrefix(owner, "_dns.")
	} else {
		baseName = owner
	}
	return baseName, isOTSOwner, originalOwner
}

// parseSVCBTransportSignal extracts and applies transport signals from an SVCB record.
// Returns true if a transport signal was successfully applied.
func (imr *Imr) parseSVCBTransportSignal(rr *dns.SVCB, serverName string, serverMap map[string]*cache.AuthServer, ctx context.Context) bool {
	if rr == nil {
		return false
	}
	server, ok := serverMap[serverName]
	if !ok {
		return false
	}

	haveLocal := false
	for _, kv := range rr.Value {
		if local, ok := kv.(*dns.SVCBLocal); ok && local.KeyCode == dns.SVCBKey(SvcbTransportKey) {
			if !imr.Quiet {
				log.Printf("SVCB transport key for %s: %q", serverName, string(local.Data))
			}
			if imr.applyTransportSignalToServer(server, string(local.Data)) {
				server.PromoteConnMode(cache.ConnModeOpportunistic)
			}
			if owner := transportOwnerForNS(serverName); owner != "" {
				imr.maybeQueryTransportSignal(ctx, owner, transportQueryReasonObservation)
			}
			imr.maybeQueryTLSA(ctx, serverName)
			haveLocal = true
			break
		}
	}
	if !haveLocal {
		for _, kv := range rr.Value {
			if a, ok := kv.(*dns.SVCBAlpn); ok && len(a.Alpn) > 0 {
				if !imr.Quiet {
					log.Printf("SVCB ALPN for %s: %v", serverName, a.Alpn)
				}
				applyAlpnSignal(serverName, strings.Join(a.Alpn, ","), serverMap)
				return true
			}
		}
	}
	return haveLocal
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
	server, ok := serverMap[serverName]
	if !ok {
		return false
	}

	val := strings.TrimPrefix(ts.Transports, "transport=")
	if !imr.Quiet {
		log.Printf("TSYNC transport value for %s: %q", serverName, val)
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

func (imr *Imr) ParseAdditionalForNSAddrs(ctx context.Context, src string, nsrrset *core.RRset, zonename string,
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
			log.Printf("ParseAdditionalForNSAddrs: empty zonename; skipping glue collection")
		}
		return map[string]*cache.AuthServer{}, nil
	}

	if Globals.Debug && !imr.Quiet {
		log.Printf("*** ParseAdditionalForNSAddrs: zonename: %q\nnsMap: %+v", zonename, nsMap)
	}

	// Collect any glue from Additional
	glue4Map := map[string]core.RRset{}
	glue6Map := map[string]core.RRset{}
	serverMapOrig, exist := imr.Cache.ServerMap.Get(zonename)

	// Create a copy of the map to avoid concurrent map read/write errors
	// The original map is stored in a concurrent map and may be read by other goroutines
	serverMap := make(map[string]*cache.AuthServer)
	if exist {
		for k, v := range serverMapOrig {
			serverMap[k] = v
		}
	}

	// Prune expired auth servers for this zone before updating
	now := time.Now()
	for name, srv := range serverMap {
		if !srv.Expire.IsZero() && srv.Expire.Before(now) {
			delete(serverMap, name)
			if Globals.Debug && !imr.Quiet {
				log.Printf("ParseAdditionalForNSAddrs: pruned expired server %s for zone %s", name, zonename)
			}
		}
	}

	// Single pass through Additional section: handle glue records and transport signals
	for _, rr := range r.Extra {
		if strings.HasSuffix(rr.Header().Name, "p.axfr.net.") {
			if !imr.Quiet {
				log.Printf("ParseAdditionalForNSAddrs: processing rr: %s", rr.String())
			}
		}

		owner := rr.Header().Name
		baseName, isOTSOwner, _ := parseOwnerName(owner)

		// Determine which server name to use and whether to process this record
		var serverName string
		var isGlueRecord bool
		var shouldProcessTransportSignal bool

		switch rr.(type) {
		case *dns.A, *dns.AAAA:
			// Glue records must match an NS name directly (not _dns.*)
			if !isOTSOwner {
				if _, exist := nsMap[baseName]; exist {
					serverName = baseName
					isGlueRecord = true
				} else {
					if !imr.Quiet {
						log.Printf("*** IterativeDNSQuery: non-glue record in Additional: %q", rr.String())
					}
					continue
				}
			} else {
				// A/AAAA with _dns. prefix is not glue, skip
				continue
			}
		case *dns.SVCB, *dns.PrivateRR:
			// Transport signals: process if:
			// 1. First pass equivalent: isOTSOwner AND baseName in nsMap (will create server entry)
			// 2. Second pass equivalent: isOTSOwner AND baseName in serverMap (server already exists)
			if isOTSOwner {
				_, inNsMap := nsMap[baseName]
				_, inServerMap := serverMap[baseName]
				if inNsMap || inServerMap {
					serverName = baseName
					shouldProcessTransportSignal = true
				} else {
					// OTS owner but server not in nsMap or serverMap, skip
					continue
				}
			} else {
				// Not OTS owner, skip transport signals (they should be _dns.*)
				if !imr.Quiet {
					log.Printf("*** IterativeDNSQuery: non-glue record in Additional: %q", rr.String())
				}
				continue
			}
		default:
			// Unknown record type, skip
			continue
		}

		// Create server entry if it doesn't exist (for glue records or transport signals with nsMap match)
		_, exist := serverMap[serverName]
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
			serverMap[serverName] = imr.Cache.GetOrCreateAuthServer(serverName)
			// Update fields for this specific context
			serverMap[serverName].SetSrc(serversrc)
			if imr.Debug {
				serverMap[serverName].PromoteDebug()
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
			addr := rr.A.String()
			if !slices.Contains(serverMap[serverName].Addrs, addr) {
				serverMap[serverName].Addrs = append(serverMap[serverName].Addrs, addr)
			}
			// set expiry for this server mapping from glue TTL
			serverMap[serverName].Expire = time.Now().Add(time.Duration(rr.Header().Ttl) * time.Second)
			tmp := glue4Map[serverName]
			tmp.RRs = append(tmp.RRs, rr)
			glue4Map[serverName] = tmp

		case *dns.AAAA:
			addr := rr.AAAA.String()
			if !slices.Contains(serverMap[serverName].Addrs, addr) {
				serverMap[serverName].Addrs = append(serverMap[serverName].Addrs, addr)
			}
			// set expiry for this server mapping from glue TTL
			serverMap[serverName].Expire = time.Now().Add(time.Duration(rr.Header().Ttl) * time.Second)
			tmp := glue6Map[serverName]
			tmp.RRs = append(tmp.RRs, rr)
			glue6Map[serverName] = tmp

		case *dns.SVCB:
			if shouldProcessTransportSignal {
				if !imr.Quiet {
					log.Printf("Additional contains an SVCB; rr: %s", rr.String())
				}
				imr.parseSVCBTransportSignal(rr, serverName, serverMap, ctx)
			}

		case *dns.PrivateRR:
			if shouldProcessTransportSignal {
				if !imr.Quiet {
					log.Printf("Additional contains TSYNC; rr: %s", rr.String())
				}
				imr.parseTSYNCTransportSignal(rr, serverName, serverMap, ctx)
			}
		}
	}

	for nsname, rrset := range glue4Map {
		if len(rrset.RRs) == 0 {
			continue
		}
		rr := rrset.RRs[0]
		if Globals.Debug && !imr.Quiet {
			fmt.Printf("ParseAdditionalForNSAddrs: Calling rrcache.Set for <%s, A> (adding glue)\n", nsname)
		}
		imr.Cache.Set(nsname, dns.TypeA, &cache.CachedRRset{
			Name:       nsname,
			RRtype:     dns.TypeA,
			RRset:      &rrset,
			Context:    cache.ContextGlue,
			State:      cache.ValidationStateIndeterminate,
			Expiration: time.Now().Add(time.Duration(rr.Header().Ttl) * time.Second),
		})
	}

	for nsname, rrset := range glue6Map {
		if len(rrset.RRs) == 0 {
			continue
		}
		rr := rrset.RRs[0]
		if Globals.Debug && !imr.Quiet {
			fmt.Printf("ParseAdditionalForNSAddrs: Calling rrcache.Set for <%s, AAAA> (adding glue)\n", nsname)
		}
		imr.Cache.Set(nsname, dns.TypeAAAA, &cache.CachedRRset{
			Name:       nsname,
			RRtype:     dns.TypeAAAA,
			RRset:      &rrset,
			Context:    cache.ContextGlue,
			State:      cache.ValidationStateIndeterminate,
			Expiration: time.Now().Add(time.Duration(rr.Header().Ttl) * time.Second),
		})
	}

	if Globals.Debug && !imr.Quiet {
		log.Printf("*** ParseAdditionalForNSAddrs: adding %d servers for zone %q to cache", len(serverMap), zonename)
	}
	// rrcache.Servers.Set(zonename, servers)
	imr.Cache.AddServers(zonename, serverMap)

	if Globals.Debug && !imr.Quiet {
		log.Printf("ParseAdditionalForNSAddrs: serverMap:")
		for n, as := range serverMap {
			log.Printf("server: %s: %s (addrs: %v)", n, as.Name, as.Addrs)
		}
	}

	return serverMap, nil
}

// parseTransportString parses strings like "doq:30,dot:20" into a map[string]uint8
// parseTransportString removed; use transport.ParseTransportString

// pickTransport chooses a transport based on configured weights, falling back sensibly
func pickTransport(server *cache.AuthServer, qname string) core.Transport {
	if server == nil {
		return core.TransportDo53
	}
	if len(server.TransportWeights) == 0 {
		if server.PrefTransport != 0 {
			return server.PrefTransport
		}
		if len(server.Transports) > 0 {
			return server.Transports[0]
		}
		return core.TransportDo53
	}
	// Build weighted list honoring server.Transports order
	var total int
	type pair struct {
		t core.Transport
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
		candidates = append(candidates, pair{t: core.TransportDo53, w: 100 - total})
		total = 100
	}
	if total == 0 {
		if server.PrefTransport != 0 {
			return server.PrefTransport
		}
		if len(server.Transports) > 0 {
			return server.Transports[0]
		}
		return core.TransportDo53
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
func buildQuery(qname string, qtype uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(qname, qtype)
	m.SetEdns0(4096, true)
	if err := edns0.AddOTSToMessage(m, edns0.OTS_OPT_IN); err != nil {
		return nil, err
	}
	return m, nil
}

func (imr *Imr) tryServer(ctx context.Context, server *cache.AuthServer, addr string, m *dns.Msg, qname string, qtype uint16) (*dns.Msg, time.Duration, error) {
	select {
	case <-ctx.Done():
		return nil, 0, ctx.Err()
	default:
	}

	t := pickTransport(server, qname)
	c, exist := imr.Cache.DNSClient[t]
	if !exist {
		return nil, 0, fmt.Errorf("no DNS client for transport %d exists", t)
	}
	server.IncrementTransportCounter(t)
	if Globals.Debug {
		log.Printf("*** tryServer: calling c.Exchange with Transport=%q, server=%s (addrs: %v), addr=%q, qname=%q, qtype=%q",
			core.TransportToString[t], server.Name, server.Addrs, addr, qname, dns.TypeToString[qtype])
	}
	// return c.Exchange(m, addr)
	r, _, err := c.Exchange(m, addr, Globals.Debug && !imr.Quiet)
	if err != nil {
		log.Printf("*** tryServer: query \"%s %s\" sent to %s returned error: %v", qname, dns.TypeToString[qtype], addr, err)
		server.RecordAddressFailure(addr, err)
		return nil, 0, err
	}
	if r != nil {
		server.RecordAddressSuccess(addr)
	}
	if Globals.Debug {
		if r == nil {
			log.Printf("*** tryServer: query \"%s %s\" sent to %s returned no response", qname, dns.TypeToString[qtype], addr)
		}
	}
	return r, 0, err
}

// applyTransportSignalToServer parses a colon-separated transport string and applies it to the given server.
// Returns true if at least one transport entry was applied.
func (imr *Imr) applyTransportSignalToServer(server *cache.AuthServer, s string) bool {
	if server == nil || s == "" {
		return false
	}
	kvMap, err := core.ParseTransportString(s)
	if err != nil {
		log.Printf("applyTransportSignalToServer: invalid transport string for %s: %q: %v", server.Name, s, err)
		return false
	}
	type pair struct {
		k string
		w uint8
	}
	var pairs []pair
	weights := map[core.Transport]uint8{}
	for k, v := range kvMap {
		t, err := core.StringToTransport(k)
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
	var transports []core.Transport
	var alpnOrder []string
	for _, p := range pairs {
		t, err := core.StringToTransport(p.k)
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
func applyAlpnSignal(owner string, alpnCSV string, serverMap map[string]*cache.AuthServer) {
	if owner == "" || serverMap == nil {
		return
	}
	server, ok := serverMap[owner]
	if !ok {
		return
	}
	weights := map[core.Transport]uint8{}
	var order []string
	tokens := strings.Split(alpnCSV, ",")
	for _, tok := range tokens {
		k := strings.TrimSpace(tok)
		if k == "" {
			continue
		}
		t, err := core.StringToTransport(k)
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
		if t, err := core.StringToTransport(k); err == nil {
			server.Transports = append(server.Transports, t)
		}
	}
	if len(server.Transports) > 0 {
		server.PrefTransport = server.Transports[0]
	}
	serverMap[owner] = server
}

// applyAlpnSignalToServer applies 100-weight transports from a comma-separated ALPN list to a specific server pointer
func applyAlpnSignalToServer(server *cache.AuthServer, alpnCSV string) {
	if server == nil {
		return
	}

	weights := map[core.Transport]uint8{}
	var order []string
	tokens := strings.Split(alpnCSV, ",")
	for _, tok := range tokens {
		k := strings.TrimSpace(tok)
		if k == "" {
			continue
		}
		t, err := core.StringToTransport(k)
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
		if t, err := core.StringToTransport(k); err == nil {
			server.Transports = append(server.Transports, t)
		}
	}
	if len(server.Transports) > 0 {
		server.PrefTransport = server.Transports[0]
	}
}

// parseTransportForServerFromAdditional looks for a transport signal for the specific server in the Additional section
func (imr *Imr) parseTransportForServerFromAdditional(ctx context.Context, server *cache.AuthServer, r *dns.Msg) {
	if imr.Options[ImrOptUseTransportSignals] != "true" {
		return
	}
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
					if imr.applyTransportSignalToServer(server, string(local.Data)) {
						server.PromoteConnMode(cache.ConnModeOpportunistic)
					}
					if owner := transportOwnerForNS(server.Name); owner != "" {
						imr.maybeQueryTransportSignal(ctx, owner, transportQueryReasonObservation)
					}
					imr.maybeQueryTLSA(ctx, server.Name)
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
			if ts, ok := x.Data.(*core.TSYNC); ok && ts != nil {
				if Globals.Verbose {
					log.Printf("**** parseTransportForServerFromAdditional: TSYNC data: %+v", ts)
					log.Printf("**** parseTransportForServerFromAdditional: TSYNC transports: \"%s\"", ts.Transports)
				}
				if ts.Transports != "" {
					val := strings.TrimPrefix(ts.Transports, "transport=")
					if Globals.Verbose {
						log.Printf("**** parseTransportForServerFromAdditional: parsing TSYNC transport value: %s", val)
					}
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
}

func (imr *Imr) applyTransportRRsetFromAnswer(qname string, rrset *core.RRset, vstate cache.ValidationState) {
	if imr.Cache == nil || rrset == nil || len(rrset.RRs) == 0 {
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
	targetMode := cache.ConnModeOpportunistic
	if vstate == cache.ValidationStateSecure {
		targetMode = cache.ConnModeValidated
	}
	for zone, sm := range imr.Cache.ServerMap.Items() {
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
						if imr.applyTransportSignalToServer(server, string(local.Data)) {
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
							imr.Cache.StoreTLSAForServer(base, ownerName, &core.RRset{
								Name:   ownerName,
								Class:  dns.ClassINET,
								RRtype: dns.TypeTLSA,
								RRs:    []dns.RR{tlsa},
							}, vstate)
						}
					}
				}
			}
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
			server.PromoteConnMode(targetMode)
			imr.Cache.ServerMap.Set(zone, sm)
		}
	}
}

func (imr *Imr) handleAnswer(ctx context.Context, qname string, qtype uint16, r *dns.Msg, force bool) (*core.RRset, int, cache.CacheContext, error, bool) {
	if r == nil {
		if Globals.Debug {
			imr.Cache.Logger.Printf("*** handleAnswer: nil response for qname=%s, qtype=%s", qname, dns.TypeToString[qtype])
		}
		return nil, dns.RcodeServerFailure, cache.ContextFailure, fmt.Errorf("nil response in handleAnswer"), false
	}

	if Globals.Debug {
		imr.Cache.Logger.Printf("*** handleAnswer: qname=%s, qtype=%s, rcode=%s, r: %s", qname, dns.TypeToString[qtype], dns.RcodeToString[r.MsgHdr.Rcode], PrintMsgFull(r, imr.LineWidth))
	}
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
			tmprrset, rcode, context, err := imr.chaseCNAME(ctx, target, qtype, force)
			if err != nil {
				return nil, rcode, context, err, true
			}
			if tmprrset != nil && len(tmprrset.RRs) != 0 {
				rrset.RRs = append(rrset.RRs, tmprrset.RRs...)
				if tmprrset.RRs[0].Header().Rrtype != dns.TypeCNAME {
					imr.Cache.Set(qname, qtype, &cache.CachedRRset{
						Name:    qname,
						RRtype:  qtype,
						Rcode:   uint8(rcode),
						RRset:   &rrset,
						Context: cache.ContextAnswer,
						// Should there not be some state here? State:      vstate,
						State:      cache.ValidationStateNone, // XXX: propagate state from chaseCNAME?
						Expiration: time.Now().Add(cache.GetMinTTL(rrset.RRs)),
					})
					return &rrset, rcode, cache.ContextAnswer, nil, true
				}
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
		var err error
		if Globals.Debug {
			imr.Cache.Logger.Printf("*** handleAnswer: validating RRset for %s %s:\n%s", qname, dns.TypeToString[qtype], rrset.String(imr.LineWidth))
		}
		vstate, err = imr.Cache.ValidateRRsetWithParentZone(ctx, &rrset, imr.IterativeDNSQueryFetcher(), imr.ParentZone)
		if err != nil {
			log.Printf("handleAnswer: failed to validate RRset: %v", err)
			return nil, r.MsgHdr.Rcode, cache.ContextFailure, err, false
		}
		if Globals.Debug {
			imr.Cache.Logger.Printf("*** handleAnswer: validated RRset for %s %s:\n%s", qname, dns.TypeToString[qtype], rrset.String(imr.LineWidth))
		}
		cr := &cache.CachedRRset{
			Name:       qname,
			RRtype:     qtype,
			Rcode:      uint8(r.MsgHdr.Rcode),
			RRset:      &rrset,
			Context:    cache.ContextAnswer,
			State:      vstate,
			Expiration: time.Now().Add(cache.GetMinTTL(rrset.RRs)),
		}
		imr.Cache.Set(qname, qtype, cr)
		if qtype == dns.TypeSVCB || qtype == core.TypeTSYNC {
			imr.applyTransportRRsetFromAnswer(qname, &rrset, vstate)
		} else if qtype == dns.TypeTLSA {
			base := baseFromTLSAOwner(qname)
			if base != "" {
				imr.Cache.StoreTLSAForServer(base, qname, &rrset, vstate)
			}
		}
		// Note: DNSKEYs are added to DnskeyCache by ValidateDNSKEYs() upon successful validation,
		// so we don't need to add them here. This ensures keys are available immediately for
		// validating subsequent RRsets (e.g., A records signed by ZSKs).
		return &rrset, r.MsgHdr.Rcode, cache.ContextAnswer, nil, true
	}
	return nil, r.MsgHdr.Rcode, cache.ContextFailure, nil, false
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

func (imr *Imr) handleReferral(ctx context.Context, qname string, qtype uint16, r *dns.Msg, force bool, visitedZones map[string]bool) (*core.RRset, int, cache.CacheContext, error) {
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
			return nil, r.MsgHdr.Rcode, cache.ContextFailure, fmt.Errorf("referral loop detected: already referred to zone %q for qname %q", zonename, qname)
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
				log.Printf("handleReferral: failed to validate NS RRset: %v", err)
				return nil, r.MsgHdr.Rcode, cache.ContextFailure, err
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
			Expiration: time.Now().Add(cache.GetMinTTL(nsRRset.RRs)),
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
		vstate := cache.ValidationStateNone
		var err error
		if len(dsSigs) > 0 {
			vstate, err = imr.Cache.ValidateRRsetWithParentZone(ctx, dsRRset, imr.IterativeDNSQueryFetcher(), imr.ParentZone)
			if err != nil {
				log.Printf("handleReferral: failed to validate DS RRset: %v", err)
				return nil, r.MsgHdr.Rcode, cache.ContextFailure, err
			}
		}
		// XXX: ValidateRRset *must* return one of secure or indeterminate. There is
		// a DS, so insecure or none should not be possible.
		imr.Cache.Set(zonename, dns.TypeDS, &cache.CachedRRset{
			Name:       zonename,
			RRtype:     dns.TypeDS,
			Rcode:      uint8(r.MsgHdr.Rcode),
			RRset:      dsRRset,
			Context:    cache.ContextReferral,
			State:      vstate,
			Expiration: time.Now().Add(cache.GetMinTTL(dsRRs)),
		})
		// Update ZoneMap based on DS validation state
		z, ok := imr.Cache.ZoneMap.Get(zonename)
		if !ok {
			z = &cache.Zone{
				ZoneName: zonename,
				State:    cache.ValidationStateIndeterminate,
			}
		}
		switch vstate {
		case cache.ValidationStateSecure, cache.ValidationStateIndeterminate:
			z.SetState(vstate)
		default:
			log.Printf("handleReferral: ERROR (should not happen): invalid DS validation state: %v", vstate)
		}
		imr.Cache.ZoneMap.Set(zonename, z)
	}
	// If we have an NS RRset but no DS record (or DS validation didn't result in secure state),
	// add the zone to ZoneMap. State depends on whether we have trust anchors:
	// - If trust anchors exist and zone is unsigned: ValidationStateInsecure
	// - If no trust anchors: ValidationStateIndeterminate
	if nsRRset != nil && zonename != "" && len(nsRRset.RRs) > 0 {
		_, exists := imr.Cache.ZoneMap.Get(zonename)
		if !exists {
			// Zone not in ZoneMap yet. Check if we have trust anchors to determine state.
			// If no trust anchors configured, state is indeterminate (we can't validate).
			// If trust anchors exist but zone is unsigned, state is insecure.
			state := cache.ValidationStateIndeterminate
			hasTrustAnchors := false
			if imr.Cache.DnskeyCache != nil {
				// Check if there are any trust anchors (DNSKEYs with TrustAnchor=true)
				for _, key := range imr.Cache.DnskeyCache.Map.Keys() {
					if val, ok := imr.Cache.DnskeyCache.Map.Get(key); ok && val.TrustAnchor {
						hasTrustAnchors = true
						break
					}
				}
			}
			if hasTrustAnchors {
				// We have trust anchors, so unsigned zone is insecure
				state = cache.ValidationStateInsecure
			}
			z := &cache.Zone{
				ZoneName: zonename,
				State:    state,
			}
			imr.Cache.ZoneMap.Set(zonename, z)
		}
	}
	serverMap, err := imr.ParseAdditionalForNSAddrs(ctx, "authority", nsRRset, zonename, nsMap, r)
	if err != nil {
		log.Printf("*** handleReferral: Error from CollectNSAddressesFromAdditional: %v", err)
		return nil, r.MsgHdr.Rcode, cache.ContextFailure, err
	}

	// For out-of-bailiwick nameservers, we still need their addresses if they
	// are not already present in cache. In-bailiwick NS should primarily use
	// glue (and, when ImrOptRevalidateNS is enabled, will later be
	// revalidated by scheduleReferralNSRevalidation / revalidateInBailiwickGlue).
	if nsRRset != nil && zonename != "" && len(nsRRset.RRs) > 0 {
		inBailiwick := func(host, zone string) bool {
			h := strings.ToLower(dns.Fqdn(host))
			z := strings.ToLower(dns.Fqdn(zone))
			return h == z || strings.HasSuffix(h, "."+z)
		}

		var oobRRset core.RRset
		// Initialize oobRRset with proper fields from nsRRset
		oobRRset.Name = zonename
		oobRRset.Class = dns.ClassINET
		oobRRset.RRtype = dns.TypeNS
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
			// out-of-bailiwick: only bother if we don't already have addresses cached
			if cA := imr.Cache.Get(ns.Ns, dns.TypeA); cA != nil && cA.RRset != nil && len(cA.RRset.RRs) > 0 {
				continue
			}
			if cAAAA := imr.Cache.Get(ns.Ns, dns.TypeAAAA); cAAAA != nil && cAAAA.RRset != nil && len(cAAAA.RRset.RRs) > 0 {
				continue
			}
			oobRRset.RRs = append(oobRRset.RRs, rr)
		}
		if len(oobRRset.RRs) > 0 {
			if err := imr.CollectNSAddresses(ctx, &oobRRset, nil); err != nil {
				log.Printf("*** handleReferral: Error from CollectNSAddresses (out-of-bailiwick): %v", err)
				// Non-fatal: we can still proceed with whatever glue we have.
			}
		}
	}

	if len(serverMap) == 0 {
		return nil, r.MsgHdr.Rcode, cache.ContextReferral, nil
	}
	// rrcache.Logger.Printf("*** handleReferral: calling revalidateReferralNS for zone %s, serverMap: %+v", zonename, serverMap)
	imr.scheduleReferralNSRevalidation(ctx, zonename, serverMap)
	//rrcache.Logger.Printf("*** handleReferral: revalidateReferralNS returned, calling IterativeDNSQuery for zone %s, serverMap: %+v", zonename, serverMap)
	return imr.IterativeDNSQueryWithLoopDetection(ctx, qname, qtype, serverMap, force, visitedZones)
}

const maxNSRevalidateServers = 3

func (imr *Imr) scheduleReferralNSRevalidation(ctx context.Context, zonename string, serverMap map[string]*cache.AuthServer) {
	if ctx == nil {
		ctx = context.Background()
	}
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
		imr.revalidateReferralNS(ctx, zonename, snapshot)
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

	rrset, rcode, _, err := imr.AuthDNSQuery(ctx, zonename, dns.TypeNS, addrs, imr.Cache.Logger, imr.Cache.Verbose)
	if err != nil || rrset == nil || len(rrset.RRs) == 0 {
		if imr.Cache.Debug && err != nil {
			log.Printf("NS revalidation for %s failed: %v", zonename, err)
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
			Expiration: time.Now().Add(cache.GetMinTTL(rrset.RRs)),
		})
	}

	imr.revalidateInBailiwickGlue(ctx, zonename, serverMap, true)
}

func collectServerAddressesForRevalidation(serverMap map[string]*cache.AuthServer) []string {
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

func collectInBailiwickNS(serverMap map[string]*cache.AuthServer, zonename string) []string {
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

func (imr *Imr) revalidateInBailiwickGlue(ctx context.Context, zonename string, serverMap map[string]*cache.AuthServer, force bool) {
	if imr.Cache == nil || imr.Options[ImrOptRevalidateNS] != "true" {
		return
	}
	hosts := collectInBailiwickNS(serverMap, zonename)
	if len(hosts) == 0 {
		return
	}
	for _, host := range hosts {
		server := serverMap[host]
		imr.revalidateGlueRR(ctx, host, dns.TypeA, server, force)
		imr.revalidateGlueRR(ctx, host, dns.TypeAAAA, server, force)
	}
}

func (imr *Imr) revalidateGlueRR(ctx context.Context, host string, rrtype uint16, server *cache.AuthServer, force bool) {
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
	rrset, _, _, err := imr.IterativeDNSQuery(ctx, host, rrtype, hostServerMap, force)
	if err != nil || rrset == nil || len(rrset.RRs) == 0 {
		return
	}

	// Always call ValidateRRset - it will check zone state even when there are no RRSIGs
	var vstate cache.ValidationState
	vstate, err = imr.Cache.ValidateRRsetWithParentZone(ctx, rrset, imr.IterativeDNSQueryFetcher(), imr.ParentZone)
	if err != nil {
		imr.Cache.Logger.Printf("*** revalidateGlueRR: Error from ValidateRRset: %v", err)
	}
	imr.Cache.Set(host, rrtype, &cache.CachedRRset{
		Name:       host,
		RRtype:     rrtype,
		Rcode:      uint8(dns.RcodeSuccess),
		RRset:      rrset,
		Context:    cache.ContextAnswer,
		State:      vstate,
		Expiration: time.Now().Add(cache.GetMinTTL(rrset.RRs)), // XXX: This will be overridden by imr.Cache.Set(). TODO: Fix this.
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

	// No Authority section: can't be a referral or a well-formed negative.
	if len(r.Ns) == 0 {
		if rcode == dns.RcodeSuccess {
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
		// Canonicalise for a simple suffix check.
		q := dns.Fqdn(strings.ToLower(qname))
		s := dns.Fqdn(strings.ToLower(soaOwner))
		return q == s || strings.HasSuffix(q, "."+s) || s == "."
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
		// NXDOMAIN without any SOA should be treated as an error and
		// the caller will typically try the next server.
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

func (imr *Imr) handleNegative(qname string, qtype uint16, r *dns.Msg) (cache.CacheContext, int, bool) {
	if r == nil {
		return cache.ContextFailure, dns.RcodeServerFailure, false
	}
	if len(r.Ns) == 0 {
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
		return cache.ContextFailure, r.MsgHdr.Rcode, false
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
		if ds := imr.Cache.Get(qname, dns.TypeDS); ds != nil && ds.RRset != nil && len(ds.RRset.RRs) > 0 && ds.State == cache.ValidationStateSecure {
			hasValidatedDS = true
		}
	}

	soaVstate := cache.ValidationStateNone
	var err error
	if !skipDNSKEYValidation && len(soarrset.RRSIGs) > 0 {
		soaVstate, err = imr.Cache.ValidateRRset(context.Background(), soarrset, imr.IterativeDNSQueryFetcher())
		if err != nil {
			log.Printf("handleNegative: failed to validate SOA RRset: %v", err)
			return cache.ContextFailure, r.MsgHdr.Rcode, false
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

	vstate := cache.ValidationStateNone
	negRcode := uint8(r.MsgHdr.Rcode)
	if !skipDNSKEYValidation && len(negAuthority) > 0 {
		vstate, negRcode, err = imr.Cache.ValidateNegativeResponse(context.Background(), qname, qtype, negRcode, negAuthority, imr.IterativeDNSQueryFetcher())
		if err != nil {
			// If validation returns ValidationStateIndeterminate (e.g., no trust anchors),
			// we should still cache and return the response, not treat it as a failure.
			if vstate == cache.ValidationStateIndeterminate {
				log.Printf("handleNegative: validation returned indeterminate state (likely no trust anchors): %v", err)
				// Continue to cache with indeterminate state
			} else {
				log.Printf("handleNegative: failed to validate negative response: %v", err)
				return cache.ContextFailure, r.MsgHdr.Rcode, false
			}
		}
	}

	cachedRcode := uint8(r.MsgHdr.Rcode)
	// In the specific case where ValidateNegativeResponse has modified the rcode from NOERROR to NXDOMAIN we propagate this change.
	if negRcode != uint8(r.MsgHdr.Rcode) && negRcode == dns.RcodeNameError && uint8(r.MsgHdr.Rcode) == dns.RcodeSuccess {
		log.Printf("handleNegative: ValidateNegativeResponse has modified the rcode from NOERROR to NXDOMAIN")
		cachedRcode = uint8(dns.RcodeNameError)
		negContext = cache.ContextNXDOMAIN
	}

	// Ensure RCODE matches the context we're caching
	// If we're caching as NXDOMAIN, the RCODE must be NXDOMAIN
	// If we're caching as NODATA, the RCODE must be NOERROR
	if negContext == cache.ContextNXDOMAIN && cachedRcode != uint8(dns.RcodeNameError) {
		log.Printf("*** handleNegative: WARNING - caching as NXDOMAIN but RCODE is %s (expected NXDOMAIN)", dns.RcodeToString[r.MsgHdr.Rcode])
		// cachedRcode = uint8(dns.RcodeNameError)
		return cache.ContextFailure, r.MsgHdr.Rcode, false
	} else if negContext == cache.ContextNoErrNoAns && cachedRcode != uint8(dns.RcodeSuccess) {
		log.Printf("*** handleNegative: WARNING - caching as NODATA but RCODE is %s (expected NOERROR)", dns.RcodeToString[r.MsgHdr.Rcode])
		// cachedRcode = uint8(dns.RcodeSuccess)
		return cache.ContextFailure, r.MsgHdr.Rcode, false
	}

	imr.Cache.Set(qname, qtype, &cache.CachedRRset{
		Name:         qname,
		RRtype:       qtype,
		Rcode:        cachedRcode,
		RRset:        soarrset,
		NegAuthority: negAuthority,
		Context:      negContext,
		State:        vstate,
		Expiration:   expiration, // XXX: This will be overridden by rrcache.Set(). TODO: Fix this.
		EDECode:      edeCode,
		EDEText:      edeText,
	})

	// XXX: should do either of:
	// push the computed TTL into the SOA RR header(s) before calling Set, or
	// teach Set to respect a non-zero crrset.Ttl/Expiration for negative entries instead of recomputing it.

	// Also cache the SOA RRset itself for future direct lookups.
	imr.Cache.Set(soaOwner, dns.TypeSOA, &cache.CachedRRset{
		Name:       soaOwner,
		RRtype:     dns.TypeSOA,
		Rcode:      uint8(dns.RcodeSuccess),
		RRset:      soarrset,
		Context:    cache.ContextAnswer,
		State:      soaVstate,
		Expiration: expiration, // XXX: This will be overridden by rrcache.Set(). TODO: Fix this.
	})

	return negContext, int(cachedRcode), true
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

func (imr *Imr) chaseCNAME(ctx context.Context, target string, qtype uint16, force bool) (*core.RRset, int, cache.CacheContext, error) {
	maxchase := 10
	cur := target
	for i := 0; i < maxchase; i++ {
		select {
		case <-ctx.Done():
			return nil, 0, cache.ContextFailure, ctx.Err()
		default:
		}
		imr.Cache.Logger.Printf("*** IterativeDNSQuery: found CNAME target: %s, chasing.", cur)
		bestmatch, tmpservers, err := imr.Cache.FindClosestKnownZone(cur)
		if err != nil {
			imr.Cache.Logger.Printf("*** IterativeDNSQuery: Error from FindClosestKnownZone: %v", err)
			return nil, dns.RcodeServerFailure, cache.ContextFailure, err
		}
		imr.Cache.Logger.Printf("*** IterativeDNSQuery: best match for target %s is %s", cur, bestmatch)
		tmprrset, rcode, context, err := imr.IterativeDNSQuery(ctx, cur, qtype, tmpservers, force)
		if err != nil {
			imr.Cache.Logger.Printf("*** IterativeDNSQuery: Error from IterativeDNSQuery: %v", err)
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
	return nil, dns.RcodeServerFailure, cache.ContextFailure, fmt.Errorf("CNAME chase exceeded max depth")
}

func (imr *Imr) DefaultDNSKEYFetcher(ctx context.Context, name string) (*core.RRset, error) {
	// implement with your IterativeDNSQuery + server selection
	best, servers, err := imr.Cache.FindClosestKnownZone(name)
	if err != nil {
		return nil, fmt.Errorf("FindClosestKnownZone error for %s: %v", name, err)
	}
	_ = best // could be used for logging
	if len(servers) == 0 {
		if sm, ok := imr.Cache.ServerMap.Get("."); ok {
			servers = sm
		}
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("no servers for %s", name)
	}
	rr, _, _, err := imr.IterativeDNSQuery(ctx, name, dns.TypeDNSKEY, servers, false)
	if err != nil || rr == nil || len(rr.RRs) == 0 {
		return nil, fmt.Errorf("dnskey fetch failed for %s: %v", name, err)
	}
	return rr, nil
}

func (imr *Imr) DefaultRRsetFetcher(ctx context.Context, qname string, qtype uint16) (*core.RRset, error) {
	// implement with your IterativeDNSQuery + server selection
	best, servers, err := imr.Cache.FindClosestKnownZone(qname)
	if err != nil {
		return nil, fmt.Errorf("FindClosestKnownZone error for %s: %v", qname, err)
	}
	_ = best // could be used for logging
	if len(servers) == 0 {
		if sm, ok := imr.Cache.ServerMap.Get("."); ok {
			servers = sm
		}
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("no servers for %s", qname)
	}
	rr, _, _, err := imr.IterativeDNSQuery(ctx, qname, qtype, servers, false)
	if err != nil || rr == nil || len(rr.RRs) == 0 {
		return nil, fmt.Errorf("fetch failed for %s %s: %v", qname, dns.TypeToString[qtype], err)
	}
	return rr, nil
}

// IterativeDNSQueryFetcher adapts IterativeDNSQuery to the RRsetFetcher interface.
// It discards the rcode and CacheContext return values, only returning the RRset and error.
func (imr *Imr) IterativeDNSQueryFetcher() cache.RRsetFetcher {
	return func(ctx context.Context, qname string, qtype uint16, servers map[string]*cache.AuthServer) (*core.RRset, error) {
		rrset, _, _, err := imr.IterativeDNSQuery(ctx, qname, qtype, servers, false)
		return rrset, err
	}
}
