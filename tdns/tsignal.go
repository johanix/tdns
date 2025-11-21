/*
 * Transport signal synthesis (SVCB / TSYNC)
 */
package tdns

import (
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// matchesConfiguredAddrs returns true if any RR in rrset matches a configured address.
// Note that the hostports are expected to be in the format "address:port".
func matchesConfiguredAddrs(hostports []string, rrset *RRset) bool {
	if rrset == nil {
		return false
	}
	for _, rr := range rrset.RRs {
		var ip string
		switch r := rr.(type) {
		case *dns.A:
			ip = r.A.String()
		case *dns.AAAA:
			ip = r.AAAA.String()
		}
		for _, hp := range hostports {
			// (b) wildcard checks: if hp is "0.0.0.0" or "0.0.0.0:port" or "[::]" or "[::]:port", always match
			if hp == "0.0.0.0" || hp == "[::]" {
				return true
			}
			if strings.HasPrefix(hp, "0.0.0.0:") || strings.HasPrefix(hp, "[::]:") {
				return true
			}

			// (a) relax: accept host or host:port in hp
			addr, _, err := net.SplitHostPort(hp)
			if err != nil {
				// Not host:port, match against whole hp
				if ip == hp {
					return true
				}
			} else {
				if ip == addr {
					return true
				}
			}
		}
	}
	return false
}

// CreateTransportSignalRRs orchestrates construction of a transport signal RRset
// for this zone. It delegates to the chosen mechanism (svcb|tsync) and assigns
// zd.TransportSignal and zd.AddTransportSignal when successful.
func (zd *ZoneData) CreateTransportSignalRRs(conf *Config) error {
	switch conf.Service.Transport.Type {
	case "none", "":
		log.Printf("CreateTransportSignalRRs: service.transport.type=none; skipping transport signal synthesis for zone %s", zd.ZoneName)
		return nil
	case "svcb":
		return zd.createTransportSignalSVCB(conf)
	case "tsync":
		return zd.createTransportSignalTSYNC(conf)
	default:
		log.Printf("CreateTransportSignalRRs: unknown transport.type=%q; skipping for zone %s", conf.Service.Transport.Type, zd.ZoneName)
		return nil
	}
}

// SVCB path
func (zd *ZoneData) createTransportSignalSVCB(conf *Config) error {
	apex, exists := zd.Data.Get(zd.ZoneName)
	if !exists {
		return fmt.Errorf("zone apex not found")
	}
	nsRRset := apex.RRtypes.GetOnlyRRSet(dns.TypeNS)
	if len(nsRRset.RRs) == 0 {
		return fmt.Errorf("no NS records found at zone apex")
	}

	// Identity NS short-circuit (out-of-bailiwick identity)
	for _, rr := range nsRRset.RRs {
		if ns, ok := rr.(*dns.NS); ok {
			nsName := ns.Ns
			if Globals.Debug {
				log.Printf("CreateTransportSignalRRs(SVCB): Zone %s: NS name: %s", zd.ZoneName, nsName)
				if Globals.ServerSVCB != nil {
					log.Printf("CreateTransportSignalRRs(SVCB): Server SVCB: %s", Globals.ServerSVCB.String())
				}
			}
			if CaseFoldContains(conf.Service.Identities, nsName) {
				if strings.HasSuffix(nsName, zd.ZoneName) {
					log.Printf("CreateTransportSignalRRs(SVCB): Zone %s: NS name %s is in-bailiwick", zd.ZoneName, nsName)
					continue // in-bailiwick; handled below
				}
				if Globals.ServerSVCB == nil {
					log.Printf("CreateTransportSignalRRs(SVCB): no Server SVCB configured; skipping identity NS %s", nsName)
					continue
				}
				values := append([]dns.SVCBKeyValue(nil), Globals.ServerSVCB.Value...)
				if sig := conf.Service.Transport.Signal; sig != "" {
					values = append(values, &dns.SVCBLocal{KeyCode: dns.SVCBKey(SvcbTransportKey), Data: []byte(sig)})
				}

				certData, err := parseCertificate(conf.Internal.CertData)
				if err != nil {
					return fmt.Errorf("CreateTransportSignalRRs(SVCB): failed to parse certificate: %v", err)
				} else {
					tlsaRR := dns.TLSA{
						Hdr:          dns.RR_Header{Name: "_443._tcp." + nsName, Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 10800},
						Usage:        3, // DANE-EE
						Selector:     1, // SPKI
						MatchingType: 1, // SHA-256
						Certificate:  certData,
					}
					tlsastr, err := MarshalTLSAToString(&tlsaRR)
					if err != nil {
						return fmt.Errorf("CreateTransportSignalRRs(SVCB): failed to marshal TLSA: %v", err)
					}
					values = append(values, &dns.SVCBLocal{KeyCode: dns.SVCBKey(SvcbTLSAKey), Data: []byte(tlsastr)})
				}

				tmp := &dns.SVCB{
					Hdr:      dns.RR_Header{Name: "_dns." + nsName, Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: 10800},
					Priority: 1,
					Target:   ".",
					Value:    values,
				}
				zd.TransportSignal = &RRset{Name: "_dns." + nsName, RRtype: dns.TypeSVCB, RRs: []dns.RR{tmp}}
				zd.AddTransportSignal = true
				log.Printf("CreateTransportSignalRRs(SVCB): Adding server SVCB to zone %s using identity NS %s", zd.ZoneName, nsName)
				log.Printf("CreateTransportSignalRRs(SVCB): SVCB: %s", tmp.String())
				return nil
			}
		}
	}

	// In-bailiwick NS path
	for _, rr := range nsRRset.RRs {
		if ns, ok := rr.(*dns.NS); ok {
			nsName := ns.Ns
			if !dns.IsSubDomain(zd.ZoneName, nsName) {
				log.Printf("CreateTransportSignalRRs(SVCB): In-bailiwick case: Zone %s: NS name %s is not in-bailiwick", zd.ZoneName, nsName)
				continue
			}
			if nsData, exists := zd.Data.Get(nsName); exists {
				// Prefer explicit SVCB at _dns.<nsName> if valid
				ownerName := "_dns." + nsName
				if ownerData, ok := zd.Data.Get(ownerName); ok {
					existingSvcb := ownerData.RRtypes.GetOnlyRRSet(dns.TypeSVCB)
					if len(existingSvcb.RRs) > 0 {
						valid := true
						for _, rr := range existingSvcb.RRs {
							if svcb, ok := rr.(*dns.SVCB); ok {
								if err := ValidateExplicitServerSVCB(svcb); err != nil {
									log.Printf("CreateTransportSignalRRs(SVCB): rejecting explicit SVCB at %s: %v", ownerName, err)
									valid = false
									break
								}
							}
						}
						if valid {
							// Start with the explicit SVCB RRset
							zd.TransportSignal = &RRset{Name: ownerName, RRtype: dns.TypeSVCB, RRs: append([]dns.RR(nil), existingSvcb.RRs...), RRSIGs: append([]dns.RR(nil), existingSvcb.RRSIGs...)}

							// If any SVCB has a non-terminal Target (not "."), attempt to include the target SVCB as well.
							// This mirrors the TSYNC alias behavior so clients get both the original and the target.
							for _, rr := range existingSvcb.RRs {
								if svcb, ok := rr.(*dns.SVCB); ok {
									if svcb.Target != "." && svcb.Target != "" {
										if bestZD, _ := FindZone(svcb.Target); bestZD != nil {
											targetOwner := "_dns." + svcb.Target
											if tOwnerData, ok := bestZD.Data.Get(targetOwner); ok {
												targetRRset := tOwnerData.RRtypes.GetOnlyRRSet(dns.TypeSVCB)
												if len(targetRRset.RRs) > 0 {
													zd.TransportSignal.RRs = append(zd.TransportSignal.RRs, targetRRset.RRs...)
													if len(targetRRset.RRSIGs) > 0 {
														zd.TransportSignal.RRSIGs = append(zd.TransportSignal.RRSIGs, targetRRset.RRSIGs...)
													}
												}
											}
										}
									}
								}
							}
							zd.AddTransportSignal = true
							log.Printf("CreateTransportSignalRRs(SVCB): Using existing SVCB at %s in zone %s", ownerName, zd.ZoneName)
							return nil
						}
					}
				}

				// Collect A/AAAA
				aRRset := nsData.RRtypes.GetOnlyRRSet(dns.TypeA)
				aaaaRRset := nsData.RRtypes.GetOnlyRRSet(dns.TypeAAAA)
				var ipv4s []net.IP
				var ipv6s []net.IP
				if aRRset.RRs != nil {
					for _, rr := range aRRset.RRs {
						if a, ok := rr.(*dns.A); ok {
							ipv4s = append(ipv4s, a.A)
						}
					}
					log.Printf("CreateTransportSignalRRs(SVCB): Zone %s: Found %d A for in-bailiwick NS %s: %v", zd.ZoneName, len(ipv4s), nsName, ipv4s)
				}
				if aaaaRRset.RRs != nil {
					for _, rr := range aaaaRRset.RRs {
						if aaaa, ok := rr.(*dns.AAAA); ok {
							ipv6s = append(ipv6s, aaaa.AAAA)
						}
					}
					log.Printf("CreateTransportSignalRRs(SVCB): Zone %s: Found %d AAAA for in-bailiwick NS %s: %v", zd.ZoneName, len(ipv6s), nsName, ipv6s)
				}

				// If any address matches configured addresses, publish SVCB
				if !matchesConfiguredAddrs(conf.DnsEngine.Addresses, &aRRset) && !matchesConfiguredAddrs(conf.DnsEngine.Addresses, &aaaaRRset) {
					log.Printf("CreateTransportSignalRRs(SVCB): Zone %s: No addresses match configured addresses for in-bailiwick NS %s", zd.ZoneName, nsName)
					log.Printf("CreateTransportSignalRRs(SVCB): Zone %s: Configured addresses: %v", zd.ZoneName, conf.DnsEngine.Addresses)
					log.Printf("CreateTransportSignalRRs(SVCB): Zone %s: A RRset: %v", zd.ZoneName, aRRset.RRs)
					log.Printf("CreateTransportSignalRRs(SVCB): Zone %s: AAAA RRset: %v", zd.ZoneName, aaaaRRset.RRs)
					continue
				} else {
					log.Printf("CreateTransportSignalRRs(SVCB): Zone %s: Addresses match configured addresses for in-bailiwick NS %s: %v, %v", zd.ZoneName, nsName, aRRset.RRs, aaaaRRset.RRs)
					values := append([]dns.SVCBKeyValue(nil), Globals.ServerSVCB.Value...)
					if len(ipv4s) > 0 {
						values = append(values, &dns.SVCBIPv4Hint{Hint: ipv4s})
					}
					if len(ipv6s) > 0 {
						values = append(values, &dns.SVCBIPv6Hint{Hint: ipv6s})
					}
					log.Printf("CreateTransportSignalRRs(SVCB): Zone %s: Added IPv4 hints %v and IPv6 hints %v for in-bailiwick NS %s", zd.ZoneName, ipv4s, ipv6s, nsName)
					if sig := conf.Service.Transport.Signal; sig != "" {
						log.Printf("CreateTransportSignalRRs(SVCB): Zone %s: Adding transport signal %s for in-bailiwick NS %s", zd.ZoneName, sig, nsName)
						values = append(values, &dns.SVCBLocal{KeyCode: dns.SVCBKey(SvcbTransportKey), Data: []byte(sig)})
					}

					certData, err := parseCertificate(conf.Internal.CertData)
					if err != nil {
						return fmt.Errorf("CreateTransportSignalRRs(SVCB): failed to parse certificate: %v", err)
					} else {
						tlsaRR := dns.TLSA{
							Hdr:          dns.RR_Header{Name: "_443._tcp." + nsName, Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 10800},
							Usage:        3, // DANE-EE
							Selector:     1, // SPKI
							MatchingType: 1, // SHA-256
							Certificate:  certData,
						}
						tlsastr, err := MarshalTLSAToString(&tlsaRR)
						if err != nil {
							return fmt.Errorf("CreateTransportSignalRRs(SVCB): failed to marshal TLSA: %v", err)
						}
						values = append(values, &dns.SVCBLocal{KeyCode: dns.SVCBKey(SvcbTLSAKey), Data: []byte(tlsastr)})
					}

					tmp := &dns.SVCB{
						Hdr:      dns.RR_Header{Name: "_dns." + nsName, Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: 10800},
						Priority: 1,
						Target:   ".",
						Value:    values,
					}
					zd.TransportSignal = &RRset{Name: "_dns." + nsName, RRtype: dns.TypeSVCB, RRs: []dns.RR{tmp}}
					zd.AddTransportSignal = true
					log.Printf("CreateTransportSignalRRs(SVCB): Adding server SVCB to zone %s using in-bailiwick NS %s", zd.ZoneName, nsName)
					log.Printf("CreateTransportSignalRRs(SVCB): SVCB: %s", tmp.String())

					if _, err := zd.SignRRset(zd.TransportSignal, "", nil, false); err != nil {
						log.Printf("CreateTransportSignalRRs(SVCB): error signing SVCB for %s: %v", "_dns."+nsName, err)
					}
					// Add into zone data
					serversvcbs := nsData.RRtypes.GetOnlyRRSet(dns.TypeSVCB)
					if len(serversvcbs.RRs) == 0 {
						nsData.RRtypes.Set(dns.TypeSVCB, RRset{RRs: []dns.RR{tmp}})
					} else {
						nsData.RRtypes.Set(dns.TypeSVCB, RRset{RRs: append(serversvcbs.RRs, tmp)})
						log.Printf("CreateTransportSignalRRs(SVCB): Added server SVCB to existing SVCB RRset for %s", nsName)
					}
					return nil
				}
			}
		}
	}
	return nil
}

// TSYNC path
func (zd *ZoneData) createTransportSignalTSYNC(conf *Config) error {
	apex, exists := zd.Data.Get(zd.ZoneName)
	if !exists {
		return fmt.Errorf("zone apex not found")
	}
	nsRRset := apex.RRtypes.GetOnlyRRSet(dns.TypeNS)
	if len(nsRRset.RRs) == 0 {
		return fmt.Errorf("no NS records found at zone apex")
	}

	// TSYNC: we only synthesize for in-bailiwick
	for _, rr := range nsRRset.RRs {
		if ns, ok := rr.(*dns.NS); ok {
			nsName := ns.Ns
			if !dns.IsSubDomain(zd.ZoneName, nsName) {
				continue
			}
			if nsData, exists := zd.Data.Get(nsName); exists {
				// Prefer explicit TSYNC at _dns.<nsName>; handle indirect via alias if present
				ownerName := "_dns." + nsName
				if ownerData, ok := zd.Data.Get(ownerName); ok {
					existingTS := ownerData.RRtypes.GetOnlyRRSet(TypeTSYNC)
					if len(existingTS.RRs) > 0 {
						// Base RRset is the explicit TSYNC
						zd.TransportSignal = &RRset{Name: ownerName, RRtype: TypeTSYNC, RRs: append([]dns.RR(nil), existingTS.RRs...)}
						zd.AddTransportSignal = true
						// Check for alias indirection
						alias := "."
						if prr, ok := existingTS.RRs[0].(*dns.PrivateRR); ok {
							if ts, ok2 := prr.Data.(*TSYNC); ok2 && ts != nil && ts.Alias != "" {
								alias = ts.Alias
							}
						}
						if alias != "." {
							log.Printf("createTransportSignalTSYNC: Looking up zone for %s TSYNC alias target %s", ownerName, alias)
							// Resolve alias target to the closest enclosing zone we serve.
							if bestZD, _ := FindZone(alias); bestZD != nil {
								targetOwner := "_dns." + alias
								log.Printf("createTransportSignalTSYNC: Resolved %s TSYNC alias target to %s", ownerName, targetOwner)
								if tOwnerData, ok := bestZD.Data.Get(targetOwner); ok {
									targetTS := tOwnerData.RRtypes.GetOnlyRRSet(TypeTSYNC)
									log.Printf("Found %d TSYNC RRs at target %s", len(targetTS.RRs), targetOwner)
									if len(targetTS.RRs) > 0 {
										zd.TransportSignal.RRs = append(zd.TransportSignal.RRs, targetTS.RRs...)
										// also carry over RRSIGs for Additional section symmetry
										if len(targetTS.RRSIGs) > 0 {
											zd.TransportSignal.RRSIGs = append(zd.TransportSignal.RRSIGs, targetTS.RRSIGs...)
										}
									}
								} else {
									log.Printf("createTransportSignalTSYNC: No TSYNC RRset data found for target %s", targetOwner)
								}
							} else {
								log.Printf("createTransportSignalTSYNC: No zone found for TSYNC target _dns.%s", alias)
							}
						}
						log.Printf("createTransportSignalTSYNC: Using existing TSYNC at %s (alias=%s) for in-bailiwick NS %s", ownerName, alias, nsName)
						return nil
					}
				}
				aRRset := nsData.RRtypes.GetOnlyRRSet(dns.TypeA)
				aaaaRRset := nsData.RRtypes.GetOnlyRRSet(dns.TypeAAAA)
				// Only synthesize TSYNC for nameservers whose address matches configured addresses
				if !(matchesConfiguredAddrs(conf.DnsEngine.Addresses, &aRRset) || matchesConfiguredAddrs(conf.DnsEngine.Addresses, &aaaaRRset)) {
					continue
				}
				var ipv4s []string
				var ipv6s []string
				for _, rr := range aRRset.RRs {
					if a, ok := rr.(*dns.A); ok {
						ipv4s = append(ipv4s, a.A.String())
					}
				}
				for _, rr := range aaaaRRset.RRs {
					if aaaa, ok := rr.(*dns.AAAA); ok {
						ipv6s = append(ipv6s, aaaa.AAAA.String())
					}
				}
				tsyncStr := fmt.Sprintf("_dns.%s 10800 IN TSYNC . %q %q %q",
					nsName,
					fmt.Sprintf("transport=%s", conf.Service.Transport.Signal),
					fmt.Sprintf("v4=%s", strings.Join(ipv4s, ",")),
					fmt.Sprintf("v6=%s", strings.Join(ipv6s, ",")),
				)
				trr, err := dns.NewRR(tsyncStr)
				if err != nil {
					log.Printf("createTransportSignalTSYNC: failed to build TSYNC: %v", err)
					continue
				}
				// Store in zone data
				existing := nsData.RRtypes.GetOnlyRRSet(TypeTSYNC)
				if len(existing.RRs) == 0 {
					nsData.RRtypes.Set(TypeTSYNC, RRset{RRs: []dns.RR{trr}})
				} else {
					nsData.RRtypes.Set(TypeTSYNC, RRset{RRs: append(existing.RRs, trr)})
				}
				zd.TransportSignal = &RRset{Name: "_dns." + nsName, RRtype: TypeTSYNC, RRs: []dns.RR{trr}}
				zd.AddTransportSignal = true
				log.Printf("createTransportSignalTSYNC: Added TSYNC to zone %s for in-bailiwick NS %s: %s", zd.ZoneName, nsName, trr.String())
				// Sign TSYNC if online signing is enabled; QueryResponder will include RRSIGs when present
				if _, err := zd.SignRRset(zd.TransportSignal, "", nil, false); err != nil {
					log.Printf("createTransportSignalTSYNC: error signing TSYNC for %s: %v", "_dns."+nsName, err)
				}
				return nil
			}
		}
	}
	return nil
}
