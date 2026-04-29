/*
 * Transport signal synthesis (SVCB / TSYNC)
 */
package tdns

import (
	"fmt"
	"net"
	"strings"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// matchesConfiguredAddrs returns true if any RR in rrset matches a configured address.
// Note that the hostports are expected to be in the format "address:port".
func matchesConfiguredAddrs(hostports []string, rrset *core.RRset) bool {
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
		lgDns.Debug("CreateTransportSignalRRs: service.transport.type=none; skipping transport signal synthesis for zone",
			"zone", zd.ZoneName)
		return nil
	case "svcb":
		return zd.createTransportSignalSVCB(conf)
	case "tsync":
		return zd.createTransportSignalTSYNC(conf)
	default:
		lgDns.Debug("CreateTransportSignalRRs: unknown transport type, skipping",
			"type", conf.Service.Transport.Type,
			"zone", zd.ZoneName)
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
			lgDns.Debug("CreateTransportSignalRRs(SVCB): checking NS", "zone", zd.ZoneName, "ns", nsName)
			if Globals.ServerSVCB != nil {
				lgDns.Debug("CreateTransportSignalRRs(SVCB): server SVCB configured", "svcb", Globals.ServerSVCB.String())
			}
			if CaseFoldContains(conf.Service.Identities, nsName) {
				if strings.HasSuffix(nsName, zd.ZoneName) {
					lgDns.Debug("CreateTransportSignalRRs(SVCB): NS is in-bailiwick, skipping identity path", "zone", zd.ZoneName, "ns", nsName)
					continue // in-bailiwick; handled below
				}
				if Globals.ServerSVCB == nil {
					lgDns.Debug("CreateTransportSignalRRs(SVCB): no server SVCB configured, skipping identity NS", "ns", nsName)
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
				zd.TransportSignal = &core.RRset{Name: "_dns." + nsName, RRtype: dns.TypeSVCB, RRs: []dns.RR{tmp}}
				zd.AddTransportSignal = true
				lgDns.Debug("CreateTransportSignalRRs(SVCB): Adding server SVCB to zone using identity NS",
					"zone", zd.ZoneName,
					"ns", nsName)
				lgDns.Debug("CreateTransportSignalRRs(SVCB): SVCB", "svcb", tmp.String())
				return nil
			}
		}
	}

	// In-bailiwick NS path
	for _, rr := range nsRRset.RRs {
		if ns, ok := rr.(*dns.NS); ok {
			nsName := ns.Ns
			if !dns.IsSubDomain(zd.ZoneName, nsName) {
				lgDns.Debug("CreateTransportSignalRRs(SVCB): NS is out-of-bailiwick, skipping",
					"zone", zd.ZoneName,
					"ns", nsName)
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
									lgDns.Debug("CreateTransportSignalRRs(SVCB): rejecting explicit SVCB", "owner", ownerName, "err", err)
									valid = false
									break
								}
							}
						}
						if valid {
							// Start with the explicit SVCB RRset
							zd.TransportSignal = &core.RRset{Name: ownerName, RRtype: dns.TypeSVCB, RRs: append([]dns.RR(nil), existingSvcb.RRs...), RRSIGs: append([]dns.RR(nil), existingSvcb.RRSIGs...)}

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
							lgDns.Debug("CreateTransportSignalRRs(SVCB): using existing SVCB",
								"owner", ownerName,
								"zone", zd.ZoneName)
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
					lgDns.Debug("CreateTransportSignalRRs(SVCB): found A records for in-bailiwick NS",
						"zone", zd.ZoneName,
						"count", len(ipv4s),
						"ns", nsName,
						"addrs", ipv4s)
				}
				if aaaaRRset.RRs != nil {
					for _, rr := range aaaaRRset.RRs {
						if aaaa, ok := rr.(*dns.AAAA); ok {
							ipv6s = append(ipv6s, aaaa.AAAA)
						}
					}
					lgDns.Debug("CreateTransportSignalRRs(SVCB): found AAAA records for in-bailiwick NS",
						"zone", zd.ZoneName,
						"count", len(ipv6s),
						"ns", nsName,
						"addrs", ipv6s)
				}

				// If any address matches configured addresses, publish SVCB
				if !matchesConfiguredAddrs(conf.DnsEngine.Addresses, &aRRset) && !matchesConfiguredAddrs(conf.DnsEngine.Addresses, &aaaaRRset) {
					lgDns.Debug("CreateTransportSignalRRs(SVCB): no addresses match configured for in-bailiwick NS",
						"zone", zd.ZoneName,
						"ns", nsName)
					lgDns.Debug("CreateTransportSignalRRs(SVCB): configured addresses",
						"zone", zd.ZoneName,
						"addresses", conf.DnsEngine.Addresses)
					lgDns.Debug("CreateTransportSignalRRs(SVCB): A RRset", "zone", zd.ZoneName, "rrset", aRRset.RRs)
					lgDns.Debug("CreateTransportSignalRRs(SVCB): AAAA RRset", "zone", zd.ZoneName, "rrset", aaaaRRset.RRs)
					continue
				} else {
					lgDns.Debug("CreateTransportSignalRRs(SVCB): addresses match configured for in-bailiwick NS",
						"zone", zd.ZoneName,
						"ns", nsName,
						"a_rrs", aRRset.RRs,
						"aaaa_rrs", aaaaRRset.RRs)
					values := append([]dns.SVCBKeyValue(nil), Globals.ServerSVCB.Value...)
					if len(ipv4s) > 0 {
						values = append(values, &dns.SVCBIPv4Hint{Hint: ipv4s})
					}
					if len(ipv6s) > 0 {
						values = append(values, &dns.SVCBIPv6Hint{Hint: ipv6s})
					}
					lgDns.Debug("CreateTransportSignalRRs(SVCB): added IP hints for in-bailiwick NS",
						"zone", zd.ZoneName,
						"ipv4hints", ipv4s,
						"ipv6hints", ipv6s,
						"ns", nsName)
					if sig := conf.Service.Transport.Signal; sig != "" {
						lgDns.Debug("CreateTransportSignalRRs(SVCB): adding transport signal for in-bailiwick NS",
							"zone", zd.ZoneName,
							"signal", sig,
							"ns", nsName)
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
					zd.TransportSignal = &core.RRset{Name: "_dns." + nsName, RRtype: dns.TypeSVCB, RRs: []dns.RR{tmp}}
					zd.AddTransportSignal = true
					lgDns.Debug("CreateTransportSignalRRs(SVCB): Adding server SVCB to zone using in-bailiwick NS",
						"zone", zd.ZoneName,
						"ns", nsName)
					lgDns.Debug("CreateTransportSignalRRs(SVCB): SVCB", "svcb", tmp.String())

					if _, err := zd.SignRRset(zd.TransportSignal, "", nil, false, nil); err != nil {
						lgDns.Debug("CreateTransportSignalRRs(SVCB): error signing SVCB", "owner", "_dns."+nsName, "err", err)
					}
					// Add into zone data
					serversvcbs := nsData.RRtypes.GetOnlyRRSet(dns.TypeSVCB)
					if len(serversvcbs.RRs) == 0 {
						nsData.RRtypes.Set(dns.TypeSVCB, core.RRset{RRs: []dns.RR{tmp}})
					} else {
						nsData.RRtypes.Set(dns.TypeSVCB, core.RRset{RRs: append(serversvcbs.RRs, tmp)})
						lgDns.Debug("CreateTransportSignalRRs(SVCB): added server SVCB to existing SVCB RRset", "ns", nsName)
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
					existingTS := ownerData.RRtypes.GetOnlyRRSet(core.TypeTSYNC)
					if len(existingTS.RRs) > 0 {
						// Base RRset is the explicit TSYNC
						zd.TransportSignal = &core.RRset{Name: ownerName, RRtype: core.TypeTSYNC, RRs: append([]dns.RR(nil), existingTS.RRs...)}
						zd.AddTransportSignal = true
						// Check for alias indirection
						alias := "."
						if prr, ok := existingTS.RRs[0].(*dns.PrivateRR); ok {
							if ts, ok2 := prr.Data.(*core.TSYNC); ok2 && ts != nil && ts.Alias != "" {
								alias = ts.Alias
							}
						}
						if alias != "." {
							lgDns.Debug("createTransportSignalTSYNC: looking up zone for TSYNC alias target",
								"owner", ownerName,
								"target", alias)
							// Resolve alias target to the closest enclosing zone we serve.
							if bestZD, _ := FindZone(alias); bestZD != nil {
								targetOwner := "_dns." + alias
								lgDns.Debug("createTransportSignalTSYNC: resolved TSYNC alias target",
									"owner", ownerName,
									"targetowner", targetOwner)
								if tOwnerData, ok := bestZD.Data.Get(targetOwner); ok {
									targetTS := tOwnerData.RRtypes.GetOnlyRRSet(core.TypeTSYNC)
									lgDns.Debug("createTransportSignalTSYNC: found TSYNC RRs at target", "count", len(targetTS.RRs), "target", targetOwner)
									if len(targetTS.RRs) > 0 {
										zd.TransportSignal.RRs = append(zd.TransportSignal.RRs, targetTS.RRs...)
										// also carry over RRSIGs for Additional section symmetry
										if len(targetTS.RRSIGs) > 0 {
											zd.TransportSignal.RRSIGs = append(zd.TransportSignal.RRSIGs, targetTS.RRSIGs...)
										}
									}
								} else {
									lgDns.Debug("createTransportSignalTSYNC: no TSYNC RRset data found for target", "target", targetOwner)
								}
							} else {
								lgDns.Debug("createTransportSignalTSYNC: no zone found for TSYNC target", "target", "_dns."+alias)
							}
						}
						lgDns.Debug("createTransportSignalTSYNC: using existing TSYNC for in-bailiwick NS",
							"owner", ownerName,
							"alias", alias,
							"ns", nsName)
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
					lgDns.Error("createTransportSignalTSYNC: failed to build TSYNC", "err", err)
					continue
				}
				// Store in zone data
				existing := nsData.RRtypes.GetOnlyRRSet(core.TypeTSYNC)
				if len(existing.RRs) == 0 {
					nsData.RRtypes.Set(core.TypeTSYNC, core.RRset{RRs: []dns.RR{trr}})
				} else {
					nsData.RRtypes.Set(core.TypeTSYNC, core.RRset{RRs: append(existing.RRs, trr)})
				}
				zd.TransportSignal = &core.RRset{Name: "_dns." + nsName, RRtype: core.TypeTSYNC, RRs: []dns.RR{trr}}
				zd.AddTransportSignal = true
				lgDns.Debug("createTransportSignalTSYNC: added TSYNC for in-bailiwick NS",
					"zone", zd.ZoneName,
					"ns", nsName,
					"rr", trr.String())
				// Sign TSYNC if online signing is enabled; QueryResponder will include RRSIGs when present
				if _, err := zd.SignRRset(zd.TransportSignal, "", nil, false, nil); err != nil {
					lgDns.Debug("createTransportSignalTSYNC: error signing TSYNC", "owner", "_dns."+nsName, "err", err)
				}
				return nil
			}
		}
	}
	return nil
}
