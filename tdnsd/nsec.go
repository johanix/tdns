/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package main

import (
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/johanix/tdns/tdns"
	"github.com/miekg/dns"
)

func ZoneOps(cp tdns.CommandPost, kdb *KeyDB) (tdns.CommandResponse, error) {
	var resp tdns.CommandResponse
	var err error

	zd, exist := tdns.Zones.Get(cp.Zone)
	if !exist {
		return resp, fmt.Errorf("Zone %s is unknown", cp.Zone)
	}

	resp.Zone = zd.ZoneName

	switch cp.SubCommand {
	case "sign-zone":
		err := SignZone(zd, kdb)
		return resp, err

	case "generate-nsec":
		err := GenerateNsecChain(zd, kdb)
		return resp, err

	case "show-nsec-chain":
		resp.Names, err = ShowNsecChain(zd)
		return resp, err

	default:
		return resp, fmt.Errorf("NsecOps: unknown sub command: \"%s\"", cp.SubCommand)
	}
	return resp, nil
}

func ShowNsecChain(zd *tdns.ZoneData) ([]string, error) {
	var nsecrrs []string
	names, err := zd.GetOwnerNames()
	if err != nil {
		return nsecrrs, err
	}
	sort.Strings(names)

	for _, name := range names {
		owner, err := zd.GetOwner(name)
		if err != nil {
			return nsecrrs, err
		}
		if name != zd.ZoneName {
			rrs := owner.RRtypes[dns.TypeNSEC].RRs
			if len(rrs) == 1 {
				nsecrrs = append(nsecrrs, rrs[0].String())
			}
		}
	}

	return nsecrrs, nil
}

func GenerateNsecChain(zd *tdns.ZoneData, kdb *KeyDB) error {
	if !zd.AllowUpdates {
		return fmt.Errorf("GenerateNsecChain: zone %s is not allowed to be updated", zd.ZoneName)
	}
	_, cs, keyrr, err := kdb.GetDnssecKey(zd.ZoneName)
	if err != nil {
		log.Printf("GenerateNsecChain: failed to get dnssec key for zone %s", zd.ZoneName)
	}

	MaybeSignRRset := func(rrset tdns.RRset, zone string, kdb *KeyDB) tdns.RRset {
		if zd.OnlineSigning && cs != nil {
			err := tdns.SignRRset(&rrset, zone, cs, keyrr)
			if err != nil {
				log.Printf("GenerateNsecChain: failed to sign %s NSEC RRset for zone %s", rrset.RRs[0].Header().Name, zd.ZoneName)
			} else {
				log.Printf("GenerateNsecChain: signed %s NSEC RRset for zone %s", rrset.RRs[0].Header().Name, zd.ZoneName)
			}
		}
		return rrset
	}

	names, err := zd.GetOwnerNames()
	if err != nil {
		return err
	}
	sort.Strings(names)

	var nextidx int
	var nextname string

	var hasRRSIG bool

	for idx, name := range names {
		owner, err := zd.GetOwner(name)
		if err != nil {
			return err
		}

		nextidx = idx + 1
		if nextidx == len(names) {
			nextidx = 0
		}
		nextname = names[nextidx]
		var tmap = []int{int(dns.TypeNSEC)}
		for rrt, _ := range owner.RRtypes {
			if rrt == dns.TypeRRSIG {
				hasRRSIG = true
				continue
			}
			if rrt != dns.TypeNSEC {
				if rrt == 0 {
					log.Printf("GenerateNsecChain: name: %s rrt: %v (not good)", name, rrt)
				}
				tmap = append(tmap, int(rrt))
			}
		}
		if hasRRSIG || (zd.OnlineSigning && cs != nil) {
			tmap = append(tmap, int(dns.TypeRRSIG))
		}

		log.Printf("GenerateNsecChain: name: %s tmap: %v", name, tmap)

		sort.Ints(tmap) // unfortunately the NSEC TypeBitMap must be in order...
		var rrts = make([]string, len(tmap))
		for idx, t := range tmap {
			rrts[idx] = dns.TypeToString[uint16(t)]
		}

		log.Printf("GenerateNsecChain: creating NSEC RR for name %s: %v %v", name, tmap, rrts)

		items := []string{name, "NSEC", nextname}
		items = append(items, rrts...)
		nsecrr, err := dns.NewRR(strings.Join(items, " "))
		if err != nil {
			return err
		}
		tmp := owner.RRtypes[dns.TypeNSEC]
		tmp.RRs = []dns.RR{nsecrr}
		owner.RRtypes[dns.TypeNSEC] = MaybeSignRRset(tmp, zd.ZoneName, kdb)

	}

	return nil
}

func SignZone(zd *tdns.ZoneData, kdb *KeyDB) error {
	if !zd.AllowUpdates {
		return fmt.Errorf("SignZone: zone %s is not allowed to be updated", zd.ZoneName)
	}
	_, cs, keyrr, err := kdb.GetDnssecKey(zd.ZoneName)
	if err != nil {
		log.Printf("GenerateNsecChain: failed to get dnssec key for zone %s", zd.ZoneName)
	}

	err = GenerateNsecChain(zd, kdb)
	if err != nil {
		return err
	}

	MaybeSignRRset := func(rrset tdns.RRset, zone string, kdb *KeyDB) tdns.RRset {
		if zd.OnlineSigning && cs != nil {
			err := tdns.SignRRset(&rrset, zone, cs, keyrr)
			if err != nil {
				log.Printf("SignZone: failed to sign %s %s RRset for zone %s", rrset.RRs[0].Header().Name, rrset.RRs[0].Header().Rrtype, zd.ZoneName)
			} else {
				log.Printf("SignZone: signed %s %s RRset for zone %s", rrset.RRs[0].Header().Name, dns.TypeToString[uint16(rrset.RRs[0].Header().Rrtype)], zd.ZoneName)
			}
		}
		return rrset
	}

	names, err := zd.GetOwnerNames()
	if err != nil {
		return err
	}
	sort.Strings(names)

	for _, name := range names {
		owner, err := zd.GetOwner(name)
		if err != nil {
			return err
		}

		for rrt, rrset := range owner.RRtypes {
			if rrt == dns.TypeRRSIG {
				continue
			}
			owner.RRtypes[rrt] = MaybeSignRRset(rrset, zd.ZoneName, kdb)
		}
	}

	return nil
}
