/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package main

import (
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/johanix/tdns/tdns"
	"github.com/miekg/dns"
)

func ZoneOps(conf *Config, cp tdns.CommandPost, kdb *KeyDB) (tdns.CommandResponse, error) {
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

	case "bump-serial":
		resp.Msg, err = BumpSerial(conf, cp.Zone)
		if err != nil {
			resp.Error = true
			resp.ErrorMsg = err.Error()
		}

	case "freeze":
		if !zd.AllowUpdates {
			return resp, fmt.Errorf("FreezeZone: zone %s does not allow updates. Freeze would be a no-op", zd.ZoneName)
		}

		if zd.Frozen {
			return resp, fmt.Errorf("FreezeZone: zone %s is already frozen", zd.ZoneName)
		}

		zd.Frozen = true
		resp.Msg = fmt.Sprintf("Zone %s is now frozen", zd.ZoneName)
		return resp, nil

	case "thaw":
		if !zd.AllowUpdates {
			return resp, fmt.Errorf("ThawZone: zone %s does not allow updates. Thaw would be a no-op", zd.ZoneName)
		}
		if !zd.Frozen {
			return resp, fmt.Errorf("ThawZone: zone %s is not frozen", zd.ZoneName)
		}
		zd.Frozen = false
		resp.Msg = fmt.Sprintf("Zone %s is now thawed", zd.ZoneName)
		return resp, nil

	case "reload":
		// XXX: Note: if the zone allows updates and is dirty, then reloading should be denied
		log.Printf("ZoneOps: reloading, will check for changes to delegation data\n")
		resp.Msg, err = ReloadZone(conf, cp.Zone, cp.Force)
		if err != nil {
			resp.Error = true
			resp.ErrorMsg = err.Error()
		}

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

func BumpSerial(conf *Config, zone string) (string, error) {
	var respch = make(chan BumperResponse, 1)
	conf.Internal.BumpZoneCh <- BumperData{
		Zone:   zone,
		Result: respch,
	}

	resp := <-respch

	if resp.Error {
		log.Printf("BumpSerial: Error from RefreshEngine: %s", resp.ErrorMsg)
		msg := fmt.Sprintf("Zone %s: error bumping SOA serial: %s", zone, resp.ErrorMsg)
		return msg, fmt.Errorf(msg)
	}

	if resp.Msg == "" {
		resp.Msg = fmt.Sprintf("Zone %s: bumped SOA serial from %d to %d", zone, resp.OldSerial, resp.NewSerial)
	}
	return resp.Msg, nil
}

func ReloadZone(conf *Config, zone string, force bool) (string, error) {
	var respch = make(chan tdns.RefresherResponse, 1)
	conf.Internal.RefreshZoneCh <- tdns.ZoneRefresher{
		Name:     zone,
		Response: respch,
		Force:    force,
	}

	var resp tdns.RefresherResponse

	select {
	case resp = <-respch:
	case <-time.After(2 * time.Second):
		return fmt.Sprintf("Zone %s: timeout waiting for response from RefreshEngine", zone), fmt.Errorf("Zone %s: timeout waiting for response from RefreshEngine", zone)
	}

	if resp.Error {
		log.Printf("ReloadZone: Error from RefreshEngine: %s", resp.ErrorMsg)
		return fmt.Sprintf("Zone %s: Error reloading: %s", zone, resp.ErrorMsg),
			fmt.Errorf("Zone %s: Error reloading: %v", zone, resp.ErrorMsg)
	}

	if resp.Msg == "" {
		resp.Msg = fmt.Sprintf("Zone %s: reloaded", zone)
	}
	return resp.Msg, nil
}

type BumperData struct {
	Zone   string
	Result chan BumperResponse
}

type BumperResponse struct {
	Time      time.Time
	Zone      string
	Msg       string
	OldSerial uint32
	NewSerial uint32
	Error     bool
	ErrorMsg  string
	Status    bool
}
