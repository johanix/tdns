/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package main

import (
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/johanix/tdns/tdns"
	"github.com/miekg/dns"
)

func ZoneOps(conf *Config, cp tdns.CommandPost, kdb *tdns.KeyDB) (tdns.CommandResponse, error) {
	var resp tdns.CommandResponse
	var err error

	zd, exist := tdns.Zones.Get(cp.Zone)
	if !exist {
		return resp, fmt.Errorf("zone %s is unknown", cp.Zone)
	}

	resp.Zone = zd.ZoneName

	switch cp.SubCommand {
	case "write-zone":
		msg, err := zd.WriteZone(false, cp.Force)
		resp.Msg = msg
		return resp, err

	case "sign-zone":
		err := zd.SignZone(kdb, cp.Force)
		return resp, err

	case "generate-nsec":
		err := zd.GenerateNsecChain(kdb)
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
		// If a zone has modifications, freezing implies that the updated
		// zone data should be written out to disk.
		if !zd.Options["allow-updates"] && !zd.Options["allow-child-updates"] {
			return resp, fmt.Errorf("FreezeZone: zone %s does not allow updates. Freeze would be a no-op", zd.ZoneName)
		}

		if zd.Options["frozen"] {
			return resp, fmt.Errorf("FreezeZone: zone %s is already frozen", zd.ZoneName)
		}

		// zd.mu.Lock()
		zd.SetOption("frozen", true)
		//zd.mu.Unlock()
		if zd.Options["dirty"] {
			tosource := true
			zd.WriteZone(tosource, false)
			resp.Msg = fmt.Sprintf("Zone %s is now frozen, modifications will be written to disk", zd.ZoneName)
		} else {
			resp.Msg = fmt.Sprintf("Zone %s is now frozen", zd.ZoneName)
		}
		return resp, nil

	case "thaw":
		if !zd.Options["allow-updates"] || !zd.Options["allow-child-updates"] {
			return resp, fmt.Errorf("ThawZone: zone %s does not allow updates. Thaw would be a no-op", zd.ZoneName)
		}
		if !zd.Options["frozen"] {
			return resp, fmt.Errorf("ThawZone: zone %s is not frozen", zd.ZoneName)
		}
		zd.Options["frozen"] = false
		resp.Msg = fmt.Sprintf("Zone %s is now thawed", zd.ZoneName)
		return resp, nil

	case "reload":
		// XXX: Note: if the zone allows updates and is dirty, then reloading should be denied
		log.Printf("ZoneOps: reloading, will check for changes to delegation data\n")
		// resp.Msg, err = ReloadZone(cp.Zone, cp.Force)
		resp.Msg, err = zd.ReloadZone(conf.Internal.RefreshZoneCh, cp.Force)
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

func BumpSerial(conf *Config, zone string) (string, error) {
	var respch = make(chan tdns.BumperResponse, 1)
	conf.Internal.BumpZoneCh <- tdns.BumperData{
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

func xxxReloadZone(conf *Config, zone string, force bool) (string, error) {
	//	if !zd.Options["dirty"] {
	//		msg := fmt.Sprintf("Zone %s: zone has been modified, reload not possible", zd.ZoneName)
	//		return msg, fmt.Errorf(msg)
	//	}
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
		return fmt.Sprintf("Zone %s: timeout waiting for response from RefreshEngine", zone), fmt.Errorf("zone %s: timeout waiting for response from RefreshEngine", zone)
	}

	if resp.Error {
		log.Printf("ReloadZone: Error from RefreshEngine: %s", resp.ErrorMsg)
		return fmt.Sprintf("zone %s: Error reloading: %s", zone, resp.ErrorMsg),
			fmt.Errorf("zone %s: Error reloading: %v", zone, resp.ErrorMsg)
	}

	if resp.Msg == "" {
		resp.Msg = fmt.Sprintf("Zone %s: reloaded", zone)
	}
	return resp.Msg, nil
}
