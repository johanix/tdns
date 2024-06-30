/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package main

import (
	//        "fmt"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/johanix/tdns/tdns"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
	// "github.com/johanix/tdns/tdns"
)

func DelegationSyncEngine(conf *Config) error {
	delsyncq := conf.Internal.DelegationSyncQ
	var ds tdns.DelegationSyncRequest
	var imr = viper.GetString("resolver.address")
	if imr == "" {
		log.Printf("DelegationSyncEngine: resolver address not specified. Terminating.")
		return fmt.Errorf("DelegationSyncEngine: resolver address not specified")
	}

	kdb := conf.Internal.KeyDB
	_ = kdb

	log.Printf("DelegationSyncEngine: starting")
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		var err error
		for {
			select {
			case ds = <-delsyncq:
				zd := ds.ZoneData
				switch ds.Command {
				case "DELEGATION-STATUS":
					log.Printf("DelegationSyncEngine: Zone %s request for delegation status.", zd.ZoneName)

					syncstate, err := AnalyseZoneDelegation(conf, zd)
					if err != nil {
						log.Printf("DelegationSyncEngine: Zone %s: Error from AnalyseZoneDelegation(): %v. Ignoring sync request.", ds.ZoneName, err)
						syncstate.Error = true
						syncstate.ErrorMsg = err.Error()
					}
					if ds.Response != nil {
						ds.Response <- syncstate
					}
					continue

				case "SYNC-DELEGATION":
					log.Printf("DelegationSyncEngine: Zone %s request for delegation sync %d adds and %d removes.", ds.ZoneName, len(ds.Adds), len(ds.Removes))
					for _, rr := range ds.Adds {
						log.Printf("ADD: %s", rr.String())
					}
					for _, rr := range ds.Removes {
						log.Printf("DEL: %s", rr.String())
					}
					zd := ds.ZoneData
					if zd.Parent == "" || zd.Parent == "." {
						zd.Parent, err = tdns.ParentZone(zd.ZoneName, imr)
						if err != nil {
							log.Printf("DelegationSyncEngine: Zone %s: Error from ParentZone(): %v. Ignoring sync request.", ds.ZoneName, err)
							continue
						}
					}

					ds := tdns.DelegationSyncStatus{
						Zone:    ds.ZoneName,
						Parent:  zd.Parent,
						Adds:    ds.Adds,
						Removes: ds.Removes,
					}

					//					err = zd.SyncWithParent(ds.Adds, ds.Removes)
					//					if err != nil {
					//						log.Printf("DelegationSyncEngine: Zone %s: Error from SyncWithParent(): %v. Ignoring sync request.", ds.ZoneName, err)
					//						continue
					//					}
					msg, rcode, err := SyncZoneDelegation(conf, zd, ds)
					if err != nil {
						log.Printf("DelegationSyncEngine: Zone %s: Error from SyncZoneDelegation(): %v. Ignoring sync request.", ds.Zone, err)
						continue
					}

					log.Printf("DelegationSyncEngine: Zone %s: SyncZoneDelegation() returned msg: %s, rcode: %s", ds.Zone, msg, dns.RcodeToString[int(rcode)])
					// 1. Figure out which scheme to use
					// 2. Call handler for that scheme

				case "EXPLICIT-SYNC-DELEGATION":
					log.Printf("DelegationSyncEngine: Zone %s request for explicit delegation sync.", ds.ZoneName)

					syncstate, err := AnalyseZoneDelegation(conf, ds.ZoneData)
					if err != nil {
						log.Printf("DelegationSyncEngine: Zone %s: Error from AnalyseZoneDelegation(): %v. Ignoring sync request.", ds.ZoneName, err)
						syncstate.Error = true
						syncstate.ErrorMsg = err.Error()
						if ds.Response != nil {
							ds.Response <- syncstate
						}
						continue
					}

					if syncstate.InSync {
						log.Printf("DelegationSyncEngine: Zone %s: delegation data in parent \"%s\" is in sync. No action needed.",
							syncstate.Zone, syncstate.Parent)
						if ds.Response != nil {
							ds.Response <- syncstate
						}
						continue
					}

					// Not in sync, let's fix that.
					msg, rcode, err := SyncZoneDelegation(conf, zd, syncstate)
					if err != nil {
						log.Printf("DelegationSyncEngine: Zone %s: Error from SyncZoneDelegation(): %v Ignoring sync request.", ds.ZoneName, err)
						syncstate.Error = true
						syncstate.ErrorMsg = err.Error()
					} else {
						log.Printf("DelegationSyncEngine: Zone %s: SyncZoneDelegation() returned msg: %s, rcode: %s", ds.ZoneName, msg, dns.RcodeToString[int(rcode)])
					}
					syncstate.Msg = msg
					syncstate.Rcode = rcode

					if ds.Response != nil {
						ds.Response <- syncstate
					}
					continue

				default:
					log.Printf("Unknown command: '%s'. Ignoring.", ds.Command)
				}
			}
		}
	}()
	wg.Wait()

	log.Println("DelegationSyncEngine: terminating")
	return nil
}

// Note that there are two types of determining whether delegation synchronization is needed:
// 1. Implicit: we notice that the delegation information in the child has changed and therefore NOTIFY or UPDATE the parent.
// 2. Explicit: we query the parent for the delegation information and if it differs from the child, we NOTIFY or UPDATE the parent.
// AnalyseZoneDelegation() is used for the second type of delegation synchronization.

// 1. Query parent servers until we get a child NS RRset back
// 2. Iterate over child NS RRset from parent and identify all in-bailiwick NS
// 3. Query same parent server as returned the NS RRset for the glue for this child NS
// 4. When all parent-side data is collected, compare to the data in the ZoneData struct

// Return insync (bool), adds, removes ([]dns.RR) and error
func AnalyseZoneDelegation(conf *Config, zd *tdns.ZoneData) (tdns.DelegationSyncStatus, error) {
	var resp = tdns.DelegationSyncStatus{Time: time.Now(), Zone: zd.ZoneName}

	err := zd.FetchParentData()
	if err != nil {
		return resp, err
	}

	resp.Zone = zd.ZoneName
	resp.Parent = zd.Parent

	var p_nsrrs []dns.RR
	var pserver string // outside loop to preserve for later re-use

	// 1. Compare NS RRsets between parent and child
	for _, pserver = range zd.ParentServers {
		p_nsrrs, err = tdns.AuthQuery(zd.ZoneName, pserver, dns.TypeNS)
		if err != nil {
			log.Printf("Error from AuthQuery(%s, %s, NS): %v", pserver, zd.ZoneName, err)
			continue
		}

		if len(p_nsrrs) == 0 {
			log.Printf("Empty respone to AuthQuery(%s, %s, NS)", pserver, zd.ZoneName)
			continue
		}

		// We have a response, no need to talk to rest of parent servers
		break
	}

	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return resp, err
	}

	differ, adds, removes := tdns.RRsetDiffer(zd.ZoneName, apex.RRtypes[dns.TypeNS].RRs,
		p_nsrrs, dns.TypeNS, zd.Logger)
	resp.InSync = !differ
	// log.Printf("AnalyseZoneDelegation: Zone %s: NS RRsetDiffer: %v InSync: %v", zd.ZoneName, differ, resp.InSync)

	if len(adds) > 0 {
		var tmp []dns.NS
		for _, rr := range adds {
			tmp = append(tmp, *rr.(*dns.NS))
		}
		resp.NsAdds = tmp
	}

	if len(removes) > 0 {
		var tmp []dns.NS
		for _, rr := range removes {
			tmp = append(tmp, *rr.(*dns.NS))
		}
		resp.NsRemoves = tmp
	}

	// 2. Compute the in-bailiwick subset of nameservers
	child_inb, _ := tdns.BailiwickNS(zd.ZoneName, apex.RRtypes[dns.TypeNS].RRs)
	// parent_inb, _ := tdns.BailiwickNS(zd.ZoneName, apex.RRtypes[dns.TypeNS].RRs)

	// 3. Compare A and AAAA glue for in child in-bailiwick nameservers
	for _, ns := range child_inb {
		owner, err := zd.GetOwner(ns)
		if err != nil {
			log.Printf("Error from zd.GetOwner(%s): %v", ns, err)
		}
		child_a_glue := owner.RRtypes[dns.TypeA].RRs
		parent_a_glue, err := tdns.AuthQuery(ns, pserver, dns.TypeA)
		if err != nil {
			log.Printf("Error from AuthQuery(%s, %s, A): %v", pserver, child_inb, err)
		}
		differ, adds, removes := tdns.RRsetDiffer(ns, child_a_glue, parent_a_glue,
			dns.TypeA, zd.Logger)
		// log.Printf("AnalyseZoneDelegation: Zone %s: A RRsetDiffer: %v InSync: %v", zd.ZoneName, differ, resp.InSync)
		if differ {
			resp.InSync = false
			if len(adds) > 0 {
				for _, rr := range adds {
					resp.AAdds = append(resp.AAdds, *rr.(*dns.A))
				}
			}

			if len(removes) > 0 {
				for _, rr := range removes {
					resp.ARemoves = append(resp.ARemoves, *rr.(*dns.A))
				}
			}
		}

		child_aaaa_glue := owner.RRtypes[dns.TypeAAAA].RRs
		parent_aaaa_glue, err := tdns.AuthQuery(ns, pserver, dns.TypeAAAA)
		if err != nil {
			log.Printf("Error from AuthQuery(%s, %s, AAAA): %v", pserver, child_inb, err)
		}
		differ, adds, removes = tdns.RRsetDiffer(ns, child_aaaa_glue, parent_aaaa_glue,
			dns.TypeAAAA, zd.Logger)
		// log.Printf("AnalyseZoneDelegation: Zone %s: AAAA RRsetDiffer: %v InSync: %v", zd.ZoneName, differ, resp.InSync)
		if differ {
			resp.InSync = false
			if len(adds) > 0 {
				for _, rr := range adds {
					resp.AAAAAdds = append(resp.AAAAAdds, *rr.(*dns.AAAA))
				}
			}

			if len(removes) > 0 {
				for _, rr := range removes {
					resp.AAAARemoves = append(resp.AAAARemoves, *rr.(*dns.AAAA))
				}
			}
		}
	}
	// 4. If NS RRsets differ, then also compare glue for parent in-bailiwick nameservers

	return resp, nil
}

// SyncZoneDelegation() is used for delegation synchronization request via API.
func SyncZoneDelegation(conf *Config, zd *tdns.ZoneData, syncstate tdns.DelegationSyncStatus) (string, uint8, error) {

	//	syncstate, err := AnalyseZoneDelegation(conf, zd)
	//	if err != nil {
	//		return "", err
	//	}

	if syncstate.InSync {
		return fmt.Sprintf("Zone \"%s\" delegation data in parent \"%s\" is in sync. No action needed.",
			syncstate.Zone, syncstate.Parent), 0, nil
	} else {
		log.Printf("Zone \"%s\" delegation data in parent \"%s\" is NOT in sync. Sync action needed.",
			syncstate.Zone, syncstate.Parent)
	}

	// var zd *tdns.ZoneData
	// var exist bool

	// if zd, exist = tdns.Zones.Get(zone); !exist {
	// 	msg := fmt.Sprintf("Zone \"%s\" is unknown.", zone)
	// 	log.Printf(msg)
	// 	return msg, fmt.Errorf(msg)
	// }

	// 1. Check what DSYNC schemes are supported by parent and preference in request
	// const update_scheme = 2
	// dsynctarget, err := tdns.LookupDSYNCTarget(zd.ZoneName, zd.ParentServers[0], dns.StringToType["ANY"], update_scheme)
	// if err != nil {
	// 	log.Printf("Error from LookupDSYNCTarget(%s, %s): %v", zd.Parent, zd.ParentServers[0], err)
	// 	return fmt.Sprintf("Error from LookupDSYNCTarget(%s, %s): %v", zd.Parent, zd.ParentServers[0], err), err
	// }

	scheme, dsynctarget, err := zd.BestSyncScheme()
	if err != nil {
		log.Printf("DelegationSyncEngine: Zone %s: Error from BestSyncScheme(): %v. Ignoring sync request.", zd.ZoneName, err)
		return "", 0, err
	}

	var msg string
	var rcode uint8

	switch scheme {
	case "UPDATE":
		msg, rcode, err = SyncZoneDelegationViaUpdate(conf, zd, syncstate, dsynctarget)
	case "NOTIFY	":
		msg, rcode, err = SyncZoneDelegationViaNotify(conf, zd, syncstate, dsynctarget)
	}

	return msg, rcode, err
}

func SyncZoneDelegationViaUpdate(conf *Config, zd *tdns.ZoneData, syncstate tdns.DelegationSyncStatus,
	dsynctarget *tdns.DsyncTarget) (string, uint8, error) {
	kdb := conf.Internal.KeyDB

	// If UPDATE:
	// 2. Create DNS UPDATE msg
	// var adds, removes []dns.RR
	for _, rr := range syncstate.NsAdds {
		syncstate.Adds = append(syncstate.Adds, dns.RR(&rr))
	}
	for _, rr := range syncstate.AAdds {
		syncstate.Adds = append(syncstate.Adds, dns.RR(&rr))
	}
	for _, rr := range syncstate.AAAAAdds {
		syncstate.Adds = append(syncstate.Adds, dns.RR(&rr))
	}

	for _, rr := range syncstate.NsRemoves {
		syncstate.Removes = append(syncstate.Removes, dns.RR(&rr))
	}
	for _, rr := range syncstate.ARemoves {
		syncstate.Removes = append(syncstate.Removes, dns.RR(&rr))
	}
	for _, rr := range syncstate.AAAARemoves {
		syncstate.Removes = append(syncstate.Removes, dns.RR(&rr))
	}

	m, err := tdns.CreateUpdate(zd.Parent, zd.ZoneName, syncstate.Adds, syncstate.Removes)
	if err != nil {
		return "", 0, err
	}

	// 3. Fetch the SIG(0) key from the keystore
	log.Printf("SyncZoneDelegationViaUpdate: Fetching the private key for %s", zd.ZoneName)
	_, cs, keyrr, err := kdb.GetSig0Key(zd.ZoneName)
	if err != nil {
		log.Printf("SyncZoneDelegationViaUpdate: Error from kdb.GetSig0Key(%s): %v", zd.ZoneName, err)
		return "", 0, err
	}
	if keyrr == nil {
		log.Printf("SyncZoneDelegationViaUpdate: No SIG(0) key found for zone %s", zd.ZoneName)
		return "", 0, fmt.Errorf("no SIG(0) key found for zone %s", zd.ZoneName)
	}

	// 4. Sign the msg
	log.Printf("SyncZoneDelegationViaUpdate: Signing the DNS UPDATE %s", zd.ZoneName)
	smsg, err := tdns.SignMsgNG(*m, zd.ZoneName, cs, keyrr)
	if err != nil {
		log.Printf("SyncZoneDelegationViaUpdate: Error from SignMsgNG(%s): %v", zd.ZoneName, err)
		return "", 0, err
	}
	if smsg == nil {
		log.Printf("SyncZoneDelegationViaUpdate: Error from SignMsgNG(%s): %v", zd.ZoneName, err)
		return "", 0, err
	}
	//	log.Printf("Signed DNS UPDATE msg:\n%s\n", smsg.String())

	// 5. Send the msg
	log.Printf("SyncZoneDelegationViaUpdate: Sending the signed update to %s (addresses: %v) port %d",
		dsynctarget.Name, dsynctarget.Addresses, dsynctarget.Port)

	rcode, err := tdns.SendUpdate(smsg, zd.Parent, dsynctarget)
	if err != nil {
		log.Printf("Error from SendUpdate(%s): %v", zd.Parent, err)
		return "", 0, err
	}
	msg := fmt.Sprintf("SendUpdate(%s) returned rcode %s", zd.Parent, dns.RcodeToString[rcode])
	log.Printf(msg)

	// 6. Check the response
	// 7. Return result to CLI

	return msg, uint8(rcode), err
}

func SyncZoneDelegationViaNotify(conf *Config, zd *tdns.ZoneData, syncstate tdns.DelegationSyncStatus,
	dsynctarget *tdns.DsyncTarget) (string, uint8, error) {

	// tdns.SendNotify(zd.Parent, zd.ZoneName, dt)

	return "", 0, nil
}
