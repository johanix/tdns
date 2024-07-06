/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package main

import (
	//        "fmt"
	"crypto"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/gookit/goutil/dump"
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

	// If we support syncing with parent via DNS UPDATE then we must ensure that a KEY RR for the zone is published.
	time.Sleep(10 * time.Second) // Allow time for zones to load

	var cs *crypto.Signer
	var keyrr *dns.KEY
	var dnskeyrr *dns.DNSKEY
	var err error

	for zname, zd := range tdns.Zones.Items() {
		log.Printf("DelegationSyncEngine: Checking whether zone %s allows updates and if so has a KEY RRset published.", zname)
		if zd.AllowUpdates {
			apex, _ := zd.GetOwner(zd.ZoneName)
			if _, exist := apex.RRtypes[dns.TypeKEY]; !exist {
				log.Printf("DelegationSyncEngine: Fetching the private SIG(0) key for %s", zd.ZoneName)
				_, _, keyrr, err = kdb.GetSig0Key(zd.ZoneName)
				if err != nil {
					log.Printf("DelegationSyncEngine: Error from kdb.GetSig0Key(%s): %v. Parent sync via UPDATE not possible.", zd.ZoneName, err)
					continue
				}
				if keyrr == nil {
					log.Printf("DelegationSyncEngine: No SIG(0) key found for zone %s. Parent sync via UPDATE not possible.", zd.ZoneName)
					continue
				}

				log.Printf("DelegationSyncEngine: Publishing KEY RR for zone %s", zd.ZoneName)
				zd.PublishKeyRR(keyrr)

				if zd.OnlineSigning {
					log.Printf("DelegationSyncEngine: Fetching the private DNSSEC key for %s in prep for signing KEY RRset", zd.ZoneName)
					_, cs, dnskeyrr, err = kdb.GetDnssecKey(zd.ZoneName)
					if err != nil {
						log.Printf("DelegationSyncEngine: Error from kdb.GetDnssecKey(%s): %v. Parent sync via UPDATE not possible.", zd.ZoneName, err)
						continue
					}
					// apex, _ := zd.GetOwner(zd.ZoneName)
					rrset := apex.RRtypes[dns.TypeKEY]
					// dump.P(rrset)
					err := tdns.SignRRset(&rrset, zd.ZoneName, cs, dnskeyrr)
					if err != nil {
						log.Printf("Error signing %s KEY RRset: %v", zd.ZoneName, err)
					} else {
						apex.RRtypes[dns.TypeKEY] = rrset
						log.Printf("Successfully signed %s KEY RRset", zd.ZoneName)
					}
				}
			} else {
				log.Printf("DelegationSyncEngine: Zone %s KEY RRset already published", zd.ZoneName)
			}
		}
	}

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

					syncstate, err := zd.AnalyseZoneDelegation()
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

					//					ds := tdns.DelegationSyncStatus{
					//						Zone:    ds.ZoneName,
					//						Parent:  zd.Parent,
					//						Adds:    ds.Adds,
					//						Removes: ds.Removes,
					//					}

					//					err = zd.SyncWithParent(ds.Adds, ds.Removes)
					//					if err != nil {
					//						log.Printf("DelegationSyncEngine: Zone %s: Error from SyncWithParent(): %v. Ignoring sync request.", ds.ZoneName, err)
					//						continue
					//					}
					msg, rcode, err := SyncZoneDelegation(conf, zd, ds.SyncStatus)
					if err != nil {
						log.Printf("DelegationSyncEngine: Zone %s: Error from SyncZoneDelegation(): %v. Ignoring sync request.", ds.ZoneName, err)
						continue
					}

					log.Printf("DelegationSyncEngine: Zone %s: SyncZoneDelegation() returned msg: %s, rcode: %s", ds.ZoneName, msg, dns.RcodeToString[int(rcode)])
					// 1. Figure out which scheme to use
					// 2. Call handler for that scheme

				case "EXPLICIT-SYNC-DELEGATION":
					log.Printf("DelegationSyncEngine: Zone %s request for explicit delegation sync.", ds.ZoneName)

					syncstate, err := zd.AnalyseZoneDelegation()
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
						log.Printf("DelegationSyncEngine: Zone %s: delegation data in parent \"%s\" is in sync with child. No action needed.",
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
					log.Printf("DelegationSyncEngine: Zone %s: Unknown command: '%s'. Ignoring.", ds.ZoneName, ds.Command)
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
// tdns.AnalyseZoneDelegation() is used for explicit delegation synchronization.
// tdns.DelegationDataChanged() is used for implicit delegation synchronization.

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
	case "NOTIFY":
		msg, rcode, err = SyncZoneDelegationViaNotify(conf, zd, syncstate, dsynctarget)
	}

	return msg, rcode, err
}

func SyncZoneDelegationViaUpdate(conf *Config, zd *tdns.ZoneData, syncstate tdns.DelegationSyncStatus,
	dsynctarget *tdns.DsyncTarget) (string, uint8, error) {
	kdb := conf.Internal.KeyDB

	dump.P(syncstate)

	// Ensure that we don't count any changes twice.
	syncstate.Adds = []dns.RR{}
	syncstate.Removes = []dns.RR{}

	// If UPDATE:
	// 2. Create DNS UPDATE msg
	// var adds, removes []dns.RR
	syncstate.Adds = append(syncstate.Adds, syncstate.NsAdds...)
	syncstate.Adds = append(syncstate.Adds, syncstate.AAdds...)
	syncstate.Adds = append(syncstate.Adds, syncstate.AAAAAdds...)
	syncstate.Removes = append(syncstate.Removes, syncstate.NsRemoves...)
	syncstate.Removes = append(syncstate.Removes, syncstate.ARemoves...)
	syncstate.Removes = append(syncstate.Removes, syncstate.AAAARemoves...)

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
	log.Print(msg)

	// 6. Check the response
	// 7. Return result to CLI

	return msg, uint8(rcode), err
}

func SyncZoneDelegationViaNotify(conf *Config, zd *tdns.ZoneData, syncstate tdns.DelegationSyncStatus,
	dsynctarget *tdns.DsyncTarget) (string, uint8, error) {

	if zd.AllowUpdates {
		// 1. Verify that a CSYNC (or CDS) RR is published. If not, create and publish as needed.
		err := zd.PublishCsyncRR()
		if err != nil {
			log.Printf("SyncZoneDelegationViaNotify: Error from PublishCsync(): %v", err)
			return "", dns.RcodeServerFailure, err
		}

		// Try to sign the CSYNC RRset
		if zd.OnlineSigning {
			apex, _ := zd.GetOwner(zd.ZoneName)
			rrset := apex.RRtypes[dns.TypeCSYNC]
			_, cs, keyrr, err := conf.Internal.KeyDB.GetDnssecKey(zd.ZoneName)
			if err != nil {
				log.Printf("SyncZoneDelegationViaNotify: failed to get dnssec key for zone %s", zd.ZoneName)
			} else {
				if cs != nil {
					err := tdns.SignRRset(&rrset, zd.ZoneName, cs, keyrr)
					if err != nil {
						log.Printf("Error signing %s: %v", zd.ZoneName, err)
					} else {
						log.Printf("Signed %s: %v", zd.ZoneName, err)
					}
				}
			}
		}
	}
	// 2. Create Notify msg
	// 3. Send Notify msg

	// Old:
	// rcode, err := tdns.SendNotify(zd.Parent, zd.ZoneName, "CSYNC", dsynctarget)
	// if err != nil {
	// 	log.Printf("Error from SendNotify(%s): %v", zd.Parent, err)
	// 	return "", 0, err
	// }
	// msg := fmt.Sprintf("SendNotify(%s) returned rcode %s", zd.Parent, dns.RcodeToString[rcode])
	// log.Printf(msg)

	// New:
	conf.Internal.NotifyQ <- tdns.NotifyRequest{
		ZoneName: zd.ZoneName,
		ZoneData: zd,
		Targets:  dsynctarget.Addresses, // already in addr:port format
	}

	msg := fmt.Sprintf("SyncZoneDelegationViaNotify: Sent notify request for zone %s to NotifierEngine", zd.ZoneName)
	log.Print(msg)

	return msg, dns.RcodeSuccess, nil
}
