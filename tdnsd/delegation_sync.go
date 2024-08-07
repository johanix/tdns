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

	"github.com/gookit/goutil/dump"
	"github.com/johanix/tdns/tdns"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
	// "github.com/johanix/tdns/tdns"
)

func DelegationSyncher(conf *Config) error {
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

	// var cs *crypto.Signer
	// var keyrr *dns.KEY
	// var dnskeyrr *dns.DNSKEY
	// var err error

	for zname, zd := range tdns.Zones.Items() {
		log.Printf("DelegationSyncher: Checking whether zone %s allows updates and if so has a KEY RRset published.", zname)
		apex, _ := zd.GetOwner(zd.ZoneName)
		_, keyrrexist := apex.RRtypes[dns.TypeKEY]

		// 1. Are updates to the zone data allowed?
		if !zd.Options["allow-updates"] {
			if keyrrexist {
				log.Printf("DelegationSyncher: Zone %s does not allow updates, but a KEY RRset is already published in the zone.", zd.ZoneName)
			} else {
				log.Printf("DelegationSyncher: Zone %s does not allow updates. Cannot publish a KEY RRset.", zd.ZoneName)
			}
			continue
		}

		// 2. Updates allowed, but there is no KEY RRset published.
		if !keyrrexist {
			log.Printf("DelegationSyncher: Fetching the private SIG(0) key for %s", zd.ZoneName)
			// _, _, keyrr, err = kdb.GetSig0PrivKey(zd.ZoneName)
			sak, err := kdb.GetSig0ActiveKeys(zd.ZoneName)
			if err != nil {
				log.Printf("DelegationSyncher: Error from kdb.GetSig0ActiveKeys(%s): %v. Parent sync via UPDATE not possible.", zd.ZoneName, err)
				continue
			}
			if len(sak.Keys) == 0 {
				log.Printf("DelegationSyncher: No active SIG(0) key found for zone %s. Parent sync via UPDATE not possible.", zd.ZoneName)
				sak, err = kdb.GenerateNewSig0ActiveKey(zd)
				if err != nil {
					log.Printf("DelegationSyncher: Error from kdb.GenerateNewSig0ActiveKey(%s): %v. Parent sync via UPDATE not possible.", zd.ZoneName, err)
					continue
				}
			}

			if len(sak.Keys) == 0 {
				log.Printf("DelegationSyncher: No active SIG(0) key found for zone %s. Parent sync via UPDATE not possible.", zd.ZoneName)
				continue
			}
			log.Printf("DelegationSyncher: Publishing KEY RR for zone %s", zd.ZoneName)
			err = zd.PublishKeyRRs(sak)
			if err != nil {
				log.Printf("DelegationSyncher: Error from PublishKeyRRs(): %s", err)
			} else {
				keyrrexist = true
			}

			//		} else {
			//			log.Printf("DelegationSyncher: Zone %s KEY RRset already published", zd.ZoneName)
			//			continue
		}

		// 3. There is a KEY RRset, question is whether it is signed or not
		if zd.Options["online-signing"] {
			log.Printf("DelegationSyncher: Fetching the private DNSSEC key for %s in prep for signing KEY RRset", zd.ZoneName)
			dak, err := kdb.GetDnssecActiveKeys(zd.ZoneName)
			if err != nil {
				log.Printf("DelegationSyncher: Error from kdb.GetDnssecActiveKeys(%s): %v. Parent sync via UPDATE not possible.", zd.ZoneName, err)
				continue
			}
			rrset := apex.RRtypes[dns.TypeKEY]
			err = tdns.SignRRset(&rrset, zd.ZoneName, dak, false)
			if err != nil {
				log.Printf("Error signing %s KEY RRset: %v", zd.ZoneName, err)
			} else {
				apex.RRtypes[dns.TypeKEY] = rrset
				log.Printf("Successfully signed %s KEY RRset", zd.ZoneName)
			}
			continue
		}

		// 4. End of the line
		log.Printf("DelegationSyncher: Zone %s does not allow online signing, KEY RRset cannot be re-signed", zd.ZoneName)
	}

	log.Printf("*** DelegationSyncher: starting ***")
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		var err error
		for ds = range delsyncq {
			zd := ds.ZoneData
			dss := ds.SyncStatus

			switch ds.Command {
			case "DELEGATION-STATUS":
				log.Printf("DelegationSyncher: Zone %s request for delegation status.", zd.ZoneName)

				syncstate, err := zd.AnalyseZoneDelegation()
				if err != nil {
					log.Printf("DelegationSyncher: Zone %s: Error from AnalyseZoneDelegation(): %v. Ignoring sync request.", ds.ZoneName, err)
					syncstate.Error = true
					syncstate.ErrorMsg = err.Error()
				}
				if ds.Response != nil {
					ds.Response <- syncstate
				}
				continue

			case "SYNC-DELEGATION":
				log.Printf("DelegationSyncher: Zone %s request for delegation sync -%d+%d NS adds and -%d+%d A glue and -%d+%d AAAA glue.", ds.ZoneName,
					len(dss.NsRemoves), len(dss.NsAdds), len(dss.ARemoves), len(dss.AAdds), len(dss.AAAARemoves), len(dss.AAAAAdds))
				zd := ds.ZoneData
				if zd.Parent == "" || zd.Parent == "." {
					zd.Parent, err = tdns.ParentZone(zd.ZoneName, imr)
					if err != nil {
						log.Printf("DelegationSyncher: Zone %s: Error from ParentZone(): %v. Ignoring sync request.", ds.ZoneName, err)
						continue
					}
				}

				msg, rcode, err := SyncZoneDelegation(conf, zd, ds.SyncStatus)
				if err != nil {
					log.Printf("DelegationSyncher: Zone %s: Error from SyncZoneDelegation(): %v. Ignoring sync request.", ds.ZoneName, err)
					continue
				}

				log.Printf("DelegationSyncher: Zone %s: SyncZoneDelegation() returned msg: %s, rcode: %s", ds.ZoneName, msg, dns.RcodeToString[int(rcode)])

			case "EXPLICIT-SYNC-DELEGATION":
				log.Printf("DelegationSyncher: Zone %s request for explicit delegation sync.", ds.ZoneName)

				syncstate, err := zd.AnalyseZoneDelegation()
				if err != nil {
					log.Printf("DelegationSyncher: Zone %s: Error from AnalyseZoneDelegation(): %v. Ignoring sync request.", ds.ZoneName, err)
					syncstate.Error = true
					syncstate.ErrorMsg = err.Error()
					if ds.Response != nil {
						ds.Response <- syncstate
					}
					continue
				}

				if syncstate.InSync {
					log.Printf("DelegationSyncher: Zone %s: delegation data in parent \"%s\" is in sync with child. No action needed.",
						syncstate.ZoneName, syncstate.Parent)
					if ds.Response != nil {
						ds.Response <- syncstate
					}
					continue
				}

				// Not in sync, let's fix that.
				msg, rcode, err := SyncZoneDelegation(conf, zd, syncstate)
				if err != nil {
					log.Printf("DelegationSyncher: Zone %s: Error from SyncZoneDelegation(): %v Ignoring sync request.", ds.ZoneName, err)
					syncstate.Error = true
					syncstate.ErrorMsg = err.Error()
				} else {
					log.Printf("DelegationSyncher: Zone %s: SyncZoneDelegation() returned msg: %s, rcode: %s", ds.ZoneName, msg, dns.RcodeToString[int(rcode)])
				}
				syncstate.Msg = msg
				syncstate.Rcode = rcode

				if ds.Response != nil {
					ds.Response <- syncstate
				}
				continue

			default:
				log.Printf("DelegationSyncher: Zone %s: Unknown command: '%s'. Ignoring.", ds.ZoneName, ds.Command)
			}
		}
	}()
	wg.Wait()

	log.Println("DelegationSyncher: terminating")
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
			syncstate.ZoneName, zd.Parent), 0, nil
	} else {
		log.Printf("Zone \"%s\" delegation data in parent \"%s\" is NOT in sync. Sync action needed.",
			syncstate.ZoneName, zd.Parent)
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

	// dump.P(syncstate)

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

	m, err := tdns.CreateChildUpdate(zd.Parent, zd.ZoneName, syncstate.Adds, syncstate.Removes)
	if err != nil {
		return "", 0, err
	}

	// 3. Fetch the SIG(0) key from the keystore
	log.Printf("SyncZoneDelegationViaUpdate: Fetching the private key for %s", zd.ZoneName)
	sak, err := kdb.GetSig0ActiveKeys(zd.ZoneName)
	if err != nil {
		log.Printf("SyncZoneDelegationViaUpdate: Error from kdb.GetSig0ActiveKeys(%s): %v", zd.ZoneName, err)
		return "", 0, err
	}
	if len(sak.Keys) == 0 {
		log.Printf("SyncZoneDelegationViaUpdate: No active SIG(0) key found for zone %s", zd.ZoneName)
		return "", 0, fmt.Errorf("no active SIG(0) key found for zone %s", zd.ZoneName)
	}

	// 4. Sign the msg
	log.Printf("SyncZoneDelegationViaUpdate: Signing the DNS UPDATE %s", zd.ZoneName)
	smsg, err := tdns.SignMsg(*m, zd.ZoneName, sak)
	if err != nil {
		log.Printf("SyncZoneDelegationViaUpdate: Error from SignMsgNG(%s): %v", zd.ZoneName, err)
		return "", 0, err
	}
	if smsg == nil {
		log.Printf("SyncZoneDelegationViaUpdate: Error from SignMsgNG(%s): %v", zd.ZoneName, err)
		return "", 0, err
	}

	// 5. Send the msg
	log.Printf("SyncZoneDelegationViaUpdate: Sending the signed update to %s (addresses: %v) port %d",
		dsynctarget.Name, dsynctarget.Addresses, dsynctarget.Port)

	rcode, err := tdns.SendUpdate(smsg, zd.Parent, dsynctarget.Addresses)
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

	if zd.Options["allow-updates"] {
		// 1. Verify that a CSYNC (or CDS) RR is published. If not, create and publish as needed.
		err := zd.PublishCsyncRR()
		if err != nil {
			log.Printf("SyncZoneDelegationViaNotify: Error from PublishCsync(): %v", err)
			return "", dns.RcodeServerFailure, err
		}

		// Try to sign the CSYNC RRset
		if zd.Options["online-signing"] {
			apex, _ := zd.GetOwner(zd.ZoneName)
			rrset := apex.RRtypes[dns.TypeCSYNC]
			dak, err := conf.Internal.KeyDB.GetDnssecActiveKeys(zd.ZoneName)
			if err != nil {
				log.Printf("SyncZoneDelegationViaNotify: failed to get dnssec key for zone %s", zd.ZoneName)
			} else {
				if len(dak.ZSKs) > 0 {
					err := tdns.SignRRset(&rrset, zd.ZoneName, dak, true) // Let's force signing
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

	dump.P(dsynctarget)
	// New:
	conf.Internal.NotifyQ <- tdns.NotifyRequest{
		ZoneName: zd.ZoneName,
		ZoneData: zd,
		RRtype:   dns.TypeCSYNC,         // this is only about syncinf delegation data, not about rolling DNSSEC keys.
		Targets:  dsynctarget.Addresses, // already in addr:port format
	}

	msg := fmt.Sprintf("SyncZoneDelegationViaNotify: Sent notify request for zone %s to NotifierEngine", zd.ZoneName)
	log.Print(msg)

	return msg, dns.RcodeSuccess, nil
}
