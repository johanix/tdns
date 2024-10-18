/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/gookit/goutil/dump"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func (kdb *KeyDB) DelegationSyncher(delsyncq chan DelegationSyncRequest, notifyq chan NotifyRequest) error {
	var ds DelegationSyncRequest
	var imr = viper.GetString("resolver.address")
	if imr == "" {
		log.Printf("DelegationSyncEngine: resolver address not specified. Terminating.")
		return fmt.Errorf("DelegationSyncEngine: resolver address not specified")
	}

	// time.Sleep(5 * time.Second) // Allow time for zones to load

	log.Printf("*** DelegationSyncher: starting ***")
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		var err error
		for ds = range delsyncq {
			zd := ds.ZoneData
			dss := ds.SyncStatus

			switch ds.Command {

			case "DELEGATION-SYNC-SETUP":
				// This is the initial setup request, when we first load a zone that has the delegation-sync-child option set.
				err = zd.DelegationSyncSetup(kdb)
				if err != nil {
					log.Printf("DelegationSyncher: Zone %s: Error from DelegationSyncSetup(): %v. Ignoring sync request.", ds.ZoneName, err)
					continue
				}

			case "INITIAL-KEY-UPLOAD":
				// This case is not yet used, intended for automating the initial key upload to parent
				log.Printf("DelegationSyncher: Zone %s request for initial key upload.", zd.ZoneName)
				// err := zd.UploadKeyToParent(kdb)
				// if err != nil {
				// 	log.Printf("DelegationSyncher: Zone %s: Error from UploadKeyToParent(): %v. Ignoring sync request.", ds.ZoneName, err)
				// 	continue
				// }
				log.Printf("DelegationSyncher: Zone %s: Initial key upload complete.", ds.ZoneName)
				continue

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
					zd.Parent, err = ParentZone(zd.ZoneName, imr)
					if err != nil {
						log.Printf("DelegationSyncher: Zone %s: Error from ParentZone(): %v. Ignoring sync request.", ds.ZoneName, err)
						continue
					}
				}

				msg, rcode, err, ur := zd.SyncZoneDelegation(kdb, notifyq, ds.SyncStatus)
				if err != nil {
					log.Printf("DelegationSyncher: Zone %s: Error from SyncZoneDelegation(): %v. Ignoring sync request.", ds.ZoneName, err)
					continue
				}
				ds.SyncStatus.UpdateResult = ur
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
				msg, rcode, err, ur := zd.SyncZoneDelegation(kdb, notifyq, syncstate)
				if err != nil {
					log.Printf("DelegationSyncher: Zone %s: Error from SyncZoneDelegation(): %v Ignoring sync request.", ds.ZoneName, err)
					syncstate.Error = true
					syncstate.ErrorMsg = err.Error()
					syncstate.UpdateResult = ur
				} else {
					log.Printf("DelegationSyncher: Zone %s: SyncZoneDelegation() returned msg: %s, rcode: %s", ds.ZoneName, msg, dns.RcodeToString[int(rcode)])
				}
				syncstate.Msg = msg
				syncstate.Rcode = rcode

				if ds.Response != nil {
					ds.Response <- syncstate
				}
				continue

			case "SYNC-DNSKEY-RRSET":
				log.Printf("DelegationSyncher: Zone %s request for DNSKEY RRset sync.", ds.ZoneName)
				if zd.Options[OptMultiSigner] {
					log.Printf("DelegationSyncher: Zone %s is a multisigner zone. Notifying multisigner controller.", ds.ZoneName)
					notifyq <- NotifyRequest{
						ZoneName: zd.ZoneName,
						ZoneData: zd,
						RRtype:   dns.TypeDNSKEY, // this is only about syncing delegation data, not about rolling DNSSEC keys.
						// Targets:  dsynctarget.Addresses, // already in addr:port format
						Targets: zd.MultiSigner.Controller.Notify.Targets,
						Urgent:  true,
					}

				}

			default:
				log.Printf("DelegationSyncher: Zone %s: Unknown command: '%s'. Ignoring.", ds.ZoneName, ds.Command)
			}
		}
	}()
	wg.Wait()

	log.Println("DelegationSyncher: terminating")
	return nil
}

func (zd *ZoneData) DelegationSyncSetup(kdb *KeyDB) error {
	log.Printf("DelegationSyncSetup: setting up zone %s", zd.ZoneName)
	if !zd.Options[OptDelSyncChild] {
		log.Printf("DelegationSyncSetup: Zone %s does not have child-side delegation sync enabled. Skipping.", zd.ZoneName)
		return nil
	}

	log.Printf("DelegationSyncSetup: Checking whether zone %s allows updates and if so has a KEY RRset published.", zd.ZoneName)
	apex, _ := zd.GetOwner(zd.ZoneName)
	_, keyrrexist := apex.RRtypes[dns.TypeKEY]

	if keyrrexist && !zd.Options[OptDontPublishKey] {
		err := zd.VerifyPublishedKeyRRs()
		if err != nil {
			zd.Logger.Printf("Error from VerifyPublishedKeyRRs(%s): %v", zd.ZoneName, err)
			return err
		}
		zd.Logger.Printf("DelegationSyncSetup: Zone %s: Verified published KEY RRset", zd.ZoneName)
	}

	algstr := viper.GetString("delegationsync.child.update.keygen.algorithm")
	alg := dns.StringToAlgorithm[strings.ToUpper(algstr)]
	if alg == 0 {
		log.Printf("DelegationSyncSetup: Unknown keygen algorithm: \"%s\", using ED25519", algstr)
		alg = dns.ED25519
	}

	// 1. Are updates to the zone data allowed?
	if !zd.Options[OptAllowUpdates] {
		if keyrrexist {
			log.Printf("DelegationSyncSetup: Zone %s does not allow updates, but a KEY RRset is already published in the zone.", zd.ZoneName)
		} else {
			log.Printf("DelegationSyncSetup: Zone %s does not allow updates. Cannot publish a KEY RRset.", zd.ZoneName)
		}
		return nil
	}

	log.Printf("DelegationSyncSetup: Zone %s allows updates. KEY RR exist: %v, dont-publish-key: %v", zd.ZoneName, keyrrexist, zd.Options[OptDontPublishKey])

	// 2. Updates allowed, but there is no KEY RRset published.
	if !keyrrexist && !zd.Options[OptDontPublishKey] {
		log.Printf("DelegationSyncSetup: Fetching the private SIG(0) key for %s", zd.ZoneName)
		sak, err := kdb.GetSig0Keys(zd.ZoneName, Sig0StateActive)
		if err != nil {
			log.Printf("DelegationSyncSetup: Error from kdb.GetSig0Keys(%s, %s): %v. Parent sync via UPDATE not possible.", zd.ZoneName, Sig0StateActive, err)
			return err
		}
		if len(sak.Keys) == 0 {
			log.Printf("DelegationSyncSetup: No active SIG(0) key found for zone %s. Will generate new key to enable parent sync via UPDATE.", zd.ZoneName)

			kp := KeystorePost{
				Command:    "sig0-mgmt",
				SubCommand: "generate",
				Zone:       zd.ZoneName,
				Algorithm:  alg,
				State:      Sig0StateActive,
				Creator:    "del-sync-setup",
			}
			resp, err := zd.KeyDB.Sig0KeyMgmt(nil, kp)
			if err != nil {
				return fmt.Errorf("DelegationSyncSetup(%s) failed to generate keypair: %v", zd.ZoneName, err)
			}
			zd.Logger.Printf(resp.Msg)

			sak, err = zd.KeyDB.GetSig0Keys(zd.ZoneName, Sig0StateActive)
			if err != nil {
				return fmt.Errorf("DelegationSyncSetup(%s, after key generation) failed to get SIG(0) active keys: %v", zd.ZoneName, err)
			}

			//			algstr := viper.GetString("delegationsync.child.update.keygen.algorithm")
			//			alg := dns.StringToAlgorithm[strings.ToUpper(algstr)]
			//			if alg == 0 {
			//				log.Printf("DelegationSynchSetup: Unknown keygen algorithm: \"%s\"", algstr)
			//				return fmt.Errorf("unknown keygen algorithm: %s", algstr)
			//			}
			//			pkc, msg, err := kdb.GenerateKeypair(zd.ZoneName, "del-sync", "active", dns.TypeKEY, alg, "", nil) // nil = no tx
			//			if err != nil {
			//				zd.Logger.Printf("Error from kdb.GeneratePrivateKey(%s, KEY, %s): %v", zd.ZoneName, algstr, err)
			//				return err
			//			}
			//			zd.Logger.Printf("DelegationSynchSetup: %s", msg)
			//			sak = &Sig0ActiveKeys{
			//				Keys: []*PrivateKeyCache{pkc},
			//			}
		}

		if len(sak.Keys) == 0 {
			log.Printf("DelegationSyncSetup: No active SIG(0) key found for zone %s. Parent sync via UPDATE not possible.", zd.ZoneName)
			return fmt.Errorf("no active SIG(0) key found for zone %s. Parent sync via UPDATE not possible.", zd.ZoneName)
		}
		log.Printf("DelegationSyncSetup: Publishing KEY RR for zone %s", zd.ZoneName)
		err = zd.PublishKeyRRs(sak)
		if err != nil {
			log.Printf("DelegationSyncSetup: Error from PublishKeyRRs(): %s", err)
			return err
		} else {
			keyrrexist = true
		}
	}

	// 3. There is a KEY RRset, question is whether it is signed or not
	if keyrrexist && zd.Options[OptOnlineSigning] {
		log.Printf("DelegationSyncSetup: Fetching the private DNSSEC key for %s in prep for signing KEY RRset", zd.ZoneName)
		//			dak, err := kdb.GetDnssecActiveKeys(zd.ZoneName)
		//			if err != nil {
		//				log.Printf("DelegationSyncher: Error from kdb.GetDnssecActiveKeys(%s): %v. Parent sync via UPDATE not possible.", zd.ZoneName, err)
		//				continue
		//			}
		rrset := apex.RRtypes[dns.TypeKEY]
		_, err := zd.SignRRset(&rrset, zd.ZoneName, nil, false)
		if err != nil {
			log.Printf("Error signing %s KEY RRset: %v", zd.ZoneName, err)
		} else {
			apex.RRtypes[dns.TypeKEY] = rrset
			log.Printf("Successfully signed %s KEY RRset", zd.ZoneName)
		}
	} else {
		log.Printf("DelegationSyncSetup: Zone %s does not allow online signing, KEY RRset cannot be re-signed", zd.ZoneName)
	}

	// 4. There is a KEY RRset, we have tried to sign it if possible. But has it been uploaded to the parent?
	// XXX: This is a bit of a hack, but we need to bootstrap the parent with the child's SIG(0) key. In the future
	// we should keep state of whether successful key bootstrapping has been done or not in the keystore.
	msg, err, ur := zd.BootstrapSig0KeyWithParent(alg)
	if err != nil {
		log.Printf("DelegationSyncSetup: Zone %s: Error from BootstrapSig0KeyWithParent(): %v.", zd.ZoneName, err)
		for _, tes := range ur.TargetStatus {
			log.Printf("DelegationSyncSetup: Zone %s: TargetUpdateStatus: %v", zd.ZoneName, tes)
		}
		return err
	}
	log.Printf("DelegationSyncSetup: Zone %s: SIG(0) key bootstrap: %s", zd.ZoneName, msg)
	return nil
}

// Note that there are two types of determining whether delegation synchronization is needed:
// 1. Implicit: we notice that the delegation information in the child has changed and therefore NOTIFY or UPDATE the parent.
// 2. Explicit: we query the parent for the delegation information and if it differs from the child, we NOTIFY or UPDATE the parent.
// tdns.AnalyseZoneDelegation() is used for explicit delegation synchronization.
// tdns.DelegationDataChanged() is used for implicit delegation synchronization.

// SyncZoneDelegation() is used for delegation synchronization request via API.
func (zd *ZoneData) SyncZoneDelegation(kdb *KeyDB, notifyq chan NotifyRequest, syncstate DelegationSyncStatus) (string, uint8, error, UpdateResult) {

	//	syncstate, err := AnalyseZoneDelegation(conf, zd)
	//	if err != nil {
	//		return "", err
	//	}

	if syncstate.InSync {
		return fmt.Sprintf("Zone \"%s\" delegation data in parent \"%s\" is in sync. No action needed.",
			syncstate.ZoneName, zd.Parent), 0, nil, UpdateResult{}
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
		return "", 0, err, UpdateResult{}
	}

	var msg string
	var rcode uint8
	var ur UpdateResult

	switch scheme {
	case "UPDATE":
		msg, rcode, err, ur = zd.SyncZoneDelegationViaUpdate(kdb, syncstate, dsynctarget)
	case "NOTIFY":
		msg, rcode, err = zd.SyncZoneDelegationViaNotify(kdb, notifyq, syncstate, dsynctarget)
	}

	return msg, rcode, err, ur
}

func (zd *ZoneData) SyncZoneDelegationViaUpdate(kdb *KeyDB, syncstate DelegationSyncStatus,
	dsynctarget *DsyncTarget) (string, uint8, error, UpdateResult) {

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

	// dump.P(syncstate)
	m, err := CreateChildUpdate(zd.Parent, zd.ZoneName, syncstate.Adds, syncstate.Removes)
	if err != nil {
		return "", 0, err, UpdateResult{}
	}

	// 3. Fetch the SIG(0) key from the keystore
	log.Printf("SyncZoneDelegationViaUpdate: Fetching the private key for %s", zd.ZoneName)
	sak, err := kdb.GetSig0Keys(zd.ZoneName, Sig0StateActive)
	if err != nil {
		log.Printf("SyncZoneDelegationViaUpdate: Error from kdb.GetSig0Keys(%s, %s): %v", zd.ZoneName, Sig0StateActive, err)
		return "", 0, err, UpdateResult{}
	}
	if len(sak.Keys) == 0 {
		log.Printf("SyncZoneDelegationViaUpdate: No active SIG(0) key found for zone %s", zd.ZoneName)
		return "", 0, fmt.Errorf("no active SIG(0) key found for zone %s", zd.ZoneName), UpdateResult{}
	}

	// 4. Sign the msg
	log.Printf("SyncZoneDelegationViaUpdate: Signing the DNS UPDATE %s", zd.ZoneName)
	smsg, err := SignMsg(*m, zd.ZoneName, sak)
	if err != nil {
		log.Printf("SyncZoneDelegationViaUpdate: Error from SignMsgNG(%s): %v", zd.ZoneName, err)
		return "", 0, err, UpdateResult{}
	}
	if smsg == nil {
		log.Printf("SyncZoneDelegationViaUpdate: Error from SignMsgNG(%s): %v", zd.ZoneName, err)
		return "", 0, err, UpdateResult{}
	}

	// 5. Send the msg
	log.Printf("SyncZoneDelegationViaUpdate: Sending the signed update to %s (addresses: %v) port %d",
		dsynctarget.Name, dsynctarget.Addresses, dsynctarget.Port)

	rcode, err, ur := SendUpdate(smsg, zd.Parent, dsynctarget.Addresses)
	if err != nil {
		log.Printf("Error from SendUpdate(%s): %v", zd.Parent, err)
		return "", 0, err, ur
	}
	msg := fmt.Sprintf("SendUpdate(%s) returned rcode %s", zd.Parent, dns.RcodeToString[rcode])
	log.Print(msg)
	for _, tes := range ur.TargetStatus {
		log.Printf("SyncZoneDelegationViaUpdate: TargetUpdateStatus: %v", tes)
	}

	// 6. Check the response
	// 7. Return result to CLI

	return msg, uint8(rcode), err, ur
}

func (zd *ZoneData) SyncZoneDelegationViaNotify(kdb *KeyDB, notifyq chan NotifyRequest, syncstate DelegationSyncStatus,
	dsynctarget *DsyncTarget) (string, uint8, error) {

	if zd.Options[OptAllowUpdates] {
		// 1. Verify that a CSYNC (or CDS) RR is published. If not, create and publish as needed.
		err := zd.PublishCsyncRR()
		if err != nil {
			log.Printf("SyncZoneDelegationViaNotify: Error from PublishCsync(): %v", err)
			return "", dns.RcodeServerFailure, err
		}

		// Try to sign the CSYNC RRset
		if zd.Options[OptOnlineSigning] {
			apex, _ := zd.GetOwner(zd.ZoneName)
			rrset := apex.RRtypes[dns.TypeCSYNC]
			//			dak, err := kdb.GetDnssecActiveKeys(zd.ZoneName)
			//			if err != nil {
			//				log.Printf("SyncZoneDelegationViaNotify: failed to get dnssec key for zone %s", zd.ZoneName)
			//			} else {
			//			if len(dak.ZSKs) > 0 {
			_, err := zd.SignRRset(&rrset, zd.ZoneName, nil, true) // Let's force signing
			if err != nil {
				log.Printf("Error signing %s: %v", zd.ZoneName, err)
			} else {
				log.Printf("Signed %s: %v", zd.ZoneName, err)
			}
			//			}
			//			}
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
	notifyq <- NotifyRequest{
		ZoneName: zd.ZoneName,
		ZoneData: zd,
		RRtype:   dns.TypeCSYNC,         // this is only about syncing delegation data, not about rolling DNSSEC keys.
		Targets:  dsynctarget.Addresses, // already in addr:port format
	}

	msg := fmt.Sprintf("SyncZoneDelegationViaNotify: Sent notify request for zone %s to NotifierEngine", zd.ZoneName)
	log.Print(msg)

	return msg, dns.RcodeSuccess, nil
}
