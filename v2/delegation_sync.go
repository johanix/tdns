/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

// Update mode constants for parent delegation updates
const (
	UpdateModeReplace = "replace" // Replace all existing delegation data with new data
	UpdateModeDelta   = "delta"   // Use incremental adds/removes (delta updates)
)

func (kdb *KeyDB) DelegationSyncher(ctx context.Context, delsyncq chan DelegationSyncRequest, notifyq chan NotifyRequest, conf *Config) error {

	lgDns.Info("DelegationSyncher: starting")
	imr := func() *Imr { return conf.Internal.ImrEngine }
	var err error
	for {
		select {
		case <-ctx.Done():
			lgDns.Info("DelegationSyncher: terminating due to context cancelled")
			return nil
		case ds, ok := <-delsyncq:
			if !ok {
				lgDns.Info("DelegationSyncher: delsyncq closed, terminating")
				return nil
			}
			zd := ds.ZoneData
			dss := ds.SyncStatus

			switch ds.Command {

			case "DELEGATION-SYNC-SETUP":
				// This is the initial setup request, when we first load a zone that has the delegation-sync-child option set.
				err = zd.DelegationSyncSetup(ctx, kdb)
				if err != nil {
					lgDns.Error("DelegationSyncher: error from DelegationSyncSetup, ignoring sync request", "zone", ds.ZoneName, "err", err)
					continue
				}

			case "INITIAL-KEY-UPLOAD":
				// This case is not yet used, intended for automating the initial key upload to parent
				lgDns.Info("DelegationSyncher: request for initial key upload", "zone", zd.ZoneName)
				// err := zd.UploadKeyToParent(kdb)
				// if err != nil {
				// 	log.Printf("DelegationSyncher: Zone %s: Error from UploadKeyToParent(): %v. Ignoring sync request.", ds.ZoneName, err)
				// 	continue
				// }
				lgDns.Info("DelegationSyncher: initial key upload complete", "zone", ds.ZoneName)
				continue

			case "DELEGATION-STATUS":
				lgDns.Info("DelegationSyncher: request for delegation status", "zone", zd.ZoneName)

				syncstate, err := zd.AnalyseZoneDelegation(imr())
				if err != nil {
					lgDns.Error("DelegationSyncher: error from AnalyseZoneDelegation, ignoring sync request", "zone", ds.ZoneName, "err", err)
					syncstate.Error = true
					syncstate.ErrorMsg = err.Error()
				}
				if ds.Response != nil {
					ds.Response <- syncstate
				}
				continue

			case "SYNC-DELEGATION":
				lgDns.Info("DelegationSyncher: request for delegation sync",
					"zone", ds.ZoneName,
					"ns_removes", len(dss.NsRemoves), "ns_adds", len(dss.NsAdds),
					"a_removes", len(dss.ARemoves), "a_adds", len(dss.AAdds),
					"aaaa_removes", len(dss.AAAARemoves), "aaaa_adds", len(dss.AAAAAdds))

				// Only the elected leader sends DDNS to the parent
				if lem := conf.Internal.LeaderElectionManager; lem != nil {
					if !lem.IsLeader(ZoneName(ds.ZoneName)) {
						lgDns.Info("DelegationSyncher: not the delegation sync leader, skipping DDNS", "zone", ds.ZoneName)
						continue
					}
				}

				zd := ds.ZoneData
				if zd.Parent == "" || zd.Parent == "." {
					zd.Parent, err = imr().ParentZone(zd.ZoneName)
					if err != nil {
						lgDns.Error("DelegationSyncher: error from ParentZone, ignoring sync request", "zone", ds.ZoneName, "err", err)
						continue
					}
				}

				msg, rcode, ur, err := zd.SyncZoneDelegation(ctx, kdb, notifyq, ds.SyncStatus, imr())
				if err != nil {
					lgDns.Error("DelegationSyncher: error from SyncZoneDelegation, ignoring sync request", "zone", ds.ZoneName, "err", err)
					continue
				}
				ds.SyncStatus.UpdateResult = ur
				lgDns.Info("DelegationSyncher: SyncZoneDelegation completed", "zone", ds.ZoneName, "msg", msg, "rcode", dns.RcodeToString[int(rcode)])
				// Notify peer agents that parent sync is done
				go notifyPeersParentSyncDone(conf, ds.ZoneName, dns.RcodeToString[int(rcode)], msg)

			case "EXPLICIT-SYNC-DELEGATION":
				lgDns.Info("DelegationSyncher: request for explicit delegation sync", "zone", ds.ZoneName)

				syncstate, err := zd.AnalyseZoneDelegation(imr())
				if err != nil {
					lgDns.Error("DelegationSyncher: error from AnalyseZoneDelegation, ignoring sync request", "zone", ds.ZoneName, "err", err)
					syncstate.Error = true
					syncstate.ErrorMsg = err.Error()
					if ds.Response != nil {
						ds.Response <- syncstate
					}
					continue
				}

				// Only the elected leader sends DDNS to the parent
				if lem := conf.Internal.LeaderElectionManager; lem != nil {
					if !lem.IsLeader(ZoneName(ds.ZoneName)) {
						lgDns.Info("DelegationSyncher: not the delegation sync leader, skipping DDNS", "zone", ds.ZoneName)
						syncstate.Msg = "not the delegation sync leader, skipping DDNS"
						if ds.Response != nil {
							ds.Response <- syncstate
						}
						continue
					}
				}

				if syncstate.InSync {
					lgDns.Info("DelegationSyncher: delegation data in parent is in sync with child, no action needed",
						"zone", syncstate.ZoneName, "parent", syncstate.Parent)
					if ds.Response != nil {
						ds.Response <- syncstate
					}
					continue
				}

				// Not in sync, let's fix that.
				msg, rcode, ur, err := zd.SyncZoneDelegation(ctx, kdb, notifyq, syncstate, imr())
				if err != nil {
					lgDns.Error("DelegationSyncher: error from SyncZoneDelegation, ignoring sync request", "zone", ds.ZoneName, "err", err)
					syncstate.Error = true
					syncstate.ErrorMsg = err.Error()
					syncstate.UpdateResult = ur
				} else {
					lgDns.Info("DelegationSyncher: SyncZoneDelegation completed", "zone", ds.ZoneName, "msg", msg, "rcode", dns.RcodeToString[int(rcode)])
					// Notify peer agents that parent sync is done
					go notifyPeersParentSyncDone(conf, ds.ZoneName, dns.RcodeToString[int(rcode)], msg)
				}
				syncstate.Msg = msg
				syncstate.Rcode = rcode

				if ds.Response != nil {
					ds.Response <- syncstate
				}
				continue

			case "SYNC-DNSKEY-RRSET":
				lgDns.Info("DelegationSyncher: request for DNSKEY RRset sync", "zone", ds.ZoneName)
				if zd.Options[OptMultiProvider] {
					lgDns.Info("DelegationSyncher: multisigner zone, notifying controller", "zone", ds.ZoneName)
					notifyq <- NotifyRequest{
						ZoneName: zd.ZoneName,
						ZoneData: zd,
						RRtype:   dns.TypeDNSKEY, // this is only about syncing delegation data, not about rolling DNSSEC keys.
						// Targets:  dsynctarget.Addresses, // already in addr:port format
						Targets: zd.MultiSigner.Controller.Notify.Targets,
						Urgent:  true,
					}
				}

				// Publish CDS records from current DNSKEYs if zone has delegation sync
				if zd.Options[OptDelSyncChild] {
					if err := zd.PublishCdsRRs(); err != nil {
						lgDns.Error("DelegationSyncher: error publishing CDS", "zone", zd.ZoneName, "err", err)
					} else {
						lgDns.Info("DelegationSyncher: published CDS from DNSKEYs", "zone", zd.ZoneName)
					}
				}

			default:
				lgDns.Warn("DelegationSyncher: unknown command, ignoring", "zone", ds.ZoneName, "command", ds.Command)
			}
		}
	}
}

// notifyPeersParentSyncDone sends STATUS-UPDATE("parentsync-done") to all
// remote agents for the zone. Called after a successful parent delegation sync.
func notifyPeersParentSyncDone(conf *Config, zonename string, result string, msg string) {
	tm := conf.Internal.MPTransport
	if tm == nil || tm.DNSTransport == nil {
		lgDns.Debug("notifyPeersParentSyncDone: no TransportManager, skipping peer notification", "zone", zonename)
		return
	}

	agents, err := tm.getAllAgentsForZone(ZoneName(zonename))
	if err != nil {
		lgDns.Warn("notifyPeersParentSyncDone: failed to get agents for zone", "zone", zonename, "err", err)
		return
	}

	if len(agents) == 0 {
		lgDns.Debug("notifyPeersParentSyncDone: no remote agents for zone", "zone", zonename)
		return
	}

	for _, agentID := range agents {
		peer, exists := tm.PeerRegistry.Get(string(agentID))
		if !exists {
			lgDns.Debug("notifyPeersParentSyncDone: agent not in peer registry, skipping", "agent", agentID, "zone", zonename)
			continue
		}

		post := &core.StatusUpdatePost{
			Zone:    zonename,
			SubType: "parentsync-done",
			Result:  result,
			Msg:     msg,
			Time:    time.Now(),
		}

		go func(p *transport.Peer, id AgentId) {
			sendCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			err := tm.DNSTransport.SendStatusUpdate(sendCtx, p, post)
			if err != nil {
				lgDns.Warn("notifyPeersParentSyncDone: failed to send", "agent", id, "zone", zonename, "err", err)
			} else {
				lgDns.Info("notifyPeersParentSyncDone: sent", "agent", id, "zone", zonename)
			}
		}(peer, agentID)
	}
}

func parseKeygenAlgorithm(configKey string, defaultAlg uint8) (uint8, error) {
	algstr := viper.GetString(configKey)
	alg := dns.StringToAlgorithm[strings.ToUpper(algstr)]
	if alg == 0 {
		lgDns.Warn("unknown keygen algorithm, using default", "algorithm", algstr, "configKey", configKey, "default", dns.AlgorithmToString[defaultAlg])
		alg = defaultAlg
	}
	return alg, nil
}

func (zd *ZoneData) DelegationSyncSetup(ctx context.Context, kdb *KeyDB) error {
	if !zd.Options[OptDelSyncChild] {
		lgDns.Debug("DelegationSyncSetup: zone does not have child-side delegation sync enabled, skipping", "zone", zd.ZoneName)
		return nil
	}

	// algstr := viper.GetString("delegationsync.child.update.keygen.algorithm")
	// alg := dns.StringToAlgorithm[strings.ToUpper(algstr)]
	// if alg == 0 {
	// 	log.Printf("Sig0KeyPreparation: Unknown keygen algorithm: \"%s\", using ED25519", algstr)
	// 	alg = dns.ED25519
	// }
	alg, err := parseKeygenAlgorithm("delegationsync.child.update.keygen.algorithm", dns.ED25519)
	if err != nil {
		lgDns.Error("DelegationSyncSetup: error from parseKeygenAlgorithm", "zone", zd.ZoneName, "err", err)
		return err
	}

	err = zd.Sig0KeyPreparation(zd.ZoneName, alg, kdb)
	if err != nil {
		lgDns.Error("DelegationSyncSetup: error from Sig0KeyPreparation", "zone", zd.ZoneName, "err", err)
		return err
	}

	// 4. There is a KEY RRset, we have tried to sign it if possible. But has it been uploaded to the parent?
	// XXX: This is a bit of a hack, but we need to bootstrap the parent with the child's SIG(0) key. In the future
	// we should keep state of whether successful key bootstrapping has been done or not in the keystore.
	msg, ur, err := zd.BootstrapSig0KeyWithParent(ctx, alg)
	if err != nil {
		lgDns.Error("DelegationSyncSetup: error from BootstrapSig0KeyWithParent", "zone", zd.ZoneName, "err", err)
		for _, tes := range ur.TargetStatus {
			lgDns.Error("DelegationSyncSetup: TargetUpdateStatus", "zone", zd.ZoneName, "status", tes)
		}
		return err
	}
	lgDns.Info("DelegationSyncSetup: SIG(0) key bootstrap complete", "zone", zd.ZoneName, "msg", msg)
	return nil
}

func (zd *ZoneData) ParentSig0KeyPrep(name string, kdb *KeyDB) error {
	// algstr := viper.GetString("delegationsync.parent.update.keygen.algorithm")
	// alg := dns.StringToAlgorithm[strings.ToUpper(algstr)]
	// if alg == 0 {
	// 	log.Printf("Sig0KeyPreparation: Unknown keygen algorithm: \"%s\", using ED25519", algstr)
	// 	alg = dns.ED25519
	// }
	alg, err := parseKeygenAlgorithm("delegationsync.parent.update.keygen.algorithm", dns.ED25519)
	if err != nil {
		lgDns.Error("ParentSig0KeyPrep: error from parseKeygenAlgorithm", "zone", zd.ZoneName, "err", err)
		return err
	}

	return zd.Sig0KeyPreparation(name, alg, kdb)
}

// MusicSig0KeyPrep and ParentSig0KeyPrep are identical except for the source of the keygen algorithm
// which is specified in the relevant section of the configuration file.
func (zd *ZoneData) MusicSig0KeyPrep(name string, kdb *KeyDB) error {
	// algstr := viper.GetString("delegationsync.child.update.keygen.algorithm")
	// alg := dns.StringToAlgorithm[strings.ToUpper(algstr)]
	// if alg == 0 {
	// 	log.Printf("Sig0KeyPreparation: Unknown keygen algorithm: \"%s\", using ED25519", algstr)
	// 	alg = dns.ED25519
	// }
	alg, err := parseKeygenAlgorithm("delegationsync.child.update.keygen.algorithm", dns.ED25519)
	if err != nil {
		lgDns.Error("MusicSig0KeyPrep: error from parseKeygenAlgorithm", "zone", zd.ZoneName, "err", err)
		return err
	}

	return zd.Sig0KeyPreparation(name, alg, kdb)
}

func (zd *ZoneData) Sig0KeyPreparation(name string, alg uint8, kdb *KeyDB) error {
	lgDns.Info("Sig0KeyPreparation: setting up SIG(0) key pair", "zone", zd.ZoneName, "name", name)

	lgDns.Debug("Sig0KeyPreparation: checking whether zone allows updates and has KEY RRset published", "zone", zd.ZoneName, "name", name)
	owner, err := zd.GetOwner(name)
	lgDns.Debug("Sig0KeyPreparation: GetOwner result", "name", name, "owner", owner, "err", err)
	if err != nil {
		return fmt.Errorf("Sig0KeyPreparation(%s) failed to get owner: %v", name, err)
	}

	var keyrrexist bool
	if owner != nil {
		_, keyrrexist = owner.RRtypes.Get(dns.TypeKEY)
	}

	if keyrrexist && !zd.Options[OptDontPublishKey] {
		err := zd.VerifyPublishedKeyRRs()
		if err != nil {
			lgDns.Error("error from VerifyPublishedKeyRRs", "name", name, "err", err)
			return err
		}
		lgDns.Info("Sig0KeyPreparation: verified published KEY RRset", "name", name)
	}

	// 1. Are updates to the zone data allowed?
	if !zd.Options[OptAllowUpdates] {
		if keyrrexist {
			lgDns.Debug("Sig0KeyPreparation: zone does not allow updates, but KEY RRset is already published", "zone", zd.ZoneName, "name", name)
		} else {
			lgDns.Debug("Sig0KeyPreparation: zone does not allow updates, cannot publish KEY RRset", "zone", zd.ZoneName, "name", name)
		}
		return nil
	}

	lgDns.Debug("Sig0KeyPreparation: zone allows updates", "zone", zd.ZoneName, "name", name, "keyrrexist", keyrrexist, "dontPublishKey", zd.Options[OptDontPublishKey])

	// 2. Updates allowed, but there is no KEY RRset published.
	if !keyrrexist && !zd.Options[OptDontPublishKey] {
		lgDns.Debug("Sig0KeyPreparation: fetching the private SIG(0) key", "name", name)
		sak, err := kdb.GetSig0Keys(name, Sig0StateActive)
		if err != nil {
			lgDns.Error("Sig0KeyPreparation: error from GetSig0Keys, parent sync via UPDATE not possible", "name", name, "state", Sig0StateActive, "err", err)
			return err
		}
		if len(sak.Keys) == 0 {
			lgDns.Info("Sig0KeyPreparation: no active SIG(0) key found, will generate new key", "name", name)

			kp := KeystorePost{
				Command:    "sig0-mgmt",
				SubCommand: "generate",
				Zone:       zd.ZoneName,
				Keyname:    name,
				Algorithm:  alg,
				State:      Sig0StateActive,
				Creator:    "del-sync-setup",
			}
			resp, err := zd.KeyDB.Sig0KeyMgmt(nil, kp)
			if err != nil {
				return fmt.Errorf("Sig0KeyPreparation(%s) failed to generate keypair: %v", name, err)
			}
			lgDns.Info("Sig0KeyPreparation: key generated", "msg", resp.Msg)

			sak, err = zd.KeyDB.GetSig0Keys(name, Sig0StateActive)
			if err != nil {
				return fmt.Errorf("Sig0KeyPreparation(%s, after key generation) failed to get SIG(0) active keys: %v", name, err)
			}
		}

		if len(sak.Keys) == 0 {
			lgDns.Error("Sig0KeyPreparation: no active SIG(0) key found, parent sync via UPDATE not possible", "name", name, "zone", zd.ZoneName)
			return fmt.Errorf("no active SIG(0) key found for name %s in zone %s. Parent sync via UPDATE not possible", name, zd.ZoneName)
		}
		lgDns.Info("Sig0KeyPreparation: publishing KEY RR", "name", name, "zone", zd.ZoneName)
		err = zd.PublishKeyRRs(sak)
		if err != nil {
			lgDns.Error("Sig0KeyPreparation: error from PublishKeyRRs", "name", name, "zone", zd.ZoneName, "err", err)
			return err
		}
	}

	return nil
}

// Note that there are two types of determining whether delegation synchronization is needed:
// 1. Implicit: we notice that the delegation information in the child has changed and therefore NOTIFY or UPDATE the parent.
// 2. Explicit: we query the parent for the delegation information and if it differs from the child, we NOTIFY or UPDATE the parent.
// tdns.AnalyseZoneDelegation() is used for explicit delegation synchronization.
// tdns.DelegationDataChanged() is used for implicit delegation synchronization.

// SyncZoneDelegation() is used for delegation synchronization request via API.
func (zd *ZoneData) SyncZoneDelegation(ctx context.Context, kdb *KeyDB, notifyq chan NotifyRequest, syncstate DelegationSyncStatus, imr *Imr) (string, uint8, UpdateResult, error) {

	//	syncstate, err := AnalyseZoneDelegation(conf, zd)
	//	if err != nil {
	//		return "", err
	//	}

	if syncstate.InSync {
		return fmt.Sprintf("Zone \"%s\" delegation data in parent \"%s\" is in sync. No action needed.",
			syncstate.ZoneName, zd.Parent), 0, UpdateResult{}, nil
	} else {
		lgDns.Info("zone delegation data in parent is NOT in sync, sync action needed",
			"zone", syncstate.ZoneName, "parent", zd.Parent)
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

	scheme, dsynctarget, err := zd.BestSyncScheme(ctx, imr)
	if err != nil {
		lgDns.Error("DelegationSyncEngine: error from BestSyncScheme, ignoring sync request", "zone", zd.ZoneName, "err", err)
		return "", 0, UpdateResult{}, err
	}

	var msg string
	var rcode uint8
	var ur UpdateResult

	switch scheme {
	case "UPDATE":
		msg, rcode, ur, err = zd.SyncZoneDelegationViaUpdate(kdb, syncstate, dsynctarget)
	case "NOTIFY":
		msg, rcode, err = zd.SyncZoneDelegationViaNotify(kdb, notifyq, syncstate, dsynctarget)
	}

	return msg, rcode, ur, err
}

func (zd *ZoneData) SyncZoneDelegationViaUpdate(kdb *KeyDB, syncstate DelegationSyncStatus,
	dsynctarget *DsyncTarget) (string, uint8, UpdateResult, error) {

	// dump.P(syncstate)

	// Check the parent-update option to determine whether to use replace or delta mode
	updateMode := UpdateModeDelta // default
	if kdb.Options != nil {
		if mode, exists := kdb.Options[AuthOptParentUpdate]; exists {
			updateMode = mode
		}
	}

	var m *dns.Msg
	var err error

	if updateMode == UpdateModeReplace {
		// Replace mode has an unresolved bug — refuse to proceed and make it visible.
		err := fmt.Errorf("parent-update replace mode is currently broken and cannot be used")
		zd.SetError(ConfigError, "parent-update replace mode is currently broken and cannot be used")
		lgDns.Error("SyncZoneDelegationViaUpdate: replace mode disabled", "zone", zd.ZoneName)
		return "", 0, UpdateResult{}, err
	} else {
		// Delta mode: use adds and removes (existing behavior)
		lgDns.Info("SyncZoneDelegationViaUpdate: using delta mode", "zone", zd.ZoneName)
		// Ensure that we don't count any changes twice.
		syncstate.Adds = []dns.RR{}
		syncstate.Removes = []dns.RR{}

		// If UPDATE:
		// 2. Create DNS UPDATE msg
		// var adds, removes []dns.RR
		syncstate.Adds = append(syncstate.Adds, syncstate.NsAdds...)
		syncstate.Adds = append(syncstate.Adds, syncstate.AAdds...)
		syncstate.Adds = append(syncstate.Adds, syncstate.AAAAAdds...)
		syncstate.Adds = append(syncstate.Adds, syncstate.DSAdds...)
		syncstate.Removes = append(syncstate.Removes, syncstate.NsRemoves...)
		syncstate.Removes = append(syncstate.Removes, syncstate.ARemoves...)
		syncstate.Removes = append(syncstate.Removes, syncstate.AAAARemoves...)
		syncstate.Removes = append(syncstate.Removes, syncstate.DSRemoves...)

		// dump.P(syncstate)
		m, err = CreateChildUpdate(zd.Parent, zd.ZoneName, syncstate.Adds, syncstate.Removes)
		if err != nil {
			return "", 0, UpdateResult{}, err
		}
	}

	// 3. Fetch the SIG(0) key from the keystore
	lgDns.Debug("SyncZoneDelegationViaUpdate: fetching the private key", "zone", zd.ZoneName)
	sak, err := kdb.GetSig0Keys(zd.ZoneName, Sig0StateActive)
	if err != nil {
		lgDns.Error("SyncZoneDelegationViaUpdate: error from GetSig0Keys", "zone", zd.ZoneName, "state", Sig0StateActive, "err", err)
		return "", 0, UpdateResult{}, err
	}
	if len(sak.Keys) == 0 {
		lgDns.Error("SyncZoneDelegationViaUpdate: no active SIG(0) key found", "zone", zd.ZoneName)
		return "", 0, UpdateResult{}, fmt.Errorf("no active SIG(0) key found for zone %s", zd.ZoneName)
	}

	// 4. Sign the msg
	lgDns.Debug("SyncZoneDelegationViaUpdate: signing the DNS UPDATE", "zone", zd.ZoneName)
	smsg, err := SignMsg(*m, zd.ZoneName, sak)
	if err != nil {
		lgDns.Error("SyncZoneDelegationViaUpdate: error from SignMsg", "zone", zd.ZoneName, "err", err)
		return "", 0, UpdateResult{}, err
	}
	if smsg == nil {
		lgDns.Error("SyncZoneDelegationViaUpdate: SignMsg returned nil", "zone", zd.ZoneName, "err", err)
		return "", 0, UpdateResult{}, err
	}

	// 5. Send the msg
	lgDns.Info("SyncZoneDelegationViaUpdate: sending the signed update",
		"target", dsynctarget.Name, "addresses", dsynctarget.Addresses, "port", dsynctarget.Port)

	rcode, ur, err := SendUpdate(smsg, zd.Parent, dsynctarget.Addresses)
	if err != nil {
		lgDns.Error("error from SendUpdate", "zone", zd.Parent, "err", err)
		return "", 0, ur, err
	}
	msg := fmt.Sprintf("SendUpdate(%s) returned rcode %s", zd.Parent, dns.RcodeToString[rcode])
	lgDns.Info("SyncZoneDelegationViaUpdate: update sent", "zone", zd.Parent, "rcode", dns.RcodeToString[rcode])
	for _, tes := range ur.TargetStatus {
		lgDns.Debug("SyncZoneDelegationViaUpdate: TargetUpdateStatus", "status", tes)
	}

	// 6. Check the response
	// 7. Return result to CLI

	return msg, uint8(rcode), ur, err
}

func (zd *ZoneData) SyncZoneDelegationViaNotify(kdb *KeyDB, notifyq chan NotifyRequest, syncstate DelegationSyncStatus,
	dsynctarget *DsyncTarget) (string, uint8, error) {

	if zd.Options[OptAllowUpdates] {
		// 1. Verify that a CSYNC (or CDS) RR is published. If not, create and publish as needed.
		err := zd.PublishCsyncRR()
		if err != nil {
			lgDns.Error("SyncZoneDelegationViaNotify: error from PublishCsyncRR", "err", err)
			return "", dns.RcodeServerFailure, err
		}

		// Try to sign the CSYNC RRset
		if zd.Options[OptOnlineSigning] || zd.Options[OptInlineSigning] {
			apex, _ := zd.GetOwner(zd.ZoneName)
			rrset, _ := apex.RRtypes.Get(dns.TypeCSYNC)
			//			dak, err := kdb.GetDnssecActiveKeys(zd.ZoneName)
			//			if err != nil {
			//				log.Printf("SyncZoneDelegationViaNotify: failed to get dnssec key for zone %s", zd.ZoneName)
			//			} else {
			//			if len(dak.ZSKs) > 0 {
			_, err := zd.SignRRset(&rrset, zd.ZoneName, nil, true) // Let's force signing
			if err != nil {
				lgDns.Error("error signing CSYNC RRset", "zone", zd.ZoneName, "err", err)
			} else {
				lgDns.Debug("signed CSYNC RRset", "zone", zd.ZoneName)
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

	lgDns.Debug("DSYNC target for NOTIFY", "zone", zd.ZoneName, "target", dsynctarget)

	// Send NOTIFY(CSYNC) for NS or glue (A/AAAA) changes
	if len(syncstate.NsAdds) > 0 || len(syncstate.NsRemoves) > 0 || len(syncstate.AAdds) > 0 || len(syncstate.ARemoves) > 0 || len(syncstate.AAAAAdds) > 0 || len(syncstate.AAAARemoves) > 0 {
		notifyq <- NotifyRequest{
			ZoneName: zd.ZoneName,
			ZoneData: zd,
			RRtype:   dns.TypeCSYNC,
			Targets:  dsynctarget.Addresses,
		}
		lgDns.Info("SyncZoneDelegationViaNotify: sent NOTIFY(CSYNC)", "zone", zd.ZoneName)
	}

	// Send NOTIFY(CDS) for DS/DNSKEY changes
	if len(syncstate.DSAdds) > 0 || len(syncstate.DSRemoves) > 0 {
		notifyq <- NotifyRequest{
			ZoneName: zd.ZoneName,
			ZoneData: zd,
			RRtype:   dns.TypeCDS,
			Targets:  dsynctarget.Addresses,
		}
		lgDns.Info("SyncZoneDelegationViaNotify: sent NOTIFY(CDS)", "zone", zd.ZoneName)
	}

	msg := fmt.Sprintf("SyncZoneDelegationViaNotify: Sent notify request(s) for zone %s to NotifierEngine", zd.ZoneName)
	return msg, dns.RcodeSuccess, nil
}
