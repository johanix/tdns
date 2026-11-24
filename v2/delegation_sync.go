/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// Update mode constants for parent delegation updates
const (
	UpdateModeReplace = "replace" // Replace all existing delegation data with new data
	UpdateModeDelta   = "delta"   // Use incremental adds/removes (delta updates)
)

// DelegationSyncher runs tdns's delegation syncher: every request on delsyncq
// is run by handleDelegationSyncRequest, on its parent's queue
// (RunDelegationSyncLanes), so a parent that does not answer holds up only the
// syncs to that parent (#1002).
func (kdb *KeyDB) DelegationSyncher(ctx context.Context, delsyncq chan DelegationSyncRequest, notifyq chan NotifyRequest, conf *Config) error {

	lgDns.Info("DelegationSyncher: starting")
	return RunDelegationSyncLanes(ctx, delsyncq, func(ctx context.Context, ds DelegationSyncRequest) {
		kdb.handleDelegationSyncRequest(ctx, delsyncq, notifyq, conf, ds)
	})
}

// handleDelegationSyncRequest runs one request: the syncher's body. Requests
// for zones under different parents run concurrently; a zone's own requests
// run one at a time, in order.
func (kdb *KeyDB) handleDelegationSyncRequest(ctx context.Context, delsyncq chan DelegationSyncRequest,
	notifyq chan NotifyRequest, conf *Config, ds DelegationSyncRequest) {

	imr := func() *Imr { return conf.Internal.ImrEngine }

	zd := ds.ZoneData

	if delegationSyncRetryStale(ds) {
		lgDns.Info("DelegationSyncher: retry dropped; the zone is no longer loaded",
			"zone", ds.ZoneName, "command", ds.Command, "attempt", ds.Attempt)
		return
	}

	switch ds.Command {

	case "DELEGATION-SYNC-SETUP":
		handleDelegationSyncSetup(ctx, conf, delsyncq, kdb, zd, ds)
		return

	case "INITIAL-KEY-UPLOAD":
		// This case is not yet used, intended for automating the initial key upload to parent
		lgDns.Info("DelegationSyncher: request for initial key upload", "zone", zd.ZoneName)
		// err := zd.UploadKeyToParent(kdb)
		// if err != nil {
		// 	log.Printf("DelegationSyncher: Zone %s: Error from UploadKeyToParent(): %v. Ignoring sync request.", ds.ZoneName, err)
		// 	continue
		// }
		lgDns.Info("DelegationSyncher: initial key upload complete", "zone", ds.ZoneName)
		return

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
		return

	case "SYNC-DELEGATION":
		handleSyncDelegationWith(ds, syncDelegationSteps{
			resolve: func() error {
				_, err := zd.ResolveParentVia(imr())
				return err
			},
			sync: func(dss DelegationSyncStatus) (string, uint8, UpdateResult, string, error) {
				return zd.syncZoneDelegationVia(ctx, kdb, notifyq, dss, imr())
			},
			requeue: func(next DelegationSyncRequest, delay time.Duration) {
				requeueLookAfter(ctx, delsyncq, next, delay)
			},
		})

	case "EXPLICIT-SYNC-DELEGATION":
		_ = handleExplicitSyncWith(ctx, conf.Internal.ImrReady, delsyncq, ds,
			func() DelegationSyncStatus { return zd.runExplicitSync(ctx, kdb, notifyq, imr()) })
		return

	case "SYNC-DS":
		// The KSK rollover engine's DS push (delsync_ds.go). The
		// engine waits for the answer with a deadline, so this
		// starts now and is never deferred; and it runs on its own
		// goroutine, because a delivery is a parent round trip, a
		// NOTIFY path a CDS publish through the zone updater first,
		// and the requests behind it in the parent's queue need not
		// wait for that. When one loop was the queue's only reader,
		// waiting here could also hold the updater, which enqueues
		// every delegation change here from afterPublish and which
		// the CDS publish needs.
		go handleDSSync(ctx, kdb, notifyq, imr(), ds)
		return

	case "SIGNALS-EDITED":
		_ = handleSignalsEditedArm(ctx, conf.Internal.ImrReady, delsyncq, zd, ds,
			func() {
				handleSignalsEditedWith(zd, ds.SignalTypes, signalsEditedStepsFor(ctx, kdb, notifyq, imr(), zd))
			})
		return

	case "SYNC-DNSKEY-RRSET":
		lgDns.Info("DelegationSyncher: request for DNSKEY RRset sync", "zone", ds.ZoneName)
		if zd.Options[OptMultiProvider] {
			lgDns.Info("DelegationSyncher: multisigner zone, notifying controller", "zone", ds.ZoneName)
			if !sendNotifyRequest(ctx, notifyq, NotifyRequest{
				ZoneName: zd.ZoneName,
				ZoneData: zd,
				RRtype:   dns.TypeDNSKEY, // this is only about syncing delegation data, not about rolling DNSSEC keys.
				// Targets:  dsynctarget.Addresses, // already in addr:port format
				Targets: zd.MultiSigner.Controller.Notify.Targets,
				Urgent:  true,
			}) {
				return // ctx ended; sendNotifyRequest said so
			}
		}

		// Publish the CDS if the zone has delegation sync. The DS engine owns
		// the CDS RRset and asks the zone's DS model what goes in it. For a
		// multi-provider zone it writes none: that DS set is the
		// multi-provider agent's to coordinate.
		if zd.Options[OptParentSync] {
			res := kdb.askDSEngine(ctx, DSEngineRequest{cmd: dsCmdEnsureCDS, zd: zd})
			switch {
			case res.err != nil:
				lgDns.Error("DelegationSyncher: error publishing CDS", "zone", zd.ZoneName, "err", res.err)
			case res.deferred != "":
				lgDns.Info("DelegationSyncher: CDS left to its owner", "zone", zd.ZoneName, "reason", res.deferred)
			default:
				lgDns.Info("DelegationSyncher: published CDS", "zone", zd.ZoneName, "keyids", cdsKeyids(res.cds))
			}
		}

	case "REFRESH-SYNC-DELEGATION":
		// A parentsync child's compare with the parent, queued after a
		// refresh changed its NS or glue, and once at load
		// (delsync_refresh.go).
		handleRefreshSyncDelegation(ctx, conf, delsyncq, kdb, notifyq, zd, ds)

	case "PROXY-SYNC", "PROXY-UPDATE-SETUP", "PROXY-UPDATE-GATE":
		// Both need an IMR: the parent's DSYNC records are discovered,
		// not configured. At startup the zone's first transfer routinely
		// arrives before InitImrEngine has finished priming, and the
		// plan then skips every scheme with "no IMR available" and
		// nothing retries -- so a restarted proxy forwarded nothing at
		// all until the child zone happened to change again.
		//
		// Put the request back rather than running it against a nil
		// IMR, and let it return exactly when the IMR is announced.
		if !conf.Internal.ImrReady.Published() {
			_ = deferForImr(ctx, delsyncq, conf.Internal.ImrReady, ds)
			return
		}
		switch ds.Command {
		case "PROXY-SYNC":
			proxySync(ctx, zd, kdb, notifyq, delsyncq, imr(), ds)
		case "PROXY-UPDATE-SETUP":
			proxyStartupReconcile(ctx, zd, kdb, notifyq, delsyncq, imr(), ds)
		case "PROXY-UPDATE-GATE":
			proxyUpdateGate(ds.ZoneName, func() (ProxyUpdateState, error) {
				return zd.ProxyUpdatePreconditionCheck(ctx, kdb, imr())
			})
		}

	default:
		lgDns.Warn("DelegationSyncher: unknown command, ignoring", "zone", ds.ZoneName, "command", ds.Command)
	}
}

// parseKeygenAlgorithm resolves a configured algorithm NAME to its code. It
// takes the value rather than a config key: reading the key here was the last
// place the delegationsync block was still consulted through viper, which is
// never populated in tdns-auth or tdns-agent, so every one of these settings was
// silently ignored no matter what an operator wrote.
func parseKeygenAlgorithm(algstr string, defaultAlg uint8) (uint8, error) {
	alg := dns.StringToAlgorithm[strings.ToUpper(algstr)]
	if alg == 0 {
		lgDns.Warn("unknown keygen algorithm, using default", "algorithm", algstr, "default", dns.AlgorithmToString[defaultAlg])
		alg = defaultAlg
	}
	return alg, nil
}

func (zd *ZoneData) DelegationSyncSetup(ctx context.Context, kdb *KeyDB) error {
	_, _, err := zd.delegationSyncSetup(ctx, kdb)
	return err
}

// delegationSyncSetup is DelegationSyncSetup that also reports whether the
// parent accepted the bootstrap ceremony (bootstrapAccepted), and the key
// algorithm it was run with.
func (zd *ZoneData) delegationSyncSetup(ctx context.Context, kdb *KeyDB) (accepted bool, alg uint8, err error) {
	if !zd.Options[OptParentSync] {
		lgDns.Debug("DelegationSyncSetup: zone does not have child-side delegation sync enabled, skipping", "zone", zd.ZoneName)
		return false, 0, nil
	}

	// algstr := ParentSyncConfig().Update.Keygen.Algorithm
	// alg := dns.StringToAlgorithm[strings.ToUpper(algstr)]
	// if alg == 0 {
	// 	log.Printf("Sig0KeyPreparation: Unknown keygen algorithm: \"%s\", using ED25519", algstr)
	// 	alg = dns.ED25519
	// }
	alg, err = parseKeygenAlgorithm(ParentSyncConfig().Update.Keygen.Algorithm, dns.ED25519)
	if err != nil {
		lgDns.Error("DelegationSyncSetup: error from parseKeygenAlgorithm", "zone", zd.ZoneName, "err", err)
		return false, 0, err
	}

	// EnsureApexKEY (PublishKeyRRs via Sig0KeyPreparation) then the ceremony.
	// The proxy path uses a no-op ensurer: the operator publishes the KEY.
	msg, ur, berr := zd.bootstrapSig0Key(ctx, alg, authApexKEY{zd: zd, kdb: kdb, alg: alg})
	return bootstrapAccepted(ur, berr), alg, zd.finishDelegationSyncSetup(msg, ur, berr)
}

// bootstrapAccepted reports whether the bootstrap ceremony reached the parent
// and was answered NOERROR: the parent has stored the key, untrusted, and is
// verifying it. The error comes first on purpose. A ceremony that was never
// sent (a manual parent, a failed lookup) returns an empty UpdateResult, whose
// zero Rcode reads as NOERROR.
func bootstrapAccepted(ur UpdateResult, err error) bool {
	return err == nil && ur.Rcode == dns.RcodeSuccess
}

func (zd *ZoneData) ParentSig0KeyPrep(name string, kdb *KeyDB) error {
	// algstr := ChildSyncConfig().Update.Keygen.Algorithm
	// alg := dns.StringToAlgorithm[strings.ToUpper(algstr)]
	// if alg == 0 {
	// 	log.Printf("Sig0KeyPreparation: Unknown keygen algorithm: \"%s\", using ED25519", algstr)
	// 	alg = dns.ED25519
	// }
	alg, err := parseKeygenAlgorithm(ChildSyncConfig().Update.Keygen.Algorithm, dns.ED25519)
	if err != nil {
		lgDns.Error("ParentSig0KeyPrep: error from parseKeygenAlgorithm", "zone", zd.ZoneName, "err", err)
		return err
	}

	return zd.Sig0KeyPreparation(name, alg, kdb)
}

// MusicSig0KeyPrep and ParentSig0KeyPrep are identical except for the source of the keygen algorithm
// which is specified in the relevant section of the configuration file.
func (zd *ZoneData) MusicSig0KeyPrep(name string, kdb *KeyDB) error {
	// algstr := ParentSyncConfig().Update.Keygen.Algorithm
	// alg := dns.StringToAlgorithm[strings.ToUpper(algstr)]
	// if alg == 0 {
	// 	log.Printf("Sig0KeyPreparation: Unknown keygen algorithm: \"%s\", using ED25519", algstr)
	// 	alg = dns.ED25519
	// }
	alg, err := parseKeygenAlgorithm(ParentSyncConfig().Update.Keygen.Algorithm, dns.ED25519)
	if err != nil {
		lgDns.Error("MusicSig0KeyPrep: error from parseKeygenAlgorithm", "zone", zd.ZoneName, "err", err)
		return err
	}

	return zd.Sig0KeyPreparation(name, alg, kdb)
}

func (zd *ZoneData) Sig0KeyPreparation(name string, alg uint8, kdb *KeyDB) error {
	lgDns.Debug("Sig0KeyPreparation: setting up SIG(0) key pair", "zone", zd.ZoneName, "name", name)

	owner, err := zd.GetOwner(name)
	lgDns.Debug("Sig0KeyPreparation: GetOwner result", "name", name, "owner", owner, "err", err)
	if err != nil {
		return fmt.Errorf("Sig0KeyPreparation(%s) failed to get owner: %v", name, err)
	}

	var keyrrexist bool
	if owner != nil {
		_, keyrrexist = owner.RRtypes.Get(dns.TypeKEY)
	}

	// 1. Did the zone ask for this key at all?
	//
	// The gate is the delegation-sync option that makes the key necessary, and
	// each of the two callers already tests it:
	//
	//   - childsync (parent side): the same option that permits the DSYNC
	//     RRset advertising this very target, published from the same block of
	//     SetupZoneSync a few lines earlier. One option, both publications.
	//   - parentsync (child side): the option that permits the apex KEY the
	//     bootstrap ceremony carries (DelegationSyncSetup's first line).
	//
	// It used to ask `allow-updates` instead, and that was the wrong question
	// (#538): `allow-updates` governs inbound RFC 2136 DDNS from the network,
	// whereas this is an INTERNAL publish -- PublishKeyRRs posts
	// UpdateRequest{InternalUpdate: true}, which ZoneUpdater admits regardless.
	// It was a second, unrelated gate on one of the two publications inside the
	// childsync block, so a parent published a DSYNC record naming an UPDATE
	// target and then never generated the key that target names. Worse,
	// `updatepolicy.zone.type: none` -- the correct posture for such a parent --
	// clears allow-updates, so refusing inbound DDNS disabled the parent's own
	// key. Restating the callers' gate here says what actually permits the
	// publish, and cannot be switched off by an unrelated policy decision.
	if !zd.Options[OptChildSync] && !zd.Options[OptParentSync] {
		lgDns.Warn("Sig0KeyPreparation: zone has neither childsync nor parentsync, no SIG(0) key will be generated or published",
			"zone", zd.ZoneName, "name", name, "keyrrexist", keyrrexist)
		return nil
	}

	// 2. Origination backstop -- defence in depth, not the load-bearing gate.
	// normalizeOptionsForRole strips BOTH childsync and parentsync from a
	// tdns-auth secondary (parentsync joined originationOptions with #538, once
	// the allow-updates gate that had justified its exclusion was gone), so
	// after a real config load such a zone never reaches here with either
	// option set. This catches a ZoneData whose Options were assembled without
	// the normalizer, and states the invariant where the publish happens:
	// content this server did not originate is not ours to write into.
	if !zoneMayOriginateContent(zd) {
		lgDns.Warn("Sig0KeyPreparation: zone may not originate content, no SIG(0) key will be generated or published",
			"zone", zd.ZoneName, "name", name, "zonetype", ZoneTypeToString[zd.ZoneType], "keyrrexist", keyrrexist)
		return nil
	}

	// A published KEY is not the same as a key this zone can sign with, and
	// until now the difference decided nothing. VerifyPublishedKeyRRs warned
	// about a published KEY with no active private key behind it -- naming the
	// exact problem -- and then the generation step below was skipped anyway,
	// because it asks only whether a KEY RRset EXISTS.
	//
	// So a zone whose private key had gone from the keystore while the record
	// remained published could neither sign updates nor bootstrap, said so in
	// its own log, and did not recover on restart: the same two lines every
	// time, until an operator deleted the published record by hand (#576).
	if keyrrexist && !zd.Options[OptDontPublishKey] {
		usable, err := zd.verifyPublishedKeyRRs(name)
		if err != nil {
			lgDns.Error("error from VerifyPublishedKeyRRs", "name", name, "err", err)
			return err
		}
		if !usable {
			// Generate and publish a replacement rather than stop here. The
			// orphan is left in place and keeps warning: removing published
			// records on the zone's behalf is a bigger decision than making it
			// able to sign again, and an extra KEY nobody holds the private
			// half of is inert -- a signer is matched by key tag.
			lgDns.Warn("Sig0KeyPreparation: the published KEY RRset has no active private key behind it;"+
				" generating a replacement. The orphaned record should be removed",
				"zone", zd.ZoneName, "name", name)
			keyrrexist = false
		} else {
			lgDns.Info("Sig0KeyPreparation: verified published KEY RRset", "name", name)
		}
	}

	// 3. The per-zone opt-out for this specific publish. Checked again inside
	// PublishKeyRRs, which refuses outright; saying so here keeps the reason
	// visible at default log level rather than only as a Debug non-event.
	if zd.Options[OptDontPublishKey] {
		lgDns.Info("Sig0KeyPreparation: dont-publish-key is set, no KEY RR will be published",
			"zone", zd.ZoneName, "name", name, "keyrrexist", keyrrexist)
		return nil
	}

	// 4. Publication allowed, but there is no KEY RRset published.
	if !keyrrexist {
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
				return fmt.Errorf("Sig0KeyPreparation(%s) failed to generate keypair: %w", name, err)
			}
			lgDns.Info("Sig0KeyPreparation: key generated", "msg", resp.Msg)

			sak, err = zd.KeyDB.GetSig0Keys(name, Sig0StateActive)
			if err != nil {
				return fmt.Errorf("Sig0KeyPreparation(%s, after key generation) failed to get SIG(0) active keys: %w", name, err)
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
	msg, rcode, ur, _, err := zd.syncZoneDelegationVia(ctx, kdb, notifyq, syncstate, imr)
	return msg, rcode, ur, err
}

// syncZoneDelegationVia is SyncZoneDelegation that also returns the scheme
// that carried the difference: "" when nothing was sent. Only an UPDATE or API
// success says the parent applied it; a NOTIFY's says the notifier took it.
func (zd *ZoneData) syncZoneDelegationVia(ctx context.Context, kdb *KeyDB, notifyq chan NotifyRequest, syncstate DelegationSyncStatus, imr *Imr) (string, uint8, UpdateResult, string, error) {

	//	syncstate, err := AnalyseZoneDelegation(conf, zd)
	//	if err != nil {
	//		return "", err
	//	}

	if syncstate.InSync {
		return fmt.Sprintf("Zone \"%s\" delegation data in parent \"%s\" is in sync. No action needed.",
			syncstate.ZoneName, zd.GetParent()), 0, UpdateResult{}, "", nil
	} else {
		lgDns.Info("zone delegation data in parent is NOT in sync, sync action needed",
			"zone", syncstate.ZoneName, "parent", zd.GetParent())
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

	// One discovery, then every usable transport in operator-preference order.
	//
	// This replaced BestSyncScheme, which picked ONE scheme and lived with it:
	// if that scheme failed, nothing else was tried even when the parent
	// advertised a transport that would have worked. The gates also settle
	// here what used to be discovered by failing -- an API scheme with no
	// credential is skipped with a reason instead of returning REFUSED, and a
	// NOTIFY for an unsigned zone (which leaves the parent nothing it can
	// validate) is not attempted at all.
	plan, err := zd.BuildParentSyncPlan(ctx, kdb, imr, SyncRoleChild)
	if err != nil {
		lgDns.Error("DelegationSyncEngine: could not build the parent sync plan, ignoring sync request",
			"zone", zd.ZoneName, "err", err)
		return "", 0, UpdateResult{}, "", err
	}
	// A parent that offers nothing this child can use is ErrNoUsableDsync:
	// one warning per zone, not an error (planUsable).
	if err := zd.planUsable(plan); err != nil {
		return "", 0, UpdateResult{}, "", err
	}

	// rcode and ur are captured from whichever attempt succeeds; on total
	// failure walkSyncPlan returns the error and they are not consulted.
	var rcode uint8
	var ur UpdateResult
	var scheme string

	msg, err := zd.walkSyncPlan(ctx, plan, func(cand SyncCandidate) (string, error) {
		var m string
		var e error
		var candRcode uint8
		var candUr UpdateResult
		switch cand.Scheme {
		case "UPDATE":
			m, candRcode, candUr, e = zd.SyncZoneDelegationViaUpdate(ctx, kdb, syncstate, cand.Target)
		case "NOTIFY":
			m, candRcode, e = zd.SyncZoneDelegationViaNotify(ctx, kdb, notifyq, syncstate, cand.Target)
		case "API":
			m, candRcode, e = zd.SyncZoneDelegationViaApi(ctx, imr, syncstate, cand.Target)
		default:
			e = fmt.Errorf("unknown scheme %q in plan", cand.Scheme)
		}
		if e != nil {
			// Only a SUCCEEDING attempt may publish its result, which is what
			// the comment above always claimed. SyncZoneDelegationViaUpdate
			// returns a POPULATED UpdateResult alongside its error, so assigning
			// unconditionally paired a failed UPDATE's TargetStatus with a later
			// transport's rcode, and the caller stored that as the outcome.
			return m, e
		}
		rcode, ur, scheme = candRcode, candUr, cand.Scheme
		return m, e
	})

	return msg, rcode, ur, scheme, err
}

func (zd *ZoneData) SyncZoneDelegationViaUpdate(ctx context.Context, kdb *KeyDB, syncstate DelegationSyncStatus,
	dsynctarget *DsyncTarget) (string, uint8, UpdateResult, error) {

	return zd.SendDelegationUpdate(ctx, kdb, syncstate, dsynctarget, childUpdateMode(kdb))
}

// childUpdateMode is the form a tdns-auth child's UPDATE takes: the operator's
// parent-update option, delta by default.
func childUpdateMode(kdb *KeyDB) string {
	if mode, exists := kdb.AuthOption(AuthOptParentUpdate); exists {
		return mode
	}
	return UpdateModeDelta
}

// sendNotifyRequest hands a NotifyRequest to the notifier, giving up if the
// context is cancelled first. Reports whether the notifier took it.
//
// These were bare channel sends. The notifier is a separate goroutine with its
// own queue, and a backed-up one blocked the delegation syncher -- the single
// goroutine that has to keep servicing every other zone -- with no way to
// abandon the wait at shutdown. Same shape as emitProxyNotifies, which already
// makes its sends ctx-aware for this reason.
//
// It waits rather than dropping on a full queue: the whole NOTIFY scheme is
// this one message, so a dropped one is a delegation that silently never
// converges. The bool exists so the caller reports the sync as not done rather
// than claiming a NOTIFY it never sent.
func sendNotifyRequest(ctx context.Context, notifyq chan NotifyRequest, req NotifyRequest) bool {
	select {
	case notifyq <- req:
		return true
	case <-ctx.Done():
		lgDns.Warn("cancelled before the NOTIFY could be handed to the notifier",
			"zone", req.ZoneName, "rrtype", dns.TypeToString[req.RRtype])
		return false
	}
}

func (zd *ZoneData) SyncZoneDelegationViaNotify(ctx context.Context, kdb *KeyDB, notifyq chan NotifyRequest,
	syncstate DelegationSyncStatus, dsynctarget *DsyncTarget) (string, uint8, error) {

	if zd.Options[OptAllowUpdates] {
		// 1. Publish the CSYNC, and WAIT for it.
		//
		// The whole of this scheme is telling the parent to come and fetch a
		// CSYNC. PublishCsyncRR only queues a ZONE-UPDATE, so notifying right
		// after it told the parent to look before the record existed -- and a
		// parent that looks and finds nothing concludes there is nothing to
		// do. Both sides then report success and the delegation does not
		// converge, which is #507's shape on a different scheme.
		if err := zd.PublishCsyncRRAndWait(ctx); err != nil {
			lgDns.Error("SyncZoneDelegationViaNotify: error from PublishCsyncRR", "err", err)
			return "", dns.RcodeServerFailure, err
		}

		// Nothing signs the CSYNC here. PublishCsyncRR only ENQUEUES a
		// ZONE-UPDATE, and the updater signs every RRset it stages before the
		// publish that carries it, so by the time the record exists it is
		// already signed by the path that owns it.
		//
		// There used to be a force-sign here, and it was wrong three times
		// over: it fetched the CSYNC before the queued update had applied, so
		// on a zone with no CSYNC yet the RRset was empty and SignRRset
		// panicked (#565); it discarded the `ok` from both lookups, which is
		// exactly the signal that would have said so; and it signed a struct
		// copy whose slices alias the live zone, mutating published records in
		// place and then throwing the result away without staging it.
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

	nsOrGlueChanged := len(syncstate.NsAdds) > 0 || len(syncstate.NsRemoves) > 0 ||
		len(syncstate.AAdds) > 0 || len(syncstate.ARemoves) > 0 ||
		len(syncstate.AAAAAdds) > 0 || len(syncstate.AAAARemoves) > 0

	// A NOTIFY(CDS) says "come and read my CDS", so the CDS has to be served
	// before it goes out -- the rule the CSYNC above already follows. Until the
	// DS engine, nothing published one at all for a zone the KSK rollover engine
	// does not manage: the parent scanned, found no CDS, both ends reported
	// success, and the walk never reached UPDATE or API.
	//
	// Asked before any NOTIFY is sent, so a candidate that cannot back its
	// NOTIFY(CDS) fails whole and the plan moves on, instead of having told the
	// parent half of it.
	notifyCds := false
	if len(syncstate.DSAdds) > 0 || len(syncstate.DSRemoves) > 0 {
		res := kdb.askDSEngine(ctx, DSEngineRequest{cmd: dsCmdEnsureCDS, zd: zd})
		switch {
		case res.err != nil:
			return "", dns.RcodeServerFailure,
				fmt.Errorf("zone %s: no CDS for a NOTIFY(CDS) to point at: %w", zd.ZoneName, res.err)
		case res.deferred != "":
			lgDns.Info("SyncZoneDelegationViaNotify: not sending NOTIFY(CDS); the DS is not delegation sync's",
				"zone", zd.ZoneName, "reason", res.deferred)
		default:
			notifyCds = true
		}
	}

	var sent []string

	// Send NOTIFY(CSYNC) for NS or glue (A/AAAA) changes
	if nsOrGlueChanged {
		if !sendNotifyRequest(ctx, notifyq, NotifyRequest{
			ZoneName: zd.ZoneName,
			ZoneData: zd,
			RRtype:   dns.TypeCSYNC,
			Targets:  dsynctarget.Addresses,
		}) {
			return "", dns.RcodeServerFailure,
				fmt.Errorf("zone %s: could not hand NOTIFY(CSYNC) to the notifier", zd.ZoneName)
		}
		lgDns.Info("SyncZoneDelegationViaNotify: sent NOTIFY(CSYNC)", "zone", zd.ZoneName)
		sent = append(sent, "CSYNC")
	}

	// Send NOTIFY(CDS) for DS/DNSKEY changes
	if notifyCds {
		if !sendNotifyRequest(ctx, notifyq, NotifyRequest{
			ZoneName: zd.ZoneName,
			ZoneData: zd,
			RRtype:   dns.TypeCDS,
			Targets:  dsynctarget.Addresses,
		}) {
			return "", dns.RcodeServerFailure,
				fmt.Errorf("zone %s: could not hand NOTIFY(CDS) to the notifier", zd.ZoneName)
		}
		lgDns.Info("SyncZoneDelegationViaNotify: sent NOTIFY(CDS)", "zone", zd.ZoneName)
		sent = append(sent, "CDS")
	}

	if len(sent) == 0 {
		return fmt.Sprintf("SyncZoneDelegationViaNotify: nothing to notify for zone %s", zd.ZoneName),
			dns.RcodeSuccess, nil
	}
	msg := fmt.Sprintf("SyncZoneDelegationViaNotify: Sent NOTIFY(%s) for zone %s to NotifierEngine",
		strings.Join(sent, ", "), zd.ZoneName)
	return msg, dns.RcodeSuccess, nil
}

// imrWaitWarnAfter is how long a deferred request waits before saying so
// loudly. It does not bound the wait -- a proxy zone cannot do anything useful
// without an IMR, so giving up would silently drop work rather than fix
// anything -- it just stops a misconfigured process from waiting in silence.
const imrWaitWarnAfter = 60 * time.Second

// deferForImr puts a proxy request back on the queue once the IMR is up.
//
// The re-enqueue happens from its own goroutine: DelegationSyncher is the only
// reader of delsyncq, so sending from the loop itself would deadlock as soon as
// the channel filled.
//
// It waits on the readiness signal rather than re-checking the IMR pointer on a
// timer. Polling a field another goroutine writes is a data race whichever way
// it is dressed up, and a bounded poll has to answer a question it cannot --
// how long is priming allowed to take -- by dropping the request when it
// guesses low. A one-shot PROXY-UPDATE-SETUP dropped that way means the startup
// reconcile never runs for that zone until the child next changes.
// The returned channel is closed when the deferred worker exits, whether it
// re-enqueued or gave up on cancellation. Production ignores it; it exists so a
// test can wait for THIS worker rather than watching the process-wide goroutine
// count, which an unrelated goroutine starting or stopping makes meaningless in
// either direction.
// ErrNoImrEngine reports that a step needed the IMR and there was not one yet.
//
// It is not a verdict on anything: InitImrEngine publishes the IMR
// asynchronously and routinely finishes after the engines start, so this is the
// ordinary state of the first seconds of a process. Matched rather than logged
// and dropped, because the one chance a child gets to bootstrap must not be the
// one it loses to startup ordering (#575).
var ErrNoImrEngine = errors.New("no IMR engine available yet")

func deferForImr(ctx context.Context, delsyncq chan DelegationSyncRequest,
	ready *ImrReadiness, ds DelegationSyncRequest) <-chan struct{} {

	lgDns.Info("DelegationSyncher: IMR not up yet, deferring this request until it is",
		"zone", ds.ZoneName, "command", ds.Command)

	done := make(chan struct{})
	go func() {
		defer close(done)
		warn := time.NewTimer(imrWaitWarnAfter)
		defer warn.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-warn.C:
				lgDns.Warn("DelegationSyncher: still waiting for the IMR;"+
					" this request cannot be served without one",
					"zone", ds.ZoneName, "command", ds.Command, "waited", imrWaitWarnAfter)
			case <-ready.Ready():
				select {
				case delsyncq <- ds:
				case <-ctx.Done():
				}
				return
			}
		}
	}()
	return done
}

// setupRetryDelay is the delegation-sync backoff for a re-enqueued setup:
// 5s, 10s, 20s, 40s for attempts 0..3, the schedule retryWithBackoff uses.
func setupRetryDelay(attempt int) time.Duration {
	d := delegationSyncInitialDelay
	for i := 0; i < attempt && d < time.Hour; i++ {
		d *= 2
	}
	return d
}

// deferSetupRetry re-enqueues a DELEGATION-SYNC-SETUP after the backoff for
// its attempt, with the attempt count advanced. Off the parent's queue so a
// waiting zone does not stall the parent's other zones; cancelled with ctx. The returned
// channel closes when the worker exits, for tests.
func deferSetupRetry(ctx context.Context, delsyncq chan DelegationSyncRequest, ds DelegationSyncRequest, reason string) <-chan struct{} {
	return deferSetupRetryAfter(ctx, delsyncq, ds, setupRetryDelay(ds.Attempt), reason)
}

// deferSetupRetryAfter is deferSetupRetry with the delay supplied, so a test
// need not wait out the real schedule.
func deferSetupRetryAfter(ctx context.Context, delsyncq chan DelegationSyncRequest, ds DelegationSyncRequest, delay time.Duration, reason string) <-chan struct{} {
	lgDns.Warn("DelegationSyncher: SIG(0) bootstrap setup deferred; will retry",
		"zone", ds.ZoneName, "reason", reason,
		"attempt", ds.Attempt+1, "of", delegationSyncMaxRetries, "delay", delay)
	next := ds
	next.Attempt++
	return requeueSetupAfter(ctx, delsyncq, next, delay)
}

// nextReBootstrap is the DELEGATION-SYNC-SETUP to enqueue, and when, after
// the parent reported the key's validation failed; ok is false once the
// rounds have run out. A round starts with a fresh transient-retry budget.
func nextReBootstrap(ds DelegationSyncRequest) (next DelegationSyncRequest, delay time.Duration, ok bool) {
	if ds.ReBootstrapRound >= childReBootstrapRounds {
		return ds, 0, false
	}
	next = ds
	next.Attempt = 0
	next.ReBootstrapRound++
	return next, childReBootstrapDelay(ds.ReBootstrapRound), true
}

// requeueSetupAfter enqueues next after delay, off the parent's queue and
// cancelled with ctx. The returned channel closes when the worker exits.
func requeueSetupAfter(ctx context.Context, delsyncq chan DelegationSyncRequest, next DelegationSyncRequest, delay time.Duration) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTimer(delay)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		select {
		case delsyncq <- next:
		case <-ctx.Done():
		}
	}()
	return done
}

// delegationSyncRetryDelays are the waits before each re-run of a compare with
// the parent that failed: a parentsync child's refresh sync or explicit sync, a
// proxy's compare, and the compare a failed stored change becomes
// (lookAgainLater). Nothing else re-sends what the parent lacks: the next
// change is a difference against a zone that already has this one, the next
// refresh is compared with a copy that has it (#722), and the next full compare
// is at load. Many failures are transient -- the parent's DSYNC endpoint could
// not be discovered, the parent was briefly unreachable -- so the first waits
// are short. The last repeats: a compare is retried until the parent answers,
// or until its zone is no longer loaded (requeueLookAfter).
var delegationSyncRetryDelays = []time.Duration{30 * time.Second, 2 * time.Minute, 8 * time.Minute, 30 * time.Minute}

// nextDelegationSyncRetry returns the request that re-runs a failed delegation
// sync and how long to wait before it. The retries do not run out: the last
// wait repeats.
func nextDelegationSyncRetry(ds DelegationSyncRequest, failedAt time.Time) (next DelegationSyncRequest, delay time.Duration) {
	next = ds
	next.Attempt++
	next.FailedAt = failedAt
	return next, delegationSyncRetryDelays[min(ds.Attempt, len(delegationSyncRetryDelays)-1)]
}

// requeueLookAfter enqueues next, a re-run of a compare with the parent, after
// delay, as requeueSetupAfter does, and marks the zone's parent as known to be
// out of step (delegationOutOfStep). When it is due, a re-run whose zone is no
// longer loaded, or has been replaced, is dropped: the retries do not run out,
// so nothing else would end them. It is checked again when its lane runs it
// (delegationSyncRetryStale).
//
// A zone instance has at most one re-run of each command waiting for its
// timer (pendingLooks). Each failed re-run starts its successor, so without
// that every failure while the parent is down would start a retry stream of
// its own, each comparing every 30 minutes for as long as the outage lasts:
// the lane merges only requests that wait in it at the same time. A re-run
// due no sooner than the one waiting joins it (mergeDelegationSyncRequests:
// the fewer attempts, the later failure); one due sooner takes its place,
// with what the waiting one carried, so a fresh trigger keeps its short wait.
//
// The returned channel closes when the worker it started exits; it is nil
// when next joined a waiting re-run and no worker was started.
func requeueLookAfter(ctx context.Context, delsyncq chan DelegationSyncRequest, next DelegationSyncRequest, delay time.Duration) <-chan struct{} {
	var key pendingLookKey
	var me *pendingLook
	if next.ZoneData != nil {
		next.ZoneData.delegationOutOfStep.Store(true)
		key = pendingLookKey{zd: next.ZoneData, command: next.Command}
		due := time.Now().Add(delay)
		register := true
		pendingLooks.Lock()
		if p := pendingLooks.m[key]; p != nil {
			merged, ok := mergeDelegationSyncRequests(p.next, next)
			switch {
			case !ok:
				// Not one the waiting re-run can stand for: it waits on a
				// timer of its own, as before, and replaces nothing.
				register = false
			case !due.Before(p.due):
				p.next = merged
				pendingLooks.Unlock()
				lgDns.Debug("DelegationSyncher: retry joins the one already waiting",
					"zone", next.ZoneName, "command", next.Command, "due", p.due)
				return nil
			default:
				next = merged
			}
		}
		if register {
			me = &pendingLook{next: next, due: due}
			pendingLooks.m[key] = me
		}
		pendingLooks.Unlock()
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTimer(delay)
		defer t.Stop()
		select {
		case <-ctx.Done():
			me.release(key)
			return
		case <-t.C:
		}
		run, current := me.take(key, next)
		if !current {
			// A re-run due sooner took its place and carries it.
			return
		}
		if !delegationSyncZoneLoaded(run) {
			lgDns.Info("DelegationSyncher: retry dropped; the zone is no longer loaded",
				"zone", run.ZoneName, "command", run.Command, "attempt", run.Attempt)
			return
		}
		select {
		case delsyncq <- run:
		case <-ctx.Done():
		}
	}()
	return done
}

// pendingLooks holds the compare re-runs waiting for their timer, at most one
// per zone instance and command (requeueLookAfter).
var pendingLooks = struct {
	sync.Mutex
	m map[pendingLookKey]*pendingLook
}{m: map[pendingLookKey]*pendingLook{}}

type pendingLookKey struct {
	zd      *ZoneData
	command string
}

// pendingLook is one re-run waiting for its timer: what it will enqueue, and
// when.
type pendingLook struct {
	next DelegationSyncRequest
	due  time.Time
}

// take ends p's wait: it returns what p is to enqueue, and whether p is still
// the zone's waiting re-run. When it is not, one due sooner replaced it. A nil
// p, a request with no zone, was never registered: it returns fallback.
func (p *pendingLook) take(key pendingLookKey, fallback DelegationSyncRequest) (DelegationSyncRequest, bool) {
	if p == nil {
		return fallback, true
	}
	pendingLooks.Lock()
	defer pendingLooks.Unlock()
	if pendingLooks.m[key] != p {
		return DelegationSyncRequest{}, false
	}
	delete(pendingLooks.m, key)
	return p.next, true
}

// release forgets p if it is still the zone's waiting re-run: its context
// ended.
func (p *pendingLook) release(key pendingLookKey) {
	if p == nil {
		return
	}
	pendingLooks.Lock()
	defer pendingLooks.Unlock()
	if pendingLooks.m[key] == p {
		delete(pendingLooks.m, key)
	}
}

// delegationSyncRetryStale reports whether ds is a retry whose zone was
// removed or replaced since it was scheduled: a compare re-run
// (requeueLookAfter), whose timer checked the zone but which may have waited
// in its parent's queue since, or a setup retry or re-bootstrap round
// (requeueSetupAfter), whose timer does not check. It is dropped: run, it would
// compare and send the delegation, or bootstrap a key with the parent, for a
// zone no longer served -- or one whose new instance does not sync with its
// parent at all.
func delegationSyncRetryStale(ds DelegationSyncRequest) bool {
	if ds.Response != nil {
		return false
	}
	switch ds.Command {
	case "EXPLICIT-SYNC-DELEGATION", "REFRESH-SYNC-DELEGATION", "PROXY-UPDATE-SETUP":
		if ds.Attempt == 0 {
			return false
		}
	case "DELEGATION-SYNC-SETUP":
		if ds.Attempt == 0 && ds.ReBootstrapRound == 0 {
			return false
		}
	default:
		return false
	}
	return !delegationSyncZoneLoaded(ds)
}

// delegationSyncZoneLoaded reports whether ds's zone is still the one loaded
// under its name.
func delegationSyncZoneLoaded(ds DelegationSyncRequest) bool {
	if ds.ZoneData == nil {
		return false
	}
	cur, live := Zones.Get(ds.ZoneData.ZoneName)
	return live && cur == ds.ZoneData
}

// noteDelegationSyncInStep records that the parent holds what the zone says: a
// compare of NS, glue and DS found it in step, or brought it there by a send
// the parent applied (inStepAfter), or a proxy sync, which declares the whole
// delegation, was applied by it. A retry of an earlier
// failure is dropped (delegationSyncRetrySuperseded), and a stored change may
// again be sent as a difference (delegationOutOfStep). A refresh sync, which
// compares no DS, does not call it.
func (zd *ZoneData) noteDelegationSyncInStep() {
	zd.mu.Lock()
	zd.delegationLastSyncOK = time.Now()
	zd.mu.Unlock()
	zd.delegationOutOfStep.Store(false)
}

// noteDelegationSyncNotSent records that a change of the zone did not reach
// the parent and nothing will retry it: the parent offers no usable scheme. A
// later change then goes as a compare, not as a difference that assumes the
// parent has this one (delegationOutOfStep).
func (zd *ZoneData) noteDelegationSyncNotSent() {
	if zd != nil {
		zd.delegationOutOfStep.Store(true)
	}
}

// noteDelegationSyncSentBy records what a send that succeeded says about the
// parent, by the scheme that carried it. A NOTIFY's success says only that
// the notifier took it: the parent has yet to come and read the zone, and may
// never, so it is marked as possibly lacking the change (delegationOutOfStep)
// until a compare finds it in step. Otherwise a later stored change could go
// as a difference by UPDATE -- the plan falls back to it when a NOTIFY cannot
// be handed off -- and leave out what the parent never read. An UPDATE's or
// an API call's success says the parent applied what was sent. That clears the
// mark only when what was sent was the whole delegation, which the callers
// know: an explicit sync's difference from a complete compare that compared
// the DS (inStepAfter), or a proxy sync (noteProxySyncForwarded). A stored
// change or a refresh sync sends a part, so here it leaves the mark as it is.
func (zd *ZoneData) noteDelegationSyncSentBy(scheme string) {
	if zd != nil && scheme == "NOTIFY" {
		zd.delegationOutOfStep.Store(true)
	}
}

// syncDelegationSteps are the parts of the SYNC-DELEGATION arm that talk to
// the parent, passed in so a test can stand in for them.
type syncDelegationSteps struct {
	resolve func() error
	sync    func(DelegationSyncStatus) (string, uint8, UpdateResult, string, error)
	requeue func(next DelegationSyncRequest, delay time.Duration)
}

// handleSyncDelegationWith is the SYNC-DELEGATION arm: send a stored change,
// the difference between two versions of the zone. The queue runs one only
// when it starts at once (RunDelegationSyncLanes). A failure is not retried
// as the same difference: the zone may change again before the parent
// answers, and the parent may then hold less than the difference assumes. It
// is retried as a compare of the zone with its parent (lookAgainLater).
//
// A success does not count as the parent being in step: the difference brought
// the parent what the zone changed, not what the parent may have missed.
func handleSyncDelegationWith(ds DelegationSyncRequest, steps syncDelegationSteps) {
	dss := ds.SyncStatus
	lgDns.Info("DelegationSyncher: request for delegation sync",
		"zone", ds.ZoneName,
		"ns_removes", len(dss.NsRemoves), "ns_adds", len(dss.NsAdds),
		"a_removes", len(dss.ARemoves), "a_adds", len(dss.AAdds),
		"aaaa_removes", len(dss.AAAARemoves), "aaaa_adds", len(dss.AAAAAdds))

	if err := steps.resolve(); err != nil {
		lookAgainLater(ds, "find the parent", err, steps.requeue)
		return
	}
	msg, rcode, _, scheme, err := steps.sync(dss)
	if errors.Is(err, ErrNoUsableDsync) {
		// Not a failure: warned about once (planUsable), and nothing to retry
		// through. But the parent lacks the change now.
		lgDns.Debug("DelegationSyncher: nothing sent", "zone", ds.ZoneName, "reason", err)
		ds.ZoneData.noteDelegationSyncNotSent()
		return
	}
	if err != nil {
		lookAgainLater(ds, "send", err, steps.requeue)
		return
	}
	// A success does not say the parent holds earlier changes; a NOTIFY's
	// does not even say it has this one.
	ds.ZoneData.noteDelegationSyncSentBy(scheme)
	lgDns.Info("DelegationSyncher: SyncZoneDelegation completed", "zone", ds.ZoneName, "msg", msg,
		"rcode", dns.RcodeToString[int(rcode)], "scheme", scheme)
}

// lookAgainLater retries ds, a stored change whose send failed, as a compare
// of the zone with its parent (delegationSyncLook) after the first retry wait.
func lookAgainLater(ds DelegationSyncRequest, step string, err error, requeue func(next DelegationSyncRequest, delay time.Duration)) {
	look, ok := delegationSyncLook(ds)
	if !ok {
		lgDns.Error("DelegationSyncher: delegation sync failed", "zone", ds.ZoneName, "command", ds.Command, "step", step, "err", err)
		return
	}
	look.Attempt, look.FailedAt = 0, time.Time{}
	next, delay := nextDelegationSyncRetry(look, time.Now())
	lgDns.Error("DelegationSyncher: delegation sync failed; the zone is compared with its parent again later",
		"zone", ds.ZoneName, "command", ds.Command, "step", step, "retry", next.Command, "retry_in", delay, "err", err)
	requeue(next, delay)
}

// delegationSyncRetrySuperseded reports whether a retry is redundant because a
// later sync for the zone has succeeded since the one it retries failed. Every
// proxy sync declares the whole delegation and takes its withdrawals from the
// parent as well as from its own trigger, and a refresh sync compares with the
// parent before it sends, so a later success covers whatever the failed one was
// sending.
func delegationSyncRetrySuperseded(zd *ZoneData, ds DelegationSyncRequest) bool {
	if ds.Attempt == 0 {
		return false
	}
	zd.mu.Lock()
	defer zd.mu.Unlock()
	return zd.delegationLastSyncOK.After(ds.FailedAt)
}

// proxySync forwards a detected change to the parent on behalf of a
// DSYNC-unaware primary, over whichever of UPDATE / API / NOTIFY is usable. The
// queue runs one only when it starts at once (RunDelegationSyncLanes). A
// failure is retried as the proxy's compare with the parent (lookAgainLater).
func proxySync(ctx context.Context, zd *ZoneData, kdb *KeyDB, notifyq chan NotifyRequest,
	delsyncq chan DelegationSyncRequest, imr *Imr, ds DelegationSyncRequest) {

	msg, scheme, err := zd.proxyDelegationSyncVia(ctx, kdb, notifyq, imr, ds.ProxyAnalysis)
	if err != nil {
		lookAgainLater(ds, "forward", err, func(next DelegationSyncRequest, delay time.Duration) {
			requeueLookAfter(ctx, delsyncq, next, delay)
		})
		return
	}
	zd.noteProxySyncForwarded(scheme)
	lgDns.Info("DelegationSyncher: proxy sync done", "zone", ds.ZoneName, "scheme", scheme, "msg", msg)
}

// noteProxySyncForwarded records what a proxy sync that returned no error
// says about the parent, by the scheme that forwarded it ("" for none). Only a
// sync the parent applied supersedes a pending retry. "Nothing forwarded" (no
// usable scheme, for instance an empty DSYNC discovery) is not an error, but
// it sent nothing, and must not cancel a retry that might. A proxy sync
// declares the whole delegation and takes its withdrawals from the parent as
// well, so one the parent applied -- an UPDATE or an API call -- leaves it in
// step. One that did not reach it leaves the parent without the change. A
// NOTIFY the notifier took marks it too, as every NOTIFY does: the parent has
// yet to come and read the zone (noteDelegationSyncSentBy).
func (zd *ZoneData) noteProxySyncForwarded(scheme string) {
	switch scheme {
	case "UPDATE", "API":
		zd.noteDelegationSyncInStep()
	case "":
		zd.noteDelegationSyncNotSent()
	default:
		zd.noteDelegationSyncSentBy(scheme)
	}
}

// proxyUpdateGate re-runs the §10.8 UPDATE gate for a parentsync-proxy zone
// whose apex KEY changed in a transfer (queueProxyUpdateGate). check is the
// gate: ProxyUpdatePreconditionCheck, which asks whether the parent advertises
// UPDATE and then sets or clears the zone's warning for the state it finds.
//
// Only when UPDATE is configured. A zone that syncs by NOTIFY or API alone has
// no use for the agent's KEY, and a warning asking the operator to publish one
// would be wrong.
func proxyUpdateGate(zone string, check func() (ProxyUpdateState, error)) {
	if !configuredSchemes(ParentSyncConfig().Schemes)["update"] {
		return
	}
	state, err := check()
	if err != nil {
		lgDns.Error("DelegationSyncher: proxy UPDATE gate failed after an apex KEY change", "zone", zone, "err", err)
		return
	}
	lgDns.Info("DelegationSyncher: proxy UPDATE gate re-run after an apex KEY change", "zone", zone, "state", state)
}

// proxyStartupReconcile builds the sync plan (which runs the KEY-bootstrap
// state machine as the UPDATE gate) and, if any transport is usable, compares
// the parent with the child and sends what differs: the proxy's compare. It
// runs on first load, catching drift from while the agent was down without
// re-sending on every restart, and in place of a PROXY-SYNC that was queued
// or failed (delegationSyncLook). A failure is retried until the parent
// answers. Off the refresh path, since DSYNC discovery and the parent compare
// are both network.
func proxyStartupReconcile(ctx context.Context, zd *ZoneData, kdb *KeyDB, notifyq chan NotifyRequest,
	delsyncq chan DelegationSyncRequest, imr *Imr, ds DelegationSyncRequest) {

	handleProxyCompareWith(zd, ds,
		func() (string, bool, error) { return zd.ProxyStartupReconcile(ctx, kdb, notifyq, imr) },
		func(next DelegationSyncRequest, delay time.Duration) { requeueLookAfter(ctx, delsyncq, next, delay) })
}

// handleProxyCompareWith is the decision half of the proxy's compare, with the
// compare (run) and the requeue passed in so a test can stand in for them. A
// failure, and a compare that could not read all of the parent's delegation
// (errDelegationNotAllRead), is retried until the parent answers. A compare
// that found the parent in step or brought it there (inStep) clears
// delegationOutOfStep; one that sent nothing because the parent offers no
// usable scheme returns no error and does not.
func handleProxyCompareWith(zd *ZoneData, ds DelegationSyncRequest, run func() (msg string, inStep bool, err error),
	requeue func(next DelegationSyncRequest, delay time.Duration)) {

	if delegationSyncRetrySuperseded(zd, ds) {
		lgDns.Info("DelegationSyncher: proxy compare retry dropped; a later sync has succeeded",
			"zone", ds.ZoneName, "attempt", ds.Attempt)
		return
	}
	msg, inStep, err := run()
	if err != nil {
		next, delay := nextDelegationSyncRetry(ds, time.Now())
		lgDns.Error("DelegationSyncher: proxy compare with the parent failed; will retry", "zone", ds.ZoneName,
			"attempt", next.Attempt, "retry_in", delay, "err", err)
		requeue(next, delay)
		return
	}
	if inStep {
		zd.noteDelegationSyncInStep()
	}
	lgDns.Info("DelegationSyncher: proxy startup reconcile", "zone", ds.ZoneName, "in_step", inStep, "msg", msg)
}

// handleDelegationSyncSetup is the DELEGATION-SYNC-SETUP arm of the syncher.
//
// Extracted from the loop because its decisions are the interesting part and
// they were unreachable from a test: which failures wait for the IMR, which
// back off, which give up, and which are simply final. Reverting any one of
// them inside the switch used to leave every test green.
//
// SETUP needs the IMR, because the parent zone is discovered rather than
// configured. At startup this request routinely arrives before InitImrEngine
// has published the engine -- the same race the PROXY arm defers for -- and it
// used to be logged and dropped, so a child never bootstrapped unaided (#575).
func handleDelegationSyncSetup(ctx context.Context, conf *Config, delsyncq chan DelegationSyncRequest,
	kdb *KeyDB, zd *ZoneData, ds DelegationSyncRequest) {

	_ = handleDelegationSyncSetupWith(ctx, conf, delsyncq, ds, setupThenPoll(
		func() (bool, uint8, error) { return zd.delegationSyncSetup(ctx, kdb) },
		func(alg uint8) { conf.pollAfterAcceptedBootstrap(ctx, kdb, zd, alg) },
	))
}

// setupThenPoll runs the setup and, when the parent accepted the bootstrap
// ceremony, starts the post-bootstrap KeyState poll. It returns the setup's
// error for the SETUP arm to act on.
//
// Only an accepted ceremony starts the poll. The parent answers NOERROR as soon
// as it has stored the key, and decides trust afterwards, by a verification
// that may fail (#677). Nothing else would tell a tdns-auth child: it would
// hear the failure only on its next delegation UPDATE, or its next reload.
func setupThenPoll(setup func() (accepted bool, alg uint8, err error), poll func(alg uint8)) func() error {
	return func() error {
		accepted, alg, err := setup()
		if accepted {
			poll(alg)
		}
		return err
	}
}

// handleDelegationSyncSetupWith is the decision half of the SETUP arm: given an
// outcome, does the request wait for the IMR, back off, give up, or stop here?
//
// setup is passed in rather than called directly because that is what makes the
// four answers reachable. Producing each of them from a real DelegationSyncSetup
// needs a differently-broken zone every time -- and the one that matters most,
// ErrNoImrEngine after readiness, is behind a fully built and loaded zone, so it
// was never covered at all.
//
// Returns the channel of whatever follow-up work it scheduled, closed when that
// work finishes, and nil when it scheduled none -- the request succeeded, or it
// was final, or the retries ran out. The engine ignores it; it exists so
// "nothing more will happen for this zone" is observable rather than inferred
// from waiting out a backoff.
func handleDelegationSyncSetupWith(ctx context.Context, conf *Config, delsyncq chan DelegationSyncRequest,
	ds DelegationSyncRequest, setup func() error) <-chan struct{} {

	// Not up yet: put the request back rather than run it against a nil IMR,
	// and let it return exactly when the IMR is announced.
	if !conf.Internal.ImrReady.Published() {
		return deferForImr(ctx, delsyncq, conf.Internal.ImrReady, ds)
	}

	err := setup()
	switch {
	case err == nil:
		return nil

	case errors.Is(err, ErrNoImrEngine):
		// Published, and STILL not usable from here. This must not go back to
		// deferForImr: that waits on ImrReady, which is already closed, so the
		// request would come straight back and the parent's queue would spin
		// on this one zone and starve the parent's other zones. Whatever the
		// cause, it is a condition to wait out, so it takes the same bounded
		// backoff as any other non-final failure.
		if ds.Attempt+1 >= delegationSyncMaxRetries {
			lgDns.Error("DelegationSyncher: SIG(0) bootstrap setup gave up; the IMR is published"+
				" but still not usable for this zone",
				"zone", ds.ZoneName, "attempts", ds.Attempt+1, "err", err)
			return nil
		}
		return deferSetupRetry(ctx, delsyncq, ds, "IMR published but not usable")

	case errors.Is(err, errBootstrapTransient):
		// The parent's answer was not final. Same bounded backoff as the
		// other non-final failures, and the same give-up limit.
		if ds.Attempt+1 >= delegationSyncMaxRetries {
			lgDns.Error("DelegationSyncher: SIG(0) bootstrap setup gave up; the parent's answer"+
				" never became final", "zone", ds.ZoneName, "attempts", ds.Attempt+1, "err", err)
			return nil
		}
		return deferSetupRetry(ctx, delsyncq, ds, "the parent's answer was not final")

	case errors.Is(err, ErrKeyDBBusy):
		// The keystore's transaction was held past Begin's wait, by another
		// zone's setup generating its key in it or by any other writer. Not a
		// verdict on this zone: the same setup succeeds once the holder is
		// done, so it takes the same bounded backoff. With a queue per parent,
		// several parents' first setups can wait on the transaction at once.
		if ds.Attempt+1 >= delegationSyncMaxRetries {
			lgDns.Error("DelegationSyncher: SIG(0) bootstrap setup gave up; the keystore stayed busy",
				"zone", ds.ZoneName, "attempts", ds.Attempt+1, "err", err)
			return nil
		}
		return deferSetupRetry(ctx, delsyncq, ds, "the keystore was busy")

	case errors.Is(err, errBootstrapAdvertisementLookup):
		// The parent's SVCB advertisement could not be looked up: not a verdict
		// on the method set, so not final. Retry with the delegation-sync
		// backoff, the way the KeyState poller and the BADKEY arm do, rather
		// than leaving the zone loaded and never bootstrapped until the next
		// reload.
		if ds.Attempt+1 >= delegationSyncMaxRetries {
			lgDns.Error("DelegationSyncher: SIG(0) bootstrap setup gave up after repeated advertisement lookup failures",
				"zone", ds.ZoneName, "attempts", ds.Attempt+1, "err", err)
			return nil
		}
		return deferSetupRetry(ctx, delsyncq, ds, "advertisement lookup failed")

	case errors.Is(err, errBootstrapValidationFailed):
		// The parent looked and did not accept the key, and keeps no state
		// waiting for us (#677). What it could not find may still appear, so
		// re-bootstrap later, which has it verify again, a few times.
		next, delay, ok := nextReBootstrap(ds)
		if !ok {
			lgDns.Error("DelegationSyncher: SIG(0) bootstrap gave up; the parent still reports the key's"+
				" validation failed after every re-bootstrap. Fix the KEY's publication and re-bootstrap",
				"zone", ds.ZoneName, "rebootstraps", ds.ReBootstrapRound, "err", err)
			return nil
		}
		lgDns.Warn("DelegationSyncher: the parent reports the SIG(0) key's validation failed; will re-bootstrap",
			"zone", ds.ZoneName, "round", next.ReBootstrapRound, "of", childReBootstrapRounds,
			"delay", delay, "err", err)
		return requeueSetupAfter(ctx, delsyncq, next, delay)

	default:
		lgDns.Error("DelegationSyncher: error from DelegationSyncSetup, ignoring sync request",
			"zone", ds.ZoneName, "err", err)
	}
	return nil
}

// errBootstrapTransient marks a SIG(0) bootstrap whose outcome is not final:
// the parent could not be reached, failed, or is still verifying the key.
// Retry with backoff rather than treating the attempt as done.
var errBootstrapTransient = errors.New("the parent's answer to the SIG(0) bootstrap is not final")

// errBootstrapValidationFailed marks a SIG(0) bootstrap the parent refused
// because its verification of the key already failed (EDE
// KEY-VALIDATION-FAILED). Final for this attempt; the setup arm re-bootstraps
// later, a limited number of times.
var errBootstrapValidationFailed = errors.New("the parent's validation of the SIG(0) key failed")

// bootstrapOutcome turns the parent's answer to the bootstrap UPDATE into an
// error the setup arm can act on.
//
// The ceremony hands back the parent's rcode and EDE with a nil error, on
// purpose -- sendUpdateVia says so, "so it can apply the draft's per-RCODE,
// per-EDE policy". Nothing applied it. DelegationSyncSetup logged "bootstrap
// complete" for a SERVFAIL or a REFUSED alike, returned nil, and the setup arm
// took nil as done: a zone whose parent answered "not yet" was left
// unbootstrapped until the next reload. #575's symptom, by another road.
//
// Three outcomes, and only one of them retries:
//   - not final -- no answer at all, SERVFAIL, or REFUSED with EDE
//     KnownButNotTrusted (the parent has the key and is still verifying it):
//     errBootstrapTransient.
//   - the parent requires manual bootstrap (EDE ManualBootstrapRequired):
//     errBootstrapManual, which the caller already treats as waiting for the
//     operator, not as an error.
//   - a failed validation (EDE KeyValidationFailed): errBootstrapValidationFailed.
//     Final now; the setup arm re-bootstraps later, when what the parent could
//     not find may have appeared.
//   - a retired key (EDE Sig0KeyRetired): ErrSig0KeyTombstoned. A trusted
//     UPDATE from the zone deleted this key at the parent, which will not
//     take it again. Final; only a new key can bootstrap.
//   - anything else, any other refusal: a plain error. Retrying a verdict only
//     repeats it.
func bootstrapOutcome(ur UpdateResult, err error) error {
	if err != nil {
		if errors.Is(err, ErrUpdateUnreachable) {
			return fmt.Errorf("%w: %v", errBootstrapTransient, err)
		}
		return err
	}
	switch ur.Rcode {
	case dns.RcodeSuccess:
		return nil
	case dns.RcodeServerFailure:
		return fmt.Errorf("%w: the parent answered SERVFAIL", errBootstrapTransient)
	case dns.RcodeRefused:
		if ur.EDEFound {
			switch ur.EDECode {
			case edns0.EDESig0KeyKnownButNotTrusted:
				return fmt.Errorf("%w: the parent has the key and is still verifying it (EDE %d)",
					errBootstrapTransient, ur.EDECode)
			case edns0.EDESig0ManualBootstrapRequired:
				return fmt.Errorf("%w (EDE %d)", errBootstrapManual, ur.EDECode)
			case edns0.EDESig0KeyValidationFailed:
				return fmt.Errorf("%w (EDE %d %q)", errBootstrapValidationFailed, ur.EDECode, ur.EDEMessage)
			case edns0.EDESig0KeyRetired:
				return fmt.Errorf("%w (EDE %d %q); make a new SIG(0) key", ErrSig0KeyTombstoned, ur.EDECode, ur.EDEMessage)
			}
		}
	}
	if ur.EDEFound {
		return fmt.Errorf("the parent refused the SIG(0) bootstrap: rcode %s, EDE %d %q",
			dns.RcodeToString[ur.Rcode], ur.EDECode, ur.EDEMessage)
	}
	return fmt.Errorf("the parent refused the SIG(0) bootstrap: rcode %s", dns.RcodeToString[ur.Rcode])
}

// finishDelegationSyncSetup decides what a bootstrap ceremony's result means
// for the setup: done, waiting for the operator, retry, or failed.
//
// Split from DelegationSyncSetup, which tail-calls it, so the decision is
// reachable from a test. Driving DelegationSyncSetup itself needs a zone, a
// DSYNC lookup and a keystore; without the split, deleting the one line that
// applies bootstrapOutcome left every test green.
func (zd *ZoneData) finishDelegationSyncSetup(msg string, ur UpdateResult, err error) error {
	err = bootstrapOutcome(ur, err)
	if errors.Is(err, ErrNoUsableDsync) {
		// The parent advertises no UPDATE target: there is nobody to
		// bootstrap the key with. The common case, not an error: warned
		// about once per zone, and the setup is done.
		zd.noteNoUpdateTarget(err)
		return nil
	}
	if errors.Is(err, errBootstrapManual) {
		zd.noteUpdateTargetFound()
		// The parent's bootstrap is manual by design; this is the state
		// MANUAL-BOOTSTRAP-REQUIRED exists for, and it recurs on every load
		// until the operator acts. Not an error.
		lgDns.Info("DelegationSyncSetup: parent requires manual SIG(0) bootstrap; the apex KEY is published, waiting for the operator",
			"zone", zd.ZoneName, "msg", msg)
		return nil
	}
	if err != nil {
		lgDns.Error("DelegationSyncSetup: error from BootstrapSig0KeyWithParent", "zone", zd.ZoneName, "err", err)
		for _, tes := range ur.TargetStatus {
			lgDns.Error("DelegationSyncSetup: TargetUpdateStatus", "zone", zd.ZoneName, "status", tes)
		}
		return err
	}
	zd.noteUpdateTargetFound()
	lgDns.Info("DelegationSyncSetup: SIG(0) key bootstrap complete", "zone", zd.ZoneName, "msg", msg)
	return nil
}

// runExplicitSync compares the zone's delegation with the parent's and, when
// they differ, sends the difference through the parent's scheme: the body of
// EXPLICIT-SYNC-DELEGATION. It compares first, so a parent already in step
// costs a lookup and is sent nothing.
func (zd *ZoneData) runExplicitSync(ctx context.Context, kdb *KeyDB, notifyq chan NotifyRequest, imr *Imr) DelegationSyncStatus {
	lgDns.Info("DelegationSyncher: request for explicit delegation sync", "zone", zd.ZoneName)
	return zd.runExplicitSyncWith(
		func() (DelegationSyncStatus, error) { return zd.AnalyseZoneDelegation(imr) },
		func(syncstate DelegationSyncStatus) (string, uint8, UpdateResult, string, error) {
			return zd.syncZoneDelegationVia(ctx, kdb, notifyq, syncstate, imr)
		})
}

// runExplicitSyncWith is runExplicitSync with the compare and the send passed
// in, so a test can stand in for the parent. send returns the scheme that
// carried the difference. It decides what the outcome means for the zone's
// mark that the parent may lack a change (delegationOutOfStep): it clears it
// only when the parent is known to hold the whole delegation (inStepAfter).
func (zd *ZoneData) runExplicitSyncWith(analyse func() (DelegationSyncStatus, error),
	send func(DelegationSyncStatus) (string, uint8, UpdateResult, string, error)) DelegationSyncStatus {

	syncstate, err := analyse()
	if err != nil {
		lgDns.Error("DelegationSyncher: error from AnalyseZoneDelegation", "zone", zd.ZoneName, "err", err)
		syncstate.Error = true
		syncstate.ErrorMsg = err.Error()
		return syncstate
	}

	if syncstate.InSync {
		lgDns.Info("DelegationSyncher: delegation data in parent is in sync with child, no action needed",
			"zone", syncstate.ZoneName, "parent", syncstate.Parent)
		if syncstate.inStepAfter("") {
			zd.noteDelegationSyncInStep()
		}
		return syncstate
	}

	// Not in sync, let's fix that.
	msg, rcode, ur, scheme, err := send(syncstate)
	if errors.Is(err, ErrNoUsableDsync) {
		// Not a failure: the answer says why nothing was sent, with no
		// error (planUsable warned once), and nothing retries, since there
		// is nothing usable to retry through. But the parent lacks the
		// difference this compare found, so a later change must go as a
		// compare too, as when a stored change is not sent for this reason.
		lgDns.Debug("DelegationSyncher: nothing sent", "zone", zd.ZoneName, "reason", err)
		zd.noteDelegationSyncNotSent()
		syncstate.noUsableScheme = true
		syncstate.Msg = err.Error()
		return syncstate
	}
	if err != nil {
		// The compare found a difference the parent did not get. A retry
		// marks that too (requeueLookAfter), but a request an operator waits
		// on is answered and not retried.
		lgDns.Error("DelegationSyncher: error from SyncZoneDelegation", "zone", zd.ZoneName, "err", err)
		zd.noteDelegationSyncNotSent()
		syncstate.Error = true
		syncstate.ErrorMsg = err.Error()
		syncstate.UpdateResult = ur
	} else {
		lgDns.Info("DelegationSyncher: SyncZoneDelegation completed", "zone", zd.ZoneName, "msg", msg,
			"rcode", dns.RcodeToString[int(rcode)], "scheme", scheme)
		if syncstate.inStepAfter(scheme) {
			zd.noteDelegationSyncInStep()
		} else {
			zd.noteDelegationSyncSentBy(scheme)
		}
	}
	syncstate.Msg = msg
	syncstate.Rcode = rcode
	return syncstate
}

// inStepAfter reports whether an explicit sync's compare, and the send by
// scheme that followed it ("" for none), leave the parent known to hold all a
// stored difference assumes. The compare must have read all it asked
// (Complete) and compared the DS (dsCompared: not while a rollover owns it).
// A send counts only when the parent said it applied it: an UPDATE or an API
// call. A NOTIFY's success says the notifier took it; the parent has yet to
// come and read it, so it marks the parent instead (noteDelegationSyncSentBy),
// and a compare that finds it in step will clear that.
func (dss DelegationSyncStatus) inStepAfter(scheme string) bool {
	if !dss.Complete() || !dss.dsCompared {
		return false
	}
	switch scheme {
	case "", "UPDATE", "API":
		return true
	}
	return false
}

// handleExplicitSyncWith is the EXPLICIT-SYNC-DELEGATION arm. The DS engine's
// first-run compare lands in exactly the window before the IMR is up, and a
// follow-keys change right after a start can too: such a request waits for it.
// One an operator is waiting on is answered at once, with the analysis error,
// as before: its caller gives up after four seconds.
//
// One nobody waits on is a compare that must reach the parent: a stored
// change queued or failed as one (delegationSyncLook), the DS engine's, a
// bootstrap's. When it fails, or could not read all of the parent's
// delegation (Complete), it is retried until the parent answers
// (requeueLookAfter). It is not dropped for a later success, as a refresh
// sync's retry is: that success may have been a refresh sync, which compares
// no DS. One that found a difference it could not send, because the parent
// offers no usable scheme, has nothing to retry through: it is not retried,
// even after an incomplete read, and the run marks the parent out of step
// (runExplicitSyncWith).
//
// It returns the channel of the worker it started -- the wait for the IMR, or
// the retry -- and nil when it started none.
func handleExplicitSyncWith(ctx context.Context, ready *ImrReadiness, delsyncq chan DelegationSyncRequest,
	ds DelegationSyncRequest, run func() DelegationSyncStatus) <-chan struct{} {

	if explicitSyncWaitsForImr(ready, ds) {
		return deferForImr(ctx, delsyncq, ready, ds)
	}
	syncstate := run()
	if ds.Response != nil {
		ds.Response <- syncstate
		return nil
	}
	if syncstate.noUsableScheme || (!syncstate.Error && syncstate.Complete()) {
		return nil
	}
	why := syncstate.ErrorMsg
	if !syncstate.Error {
		why = fmt.Sprintf("the parent's delegation was not all read: %v", syncstate.Unread)
	}
	next, delay := nextDelegationSyncRetry(ds, time.Now())
	lgDns.Error("DelegationSyncher: explicit sync failed; will compare with the parent again",
		"zone", ds.ZoneName, "attempt", next.Attempt, "retry_in", delay, "err", why)
	return requeueLookAfter(ctx, delsyncq, next, delay)
}

// handleSignalsEditedArm is the SIGNALS-EDITED arm: an operator's edit of the
// apex CDS, CDNSKEY or CSYNC (delsync_signals.go). Nothing goes out while a
// transaction holds the zone -- the edit is not served yet, and a NOTIFY tells
// the parent to come and read it -- nor before the IMR is up, which the parent's
// DSYNC lookup needs. It returns the deferred worker's done channel when it
// deferred, nil when it ran.
func handleSignalsEditedArm(ctx context.Context, ready *ImrReadiness, delsyncq chan DelegationSyncRequest,
	zd *ZoneData, ds DelegationSyncRequest, run func()) <-chan struct{} {

	if zd.txOpenCount() > 0 {
		return deferUntilHoldEnds(ctx, delsyncq, zd, ds)
	}
	if explicitSyncWaitsForImr(ready, ds) {
		return deferForImr(ctx, delsyncq, ready, ds)
	}
	run()
	return nil
}

// explicitSyncWaitsForImr reports whether a request that needs the IMR should
// wait for it rather than run now. Only a request nobody is waiting on: an
// operator's is answered at once. A process with no readiness signal at all
// never waits, since nothing would ever end the wait.
func explicitSyncWaitsForImr(ready *ImrReadiness, ds DelegationSyncRequest) bool {
	return ds.Response == nil && ready != nil && !ready.Published()
}

// txHoldPollInterval is how often a request deferred by deferUntilHoldEnds
// looks again. A variable only so a test need not wait.
var txHoldPollInterval = 250 * time.Millisecond

// deferUntilHoldEnds puts a request back on the queue once the zone has no open
// transaction. Off the syncher's goroutine, like deferForImr, so a held zone
// does not stall the others. A hold is bounded (txHoldLimit), so the wait is
// too; it says so if it runs longer. The returned channel closes when the
// worker exits, for tests.
func deferUntilHoldEnds(ctx context.Context, delsyncq chan DelegationSyncRequest, zd *ZoneData,
	ds DelegationSyncRequest) <-chan struct{} {

	lgDns.Info("DelegationSyncher: the zone has an open transaction; deferring until it commits",
		"zone", ds.ZoneName, "command", ds.Command)
	done := make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(txHoldPollInterval)
		defer tick.Stop()
		warn := time.NewTimer(2 * txHoldLimit)
		defer warn.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-warn.C:
				lgDns.Warn("DelegationSyncher: still waiting for the zone's transaction to end",
					"zone", ds.ZoneName, "command", ds.Command, "waited", 2*txHoldLimit)
			case <-tick.C:
				if zd.txOpenCount() > 0 {
					continue
				}
				select {
				case delsyncq <- ds:
				case <-ctx.Done():
				}
				return
			}
		}
	}()
	return done
}
