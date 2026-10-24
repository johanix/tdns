/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"errors"
	"fmt"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

func (zd *ZoneData) PublishKeyRRs(sak *Sig0ActiveKeys) error {
	lgHandler.Debug("PublishKeyRRs: received request to publish KEY records", "zone", zd.ZoneName)
	if zd.Options[OptDontPublishKey] {
		return fmt.Errorf("zone %q does not allow KEY RR publication", zd.ZoneName)
	}

	if zd.KeyDB.UpdateQ == nil {
		return fmt.Errorf("PublishKeyRRs: KeyDB.UpdateQ is nil")
	}

	rrset := core.RRset{
		Name: zd.ZoneName,
	}

	for _, pkc := range sak.Keys {
		if !dns.IsSubDomain(zd.ZoneName, pkc.KeyRR.Header().Name) {
			lgHandler.Debug("PublishKeyRRs: SIG(0) key is not a subdomain of zone", "key", pkc.KeyRR.Header().Name, "zone", zd.ZoneName)
			return fmt.Errorf("PublishKeyRRs: SIG(0) key %q is not a subdomain of zone %q", pkc.KeyRR.Header().Name, zd.ZoneName)
		}
		rrset.RRs = append(rrset.RRs, &pkc.KeyRR)
	}

	zd.KeyDB.UpdateQ <- UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       zd.ZoneName,
		Actions:        rrset.RRs,
		InternalUpdate: true,
	}

	return nil
}

func (zd *ZoneData) UnpublishKeyRRs() error {
	anti_key_rr, err := dns.NewRR(fmt.Sprintf("%s 0 ANY KEY 0 0 0 AA==", zd.ZoneName))
	if err != nil {
		return err
	}

	zd.KeyDB.UpdateQ <- UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       zd.ZoneName,
		Actions:        []dns.RR{anti_key_rr},
		InternalUpdate: true,
	}

	return nil
}

// sig0KeyIsUsable reports whether any KEY published at name is backed by an
// active private key -- i.e. whether this zone can actually sign with what it
// has published.
//
// The distinction matters because a published KEY used to be taken as proof
// that the key situation was in hand. It is not: the record can outlive the
// private key, and then the zone can neither sign updates nor bootstrap, while
// looking from the outside exactly like one that can (#576).
func (zd *ZoneData) sig0KeyIsUsable(name string) bool {
	usable, _ := zd.verifyPublishedKeyRRs(name)
	return usable
}

// VerifyPublishedKeyRRs checks that every KEY published at name is backed by a
// private key this server actually holds, and warns about the ones that are
// not. It reports only whether the check could be CARRIED OUT; use
// sig0KeyIsUsable for the answer itself.
//
// name, not the zone apex. On a childsync zone the caller passes the
// DSYNC UPDATE target (updates.<zone>), where the apex is the wrong owner
// entirely: the check found no KEY there, concluded the zone had none, and
// minted an apex SIG(0) key nothing had asked for -- using the algorithm from
// the CHILD half of the delegationsync config, which on a parent is usually
// unset, so the whole call failed with "unknown keygen algorithm". On the child
// path name IS the apex, so nothing changes there.
//
// The generate-and-publish tail this function once had is gone. Publishing was
// never its job: the caller's own step 4 does it, for the right name and with
// the algorithm the caller was given, and reaches it in exactly the case this
// function is not called (no KEY published yet).
func (zd *ZoneData) VerifyPublishedKeyRRs(name string) error {
	_, err := zd.verifyPublishedKeyRRs(name)
	return err
}

// verifyPublishedKeyRRs is VerifyPublishedKeyRRs plus the answer it was already
// computing and throwing away: whether at least one published KEY has an active
// private key behind it.
func (zd *ZoneData) verifyPublishedKeyRRs(name string) (bool, error) {
	owner, err := zd.GetOwner(name)
	if err != nil {
		return false, err
	}
	if owner == nil || owner.RRtypes == nil {
		return false, nil // nothing published at name, nothing to verify
	}
	key_rrset, exist := owner.RRtypes.Get(dns.TypeKEY)
	numpubkeys := len(key_rrset.RRs)
	if !exist || numpubkeys == 0 {
		return false, nil
	}

	if numpubkeys > 1 {
		zd.Logger.Printf("Warning: %q has %d KEY records published. This is likely a mistake.", name, numpubkeys)
	}

	// A published KEY is only useful if we can sign with it.
	zd.Logger.Printf("VerifyPublishedKeyRRs(%q): KEY RRset exists. Checking availability of private key.", name)
	sak, err := zd.KeyDB.GetSig0Keys(name, Sig0StateActive)
	if err != nil {
		zd.Logger.Printf("Error from GetSig0Keys(%q, %s): %v", name, Sig0StateActive, err)
		return false, err
	}
	usable := false
	for _, pkey := range key_rrset.RRs {
		found := false
		published, ok := pkey.(*dns.KEY)
		if !ok {
			continue
		}
		pkeyid := published.KeyTag()
		for _, key := range sak.Keys {
			// The whole key, not the tag. A key tag is sixteen bits and is not
			// unique: an active keystore key can collide with an orphaned
			// published one, and on a tag-only match this reported the orphan
			// as usable and skipped publishing the active key. The zone then
			// looks prepared, signs with a key nobody can find, and every
			// signature fails to validate against the published record -- the
			// #576 failure again, reached by a different route and with no
			// warning at all, because the tag matched.
			if sameKeyRdata(&key.KeyRR, published) {
				found = true
				break
			}
		}
		if found {
			usable = true
			continue
		}
		zd.Logger.Printf("Warning: %q: no active private key for the published KEY with keyid=%d. This key should be removed.", name, pkeyid)
	}
	return usable, nil
}

// errBootstrapManual: the selected SIG(0) bootstrap method is manual, so no
// automatic ceremony was (or could be) sent. The draft's
// MANUAL-BOOTSTRAP-REQUIRED state seen from the child's side; callers with a
// per-load or retry loop treat it as "waiting for the operator", not as an
// error to retry or to log as such.
var errBootstrapManual = errors.New("manual SIG(0) bootstrap required by the parent")

func (zd *ZoneData) BootstrapSig0KeyWithParent(ctx context.Context, alg uint8) (string, UpdateResult, error) {
	return zd.bootstrapSig0KeyWithParent(ctx, alg, zd.zoneChildBootstrapMethods())
}

func (zd *ZoneData) bootstrapSig0KeyWithParent(ctx context.Context, alg uint8, willing []string) (string, UpdateResult, error) {
	if err := zd.resolveParentZone(); err != nil {
		return "", UpdateResult{}, fmt.Errorf("BootstrapSig0KeyWithParent(%q): %w", zd.ZoneName, err)
	}

	sak, err := zd.KeyDB.GetSig0Keys(zd.ZoneName, Sig0StateActive)
	if err != nil {
		return fmt.Sprintf("BootstrapSig0KeyWithParent(%q) failed to get SIG(0) active keys: %v", zd.ZoneName, err), UpdateResult{}, err
	}
	if len(sak.Keys) == 0 {
		// XXX: Should we generate new keys or return an error?
		//		log.Printf("No active SIG(0) key found for zone %s. Generating new key with algorithm %s", zd.ZoneName, dns.AlgorithmToString[alg])
		//		pkc, msg, err := zd.KeyDB.GenerateKeypair(zd.ZoneName, "bootstrap-sig0", "created", dns.TypeKEY, alg, "", nil) // nil = no tx
		//		if err != nil {
		//			msg := fmt.Sprintf("RolloverSig0KeyWithParent(%s) failed to generate keypair: %v", zd.ZoneName, err)
		//			log.Printf(msg)
		//			return msg, err
		//		}
		//		sak.Keys = append(sak.Keys, pkc)
		//		zd.Logger.Printf(msg)

		kp := KeystorePost{
			Command:     "sig0-mgmt",
			SubCommand:  "generate",
			Zone:        zd.ZoneName,
			Algorithm:   alg,
			State:       Sig0StateActive,
			ParentState: 255, // XXX: FIXME johani 20250930
			Creator:     "bootstrap-sig0",
		}
		resp, err := zd.KeyDB.Sig0KeyMgmt(nil, kp)
		if err != nil {
			return fmt.Sprintf("BootstrapSig0KeyWithParent(%q) failed to generate keypair: %v", zd.ZoneName, err), UpdateResult{}, err
		}
		zd.Logger.Printf("%s", resp.Msg)

		sak, err = zd.KeyDB.GetSig0Keys(zd.ZoneName, Sig0StateActive)
		if err != nil {
			return fmt.Sprintf("BootstrapSig0KeyWithParent(%q, after key generation) failed to get SIG(0) active keys: %v",
				zd.ZoneName, err), UpdateResult{}, err
		}
		if len(sak.Keys) == 0 {
			return fmt.Sprintf("BootstrapSig0KeyWithParent(%q, after key generation) failed to get SIG(0) active keys: %v",
				zd.ZoneName, err), UpdateResult{}, err
		}
	}

	if len(sak.Keys) == 0 {
		return "BootstrapSig0KeyWithParent: no active SIG(0) keys available", UpdateResult{}, fmt.Errorf("no active SIG(0) keys for zone %q", zd.ZoneName)
	}
	pkc := sak.Keys[0]

	// 2. Get the parent DSYNC RRset
	dsyncTarget, err := Globals.ImrEngine.LookupDSYNCTarget(ctx, zd.ZoneName, dns.TypeANY, core.SchemeUpdate)
	if err != nil {
		return fmt.Sprintf("BootstrapSig0KeyWithParent(%q) failed to lookup DSYNC target: %v", zd.ZoneName, err), UpdateResult{}, err
	}

	lgHandler.Info("BootstrapSig0KeyWithParent: DSYNC target found", "zone", zd.ZoneName, "target", dsyncTarget.RR)

	advertised, present, aerr := advertisedBootstrapMethods(ctx, Globals.ImrEngine, dsyncTarget,
		ParentSyncConfig().Update.AllowInsecure)
	if aerr != nil {
		// Retryable, not "no advertisement": see advertisedBootstrapMethods.
		return fmt.Sprintf("BootstrapSig0KeyWithParent(%q): %v", zd.ZoneName, aerr), UpdateResult{},
			fmt.Errorf("BootstrapSig0KeyWithParent(%q): %w", zd.ZoneName, aerr)
	}
	method, merr := selectChildBootstrapMethod(advertised, present, willing)
	if merr != nil {
		return fmt.Sprintf("BootstrapSig0KeyWithParent(%q): %v", zd.ZoneName, merr), UpdateResult{}, merr
	}
	lgHandler.Info("BootstrapSig0KeyWithParent: selected bootstrap method",
		"zone", zd.ZoneName, "method", method, "advertised", advertised, "willing", willing)
	if method == "manual" {
		// Not a failure: the parent said so (its SVCB advertisement, or the
		// child's own list), and the operator has to do the rest. Callers
		// that run on every zone load log this at Info, not Error.
		msg := fmt.Sprintf("BootstrapSig0KeyWithParent(%q): parent requires manual SIG(0) bootstrap; not sending KEY UPDATE", zd.ZoneName)
		return msg, UpdateResult{}, fmt.Errorf("%w for %s", errBootstrapManual, zd.ZoneName)
	}
	if method == "at-ns" {
		// The parent will look for this KEY at _sig0key.<child>._signal.<ns>
		// (atNsFindings) the moment the ceremony arrives, so it has
		// to be APPLIED, not merely queued, before the ceremony is sent; the
		// publish waits for the updater's verdict. The willing list only
		// offers at-ns when at least one signal name is publishable here, so
		// zero means the zone changed under us or the apply failed.
		if n := zd.publishSig0KeyAtSignalNames(ctx, []dns.RR{&pkc.KeyRR}); n == 0 {
			msg := fmt.Sprintf("BootstrapSig0KeyWithParent(%q): at-ns selected but the KEY could not be published at any _signal name", zd.ZoneName)
			return msg, UpdateResult{}, fmt.Errorf("at-ns bootstrap: no _sig0key._signal name for %s is in a zone this server is primary for", zd.ZoneName)
		}
	}

	// 3. Create the self-signed bootstrap ceremony "DEL <child> ANY KEY" +
	// "ADD <child> KEY" (draft-ietf-dnsop-delegation-mgmt-via-ddns-02
	// §"Bootstrapping the Child's Key"). The DEL removes any previously
	// published keys for this child; the parent UPDATE Receiver MUST defer it
	// until this new key is validated, so it never evicts an already-trusted
	// key on an un-validated bootstrap. RemoveRRset builds the class-ANY RRset
	// delete (CreateUpdate's Remove would emit class-NONE per-RR deletes).
	msg := new(dns.Msg)
	msg.SetUpdate(zd.GetParent())
	msg.RemoveRRset([]dns.RR{&pkc.KeyRR}) // DEL <child> ANY KEY
	msg.Insert([]dns.RR{&pkc.KeyRR})      // ADD <child> KEY
	msg.SetEdns0(1232, true)              // OPT RR so the parent can return EDE

	msg, err = SignMsg(*msg, zd.ZoneName, sak)
	if err != nil {
		return fmt.Sprintf("BootstrapSig0KeyWithParent(%q) failed to sign message: %v", zd.ZoneName, err), UpdateResult{}, err
	}

	// 4. Send the message to the parent
	rcode, ur, err := SendUpdate(ctx, msg, zd.GetParent(), dsyncTarget.Addresses)
	if err != nil {
		return fmt.Sprintf("BootstrapSig0KeyWithParent(%q) failed to send update message: %v", zd.ZoneName, err), ur, err
	}

	if rcode == dns.RcodeSuccess {
		tx, err := zd.KeyDB.Begin("BootstrapSig0KeyWithParent")
		if err != nil {
			return fmt.Sprintf("BootstrapSig0KeyWithParent(%q) failed to begin transaction: %v", zd.ZoneName, err), UpdateResult{}, err
		}
		var sig0InvalidateZones []string
		defer func() {
			if err != nil {
				tx.Rollback()
				return
			}
			if cerr := tx.Commit(); cerr != nil {
				return
			}
			for _, zone := range sig0InvalidateZones {
				zd.KeyDB.invalidateSig0Cache(zone)
			}
		}()

		// 5. Change state of the new key from "created" to "active".
		kp := KeystorePost{
			Command:    "sig0-mgmt",
			SubCommand: "setstate",
			Keyname:    pkc.KeyRR.Header().Name,
			Keyid:      uint16(pkc.KeyRR.KeyTag()),
			State:      Sig0StateActive,
		}

		resp, err := zd.KeyDB.Sig0KeyMgmt(tx, kp)
		if err != nil {
			str := fmt.Sprintf("BootstrapSig0KeyWithParent(%q) failed to change state of key %d to active: %v",
				zd.ZoneName, pkc.KeyRR.KeyTag(), err)
			zd.Logger.Print(str)
			return str, UpdateResult{}, errors.New(str)
		}
		if resp.Error {
			return fmt.Sprintf("BootstrapSig0KeyWithParent(%q) failed to change state of key %d to active: %v",
				zd.ZoneName, pkc.KeyRR.KeyTag(), resp.ErrorMsg), UpdateResult{}, fmt.Errorf("%s", resp.ErrorMsg)
		}
		sig0InvalidateZones = resp.BulkSig0InvalidateZones
		zd.Logger.Printf("%s", resp.Msg)
	}

	return fmt.Sprintf("BootstrapSig0KeyWithParent(%q) sent update message; received rcode %s back", zd.ZoneName, dns.RcodeToString[rcode]), ur, nil
}

// rolloverLookupDSYNCTarget and rolloverSendUpdate are the parent exchanges
// RolloverSig0KeyWithParent makes; a test replaces them to play the parent.
var rolloverLookupDSYNCTarget = func(ctx context.Context, zone string) (*DsyncTarget, error) {
	return Globals.ImrEngine.LookupDSYNCTarget(ctx, zone, dns.TypeANY, core.SchemeUpdate)
}
var rolloverSendUpdate = SendUpdate

// beginSig0Rollover claims zone for one SIG(0) rollover, and the func it
// returns gives the claim back. A second claim while one is held is refused,
// not queued: two rollovers of one zone would each get a new key accepted by
// the parent and each make its own key active.
func (kdb *KeyDB) beginSig0Rollover(zone string) (func(), error) {
	zone = dns.CanonicalName(zone)
	kdb.sig0RolloverMu.Lock()
	defer kdb.sig0RolloverMu.Unlock()
	if kdb.sig0Rollovers[zone] {
		return nil, fmt.Errorf("a SIG(0) rollover for %s is already running", zone)
	}
	if kdb.sig0Rollovers == nil {
		kdb.sig0Rollovers = map[string]bool{}
	}
	kdb.sig0Rollovers[zone] = true
	return func() {
		kdb.sig0RolloverMu.Lock()
		delete(kdb.sig0Rollovers, zone)
		kdb.sig0RolloverMu.Unlock()
	}, nil
}

// Returns msg, old keyid, new keyid, error, UpdateResult
//
// No keystore transaction is held across an UPDATE to the parent, or every
// other keystore writer would wait for the parent. The new key is committed
// before the parent is asked to trust it, and the local state changes are a
// second short transaction once the parent has accepted the roll. One
// rollover per zone at a time (beginSig0Rollover).
func (zd *ZoneData) RolloverSig0KeyWithParent(ctx context.Context, alg uint8, action string) (string, uint16, uint16, UpdateResult, error) {
	release, err := zd.KeyDB.beginSig0Rollover(zd.ZoneName)
	if err != nil {
		return "", 0, 0, UpdateResult{}, fmt.Errorf("RolloverSig0KeyWithParent(%q): %w", zd.ZoneName, err)
	}
	defer release()

	// 1. Get the parent zone
	if err := zd.resolveParentZone(); err != nil {
		return "", 0, 0, UpdateResult{}, fmt.Errorf("RolloverSig0KeyWithParent(%q): %w", zd.ZoneName, err)
	}

	// 2. Get the parent DSYNC RRset
	dsyncTarget, err := rolloverLookupDSYNCTarget(ctx, zd.ZoneName)
	if err != nil {
		return "", 0, 0, UpdateResult{}, fmt.Errorf("RolloverSig0KeyWithParent(%q) failed to lookup DSYNC target: %v", zd.ZoneName, err)
	}
	lgHandler.Info("RolloverSig0KeyWithParent: DSYNC target found", "zone", zd.ZoneName)

	//	if action == "complete" || action == "add" {
	sak, err := zd.KeyDB.GetSig0Keys(zd.ZoneName, Sig0StateActive)
	if err != nil {
		return "", 0, 0, UpdateResult{}, fmt.Errorf("RolloverSig0KeyWithParent(%q) failed to get SIG(0) active keys: %v", zd.ZoneName, err)
	}
	if len(sak.Keys) == 0 {
		return "", 0, 0, UpdateResult{}, fmt.Errorf("RolloverSig0KeyWithParent(%q): no active SIG(0) keys found", zd.ZoneName)
	}
	oldkey := sak.Keys[0]

	// 3. Generate a new key. With a nil tx Sig0KeyMgmt commits it in a short
	// transaction of its own. The key is taken from the result: a query for
	// created keys can find an older one.
	kpresp, err := zd.KeyDB.Sig0KeyMgmt(nil, KeystorePost{
		Command:    "sig0-mgmt",
		SubCommand: "generate",
		Zone:       zd.ZoneName,
		Algorithm:  alg,
		State:      Sig0StateCreated,
		Creator:    "rollover-sig0",
	})
	if err != nil {
		return "", 0, 0, UpdateResult{}, fmt.Errorf("RolloverSig0KeyWithParent(%q) failed to generate keypair: %v", zd.ZoneName, err)
	}
	pkc := kpresp.GeneratedSig0Key
	if pkc == nil {
		return "", 0, 0, UpdateResult{}, fmt.Errorf("RolloverSig0KeyWithParent(%q): key generation returned no key", zd.ZoneName)
	}
	zd.Logger.Printf("%s", kpresp.Msg)

	oldkeyid := oldkey.KeyRR.KeyTag()
	newkeyid := pkc.KeyRR.KeyTag()

	// 4. Create the DNS UPDATE message
	m, err := CreateUpdate(zd.GetParent(), []dns.RR{&pkc.KeyRR}, []dns.RR{})
	if err != nil {
		zd.discardRolloverKey(pkc)
		return "", 0, 0, UpdateResult{}, fmt.Errorf("RolloverSig0KeyWithParent(%q) failed to create update message: %v", zd.ZoneName, err)
	}

	lgHandler.Info("RolloverSig0KeyWithParent: signing addition of new key",
		"zone", zd.ZoneName, "newKeyid", newkeyid, "signingKeyid", oldkeyid)

	m, err = SignMsg(*m, zd.ZoneName, sak)
	if err != nil {
		zd.discardRolloverKey(pkc)
		return "", 0, 0, UpdateResult{}, fmt.Errorf("RolloverSig0KeyWithParent(%q) failed to sign message: %v", zd.ZoneName, err)
	}

	// 5. Send the ADD message to the parent
	rcode, ur, err := rolloverSendUpdate(ctx, m, zd.GetParent(), dsyncTarget.Addresses)
	if err != nil {
		// No answer, so the parent may have applied the UPDATE: keep the key.
		return "", 0, 0, ur, fmt.Errorf("RolloverSig0KeyWithParent(%q) failed to send update message: %v (new key %d kept in state %s)",
			zd.ZoneName, err, newkeyid, Sig0StateCreated)
	}

	// XXX: Here it is *very important* to update the active key in the keystore
	// to the new key, but only after we have received a successful response
	// from the parent.

	if rcode != dns.RcodeSuccess {
		zd.discardRolloverKey(pkc)
		return "", 0, 0, ur, fmt.Errorf("RolloverSig0KeyWithParent(%q) update message failed: %s. Rollover aborted",
			zd.ZoneName, dns.RcodeToString[rcode])
	}

	if action == "add" {
		return fmt.Sprintf("RolloverSig0KeyWithParent(%q) successfully added new key with keyid %d",
			zd.ZoneName, newkeyid), oldkeyid, newkeyid, ur, nil
	}
	//	} // end of phase 1

	//	if action == "complete" || action == "remove" {
	// 6. Request deletion of the old active key from the parent, signed by the new active key.
	m, err = CreateUpdate(zd.GetParent(), []dns.RR{}, []dns.RR{&oldkey.KeyRR})
	if err != nil {
		return fmt.Sprintf("RolloverSig0KeyWithParent(%q) failed to create update message: %v",
			zd.ZoneName, err), oldkeyid, newkeyid, ur, err
	}

	newSak := &Sig0ActiveKeys{Keys: []*PrivateKeyCache{pkc}}
	lgHandler.Info("RolloverSig0KeyWithParent: signing removal of old key",
		"zone", zd.ZoneName, "removeKeyid", oldkeyid, "signingKeyid", newkeyid)
	m, err = SignMsg(*m, zd.ZoneName, newSak)
	if err != nil {
		return "", oldkeyid, newkeyid, ur, fmt.Errorf("RolloverSig0KeyWithParent(%q) failed to sign message: %v", zd.ZoneName, err)
	}

	// 7. Send the REMOVE message to the parent
	rcode, ur, err = rolloverSendUpdate(ctx, m, zd.GetParent(), dsyncTarget.Addresses)
	if err != nil {
		// No answer, so the parent may have dropped the old key: then it
		// trusts only the new one, as after a failed activation below. It
		// accepted the new key either way, so making that one active is safe.
		return "", oldkeyid, newkeyid, ur, fmt.Errorf("RolloverSig0KeyWithParent(%q): the REMOVE of key %d got no answer: %v. "+
			"The parent accepted key %d and may or may not have dropped key %d. "+
			"Do not run roll-key again: if the parent dropped key %d, its ADD would be signed by a key the parent no longer trusts. "+
			"The parent trusts key %d either way, so finish the roll with this daemon's CLI: %s",
			zd.ZoneName, oldkeyid, err, newkeyid, oldkeyid, oldkeyid, newkeyid,
			sig0SetstateRecovery(zd.ZoneName, newkeyid, oldkeyid))
	}

	if rcode != dns.RcodeSuccess {
		// Delete of the old active key from the parent truststore failed. So we will continue to use the old key.
		return "", oldkeyid, newkeyid, ur, fmt.Errorf("RolloverSig0KeyWithParent(%q) update message failed: %s. Rollover aborted",
			zd.ZoneName, dns.RcodeToString[rcode])
	}
	//	} // end of phase 2

	// At this point we have successfully rolled the trusted SIG(0) key in the parent truststore.
	// We now need to update the active key in our own keystore to the new key and also possibly publish the new key.

	//	if action == "complete" || action == "update-local" {
	// 8. Change state of the new key from "created" to "active". Change state of the old key from "active" to "retired".
	if err := zd.activateRolledSig0Key(pkc, oldkey); err != nil {
		// The parent trusts only the new key now, and this zone still signs
		// with the old one. A new roll-key would sign its ADD with the old key
		// too, so name the way out instead.
		msg := fmt.Sprintf("RolloverSig0KeyWithParent(%q): the parent accepted the roll and now trusts only key %d, but the local key state change failed: %v. "+
			"Do not run roll-key again: its ADD would be signed by key %d, which the parent has dropped. "+
			"Set the states with this daemon's CLI: %s",
			zd.ZoneName, newkeyid, err, oldkeyid, sig0SetstateRecovery(zd.ZoneName, newkeyid, oldkeyid))
		zd.Logger.Print(msg)
		return "", oldkeyid, newkeyid, ur, errors.New(msg)
	}

	// 9. Publish the new key
	if err := zd.PublishKeyRRs(newSak); err != nil {
		msg := fmt.Sprintf("RolloverSig0KeyWithParent(%q) failed to publish new key: %v", zd.ZoneName, err)
		zd.Logger.Print(msg)
		return "", oldkeyid, newkeyid, ur, errors.New(msg)
	}
	// And wherever an at-ns bootstrap put the old one.
	zd.refreshSig0KeyAtSignalNames(ctx, []dns.RR{&pkc.KeyRR})
	//	} // end of phase 3

	return fmt.Sprintf("RolloverSig0KeyWithParent(%q) successfully rolled from SIG(0) key %d to SIG(0) key %d",
		zd.ZoneName, oldkeyid, newkeyid), oldkeyid, newkeyid, ur, nil
}

// sig0SetstateRecovery names the CLI commands that finish a SIG(0) roll by
// hand: newkeyid active, then oldkeyid retired. Without the CLI's own prefix,
// which differs between the daemons that serve roll-key.
func sig0SetstateRecovery(zone string, newkeyid, oldkeyid uint16) string {
	return fmt.Sprintf("\"keystore sig0 setstate -z %s --keyid %d --state %s\", then \"keystore sig0 setstate -z %s --keyid %d --state %s\"",
		zone, newkeyid, Sig0StateActive, zone, oldkeyid, Sig0StateRetired)
}

// discardRolloverKey removes a new rollover key that the parent cannot hold:
// it was never sent, or the parent refused it. Logged, not returned, since
// the rollover has already failed for the reason the caller reports.
func (zd *ZoneData) discardRolloverKey(pkc *PrivateKeyCache) {
	keyname := pkc.KeyRR.Header().Name
	keyid := pkc.KeyRR.KeyTag()
	_, err := zd.KeyDB.Sig0KeyMgmt(nil, KeystorePost{
		Command:    "sig0-mgmt",
		SubCommand: "delete",
		Zone:       keyname,
		Keyname:    keyname,
		Keyid:      keyid,
	})
	if err != nil {
		lgHandler.Error("RolloverSig0KeyWithParent: failed to remove the new key after the rollover failed",
			"zone", zd.ZoneName, "keyid", keyid, "err", err)
	}
}

// activateRolledSig0Key makes newkey the zone's active SIG(0) key and retires
// oldkey, in one short transaction.
func (zd *ZoneData) activateRolledSig0Key(newkey, oldkey *PrivateKeyCache) error {
	tx, err := zd.KeyDB.Begin("RolloverSig0KeyWithParent")
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %v", err)
	}
	for _, change := range []struct {
		key   *PrivateKeyCache
		state string
	}{{newkey, Sig0StateActive}, {oldkey, Sig0StateRetired}} {
		kpresp, err := zd.KeyDB.Sig0KeyMgmt(tx, KeystorePost{
			Command:    "sig0-mgmt",
			SubCommand: "setstate",
			Keyname:    change.key.KeyRR.Header().Name,
			Keyid:      change.key.KeyRR.KeyTag(),
			State:      change.state,
		})
		if err == nil && kpresp.Error {
			err = errors.New(kpresp.ErrorMsg)
		}
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to change state of key %d to %s: %v", change.key.KeyRR.KeyTag(), change.state, err)
		}
		zd.Logger.Printf("%s", kpresp.Msg)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit the key state changes: %v", err)
	}
	// setstate only schedules the drop (BulkSig0InvalidateZones); apply it
	// after OUR commit so a read-through cannot repopulate from pre-commit rows.
	zd.KeyDB.invalidateSig0Cache(newkey.KeyRR.Header().Name)
	return nil
}

// sameKeyRdata reports whether two KEY records carry the same key.
//
// RDATA only: owner name and TTL are not part of the key's identity, and the
// two sides genuinely differ there -- one is read from the published RRset at
// some owner, the other from the keystore.
func sameKeyRdata(a, b *dns.KEY) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Flags == b.Flags &&
		a.Protocol == b.Protocol &&
		a.Algorithm == b.Algorithm &&
		a.PublicKey == b.PublicKey
}
