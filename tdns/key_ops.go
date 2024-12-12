/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"fmt"
	"log"
	"strings"

	"github.com/gookit/goutil/dump"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func (zd *ZoneData) PublishKeyRRs(sak *Sig0ActiveKeys) error {
	if zd.Options[OptDontPublishKey] {
		return fmt.Errorf("Zone %s does not allow KEY RR publication", zd.ZoneName)
	}

	rrset := RRset{
		Name: zd.ZoneName,
	}

	for _, pkc := range sak.Keys {
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
	anti_key_rr, err := dns.NewRR(fmt.Sprintf("%s 0 ANY KEY 0 0 0 tomtarpaloftet", zd.ZoneName))
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

func (zd *ZoneData) VerifyPublishedKeyRRs() error {
	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return err
	}
	key_rrset, exist := apex.RRtypes.Get(dns.TypeKEY)
	numpubkeys := len(key_rrset.RRs)
	if exist && numpubkeys > 0 {
		// If there is already a KEY RRset, we must ensure that we have access to the
		// private key to be able to sign updates.
		if numpubkeys > 1 {
			zd.Logger.Printf("Warning: Zone %s has %d KEY records published. This is likely a mistake.", zd.ZoneName, numpubkeys)
		}
		// 1. Get the keys from the keystore
		zd.Logger.Printf("VerifyPublishedKeyRRs(%s): KEY RRset exists. Checking availability of private key.", zd.ZoneName)
		sak, err := zd.KeyDB.GetSig0Keys(zd.ZoneName, Sig0StateActive)
		if err != nil {
			zd.Logger.Printf("Error from GetSig0Keys(%s, %s): %v", zd.ZoneName, Sig0StateActive, err)
			return err
		}
		// 2. Iterate through the keys to match against keyid of published keys.
		for _, pkey := range key_rrset.RRs {
			found := false
			pkeyid := pkey.(*dns.KEY).KeyTag()
			for _, key := range sak.Keys {
				if key.KeyRR.KeyTag() == pkeyid {
					found = true
					break
				}
			}
			if !found {
				zd.Logger.Printf("Warning: Zone %s: no active private key for the published KEY with keyid=%d. This key should be removed.", zd.ZoneName, pkeyid)
			}
		}
		return nil
	}

	// No KEY RRset found, try to find an active key in the keystore
	sak, err := zd.KeyDB.GetSig0Keys(zd.ZoneName, Sig0StateActive)
	if err != nil {
		return fmt.Errorf("VerifyPublishedKeyRRs(%s) failed to get SIG(0) active keys: %v", zd.ZoneName, err)
	}
	if len(sak.Keys) == 0 {
		// Ok, no active key found, try to generate a new one
		algstr := viper.GetString("delegationsync.child.update.keygen.algorithm")
		alg := dns.StringToAlgorithm[strings.ToUpper(algstr)]
		if alg == 0 {
			return fmt.Errorf("Unknown keygen algorithm: \"%s\"", algstr)
		}
		// Generate a new key and store it in the KeyStore
		// pkc, msg, err := zd.KeyDB.GenerateKeypair(zd.ZoneName, "tdnsd", "active", dns.TypeKEY, alg, "", nil) // nil = no tx
		// if err != nil {
		// 	zd.Logger.Printf("Error from GeneratePrivateKey(%s, KEY, %s): %v", zd.ZoneName, algstr, err)
		// 	return err
		// }

		// zd.Logger.Printf(msg)

		kp := KeystorePost{
			Command:     "sig0-mgmt",
			SubCommand:  "generate",
			Zone:        zd.ZoneName,
			Algorithm:   alg,
			State:       Sig0StateActive,
			ParentState: 255,
			Creator:     "bootstrap-sig0",
		}
		resp, err := zd.KeyDB.Sig0KeyMgmt(nil, kp)
		if err != nil {
			return fmt.Errorf("VerifyPublishedKeyRRs(%s) failed to generate keypair: %v", zd.ZoneName, err)
		}
		zd.Logger.Printf(resp.Msg)

		sak, err = zd.KeyDB.GetSig0Keys(zd.ZoneName, Sig0StateActive)
		if err != nil {
			return fmt.Errorf("VerifyPublishedKeyRRs(%s) failed to get SIG(0) active keys: %v", zd.ZoneName, err)
		}
		if len(sak.Keys) == 0 {
			return fmt.Errorf("VerifyPublishedKeyRRs(%s) failed to get SIG(0) active keys: %v", zd.ZoneName, err)
		}
	}

	err = zd.PublishKeyRRs(sak)
	if err != nil {
		zd.Logger.Printf("Error from PublishKeyRRs(%s): %v", zd.ZoneName, err)
		return err
	}
	return nil
}

func (zd *ZoneData) BootstrapSig0KeyWithParent(alg uint8) (string, error, UpdateResult) {
	var err error
	fmt.Printf("BERRA - BootstrapSig0KeyWithParent(%s)\n", zd.ZoneName)

	// 1. Get the parent zone
	if zd.Parent == "" {
		zd.Parent, err = ParentZone(zd.ZoneName, Globals.IMR)
		if err != nil {
			return "", err, UpdateResult{}
		}
	}

	sak, err := zd.KeyDB.GetSig0Keys(zd.ZoneName, Sig0StateActive)
	if err != nil {
		return fmt.Sprintf("BootstrapSig0KeyWithParent(%s) failed to get SIG(0) active keys: %v", zd.ZoneName, err), err, UpdateResult{}
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
			ParentState: 255,
			Creator:     "bootstrap-sig0",
		}
		resp, err := zd.KeyDB.Sig0KeyMgmt(nil, kp)
		if err != nil {
			return fmt.Sprintf("BootstrapSig0KeyWithParent(%s) failed to generate keypair: %v", zd.ZoneName, err), err, UpdateResult{}
		}
		zd.Logger.Printf(resp.Msg)

		sak, err = zd.KeyDB.GetSig0Keys(zd.ZoneName, Sig0StateActive)
		if err != nil {
			return fmt.Sprintf("BootstrapSig0KeyWithParent(%s, after key generation) failed to get SIG(0) active keys: %v",
				zd.ZoneName, err), err, UpdateResult{}
		}
		if len(sak.Keys) == 0 {
			return fmt.Sprintf("BootstrapSig0KeyWithParent(%s, after key generation) failed to get SIG(0) active keys: %v",
				zd.ZoneName, err), err, UpdateResult{}
		}
	}

	pkc := sak.Keys[0]

	// 2. Get the parent DSYNC RRset
	dsyncTarget, err := LookupDSYNCTarget(zd.ZoneName, Globals.IMR, dns.TypeANY, SchemeUpdate)
	if err != nil {
		return fmt.Sprintf("BootstrapSig0KeyWithParent(%s) failed to lookup DSYNC target: %v", zd.ZoneName, err), err, UpdateResult{}
	}

	log.Printf("BootstrapSig0KeyWithParent(%s): DSYNC target: %+v", zd.ZoneName, dsyncTarget.RR)
	// dump.P(dsyncTarget)

	// 3. Create the DNS UPDATE message
	// adds := []dns.RR{&sak.Keys[0].KeyRR}
	adds := []dns.RR{&pkc.KeyRR}
	msg, err := CreateUpdate(zd.Parent, adds, []dns.RR{})
	if err != nil {
		return fmt.Sprintf("BootstrapSig0KeyWithParent(%s) failed to create update message: %v", zd.ZoneName, err), err, UpdateResult{}
	}

	const OptionCodeKeyState = 65002
	// Create the KeyState EDNS(0) option
	keyStateOption := &dns.EDNS0_LOCAL{
		Code: OptionCodeKeyState,
		Data: createKeyStateData(pkc.KeyId, 0, "Automatic requested"),
	}

	// Add the option to the Extra section of the message
	msg.Extra = []dns.RR{&dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
			Class:  dns.DefaultMsgSize,
		},
		Option: []dns.EDNS0{keyStateOption},
	}}

	msg, err = SignMsg(*msg, zd.ZoneName, sak)
	if err != nil {
		return fmt.Sprintf("BootstrapSig0KeyWithParent(%s) failed to sign message: %v", zd.ZoneName, err), err, UpdateResult{}
	}

	// 4. Send the message to the parent
	rcode, err, ur := SendUpdate(msg, zd.Parent, dsyncTarget.Addresses)
	if err != nil {
		return fmt.Sprintf("BootstrapSig0KeyWithParent(%s) failed to send update message: %v", zd.ZoneName, err), err, ur
	}

	if rcode == dns.RcodeSuccess {
		tx, err := zd.KeyDB.Begin("BootstrapSig0KeyWithParent")
		if err != nil {
			return fmt.Sprintf("BootstrapSig0KeyWithParent(%s) failed to begin transaction: %v", zd.ZoneName, err), err, UpdateResult{}
		}
		defer func() {
			if err != nil {
				tx.Rollback()
			} else {
				tx.Commit()
			}
		}()

		if ur.TargetStatus[dsyncTarget.Addresses[0]].KeyStateFound {
			//response, _ := processKeyState(keystate, zd.KeyDB, zd.ZoneName)
			parentstate := ur.TargetStatus[dsyncTarget.Addresses[0]].KeyState
			//AttachKeyStateToResponse(msg, response)

			fmt.Printf("BootstrapSig0KeyWithParent(%s): parentstate: %d\n", zd.ZoneName, parentstate)

			kpparent := KeystorePost{
				Command:     "sig0-mgmt",
				SubCommand:  "setparentstate",
				Keyname:     pkc.KeyRR.Header().Name,
				Keyid:       uint16(pkc.KeyRR.KeyTag()),
				ParentState: parentstate,
			}

			resp, err := zd.KeyDB.Sig0KeyMgmt(tx, kpparent)
			if err != nil {
				return fmt.Sprintf("BootstrapSig0KeyWithParent(%s) failed to set parent state of key %d to %d: %v",
					zd.ZoneName, pkc.KeyRR.KeyTag(), parentstate, err), err, UpdateResult{}
			}
			zd.Logger.Printf(resp.Msg)
		}
		/*
			if opt := ur.Status.IsEdns0(); opt != nil {
				for _, option := range opt.Option {
					if local, ok := option.(*dns.EDNS0_LOCAL); ok {
						fmt.Printf("QueryResponder: Found KeyState option\n")
						fmt.Printf("QueryResponder: local.Code: %d\n", local.Code)
						if local.Code == OptcodeKeyState {
							keystate, err := ParseKeyStateOption(local)
							if err != nil {
								log.Printf("Error parsing KeyState option: %v", err)
								continue
							}

							response, err := processKeyState(keystate, kdb, qname)
							if err != nil {
								log.Printf("Error handling KeyState request: %v", err)
								continue
							}
							fmt.Printf("QueryResponder: Found KeyState response\n")
							// Lägg till KeyState response som EDNS0 option
							AttachKeyStateToResponse(msg, response)


						}
					}
				}
			}
		*/

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
			str := fmt.Sprintf("BootstrapSig0KeyWithParent(%s) failed to change state of key %d to active: %v",
				zd.ZoneName, pkc.KeyRR.KeyTag(), err)
			log.Printf(str)
			return str, fmt.Errorf(str), UpdateResult{}
		}
		if resp.Error {
			return fmt.Sprintf("BootstrapSig0KeyWithParent(%s) failed to change state of key %d to active: %v",
				zd.ZoneName, pkc.KeyRR.KeyTag(), resp.ErrorMsg), fmt.Errorf(resp.ErrorMsg), UpdateResult{}
		}
		zd.Logger.Printf(resp.Msg)
	}

	dump.P(ur)
	return fmt.Sprintf("BootstrapSig0KeyWithParent(%s) sent update message; received rcode %s back", zd.ZoneName, dns.RcodeToString[rcode]), nil, ur
}

// Returns msg, old keyid, new keyid, error, UpdateResult
func (zd *ZoneData) RolloverSig0KeyWithParent(alg uint8, action string, oldkeyid, newkeyid uint16) (string, uint16, uint16, error, UpdateResult) {
	var err error
	var sak, newSak *Sig0ActiveKeys
	var pkc *PrivateKeyCache
	var dsyncTarget *DsyncTarget
	var msg string
	var kpresp *KeystoreResponse

	// 1. Get the parent zone
	if zd.Parent == "" {
		zd.Parent, err = ParentZone(zd.ZoneName, Globals.IMR)
		if err != nil {
			return "", 0, 0, err, UpdateResult{}
		}
	}

	// 2. Get the parent DSYNC RRset
	dsyncTarget, err = LookupDSYNCTarget(zd.ZoneName, Globals.IMR, dns.TypeANY, SchemeUpdate)
	if err != nil {
		return "", 0, 0, fmt.Errorf("RolloverSig0KeyWithParent(%s) failed to lookup DSYNC target: %v", zd.ZoneName, err), UpdateResult{}
	}
	log.Printf("RolloverSig0KeyWithParent(%s): DSYNC target:", zd.ZoneName)

	//	if action == "complete" || action == "add" {
	sak, err = zd.KeyDB.GetSig0Keys(zd.ZoneName, Sig0StateActive)
	if err != nil {
		return "", 0, 0, fmt.Errorf("RolloverSig0KeyWithParent(%s) failed to get SIG(0) active keys: %v", zd.ZoneName, err), UpdateResult{}
	}

	tx, err := zd.KeyDB.Begin("RolloverSig0KeyWithParent")
	if err != nil {
		return "", 0, 0, fmt.Errorf("RolloverSig0KeyWithParent(%s) failed to begin transaction: %v", zd.ZoneName, err), UpdateResult{}
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		} else {
			tx.Commit()
		}
	}()

	// 3. Generate a new key
	//	pkc, msg, err = zd.KeyDB.GenerateKeypair(zd.ZoneName, "api-request", "created", dns.TypeKEY, alg, "", nil) // nil = no tx
	//	if err != nil {
	//		return "", 0, 0, fmt.Errorf("RolloverSig0KeyWithParent(%s) failed to generate keypair: %v", zd.ZoneName, err)
	//	}
	kp := KeystorePost{
		Command:     "sig0-mgmt",
		SubCommand:  "generate",
		Zone:        zd.ZoneName,
		Algorithm:   alg,
		State:       Sig0StateCreated,
		Creator:     "rollover-sig0",
		ParentState: 255,
	}
	kpresp, err = zd.KeyDB.Sig0KeyMgmt(tx, kp)
	if err != nil {
		return "", 0, 0, fmt.Errorf("RolloverSig0KeyWithParent(%s) failed to generate keypair: %v", zd.ZoneName, err), UpdateResult{}
	}
	zd.Logger.Printf(kpresp.Msg)

	tx.Commit() //

	// 4. Get the new key from the keystore
	newSak, err = zd.KeyDB.GetSig0Keys(zd.ZoneName, Sig0StateCreated)
	if err != nil {
		return "", 0, 0, fmt.Errorf("RolloverSig0KeyWithParent(%s) failed to get SIG(0) created keys: %v", zd.ZoneName, err), UpdateResult{}
	}
	if len(newSak.Keys) == 0 {
		return "", 0, 0, fmt.Errorf("RolloverSig0KeyWithParent(%s) failed to get SIG(0) created keys: %v", zd.ZoneName, err), UpdateResult{}
	}

	pkc = newSak.Keys[0]
	zd.Logger.Printf(msg)

	// 3. Create the DNS UPDATE message
	adds := []dns.RR{&pkc.KeyRR}
	m, err := CreateUpdate(zd.Parent, adds, []dns.RR{})
	if err != nil {
		return "", 0, 0, fmt.Errorf("RolloverSig0KeyWithParent(%s) failed to create update message: %v", zd.ZoneName, err), UpdateResult{}
	}

	log.Printf("RolloverSig0KeyWithParent(%s): signing addition of new key keyid %d with keyid %d:",
		zd.ZoneName, pkc.KeyRR.KeyTag(), sak.Keys[0].KeyRR.KeyTag())

	m, err = SignMsg(*m, zd.ZoneName, sak)
	if err != nil {
		return "", 0, 0, fmt.Errorf("RolloverSig0KeyWithParent(%s) failed to sign message: %v", zd.ZoneName, err), UpdateResult{}
	}

	// 4. Send the ADD message to the parent
	rcode, err, ur := SendUpdate(m, zd.Parent, dsyncTarget.Addresses)
	if err != nil {
		return "", 0, 0, fmt.Errorf("RolloverSig0KeyWithParent(%s) failed to send update message: %v", zd.ZoneName, err), ur
	}

	// XXX: Here it is *very important* to update the active key in the keystore
	// to the new key, but only after we have received a successful response
	// from the parent.

	if rcode != dns.RcodeSuccess {
		return "", 0, 0, fmt.Errorf("RolloverSig0KeyWithParent(%s) update message failed: %s. Rollover aborted.",
			zd.ZoneName, dns.RcodeToString[rcode]), ur
	}

	oldkeyid = sak.Keys[0].KeyRR.KeyTag()
	newkeyid = pkc.KeyRR.KeyTag()

	if action == "add" {
		return fmt.Sprintf("RolloverSig0KeyWithParent(%s) successfully added new key with keyid %d",
			zd.ZoneName, newkeyid), oldkeyid, newkeyid, nil, ur
	}
	//	} // end of phase 1

	//	if action == "complete" || action == "remove" {
	// 6. Request deletion of the old active key from the parent, signed by the new active key.
	removes := []dns.RR{&sak.Keys[0].KeyRR}
	m, err = CreateUpdate(zd.Parent, []dns.RR{}, removes)
	if err != nil {
		return fmt.Sprintf("RolloverSig0KeyWithParent(%s) failed to create update message: %v",
			zd.ZoneName, err), oldkeyid, newkeyid, err, ur
	}

	newSak = &Sig0ActiveKeys{Keys: []*PrivateKeyCache{pkc}}
	log.Printf("RolloverSig0KeyWithParent(%s): signing removal of key keyid %d with keyid %d:",
		zd.ZoneName, sak.Keys[0].KeyRR.KeyTag(), pkc.KeyRR.KeyTag())
	m, err = SignMsg(*m, zd.ZoneName, newSak)
	if err != nil {
		return "", oldkeyid, newkeyid, fmt.Errorf("RolloverSig0KeyWithParent(%s) failed to sign message: %v", zd.ZoneName, err), ur
	}

	// 7. Send the REMOVE message to the parent
	rcode, err, ur = SendUpdate(m, zd.Parent, dsyncTarget.Addresses)
	if err != nil {
		return "", oldkeyid, newkeyid, fmt.Errorf("RolloverSig0KeyWithParent(%s) failed to send update message: %v",
			zd.ZoneName, err), ur
	}

	if rcode != dns.RcodeSuccess {
		// Delete of the old active key from the parent truststore failed. So we will continue to use the old key.
		return "", oldkeyid, newkeyid, fmt.Errorf("RolloverSig0KeyWithParent(%s) update message failed: %s. Rollover aborted.",
			zd.ZoneName, dns.RcodeToString[rcode]), ur
	}
	//	} // end of phase 2

	// At this point we have successfully rolled the trusted SIG(0) key in the parent truststore.
	// We now need to update the active key in our own keystore to the new key and also possibly publish the new key.

	//	if action == "complete" || action == "update-local" {
	// var resp *KeystoreResponse
	tx, err = zd.KeyDB.Begin("RolloverSig0KeyWithParent")
	if err != nil {
		return "", oldkeyid, newkeyid, fmt.Errorf("RolloverSig0KeyWithParent(%s) failed to begin transaction: %v",
			zd.ZoneName, err), ur
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		} else {
			tx.Commit()
		}
	}()

	// 8. Change state of the new key from "created" to "active". Change state of the old key from "active" to "retired".
	kp = KeystorePost{
		Command:    "sig0-mgmt",
		SubCommand: "setstate",
		Keyname:    pkc.KeyRR.Header().Name,
		Keyid:      uint16(pkc.KeyRR.KeyTag()),
		State:      "active",
	}

	kpresp, err = zd.KeyDB.Sig0KeyMgmt(tx, kp)
	if err != nil {
		msg = fmt.Sprintf("RolloverSig0KeyWithParent(%s) failed to change state of key %d to active: %v",
			zd.ZoneName, pkc.KeyRR.KeyTag(), err)
		log.Printf(msg)
		return "", oldkeyid, newkeyid, fmt.Errorf(msg), ur
	}
	if kpresp.Error {
		return "", oldkeyid, newkeyid, fmt.Errorf("RolloverSig0KeyWithParent(%s) failed to change state of key %d to active: %v",
			zd.ZoneName, pkc.KeyRR.KeyTag(), kpresp.ErrorMsg), ur
	}
	zd.Logger.Printf(kpresp.Msg)

	kp = KeystorePost{
		Command:    "sig0-mgmt",
		SubCommand: "setstate",
		Keyname:    sak.Keys[0].KeyRR.Header().Name,
		Keyid:      uint16(sak.Keys[0].KeyRR.KeyTag()),
		State:      "retired",
	}
	kpresp, err = zd.KeyDB.Sig0KeyMgmt(tx, kp)
	if err != nil {
		msg = fmt.Sprintf("RolloverSig0KeyWithParent(%s) failed to change state of key %d to retired: %v", zd.ZoneName, sak.Keys[0].KeyRR.KeyTag(), err)
		log.Printf(msg)
		return "", oldkeyid, newkeyid, fmt.Errorf(msg), ur
	}
	if kpresp.Error {
		return "", oldkeyid, newkeyid, fmt.Errorf("RolloverSig0KeyWithParent(%s) failed to change state of key %d to retired: %v",
			zd.ZoneName, sak.Keys[0].KeyRR.KeyTag(), kpresp.ErrorMsg), ur
	}
	zd.Logger.Printf(kpresp.Msg)

	// 9. Publish the new key
	err = zd.PublishKeyRRs(newSak)
	if err != nil {
		msg = fmt.Sprintf("RolloverSig0KeyWithParent(%s) failed to publish new key: %v", zd.ZoneName, err)
		log.Printf(msg)
		return "", oldkeyid, newkeyid, fmt.Errorf(msg), ur
	}
	//	} // end of phase 3

	return fmt.Sprintf("RolloverSig0KeyWithParent(%s) successfully rolled from SIG(0) key %d to SIG(0) key %d",
		zd.ZoneName, sak.Keys[0].KeyRR.KeyTag(), pkc.KeyRR.KeyTag()), oldkeyid, newkeyid, nil, ur
}
