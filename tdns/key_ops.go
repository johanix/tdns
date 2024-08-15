/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func (zd *ZoneData) PublishKeyRRs(sak *Sig0ActiveKeys) error {
	if !zd.Options["allow-updates"] {
		return fmt.Errorf("Zone %s does not allow updates. KEY RR publication not possible", zd.ZoneName)
	}
	if zd.Options["dont-publish-key"] {
		return fmt.Errorf("Zone %s does not allow KEY RR publication", zd.ZoneName)
	}

	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return err
	}

	zd.mu.Lock()
	for _, pkc := range sak.Keys {
		rrset := RRset{
			Name:   zd.ZoneName,
			RRs:    []dns.RR{&pkc.KeyRR},
			RRSIGs: []dns.RR{},
		}
		apex.RRtypes[dns.TypeKEY] = rrset
	}
	zd.Options["dirty"] = true
	zd.mu.Unlock()

	zd.BumpSerial()

	return nil
}

func (zd *ZoneData) UnpublishKeyRRs() error {
	if !zd.Options["allow-updates"] {
		return fmt.Errorf("Zone %s does not allow updates. KEY unpublication not possible", zd.ZoneName)
	}

	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return err
	}

	zd.mu.Lock()
	delete(apex.RRtypes, dns.TypeKEY)
	zd.Options["dirty"] = true
	zd.mu.Unlock()

	zd.BumpSerial()

	return nil
}

func (zd *ZoneData) VerifyPublishedKeyRRs() error {
	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return err
	}
	key_rrset, exist := apex.RRtypes[dns.TypeKEY]
	numpubkeys := len(key_rrset.RRs)
	if exist && numpubkeys > 0 {
		// If there is already a KEY RRset, we must ensure that we have access to the
		// private key to be able to sign updates.
		if numpubkeys > 1 {
			zd.Logger.Printf("Warning: Zone %s has %d KEY records published. This is likely a mistake.", zd.ZoneName, numpubkeys)
		}
		// 1. Get the keys from the keystore
		zd.Logger.Printf("VerifyPublishedKeyRRs(%s): KEY RRset exists. Checking availability of private key.", zd.ZoneName)
		sak, err := zd.KeyDB.GetSig0ActiveKeys(zd.ZoneName)
		if err != nil {
			zd.Logger.Printf("Error from GetSig0ActiveKeys(%s): %v", zd.ZoneName, err)
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
	} else {
		// XXX: We must generate a new key pair, store it in the keystore and publish the public key.
		algstr := viper.GetString("delegationsync.child.update.keygen.algorithm")
		alg := dns.StringToAlgorithm[strings.ToLower(algstr)]
		if alg == 0 {
			return fmt.Errorf("Unknown keygen algorithm: \"%s\"", algstr)
		}
		// Generate a new key and store it in the KeyStore
		pkc, msg, err := zd.KeyDB.GenerateKeypair(zd.ZoneName, "tdnsd", "active", dns.TypeKEY, alg, "", nil) // nil = no tx
		if err != nil {
			zd.Logger.Printf("Error from GeneratePrivateKey(%s, KEY, %s): %v", zd.ZoneName, algstr, err)
			return err
		}

		zd.Logger.Printf(msg)

		sak := &Sig0ActiveKeys{
			Keys: []*PrivateKeyCache{pkc},
		}
		err = zd.PublishKeyRRs(sak)
		if err != nil {
			zd.Logger.Printf("Error from PublishKeyRRs(%s): %v", zd.ZoneName, err)
			return err
		}
	}
	return nil
}
