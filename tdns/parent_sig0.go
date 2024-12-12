package tdns

import (
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// InitializeParentSig0Key skapar och publicerar en ny SIG(0)-nyckel för parent-zonen
// om det behövs
func (zd *ZoneData) InitializeParentSig0Key() error {
	fmt.Printf("InitializeParentSig0Key(%s)\n", zd.ZoneName)
	if !zd.Options[OptAllowUpdates] {
		return fmt.Errorf("InitializeParentSig0Key: zone %s is not allowed to be updated", zd.ZoneName)
	}

	// Kontrollera om det redan finns en aktiv nyckel
	sak, err := zd.KeyDB.GetSig0Keys(zd.ZoneName, Sig0StateActive)
	if err != nil {
		return fmt.Errorf("failed to get active SIG(0) keys: %v", err)
	}

	if len(sak.Keys) > 0 {
		zd.Logger.Printf("Parent zone %s already has active SIG(0) key(s)", zd.ZoneName)
		return nil
	}

	// Generera ny nyckel
	pkc, msg, err := zd.KeyDB.GenerateKeypair(
		zd.ZoneName,
		"parent-sig0",
		Sig0StateActive,
		dns.TypeKEY,
		dns.ECDSAP256SHA256, // eller annan algoritm enligt policy
		"",
		nil,
	)
	if err != nil {
		return fmt.Errorf("failed to generate new SIG(0) key: %v", err)
	}
	zd.Logger.Printf(msg)

	// Publicera nyckeln i DNS
	err = zd.PublishParentSig0Key(pkc)
	if err != nil {
		return fmt.Errorf("failed to publish parent SIG(0) key: %v", err)
	}

	return nil
}

// PublishParentSig0Key publicerar en SIG(0)-nyckel i parent-zonen
func (zd *ZoneData) PublishParentSig0Key(pkc *PrivateKeyCache) error {
	owner, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return err
	}

	rrset := owner.RRtypes.GetOnlyRRSet(dns.TypeKEY)
	rrset.RRs = []dns.RR{&pkc.KeyRR}
	owner.RRtypes.Set(dns.TypeKEY, rrset)

	// Om zonen är DNSSEC-signerad behöver vi signera KEY RRset
	if zd.Options[OptOnlineSigning] {
		_, err = zd.SignRRset(&rrset, zd.ZoneName, nil, true)
		if err != nil {
			return fmt.Errorf("failed to sign KEY RRset: %v", err)
		}
	}

	return nil
}

// VerifyParentSig0Key verifierar att en parent SIG(0)-nyckel är korrekt publicerad
func (zd *ZoneData) VerifyParentSig0Key(keyname string, keyid uint16) error {
	// Hämta nyckeln från DNS
	owner, err := zd.GetOwner(keyname)
	if err != nil {
		return err
	}

	rrset := owner.RRtypes.GetOnlyRRSet(dns.TypeKEY)
	if len(rrset.RRs) == 0 {
		return fmt.Errorf("no KEY record found for %s", keyname)
	}

	// Verifiera att nyckeln matchar keyid
	found := false
	for _, rr := range rrset.RRs {
		if key, ok := rr.(*dns.KEY); ok {
			if key.KeyTag() == keyid {
				found = true
				break
			}
		}
	}

	if !found {
		return fmt.Errorf("KEY with id %d not found for %s", keyid, keyname)
	}

	return nil
}

// RolloverParentSig0Key utför en key rollover för parent's SIG(0)-nyckel
func (zd *ZoneData) RolloverParentSig0Key() error {
	// 1. Generera ny nyckel
	newpkc, msg, err := zd.KeyDB.GenerateKeypair(
		zd.ZoneName,
		"parent-sig0",
		Sig0StatePublished,
		dns.TypeKEY,
		dns.ECDSAP256SHA256,
		"",
		nil,
	)
	if err != nil {
		return fmt.Errorf("failed to generate new SIG(0) key: %v", err)
	}
	zd.Logger.Printf(msg)

	// 2. Publicera den nya nyckeln
	err = zd.PublishParentSig0Key(newpkc)
	if err != nil {
		return fmt.Errorf("failed to publish new parent SIG(0) key: %v", err)
	}

	// 3. Vänta på propagering (kan konfigureras)
	time.Sleep(5 * time.Minute)

	// 4. Aktivera den nya nyckeln
	/*err = zd.KeyDB.PromoteSig0Key(zd.ZoneName, newpkc.KeyId, Sig0StatePublished, Sig0StateActive)
	if err != nil {
		return fmt.Errorf("failed to promote new SIG(0) key to active: %v", err)
	}

	// 5. Inaktivera gamla nycklar
	sak, err := zd.KeyDB.GetSig0Keys(zd.ZoneName, Sig0StateActive)
	if err != nil {
		return fmt.Errorf("failed to get active SIG(0) keys: %v", err)
	}

	for _, key := range sak.Keys {
		if key.KeyId != newpkc.KeyId {
			err = zd.KeyDB.PromoteSig0Key(zd.ZoneName, key.KeyId, Sig0StateActive, Sig0StateInactive)
			if err != nil {
				zd.Logger.Printf("Warning: failed to deactivate old SIG(0) key %d: %v", key.KeyId, err)
			}
		}
	}
	*/
	return nil
}
