/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// FetchZoneDnskeysSql is the canonical SQL for "DNSKEYs that belong in the
// served zone DNSKEY RRset, as built from the keystore": the rows with pub
// set (design D3). Whatever state a row is in, tdns's own or an owner's, the
// column says whether the key is served; the signing keys are among them.
// Both PublishDnskeyRRs (sign-time RRset construction) and CollectDynamicRRs
// (refresh-time snapshot) build the set through servedDnskeyRRs, so the two
// cannot drift apart -- a divergence would produce a brief window after
// refresh where standby DNSKEYs disappear from the served RRset until the
// next SignZone call.
const FetchZoneDnskeysSql = `
SELECT keyid, flags, algorithm, keyrr FROM DnssecKeyStore WHERE zonename=? AND pub=1`

// servedDnskeyRRs is the zone's DNSKEY RRset as the keystore says it should
// be: the pub=1 rows, plus the signing keys the caller holds in dak (every
// signing key has pub set, so these only add a key the caller minted and the
// database does not show yet), without duplicates.
func servedDnskeyRRs(kdb *KeyDB, zone string, dak *DnssecKeys) ([]dns.RR, error) {
	var out []dns.RR
	seen := map[string]bool{}
	add := func(rr dns.RR) {
		id := dnskeyIdentity(rr)
		if seen[id] {
			return
		}
		seen[id] = true
		out = append(out, rr)
	}
	if dak != nil {
		for _, ksk := range dak.KSKs {
			add(dns.RR(&ksk.DnskeyRR))
		}
		for _, zsk := range dak.ZSKs {
			// A ZSK with flags 257 is the KSK reused as CSK, already added.
			if zsk.DnskeyRR.Flags == 257 {
				continue
			}
			add(dns.RR(&zsk.DnskeyRR))
		}
	}
	rows, err := kdb.Query(FetchZoneDnskeysSql, zone)
	if err != nil {
		return nil, fmt.Errorf("servedDnskeyRRs: query the keystore for %s: %w", zone, err)
	}
	defer rows.Close()
	for rows.Next() {
		var keyid, flags, algorithm, keyrr string
		if err := rows.Scan(&keyid, &flags, &algorithm, &keyrr); err != nil {
			return nil, fmt.Errorf("servedDnskeyRRs: scan a key row of %s: %w", zone, err)
		}
		rr, err := dns.NewRR(keyrr)
		if err != nil {
			return nil, fmt.Errorf("servedDnskeyRRs: %s keyid %s: parse the stored DNSKEY: %w", zone, keyid, err)
		}
		if _, ok := rr.(*dns.DNSKEY); !ok {
			lgHandler.Error("servedDnskeyRRs: stored key row is not a DNSKEY", "zone", zone, "keyid", keyid, "rrtype", dns.TypeToString[rr.Header().Rrtype])
			continue
		}
		add(rr)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("servedDnskeyRRs: iterate the key rows of %s: %w", zone, err)
	}
	return out, nil
}

// dnskeyIdentity identifies a DNSKEY by what makes it the same key: flags,
// protocol, algorithm and public key, not TTL or owner case.
func dnskeyIdentity(rr dns.RR) string {
	dk, ok := rr.(*dns.DNSKEY)
	if !ok {
		return rr.String()
	}
	return fmt.Sprintf("%d %d %d %s", dk.Flags, dk.Protocol, dk.Algorithm, dk.PublicKey)
}

func (zd *ZoneData) PublishDnskeyRRs(dak *DnssecKeys) error {
	if !zd.Options[OptAllowUpdates] && !zd.Options[OptOnlineSigning] && !zd.Options[OptInlineSigning] {
		return fmt.Errorf("zone %s does not allow updates or signing", zd.ZoneName)
	}

	zd.mu.Lock()
	defer zd.mu.Unlock()
	return zd.publishDnskeyRRsLocked(dak)
}

func (zd *ZoneData) publishDnskeyRRsLocked(dak *DnssecKeys) error {
	apex := zd.stagedOwner(zd.ZoneName)
	if apex == nil {
		return fmt.Errorf("PublishDnskeyRRs: zone apex %q not found", zd.ZoneName)
	}

	// Read before the new RRset replaces the old one; see the DS engine note at
	// the end.
	var servesCds bool
	var oldSEP map[string]struct{}
	if apex.RRtypes != nil {
		servesCds = len(apex.RRtypes.GetOnlyRRSet(dns.TypeCDS).RRs) > 0
		oldSEP = sepKeyIdentities(apex.RRtypes.GetOnlyRRSet(dns.TypeDNSKEY).RRs)
	}

	// The served set is the keystore's pub=1 rows plus whatever signing keys
	// the caller holds; see servedDnskeyRRs. Nothing here judges which keys
	// belong: the columns do.
	zd.Logger.Printf("PublishDnskeyRRs: there are %d signing KSKs and %d signing ZSKs", len(dak.KSKs), len(dak.ZSKs))
	publishkeys, err := servedDnskeyRRs(zd.KeyDB, zd.ZoneName, dak)
	if err != nil {
		lgHandler.Error("PublishDnskeyRRs: error building the DNSKEY RRset from the keystore", "zone", zd.ZoneName, "err", err)
		return err
	}

	// Remote DNSKEY merge for multi-signer (mode 4) is handled by
	// mpzd.PublishDnskeyRRs() in tdns-mp. This version is mode 1 only.

	zd.Logger.Printf("PublishDnskeyRRs: publishkeys (all): %v", publishkeys)

	// Build the DNSKEY RRset: replace the zone's DNSKEY RRset entirely with
	// publishkeys (local + keystore published/retired).
	dnskeys := core.RRset{
		RRs: publishkeys,
	}

	zd.stageRRsetLocked(zd.ZoneName, dnskeys)

	// A zone that serves a CDS must not go on serving one that no longer
	// matches its keys: a parent polling CDS would point the DS at keys the zone
	// has stopped using. This is the one place the DNSKEY RRset is built from
	// the keystore, so it is where a KSK change shows; the DS engine owns the CDS
	// and decides what follows. It never blocks, which matters with zd.mu held.
	if servesCds && !sameKeyIdentities(oldSEP, sepKeyIdentities(publishkeys)) {
		zd.KeyDB.dsEngineKeysChanged(zd)
	}

	return nil
}
