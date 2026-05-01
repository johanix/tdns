/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// FetchZoneDnskeysSql is the canonical SQL for "DNSKEYs that belong in
// the served zone DNSKEY RRset, as built from the keystore." Both
// PublishDnskeyRRs (sign-time RRset construction) and CollectDynamicRRs
// (refresh-time snapshot) must use this exact predicate so the two
// build identical sets — divergence between them would produce a
// brief window after refresh where standby DNSKEYs disappear from
// the served RRset until the next SignZone call.
//
// The set is `published` ∪ `standby` ∪ `retired`. Active keys are
// fetched separately via GetDnssecKeys(..., DnskeyStateActive).
const FetchZoneDnskeysSql = `
SELECT keyid, flags, algorithm, keyrr FROM DnssecKeyStore WHERE zonename=? AND (state='published' OR state='standby' OR state='retired')`

func (zd *ZoneData) PublishDnskeyRRs(dak *DnssecKeys) error {
	if !zd.Options[OptAllowUpdates] && !zd.Options[OptOnlineSigning] && !zd.Options[OptInlineSigning] {
		return fmt.Errorf("zone %s does not allow updates or signing", zd.ZoneName)
	}

	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return err
	}
	if apex == nil {
		return fmt.Errorf("PublishDnskeyRRs: zone apex %q not found", zd.ZoneName)
	}

	// Ensure that all active DNSKEYs are included in the DNSKEY RRset
	// XXX: Note that here we do not judge whether some other DNSKEY shouldn't
	// be part of the DNSKEY RRset. We just include all active DNSKEYs.
	var publishkeys []dns.RR
	for _, ksk := range dak.KSKs {
		zd.Logger.Printf("PublishDnskeyRRs: ksk: %v", ksk.DnskeyRR.String())
		publishkeys = append(publishkeys, dns.RR(&ksk.DnskeyRR))
	}
	for _, zsk := range dak.ZSKs {
		zd.Logger.Printf("PublishDnskeyRRs: zsk: %v", zsk.DnskeyRR.String())
		// If a ZSK has flags = 257 then it is a clone of a KSK and should not be included twice
		if zsk.DnskeyRR.Flags == 257 {
			continue
		}
		publishkeys = append(publishkeys, dns.RR(&zsk.DnskeyRR))
	}

	zd.Logger.Printf("PublishDnskeyRRs: there are %d active KSKs and %d active ZSKs", len(dak.KSKs), len(dak.ZSKs))
	zd.Logger.Printf("PublishDnskeyRRs: publishkeys (active): %v", publishkeys)

	rows, err := zd.KeyDB.Query(FetchZoneDnskeysSql, zd.ZoneName)
	if err != nil {
		lgHandler.Error("PublishDnskeyRRs: error querying DNSKEY store", "zone", zd.ZoneName, "err", err)
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var keyid, flags, algorithm string
		var keyrr string
		err = rows.Scan(&keyid, &flags, &algorithm, &keyrr)
		if err != nil {
			lgHandler.Error("PublishDnskeyRRs: error scanning DNSKEY row", "err", err)
			return err
		}

		rr, err := dns.NewRR(keyrr)
		if err != nil {
			lgHandler.Error("PublishDnskeyRRs: error creating dns.RR from keyrr", "err", err)
			return err
		}
		if _, ok := rr.(*dns.DNSKEY); !ok {
			lgHandler.Error("PublishDnskeyRRs: parsed RR is not a DNSKEY", "rrtype", dns.TypeToString[rr.Header().Rrtype], "keyrr", keyrr)
			continue
		}
		publishkeys = append(publishkeys, rr)
	}
	if err = rows.Err(); err != nil {
		lgHandler.Error("PublishDnskeyRRs: rows iteration error", "err", err)
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

	apex.RRtypes.Set(dns.TypeDNSKEY, dnskeys)

	return nil
}
