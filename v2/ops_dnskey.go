/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

func (zd *ZoneData) PublishDnskeyRRs(dak *DnssecKeys) error {
	if !zd.Options[OptAllowUpdates] && !zd.Options[OptOnlineSigning] && !zd.Options[OptInlineSigning] {
		return fmt.Errorf("zone %s does not allow updates or signing", zd.ZoneName)
	}

	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return err
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

	const (
		fetchZoneDnskeysSql = `
SELECT keyid, flags, algorithm, keyrr FROM DnssecKeyStore WHERE zonename=? AND (state='mpdist' OR state='published' OR state='standby' OR state='retired' OR state='foreign')`
	)

	rows, err := zd.KeyDB.Query(fetchZoneDnskeysSql, zd.ZoneName)
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
		publishkeys = append(publishkeys, rr)
	}

	// Multi-signer mode 4: merge remote DNSKEYs from other providers.
	// Per RFC 8901, each signer includes all signers' DNSKEYs in the RRset.
	if len(zd.RemoteDNSKEYs) > 0 {
		for _, rk := range zd.RemoteDNSKEYs {
			// Deduplicate: only add if not already present
			dup := false
			for _, pk := range publishkeys {
				if dns.IsDuplicate(rk, pk) {
					dup = true
					break
				}
			}
			if !dup {
				publishkeys = append(publishkeys, rk)
			}
		}
		zd.Logger.Printf("PublishDnskeyRRs: merged remote DNSKEYs (multi-signer mode 4), total keys: %d", len(publishkeys))
	}

	zd.Logger.Printf("PublishDnskeyRRs: publishkeys (all): %v", publishkeys)

	// Build the DNSKEY RRset: replace the zone's DNSKEY RRset entirely with
	// publishkeys (local + keystore published/retired/foreign + remote).
	// This ensures stale keys from incoming zones are stripped.
	var dnskeys core.RRset
	dnskeys = core.RRset{
		RRs: publishkeys,
	}

	apex.RRtypes.Set(dns.TypeDNSKEY, dnskeys)

	return nil
}
