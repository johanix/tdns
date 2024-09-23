/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"
	"log"

	"github.com/miekg/dns"
)

func (zd *ZoneData) PublishDnskeyRRs(dak *DnssecKeys) error {
	if !zd.Options["allow-updates"] {
		return fmt.Errorf("Zone %s does not allow updates", zd.ZoneName)
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
SELECT keyid, flags, algorithm, keyrr FROM DnssecKeyStore WHERE zonename=? AND (state='published' OR state='retired' OR state='foreign')`
	)

	rows, err := zd.KeyDB.Query(fetchZoneDnskeysSql, zd.ZoneName)
	if err != nil {
		log.Printf("Error from kdb.Query(%s, %s): %v", fetchZoneDnskeysSql, zd.ZoneName, err)
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var keyid, flags, algorithm string
		var keyrr string
		err = rows.Scan(&keyid, &flags, &algorithm, &keyrr)
		if err != nil {
			log.Printf("Error from rows.Scan(): %v", err)
			return err
		}

		rr, err := dns.NewRR(keyrr)
		if err != nil {
			log.Printf("Error creating dns.RR from keyrr: %v", err)
			return err
		}
		publishkeys = append(publishkeys, rr)
	}

	zd.Logger.Printf("PublishDnskeyRRs: publishkeys (all): %v", publishkeys)

	//	for _, k := range dak.KSKs {
	//		dump.P(k.DnskeyRR.String())
	//	}
	//	for _, k := range dak.ZSKs {
	//		dump.P(k.DnskeyRR.String())
	//	}

	var dnskeys RRset
	var exist bool

	if dnskeys, exist = apex.RRtypes[dns.TypeDNSKEY]; exist {
		for _, k := range publishkeys {
			present := false
			for _, dnskey := range dnskeys.RRs {
				if dns.IsDuplicate(k, dnskey) {
					present = true
					break
				}
			}
			if !present {
				dnskeys.RRs = append(dnskeys.RRs, k)
			}
		}
	} else {
		dnskeys = RRset{
			RRs: publishkeys,
		}
	}

	apex.RRtypes[dns.TypeDNSKEY] = dnskeys

	return nil
}
