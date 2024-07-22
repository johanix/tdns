/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"

	"github.com/gookit/goutil/dump"
	"github.com/miekg/dns"
)

func (zd *ZoneData) PublishDnskeyRRs(dak *DnssecActiveKeys) error {
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
	var activekeys []dns.RR
	for _, ksk := range dak.KSKs {
		activekeys = append(activekeys, dns.RR(&ksk.DnskeyRR))
	}
	for _, zsk := range dak.ZSKs {
		// If a ZSK has flags = 257 then it is a clone of a KSK and should not be included twice
		if zsk.DnskeyRR.Flags == 257 {
			continue
		}
		activekeys = append(activekeys, dns.RR(&zsk.DnskeyRR))
	}

	for _, k := range dak.KSKs {
		dump.P(k.DnskeyRR.String())
	}
	for _, k := range dak.ZSKs {
		dump.P(k.DnskeyRR.String())
	}

	var dnskeys RRset
	var exist bool

	if dnskeys, exist = apex.RRtypes[dns.TypeDNSKEY]; exist {
		for _, k := range activekeys {
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
			RRs: activekeys,
		}
	}

	apex.RRtypes[dns.TypeDNSKEY] = dnskeys

	return nil
}
