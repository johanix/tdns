/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// PublishCdsRRs synthesizes CDS records from the current KSK DNSKEYs in the zone
// and publishes them at the zone apex. CDS records signal to the parent that the
// child wants to update its DS records (RFC 7344).
//
// Only KSK DNSKEYs (flags & 0x0001 == SEP bit set) are used for CDS synthesis.
// We publish CDS with digest type SHA-256 (2) which is the mandatory-to-implement
// algorithm per RFC 8624.
func (zd *ZoneData) PublishCdsRRs() error {
	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return fmt.Errorf("PublishCdsRRs: cannot get apex for zone %s: %v", zd.ZoneName, err)
	}

	dnskeyRRset, exists := apex.RRtypes.Get(dns.TypeDNSKEY)
	if !exists || len(dnskeyRRset.RRs) == 0 {
		return fmt.Errorf("PublishCdsRRs: zone %s has no DNSKEY RRset", zd.ZoneName)
	}

	var cdsRRs []dns.RR

	for _, rr := range dnskeyRRset.RRs {
		dnskey, ok := rr.(*dns.DNSKEY)
		if !ok {
			continue
		}
		// Only synthesize CDS from KSKs (SEP bit set)
		if dnskey.Flags&dns.SEP == 0 {
			continue
		}
		// Create DS from DNSKEY using SHA-256 (digest type 2)
		ds := dnskey.ToDS(dns.SHA256)
		if ds == nil {
			continue
		}
		// Convert DS to CDS (same wire format, different type)
		cds := &dns.CDS{
			DS: *ds,
		}
		cds.Hdr = dns.RR_Header{
			Name:   zd.ZoneName,
			Rrtype: dns.TypeCDS,
			Class:  dns.ClassINET,
			Ttl:    120,
		}
		cdsRRs = append(cdsRRs, cds)
	}

	if len(cdsRRs) == 0 {
		// No KSKs found — nothing to publish
		return nil
	}

	// First delete any existing CDS RRset, then add the new one
	antiCds := &dns.CDS{}
	antiCds.Hdr = dns.RR_Header{
		Name:   zd.ZoneName,
		Rrtype: dns.TypeCDS,
		Class:  dns.ClassANY, // Delete entire CDS RRset
		Ttl:    0,
	}

	actions := []dns.RR{antiCds}
	actions = append(actions, cdsRRs...)

	select {
	case zd.KeyDB.UpdateQ <- UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       zd.ZoneName,
		Actions:        actions,
		InternalUpdate: true,
	}:
	case <-time.After(5 * time.Second):
		return fmt.Errorf("PublishCdsRRs: timeout sending update for zone %s", zd.ZoneName)
	}

	return nil
}

// UnpublishCdsRRs removes the CDS RRset from the zone apex.
func (zd *ZoneData) UnpublishCdsRRs() error {
	antiCds := &dns.CDS{}
	antiCds.Hdr = dns.RR_Header{
		Name:   zd.ZoneName,
		Rrtype: dns.TypeCDS,
		Class:  dns.ClassANY, // Delete entire CDS RRset
		Ttl:    0,
	}

	select {
	case zd.KeyDB.UpdateQ <- UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       zd.ZoneName,
		Actions:        []dns.RR{antiCds},
		InternalUpdate: true,
	}:
	case <-time.After(5 * time.Second):
		return fmt.Errorf("UnpublishCdsRRs: timeout sending update for zone %s", zd.ZoneName)
	}

	return nil
}
