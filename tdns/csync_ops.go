/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"

	"github.com/miekg/dns"
)

func (zd *ZoneData) PublishCsyncRR() error {
	if !zd.Options["allow-updates"] {
		return fmt.Errorf("Zone %s does not allow updates. CSYNC publication not possible", zd.ZoneName)
	}

	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return err
	}

	var flags uint16
	var typebitmap = []uint16{dns.StringToType["A"], dns.StringToType["NS"], dns.StringToType["AAAA"]}
	var csync = dns.CSYNC{
		Serial:     zd.CurrentSerial,
		Flags:      flags,
		TypeBitMap: typebitmap,
	}
	csync.Hdr = dns.RR_Header{
		Name:   zd.ZoneName,
		Rrtype: dns.TypeCSYNC,
		Class:  dns.ClassINET,
		Ttl:    120,
	}

	rrset := RRset{
		Name:   zd.ZoneName,
		RRs:    []dns.RR{&csync}, // Use a pointer to dns.CSYNC
		RRSIGs: []dns.RR{},
	}

	zd.mu.Lock()
	apex.RRtypes[dns.TypeCSYNC] = rrset
	zd.Options["dirty"] = true
	zd.mu.Unlock()

	zd.BumpSerial()

	return nil
}

func (zd *ZoneData) UnpublishCsyncRR() error {
	if !zd.Options["allow-updates"] {
		return fmt.Errorf("Zone %s does not allow updates. CSYNC unpublication not possible", zd.ZoneName)
	}

	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return err
	}

	zd.mu.Lock()
	delete(apex.RRtypes, dns.TypeCSYNC)
	zd.Options["dirty"] = true
	zd.mu.Unlock()

	zd.BumpSerial()

	return nil
}
