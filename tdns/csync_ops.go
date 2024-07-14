/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"

	"github.com/miekg/dns"
)

func (zd *ZoneData) PublishCsyncRR() error {
	if !zd.Options["allowupdates"] {
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

	rrset := RRset{
		Name:   zd.ZoneName,
		RRs:    []dns.RR{&csync}, // Use a pointer to dns.CSYNC
		RRSIGs: []dns.RR{},
	}

	zd.mu.Lock()
	apex.RRtypes[dns.TypeCSYNC] = rrset
	zd.mu.Unlock()

	zd.BumpSerial()

	return nil
}

func (zd *ZoneData) UnpublishCsyncRR() error {
	if !zd.Options["allowupdates"] {
		return fmt.Errorf("Zone %s does not allow updates. CSYNC unpublication not possible", zd.ZoneName)
	}

	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return err
	}

	zd.mu.Lock()
	delete(apex.RRtypes, dns.TypeCSYNC)
	zd.mu.Unlock()

	zd.BumpSerial()

	return nil
}
