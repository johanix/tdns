/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"fmt"

	"github.com/miekg/dns"
)

func (zd *ZoneData) PublishCsyncRR() error {
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

	zd.KeyDB.UpdateQ <- UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       zd.ZoneName,
		Actions:        []dns.RR{&csync},
		InternalUpdate: true,
	}

	return nil
}

func (zd *ZoneData) UnpublishCsyncRR() error {
	anti_csync_rr, err := dns.NewRR(fmt.Sprintf("%s 0 IN CSYNC 0 0 A NS AAAA", zd.ZoneName))
	if err != nil {
		return err
	}
	anti_csync_rr.Header().Class = dns.ClassANY // XXX: dns.NewRR fails to parse a CLASS ANY CSYNC RRset, so we set the class manually.

	zd.KeyDB.UpdateQ <- UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       zd.ZoneName,
		Actions:        []dns.RR{anti_csync_rr},
		InternalUpdate: true,
	}

	return nil
}
