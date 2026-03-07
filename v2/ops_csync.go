/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"fmt"
	"time"

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

	select {
	case zd.KeyDB.UpdateQ <- UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       zd.ZoneName,
		Actions:        []dns.RR{&csync},
		InternalUpdate: true,
	}:
	case <-time.After(5 * time.Second):
		return fmt.Errorf("PublishCsyncRR: timeout sending update for zone %s", zd.ZoneName)
	}

	return nil
}

func (zd *ZoneData) UnpublishCsyncRR() error {
	var typebitmap = []uint16{dns.StringToType["A"], dns.StringToType["NS"], dns.StringToType["AAAA"]}
	var anti_csync = dns.CSYNC{
		Serial:     0,
		Flags:      0,
		TypeBitMap: typebitmap,
	}
	anti_csync.Hdr = dns.RR_Header{
		Name:   zd.ZoneName,
		Rrtype: dns.TypeCSYNC,
		Class:  dns.ClassANY, // Delete CSYNC RRset
		Ttl:    0,
	}

	select {
	case zd.KeyDB.UpdateQ <- UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       zd.ZoneName,
		Actions:        []dns.RR{&anti_csync},
		InternalUpdate: true,
	}:
	case <-time.After(5 * time.Second):
		return fmt.Errorf("UnpublishCsyncRR: timeout sending update for zone %s", zd.ZoneName)
	}

	return nil
}
