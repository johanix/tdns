/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// csyncPublishedTypes is the CSYNC type bitmap the child publishes: the types
// a parent is asked to copy from the child.
var csyncPublishedTypes = []uint16{dns.TypeA, dns.TypeNS, dns.TypeAAAA}

// csyncDeleteRR returns the class-ANY record that removes the whole CSYNC
// RRset at zone's apex (RFC 2136 section 2.5.2).
//
// PublishCsyncRR sends this ahead of the new record so that publishing
// REPLACES rather than appends. Without it the RRset grew by one record per
// republish, and they are not duplicates: each carries the serial that was
// current when it was published, so nothing collapses them. A parent then sees
// several CSYNCs with different serials and RFC 7477 section 3 gives it no way
// to choose -- it acts on "the CSYNC record", and the newest is
// indistinguishable from the stale ones without comparing serials, which it
// does not do.
//
// The record carries no RDATA: RFC 2136 section 2.5.2 requires RDLENGTH zero
// for a delete-RRset, and the zone updater keys such a delete on owner and
// type alone, so a bitmap here would be both wrong and unused.
func csyncDeleteRR(zone string) dns.RR {
	anti := &dns.CSYNC{}
	anti.Hdr = dns.RR_Header{
		Name:   zone,
		Rrtype: dns.TypeCSYNC,
		Class:  dns.ClassANY, // Delete CSYNC RRset
		Ttl:    0,
	}
	return anti
}

func (zd *ZoneData) PublishCsyncRR() error {
	csync := dns.CSYNC{
		Serial: zd.CurrentSerial,
		// The immediate flag is what makes a parent act on this CSYNC at all:
		// ProcessCSYNCNotify refuses one without it, so a CSYNC published with
		// no flags -- which is what this was, from an unassigned variable --
		// could never complete the NOTIFY scheme between two tdns instances.
		//
		// soaminimum is deliberately not set. The serial published here IS the
		// child's current SOA serial, so the gate it controls
		// (csyncSuppressedBySoaMinimum: serial > SOA serial) could never fire,
		// and setting it would add a suppression path that only ever bites if
		// serial handling changes later.
		Flags:      csyncFlagImmediate,
		TypeBitMap: csyncPublishedTypes,
	}
	csync.Hdr = dns.RR_Header{
		Name:   zd.ZoneName,
		Rrtype: dns.TypeCSYNC,
		Class:  dns.ClassINET,
		Ttl:    120,
	}

	select {
	case zd.KeyDB.UpdateQ <- UpdateRequest{
		Cmd:      "ZONE-UPDATE",
		ZoneName: zd.ZoneName,
		// Delete then add, in one update: the apex must never hold more than
		// one CSYNC, and doing it as two updates would cost an extra serial
		// bump and leave a window with none published at all.
		Actions:        []dns.RR{csyncDeleteRR(zd.ZoneName), &csync},
		InternalUpdate: true,
	}:
	case <-time.After(5 * time.Second):
		return fmt.Errorf("PublishCsyncRR: timeout sending update for zone %s", zd.ZoneName)
	}

	return nil
}

func (zd *ZoneData) UnpublishCsyncRR() error {
	select {
	case zd.KeyDB.UpdateQ <- UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       zd.ZoneName,
		Actions:        []dns.RR{csyncDeleteRR(zd.ZoneName)},
		InternalUpdate: true,
	}:
	case <-time.After(5 * time.Second):
		return fmt.Errorf("UnpublishCsyncRR: timeout sending update for zone %s", zd.ZoneName)
	}

	return nil
}
