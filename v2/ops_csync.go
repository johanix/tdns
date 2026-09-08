/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
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

// PublishCsyncRR stages the CSYNC and returns as soon as the update is queued.
//
// PublishCsyncRRAndWait is the variant for a caller that is about to tell
// somebody else to come and look.
func (zd *ZoneData) PublishCsyncRR() error {
	return zd.publishCsyncRR(context.Background(), nil)
}

// PublishCsyncRRAndWait stages the CSYNC and waits for the update to be
// applied and published.
//
// The plain version returns once the request is QUEUED, which is the right
// answer for a caller that only wants the record to exist eventually -- and the
// wrong one for the NOTIFY scheme, which follows it by telling the parent to
// come and fetch a CSYNC that may not be there yet.
//
// Not the default, because the zone updater itself publishes a CSYNC on one of
// its own paths: waiting there would be the updater waiting on itself.
func (zd *ZoneData) PublishCsyncRRAndWait(ctx context.Context) error {
	resp := make(chan ZoneUpdateResult, 1)
	if err := zd.publishCsyncRR(ctx, resp); err != nil {
		return err
	}
	select {
	case res := <-resp:
		if res.Err != nil {
			return fmt.Errorf("publishing the CSYNC for %s: %w", zd.ZoneName, res.Err)
		}
		// res.Applied being false is not by itself a failure: republishing the
		// same CSYNC over an identical one changes nothing, and the record the
		// caller is about to advertise IS there. But it also covers an update
		// the zone declined to apply, where it is not. The two are opposite
		// outcomes behind one false, so the postcondition is checked directly
		// rather than inferred from the signal.
		if !zd.csyncIsPublished() {
			return fmt.Errorf("publishing the CSYNC for %s: the update was accepted but"+
				" no CSYNC is published", zd.ZoneName)
		}
		return nil
	case <-ctx.Done():
		return fmt.Errorf("publishing the CSYNC for %s: %w", zd.ZoneName, ctx.Err())
	case <-time.After(UpdateApplyTimeout):
		return fmt.Errorf("publishing the CSYNC for %s: timed out after %s waiting for it to be applied",
			zd.ZoneName, UpdateApplyTimeout)
	}
}

func (zd *ZoneData) publishCsyncRR(ctx context.Context, resp chan ZoneUpdateResult) error {
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
		Resp:           resp,
	}:
	case <-ctx.Done():
		return fmt.Errorf("PublishCsyncRR: %s: %w", zd.ZoneName, ctx.Err())
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

// csyncIsPublished reports whether the zone is currently serving a CSYNC at its
// apex.
//
// The NOTIFY scheme's whole promise is "come and fetch my CSYNC", so this is
// the condition worth checking before making it -- as opposed to whether some
// particular update reported that it changed something.
func (zd *ZoneData) csyncIsPublished() bool {
	rrset, err := zd.GetRRset(zd.ZoneName, dns.TypeCSYNC)
	if err != nil {
		lgDns.Error("could not read back the published CSYNC", "zone", zd.ZoneName, "err", err)
		return false
	}
	return rrset != nil && len(rrset.RRs) > 0
}
