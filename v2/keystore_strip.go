/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"slices"

	"github.com/miekg/dns"
)

// stagedStrip is a strip of a zone's RRSIGs made under a keystore transaction,
// for the key change that transaction writes: DnssecKeyMgmt's clear and
// policy-cleanup (#985). The strip is staged, and the zone held, so that
// nothing publishes it before the transaction ends. A publish under the
// transaction waited for it: the publish records its serial in the keystore
// through the pool (recordPublishedSerialLocked), and that write waited the
// busy timeout for the transaction's lock, then failed.
//
// finish ends it. After a commit it releases the hold, and the gate publishes
// the strip; a publish that is refused leaves it staged for the next one. After
// a rollback it puts back what the strip took, since the key change it was for
// did not happen, and then releases the hold.
type stagedStrip struct {
	zd   *ZoneData
	hold TxID // the zone's publish hold; "" when the zone could not be held
	took []strippedRRset
	done bool
}

// strippedRRset is one RRset a strip took RRSIGs from: its owner, its type, its
// records as they were, and the RRSIGs taken.
type strippedRRset struct {
	name   string
	rrtype uint16
	rrs    []dns.RR
	sigs   []dns.RR
}

// stageStripUnderKeystoreTx stages the strip of the RRSIGs remove selects, and
// holds the zone until finish. A zone that may not originate content cannot be
// held (BeginTx); its strip is staged without a hold, and finish publishes it
// all the same. A strip that fails is returned unfinished, with the error:
// the caller rolls the key change back and then finishes it, which puts it
// back and releases the hold. Releasing it here, with the transaction still
// open, would publish while the transaction holds the keystore.
func (zd *ZoneData) stageStripUnderKeystoreTx(ctx context.Context, remove func(*dns.RRSIG) bool) (*stagedStrip, error) {
	s := &stagedStrip{zd: zd}
	if id, err := zd.BeginTx(0); err == nil {
		s.hold = id
	}
	zd.mu.Lock()
	n, err := zd.stripZoneRRSIGsLocked(ctx, remove, func(name string, rrtype uint16, rrs, sigs []dns.RR) {
		s.took = append(s.took, strippedRRset{name: name, rrtype: rrtype, rrs: rrs, sigs: sigs})
	})
	zd.mu.Unlock()
	if err != nil {
		return s, err
	}
	if n > 0 {
		lgSigner.Info("staged the strip of RRSIGs; it is published after the keystore commit",
			"zone", zd.ZoneName, "count", n)
	}
	return s, nil
}

// finish ends the strip once its keystore transaction has ended; committed
// says whether it committed. A nil strip, or one already finished, does
// nothing.
func (s *stagedStrip) finish(committed bool) {
	if s == nil || s.done {
		return
	}
	s.done = true
	zd := s.zd
	if !committed && len(s.took) > 0 {
		zd.mu.Lock()
		zd.unstripLocked(s.took)
		zd.mu.Unlock()
		lgSigner.Info("the keystore transaction did not commit; the RRSIGs its strip took are staged again",
			"zone", zd.ZoneName, "rrsets", len(s.took))
	}
	switch {
	case s.hold != "":
		// Closing the hold publishes what is staged, through the gate.
		if err := zd.CommitTx(s.hold); err != nil {
			lgSigner.Error("the publish after the keystore transaction was refused; the change stays staged",
				"zone", zd.ZoneName, "err", err)
			// A hold that ran out is no longer open. Its release published what
			// was staged then: the strip, if it ran out after the strip was
			// staged, or none of it, if before. What is staged now, the strip or
			// what a rollback put back, needs a publish of its own.
			if len(s.took) > 0 {
				zd.requestPublish(false)
			}
		}
	case len(s.took) > 0:
		zd.requestPublish(false)
	}
}

// unstripLocked puts the RRSIGs a strip took back into their RRsets in the
// working set. Not into an RRset that is gone, nor into one whose records have
// changed since: the RRSIGs do not cover those, and signing the new records is
// the job of whoever changed them. An RRSIG the RRset holds already is not
// added twice. Caller holds zd.mu.
func (zd *ZoneData) unstripLocked(took []strippedRRset) {
	zd.ensureWorkingSet()
	for _, t := range took {
		owner := zd.workingSet[t.name]
		if owner == nil {
			continue
		}
		rrset := owner.RRtypes.GetOnlyRRSet(t.rrtype)
		if len(rrset.RRs) == 0 {
			continue
		}
		if !sameRecords(rrset.RRs, t.rrs) {
			lgSigner.Debug("an RRset changed after the strip; its RRSIGs are not put back",
				"zone", zd.ZoneName, "owner", t.name, "rrtype", dns.TypeToString[t.rrtype])
			continue
		}
		back := slices.Clip(rrset.RRSIGs)
		for _, sig := range t.sigs {
			if !slices.ContainsFunc(back, func(have dns.RR) bool { return dns.IsDuplicate(have, sig) }) {
				back = append(back, sig)
			}
		}
		if len(back) == len(rrset.RRSIGs) {
			continue
		}
		rrset.RRtype = t.rrtype
		rrset.RRSIGs = back
		zd.stageRRsetLocked(t.name, rrset)
	}
}
