/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Where the proof in a negative answer comes from.
 *
 * A negative answer to a DO query carries NSEC records, with their
 * signatures, showing that the name or the type is not there (RFC 4035
 * section 3.1.3). Which records depends on the zone, not on the query:
 *
 *   - a zone this server signs synthesizes a compact denial for each response
 *     and signs it (RFC 9824);
 *   - a zone with a stored NSEC chain proves it with the chain's own records,
 *     served with the signatures they already carry. That is the only proof a
 *     secondary can give, since it holds no key;
 *   - a signed zone with no chain this server can read -- a secondary of a
 *     compact-denial primary, or an NSEC3 zone -- has no proof to give;
 *   - an unsigned zone has none to give either, and answers a DO query as it
 *     answers one without DO.
 *
 * Before this, every zone synthesized, and a zone with no key served the
 * synthesized NSEC unsigned: NOERROR for a name that does not exist, beside a
 * record no validator can use (#770, #771).
 *
 * See docs/2026-09-25-negative-answers-from-zone-data.md.
 */

package tdns

import (
	"errors"
	"fmt"

	core "github.com/johanix/tdns/v2/core"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// denialSource is where a zone's negative answers get their proof (the
// design's §3.1).
type denialSource uint8

const (
	// denialCompact: synthesized and signed per response (row A).
	denialCompact denialSource = iota
	// denialChain: the zone's stored NSEC chain (row B).
	denialChain
	// denialNoChain: the zone is signed but holds no NSEC chain -- a
	// secondary of a compact-denial primary, or an NSEC3 zone (rows C, D).
	denialNoChain
	// denialUnsigned: the zone is not signed (row E).
	denialUnsigned
)

// errDenialUnproven is the error of a zone signed here whose own chain cannot
// prove a denial. The zone is ours and broken, so the caller answers SERVFAIL,
// as ErrZoneUnsigned has it do for stored data without signatures, rather
// than synthesize a proof that would hide the gap.
var errDenialUnproven = errors.New("zone must be signed but its NSEC chain cannot prove the denial")

// signsHere reports whether this server signs zd, the test signRRsetForZone
// applies as well.
func (zd *ZoneData) signsHere() bool {
	return zd.Options[OptOnlineSigning] || zd.Options[OptInlineSigning]
}

// denialSourceFor says where zd's negative answers get their proof, given the
// apex of the snapshot being answered from. For a zone signed here its options
// decide; for any other zone its data does.
//
// black-lies on a zone that is not signed here changes nothing: there is no
// key to sign a synthesized NSEC with.
func (zd *ZoneData) denialSourceFor(apex *OwnerData) denialSource {
	if zd.signsHere() {
		return denialCompact
	}
	switch {
	case apex == nil || apex.RRtypes == nil:
		return denialUnsigned
	case len(apex.NSEC.RRs) > 0:
		return denialChain
	case len(apex.RRtypes.GetOnlyRRSet(dns.TypeSOA).RRSIGs) > 0:
		return denialNoChain
	}
	return denialUnsigned
}

// noChainReason says why a signed zone's denials carry no proof.
func noChainReason(apex *OwnerData) string {
	if apex != nil && apex.RRtypes != nil {
		if _, ok := apex.RRtypes.Get(dns.TypeNSEC3PARAM); ok {
			return "the zone uses NSEC3, which is not served yet"
		}
	}
	return "the zone is signed but holds no NSEC chain"
}

// denialKind is the kind of negative answer.
type denialKind uint8

const (
	denyName denialKind = iota // the name does not exist: NXDOMAIN
	denyType                   // the name exists, the type does not: NODATA
	denyENT                    // an empty non-terminal: NODATA
)

// denial describes one negative answer.
type denial struct {
	kind  denialKind
	qname string // the name that was asked
	qtype uint16 // the type that was asked
	// owner is, for denyType, the node that matched: qname's own, the
	// wildcard that matched it, or the zone cut a DS query stops at.
	owner *OwnerData
	// types is, for denyType, the types a compact denial lists in its bitmap.
	types []uint16
}

// addDenial adds the proof of a negative answer to AUTHORITY. The caller has
// set the rcode and added the SOA; only a compact denial changes the rcode
// (addCDEResponse). The error is that of a zone that must be signed and cannot
// prove the denial, and the caller answers SERVFAIL on it (failUnsignedDenial).
func (zd *ZoneData) addDenial(m *dns.Msg, snap *zoneSnapshot, apex *OwnerData, d denial,
	msgoptions *edns0.MsgOptions, signFunc func(core.RRset, string) (core.RRset, error)) error {
	if apex == nil || apex.RRtypes == nil {
		return nil
	}
	soaSigs := apex.RRtypes.GetOnlyRRSet(dns.TypeSOA).RRSIGs
	if zd.signsHere() && len(soaSigs) == 0 {
		// A zone signed here whose SOA carries no signature is broken, on
		// every negative path, as it is on the positive one.
		lgHandler.Error("must-be-signed zone has no signature over its SOA; serving SERVFAIL for a denial",
			"zone", zd.ZoneName, "qname", d.qname)
		return ErrZoneUnsigned
	}

	switch zd.denialSourceFor(apex) {
	case denialCompact:
		var types []uint16
		switch d.kind {
		case denyType:
			types = append([]uint16{}, d.types...)
		case denyENT:
			types = []uint16{}
		}
		return zd.addCDEResponse(m, d.qname, apex, types, msgoptions, signFunc)

	case denialChain:
		m.Ns = append(m.Ns, soaSigs...)
		return zd.addChainProof(m, snap, d)

	case denialNoChain:
		m.Ns = append(m.Ns, soaSigs...)
		snap.warnDenial(zd.ZoneName, noChainReason(apex), d.qname)
		return nil
	}
	return nil
}

// addChainProof adds the stored NSEC records that prove d, with the signatures
// they carry (RFC 4035 section 3.1.3):
//
//   - a name that does not exist: the NSEC covering it and the NSEC covering
//     the wildcard at its closest encloser;
//   - a type that does not exist at an owner: the owner's own NSEC; through a
//     wildcard, also the NSEC covering the name asked (section 3.1.3.4);
//   - an empty non-terminal: the NSEC covering it, whose next name lies below
//     it.
//
// A record that is missing, or that is there and does not prove the claim, is
// a gap. A zone not signed here serves what it holds and warns once per serial;
// a zone signed here is broken, and gets errDenialUnproven.
func (zd *ZoneData) addChainProof(m *dns.Msg, snap *zoneSnapshot, d denial) error {
	var proof []core.RRset
	var gap string
	noteGap := func(format string, args ...interface{}) {
		if gap == "" {
			gap = fmt.Sprintf(format, args...)
		}
	}
	add := func(rs core.RRset) {
		for _, have := range proof {
			if core.EqualNames(have.RRs[0].Header().Name, rs.RRs[0].Header().Name) {
				return
			}
		}
		proof = append(proof, rs)
	}

	switch d.kind {
	case denyName:
		if rs, ok := nsecCoveringFrom(snap, d.qname); ok {
			add(rs)
		} else {
			noteGap("no NSEC covers %s", d.qname)
		}
		wild := wildcardSourceFrom(snap, zd.ZoneName, d.qname)
		if rs, ok := nsecCoveringFrom(snap, wild); ok {
			add(rs)
		} else {
			noteGap("no NSEC covers the wildcard %s", wild)
		}

	case denyENT:
		if rs, ok := nsecCoveringFrom(snap, d.qname); ok && nsecNextIsBelow(rs, d.qname) {
			add(rs)
		} else {
			noteGap("no NSEC covers the empty non-terminal %s", d.qname)
		}

	case denyType:
		if d.owner != nil && !core.EqualNames(d.owner.Name, d.qname) {
			// A wildcard matched: prove too that the name asked does not exist.
			if rs, ok := nsecCoveringFrom(snap, d.qname); ok {
				add(rs)
			} else {
				noteGap("no NSEC covers %s", d.qname)
			}
		}
		switch {
		case d.owner == nil || len(d.owner.NSEC.RRs) == 0:
			noteGap("no NSEC at %s", d.qname)
		case !nsecDeniesType(d.owner.NSEC, d.qtype):
			noteGap("the NSEC at %s lists %s or CNAME", d.owner.Name, dns.TypeToString[d.qtype])
		default:
			add(d.owner.NSEC)
		}
	}

	for _, rs := range proof {
		if len(rs.RRSIGs) == 0 {
			noteGap("the NSEC at %s has no RRSIG", rs.RRs[0].Header().Name)
		}
	}
	if gap != "" && zd.signsHere() {
		lgHandler.Error("the zone's own NSEC chain cannot prove a denial; serving SERVFAIL",
			"zone", zd.ZoneName, "qname", d.qname, "reason", gap)
		return errDenialUnproven
	}
	for _, rs := range proof {
		m.Ns = append(m.Ns, rs.RRs...)
		m.Ns = append(m.Ns, rs.RRSIGs...)
	}
	if gap != "" {
		snap.warnDenial(zd.ZoneName, gap, d.qname)
	}
	return nil
}

// addReferralDenial adds to a referral the proof that the delegation has no
// DS: in a zone with a chain, the chain's NSEC at the cut, whose bitmap holds
// NS and not DS. The error is as addDenial's.
func (zd *ZoneData) addReferralDenial(m *dns.Msg, snap *zoneSnapshot, cdd *ChildDelegationData, apex *OwnerData,
	signFunc func(core.RRset, string) (core.RRset, error)) error {
	switch zd.denialSourceFor(apex) {
	case denialCompact:
		return addReferralNSEC(m, cdd, apex, zd.ZoneName, signFunc)

	case denialChain:
		var gap string
		cut := getOwnerFrom(snap, cdd.ChildName)
		switch {
		case cut == nil || len(cut.NSEC.RRs) == 0:
			gap = fmt.Sprintf("no NSEC at the delegation %s", cdd.ChildName)
		case !nsecProvesInsecureCut(cut.NSEC):
			gap = fmt.Sprintf("the NSEC at %s does not show NS without DS", cdd.ChildName)
		case len(cut.NSEC.RRSIGs) == 0:
			gap = fmt.Sprintf("the NSEC at %s has no RRSIG", cdd.ChildName)
		}
		if gap != "" && zd.signsHere() {
			lgHandler.Error("the zone's own NSEC chain cannot prove a delegation insecure; serving SERVFAIL",
				"zone", zd.ZoneName, "child", cdd.ChildName, "reason", gap)
			return errDenialUnproven
		}
		if cut != nil && len(cut.NSEC.RRs) > 0 && nsecProvesInsecureCut(cut.NSEC) {
			m.Ns = append(m.Ns, cut.NSEC.RRs...)
			m.Ns = append(m.Ns, cut.NSEC.RRSIGs...)
		}
		if gap != "" {
			snap.warnDenial(zd.ZoneName, gap, cdd.ChildName)
		}

	case denialNoChain:
		snap.warnDenial(zd.ZoneName, noChainReason(apex), cdd.ChildName)
	}
	return nil
}

// nsecDeniesType reports whether the NSEC in rs proves that its owner holds no
// qtype: its bitmap lists neither qtype nor CNAME, which a resolver would have
// been sent to follow instead. ANY asks for no one type.
func nsecDeniesType(rs core.RRset, qtype uint16) bool {
	nsec, ok := rs.RRs[0].(*dns.NSEC)
	if !ok {
		return false
	}
	for _, t := range nsec.TypeBitMap {
		if t == dns.TypeCNAME || (t == qtype && qtype != dns.TypeANY) {
			return false
		}
	}
	return true
}

// nsecNextIsBelow reports whether the NSEC in rs has a next name strictly below
// qname, which is what makes a covering NSEC the proof of an empty
// non-terminal rather than of a name that does not exist.
func nsecNextIsBelow(rs core.RRset, qname string) bool {
	nsec, ok := rs.RRs[0].(*dns.NSEC)
	if !ok {
		return false
	}
	return dns.IsSubDomain(qname, nsec.NextDomain) && !core.EqualNames(qname, nsec.NextDomain)
}

// nsecProvesInsecureCut reports whether the NSEC in rs is a parent-side NSEC at
// a delegation with no DS: NS in its bitmap, and neither DS nor SOA.
func nsecProvesInsecureCut(rs core.RRset) bool {
	nsec, ok := rs.RRs[0].(*dns.NSEC)
	if !ok {
		return false
	}
	var ns bool
	for _, t := range nsec.TypeBitMap {
		switch t {
		case dns.TypeNS:
			ns = true
		case dns.TypeDS, dns.TypeSOA:
			return false
		}
	}
	return ns
}

// logDenialGap reports a serial whose negative answers cannot be fully proved.
// A variable so that tests can count the calls.
var logDenialGap = func(zone string, serial uint32, reason, qname string) {
	lgHandler.Warn("negative answers from this serial carry an incomplete proof, which validators reject",
		"zone", zone, "serial", serial, "reason", reason, "qname", qname)
}

// warnDenial reports, once per snapshot, the first negative answer from it
// that could not be fully proved. It is called only when there is something to
// report, so a serial whose early answers prove fine still warns at its first
// gap.
func (s *zoneSnapshot) warnDenial(zone, reason, qname string) {
	if s == nil {
		return
	}
	s.denialWarn.Do(func() {
		logDenialGap(zone, s.Serial, reason, qname)
	})
}

// prepareDenialIndex builds the chain index of a snapshot that is about to be
// published, when its apex holds an NSEC. Built here, under the zone lock and
// before the snapshot is stored, it is ready before any query reads the
// snapshot; built on first use instead, the first negative answer of every
// serial would build it and every other query needing it would wait (the
// design's Q7).
func (s *zoneSnapshot) prepareDenialIndex() {
	if s != nil && s.Apex != nil && len(s.Apex.NSEC.RRs) > 0 {
		s.nsecOwners()
	}
}
