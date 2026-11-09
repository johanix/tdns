/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"slices"
	"sort"

	"github.com/miekg/dns"
)

// Comparing a zone's content with the version it replaces, in the terms that
// decide whether a new serial is owed (#1006).
//
// "Content" here is what the zone serves as data: every RRset in every owner's
// RRtypes. Left out is what the server derives and regenerates on every
// publish -- RRSIGs (carried on the RRset, not in RRtypes), the NSEC property,
// a ZONEMD the zone manages -- and the SOA serial, which is the thing being
// decided. Two versions equal in these terms are the same zone: publishing the
// second under a new serial would only make every secondary fetch it again.
//
// In a zone that does not sign its own content, any RRSIGs and NSEC records
// came with the content -- a zone signed elsewhere -- and are compared like
// the rest: a file re-signed under the same serial has changed, and serving
// the old signatures until they expire would be wrong.

// contentTerms says what a content comparison leaves out.
type contentTerms struct {
	skipZonemd bool // the zone makes its own ZONEMD
	withSigs   bool // RRSIGs and NSEC are content: the zone does not sign itself
}

func (zd *ZoneData) contentTerms() contentTerms {
	return contentTerms{skipZonemd: zd.zoneManagesZonemd(), withSigs: !zd.signsItsOwnContent()}
}

// authoredContentEqual reports whether two owner maps carry the same content,
// in the terms above. It stops at the first difference, so a reload that did
// change something costs little; the whole zone is compared only when nothing
// differs.
//
// An owner holding no data counts as absent on either side: a name can linger
// in one map with nothing but an emptied RRset, and it serves nothing.
func authoredContentEqual(zoneName string, a, b map[string]*OwnerData, terms contentTerms) bool {
	for name, aod := range a {
		bod := b[name]
		if aod == bod || sharesOwnerStorage(aod, bod) {
			continue
		}
		if !authoredOwnerEqual(zoneName, name, aod, bod, terms) {
			return false
		}
	}
	for name, bod := range b {
		if _, ok := a[name]; !ok && ownerHasData(bod) {
			return false
		}
	}
	return true
}

func authoredOwnerEqual(zoneName, name string, a, b *OwnerData, terms contentTerms) bool {
	types := map[uint16]bool{}
	for _, t := range ownerTypes(a) {
		types[t] = true
	}
	for _, t := range ownerTypes(b) {
		types[t] = true
	}
	apex := name == zoneName
	for t := range types {
		if terms.skipZonemd && apex && t == dns.TypeZONEMD {
			// Made here, so its digests differ on every publish; but its
			// parameters are configuration, and a change to them must publish.
			if !slices.Equal(zonemdParams(ownerRRset(a, t).RRs), zonemdParams(ownerRRset(b, t).RRs)) {
				return false
			}
			continue
		}
		ars, brs := ownerRRset(a, t).RRs, ownerRRset(b, t).RRs
		if apex && t == dns.TypeSOA {
			ars, brs = soaWithoutSerial(ars), soaWithoutSerial(brs)
		}
		if !sameRRs(ars, brs) {
			return false
		}
		if terms.withSigs && !sameRRs(ownerRRset(a, t).RRSIGs, ownerRRset(b, t).RRSIGs) {
			return false
		}
	}
	if terms.withSigs {
		an, bn := ownerNsec(a), ownerNsec(b)
		if !sameRRs(an.RRs, bn.RRs) || !sameRRs(an.RRSIGs, bn.RRSIGs) {
			return false
		}
	}
	return true
}

// zonemdParams returns the scheme and hash algorithm of each ZONEMD record,
// sorted: what the zone's configuration decides, without the digest and serial
// every publish recomputes.
func zonemdParams(rrs []dns.RR) []string {
	out := make([]string, 0, len(rrs))
	for _, rr := range rrs {
		if z, ok := rr.(*dns.ZONEMD); ok {
			out = append(out, fmt.Sprintf("%d/%d", z.Scheme, z.Hash))
		}
	}
	sort.Strings(out)
	return out
}

// sameRRs reports whether two RR slices hold the same records, in any order.
func sameRRs(a, b []dns.RR) bool {
	if len(a) != len(b) {
		return false
	}
	onlyA, onlyB := rrDiff(a, b)
	return len(onlyA) == 0 && len(onlyB) == 0
}

// soaWithoutSerial returns copies of the SOA RRs with the serial zeroed, so
// two SOAs compare on everything but the serial.
func soaWithoutSerial(rrs []dns.RR) []dns.RR {
	out := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		if soa, ok := rr.(*dns.SOA); ok {
			c := dns.Copy(soa).(*dns.SOA)
			c.Serial = 0
			out = append(out, c)
			continue
		}
		out = append(out, rr)
	}
	return out
}

// authoredContentDigest returns a digest of an owner map's content, in the
// same terms as authoredContentEqual: equal digests mean equal content. Used to
// tell, at a restart, whether the zone just loaded is the one last published.
//
// Not ZONEMD: that digest covers the SOA serial and the derived records, both
// of which this has to ignore, and it is defined over canonical wire form, which
// costs more than this needs. The text form of each RR is enough to compare a
// zone with itself across a restart of the same software.
func authoredContentDigest(zoneName string, data map[string]*OwnerData, terms contentTerms) string {
	names := make([]string, 0, len(data))
	for name := range data {
		names = append(names, name)
	}
	sort.Strings(names)

	h := sha256.New()
	for _, name := range names {
		od := data[name]
		types := ownerTypes(od)
		sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })
		apex := name == zoneName
		for _, t := range types {
			if terms.skipZonemd && apex && t == dns.TypeZONEMD {
				for _, p := range zonemdParams(ownerRRset(od, t).RRs) {
					h.Write([]byte("ZONEMD " + p + "\n"))
				}
				continue
			}
			rrs := ownerRRset(od, t).RRs
			if apex && t == dns.TypeSOA {
				rrs = soaWithoutSerial(rrs)
			}
			digestRRs(h, rrs)
			if terms.withSigs {
				digestRRs(h, ownerRRset(od, t).RRSIGs)
			}
		}
		if terms.withSigs {
			nsec := ownerNsec(od)
			digestRRs(h, nsec.RRs)
			digestRRs(h, nsec.RRSIGs)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// digestRRs writes the records' text into h, sorted, one per line.
func digestRRs(h io.Writer, rrs []dns.RR) {
	lines := make([]string, 0, len(rrs))
	for _, rr := range rrs {
		lines = append(lines, rr.String())
	}
	sort.Strings(lines)
	for _, l := range lines {
		h.Write([]byte(l))
		h.Write([]byte{'\n'})
	}
}

// fileSOASigned reports whether a parsed zone's apex SOA came with signatures:
// the zone was signed before it reached this server.
func fileSOASigned(zd *ZoneData) bool {
	if zd == nil || zd.Data == nil {
		return false
	}
	apex, ok := zd.Data.Get(zd.ZoneName)
	if !ok || apex.RRtypes == nil {
		return false
	}
	return len(apex.RRtypes.GetOnlyRRSet(dns.TypeSOA).RRSIGs) > 0
}
