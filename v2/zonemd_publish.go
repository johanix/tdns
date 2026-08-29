/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"fmt"
	"strings"
	"time"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// Publishing ZONEMD (RFC 8976).
//
// The digest covers the SOA, and the SOA's serial moves on every publish --
// on a signed zone its RRSIG is rewritten too. So every publish invalidates
// the ZONEMD, and there is nowhere for it to live except inside the publish
// that creates the snapshot it describes. This is the same argument the NSEC
// chain answers to (docs/2026-08-22-nsec-chain-correctness.md §1): repairing
// a derived record after the swap means a second serial, and a window in
// which the zone advertises a digest that does not describe what it serves.
// For ZONEMD that window is worse than a stale chain, because a verifier
// cannot tell a stale digest from a tampered zone.
//
// Two entry points, straddling the NSEC restitch, because there is a cycle to
// break:
//
//	ensureZonemdPresenceLocked  -- decides whether the apex HAS a ZONEMD, so
//	                               restitch can put the type in the apex NSEC
//	                               bitmap
//	restitchNsecLocked
//	updateZonemdLocked          -- computes the digest, which covers the NSEC
//	                               records restitch has just written, and
//	                               signs it
//
// Writing the digest after the bitmap is safe in both directions: RDATA does
// not appear in a type bitmap, and ZoneDigest excludes the apex ZONEMD RRset
// AND the RRSIG covering it (zonemd.go, per §3.3.1), so neither the value nor
// its signature can invalidate what was just computed.

// zonemdDigestPlaceholder is what a ZONEMD RR carries between the two steps.
//
// It never reaches the wire: updateZonemdLocked either overwrites it in the
// same publish or removes the record. It exists because the two steps are
// separated by the restitch, and a ZONEMD RR has to be well-formed in between
// -- the bitmap is decided from the RRset's presence, and an RRset that cannot
// be packed is not a presence anything can reason about.
func zonemdDigestPlaceholder(alg uint8) string {
	switch alg {
	case ZonemdAlgSHA512:
		return strings.Repeat("00", 64)
	default:
		return strings.Repeat("00", 48)
	}
}

// zoneManagesZonemd reports whether this zone's apex ZONEMD RRset is ours to
// maintain.
//
// The origination check duplicates what normalizeOptionsForRole already does
// by stripping OptPublishZonemd from a tdns-auth secondary that may not
// originate. It is here for the same reason resignWorkingSetSOAIfSigned has
// one: this runs on EVERY publish including the refresh path, and a zone that
// mirrors upstream content must not have a locally computed record injected
// into it. Defence in depth behind the normalizer, not instead of it.
func (zd *ZoneData) zoneManagesZonemd() bool {
	if zd == nil || !zd.Options[OptPublishZonemd] {
		return false
	}
	return zoneMayOriginateContent(zd)
}

// zonemdSchemeLocked and zonemdAlgsLocked resolve the configured parameters,
// defaulting to SIMPLE/SHA-384: the only scheme RFC 8976 defines, and its
// mandatory-to-implement hash.
func (zd *ZoneData) zonemdSchemeLocked() uint8 {
	if zd.zonemdScheme == 0 {
		return ZonemdSchemeSimple
	}
	return zd.zonemdScheme
}

func (zd *ZoneData) zonemdAlgsLocked() []uint8 {
	if len(zd.zonemdAlgs) == 0 {
		return []uint8{ZonemdAlgSHA384}
	}
	return zd.zonemdAlgs
}

// zonemdSignableLocked reports whether a ZONEMD published now could be signed.
//
// A zone configured to be signed must not publish an unsigned apex RRset: a
// validator asking for it gets an answer with no signature, which is BOGUS
// rather than merely undigested. The window this closes is real and ordinary
// -- a new zone's DNSSEC policy is bound post-Ready, so the first publishes of
// its life run with zd.DnssecPolicy == nil.
//
// Checked here, cheaply, rather than by resolving the keys: this runs BEFORE
// the restitch, where the answer decides whether the apex NSEC bitmap lists
// ZONEMD at all, and EnsureActiveDnssecKeys is not a predicate -- it mints a
// zone's first keys as a side effect.
func (zd *ZoneData) zonemdSignableLocked() bool {
	if !zd.Options[OptOnlineSigning] && !zd.Options[OptInlineSigning] {
		return true // unsigned zone: nothing to sign, so nothing to be unable to sign
	}
	return zd.DnssecPolicy != nil && zd.KeyDB != nil
}

// zonemdTTLLocked returns the TTL for the apex ZONEMD RRset: the SOA's own,
// which is what the record's neighbours at the apex carry and what every
// other implementation publishes.
func (zd *ZoneData) zonemdTTLLocked() uint32 {
	od := zd.stagedOwner(zd.ZoneName)
	if od == nil {
		return 3600
	}
	soa := od.RRtypes.GetOnlyRRSet(dns.TypeSOA)
	if len(soa.RRs) == 0 {
		return 3600
	}
	return soa.RRs[0].Header().Ttl
}

// currentZonemdSerialLocked returns the serial the staged apex SOA carries, so
// a placeholder is not born with a serial from another zone version. The real
// value is written by updateZonemdLocked from the serial being published.
func (zd *ZoneData) currentZonemdSerialLocked() uint32 {
	od := zd.stagedOwner(zd.ZoneName)
	if od == nil {
		return zd.CurrentSerial
	}
	soa := od.RRtypes.GetOnlyRRSet(dns.TypeSOA)
	if len(soa.RRs) == 0 {
		return zd.CurrentSerial
	}
	if s, ok := soa.RRs[0].(*dns.SOA); ok {
		return s.Serial
	}
	return zd.CurrentSerial
}

// zonemdPairsMatch reports whether rs is exactly one ZONEMD RR per requested
// (scheme, algorithm) pair and nothing else.
func zonemdPairsMatch(rs core.RRset, scheme uint8, algs []uint8) bool {
	if len(rs.RRs) != len(algs) {
		return false
	}
	want := make(map[uint8]bool, len(algs))
	for _, a := range algs {
		want[a] = true
	}
	for _, rr := range rs.RRs {
		z, ok := rr.(*dns.ZONEMD)
		if !ok || z.Scheme != scheme || !want[z.Hash] {
			return false
		}
		delete(want, z.Hash)
	}
	return len(want) == 0
}

// ensureZonemdPresenceLocked settles whether the apex carries a ZONEMD RRset,
// and with which (scheme, algorithm) pairs -- but not what it says.
//
// It runs before restitchNsecLocked so the apex NSEC bitmap describes the
// record set the snapshot will actually hold. Anything that can make this
// publish unable to produce a correct ZONEMD has to be decided here, not
// later: a bitmap claiming a ZONEMD the zone does not carry is an NXRRSET
// proof no validator will accept.
//
// Runs with zd.mu held.
func (zd *ZoneData) ensureZonemdPresenceLocked() {
	if zd.workingSet == nil {
		return
	}
	if !zd.zoneManagesZonemd() || !zd.zonemdSignableLocked() {
		// Only our own record comes out. An apex ZONEMD on a zone that does
		// not manage one is operator data -- someone wrote it into the zone
		// file -- and removing it because we happen not to be maintaining it
		// would be deleting content nobody asked us to touch.
		if zd.zonemdManaged {
			zd.removeZonemdLocked()
		}
		return
	}

	apex := zd.workingSet[zd.ZoneName]
	if apex == nil {
		return
	}
	scheme, algs := zd.zonemdSchemeLocked(), zd.zonemdAlgsLocked()
	cur := apex.RRtypes.GetOnlyRRSet(dns.TypeZONEMD)
	if zd.zonemdManaged && zonemdPairsMatch(cur, scheme, algs) {
		// Presence is already right. Leaving the RRset untouched keeps this
		// publish from reporting the apex as changed on account of a record
		// whose value has not been computed yet.
		return
	}

	ttl, serial := zd.zonemdTTLLocked(), zd.currentZonemdSerialLocked()
	rs := core.RRset{
		Name:   zd.ZoneName,
		Class:  dns.ClassINET,
		RRtype: dns.TypeZONEMD,
	}
	for _, alg := range algs {
		rs.RRs = append(rs.RRs, &dns.ZONEMD{
			Hdr: dns.RR_Header{
				Name:   zd.ZoneName,
				Rrtype: dns.TypeZONEMD,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			},
			Serial: serial,
			Scheme: scheme,
			Hash:   alg,
			Digest: zonemdDigestPlaceholder(alg),
		})
	}
	zd.stageRRsetLocked(zd.ZoneName, rs)
}

// updateZonemdLocked computes the digest over the working set, writes it into
// the staged apex ZONEMD RRset, and signs the result.
//
// This is the last step that may change zone content in a publish. Everything
// after it -- the delta computation, the IXFR chain, the snapshot swap -- only
// reads. Move it later and the digest stops describing what is published;
// move it earlier and it stops covering the NSEC records.
//
// Returns false when the publish must be ABANDONED. That is not the ordinary
// failure: a zone that cannot produce a digest is published without one (see
// abandonZonemdLocked). It happens only when dropping the ZONEMD leaves an
// apex NSEC that still claims the type and the chain cannot be repaired --
// at which point the zone is in the state refuseUnrepairableChainLocked
// exists to keep off the wire.
//
// prevSerial is the serial to restore if the publish is abandoned.
//
// Runs with zd.mu held.
func (zd *ZoneData) updateZonemdLocked(serial, prevSerial uint32) bool {
	if zd.workingSet == nil {
		return true
	}
	if !zd.zoneManagesZonemd() || !zd.zonemdSignableLocked() {
		zd.zonemdDigests = nil
		zd.zonemdDigestSerial = 0
		return true
	}
	if zd.workingSet[zd.ZoneName] == nil {
		return true
	}

	scheme, algs := zd.zonemdSchemeLocked(), zd.zonemdAlgsLocked()

	// Every algorithm in one pass. The canonical blocks do not depend on the
	// hash, so a zone publishing SHA-384 and SHA-512 renders once and hashes
	// twice -- and the blocks of every owner this publish did not touch are
	// reused rather than rebuilt. See zonemd_cache.go.
	digests, derr := zd.zonemdDigestsLocked(scheme, algs)
	if derr != nil {
		return zd.abandonZonemdLocked(prevSerial, fmt.Errorf("computing the digest: %w", derr))
	}

	ttl := zd.zonemdTTLLocked()
	rs := core.RRset{
		Name:   zd.ZoneName,
		Class:  dns.ClassINET,
		RRtype: dns.TypeZONEMD,
	}
	for _, alg := range algs {
		digest, ok := digests[alg]
		if !ok {
			return zd.abandonZonemdLocked(prevSerial,
				fmt.Errorf("no %s digest was produced", zonemdAlgName(alg)))
		}
		rs.RRs = append(rs.RRs, &dns.ZONEMD{
			Hdr: dns.RR_Header{
				Name:   zd.ZoneName,
				Rrtype: dns.TypeZONEMD,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			},
			Serial: serial,
			Scheme: scheme,
			Hash:   alg,
			Digest: digest,
		})
	}

	if zd.Options[OptOnlineSigning] || zd.Options[OptInlineSigning] {
		// Resolved here with zdLocked=true and passed into SignRRset, so
		// SignRRset does not reach its own EnsureActiveDnssecKeys -- that path
		// gets to PublishDnskeyRRs and re-locks zd.mu. Same deadlock class as
		// the SOA re-sign and the NSEC restitch alongside this.
		dak, err := zd.EnsureActiveDnssecKeys(zd.KeyDB, true)
		if err != nil {
			return zd.abandonZonemdLocked(prevSerial,
				fmt.Errorf("resolving keys to sign the ZONEMD: %w", err))
		}
		var clamp *ClampParams
		if zd.DnssecPolicy != nil {
			clamp, err = ClampParamsForZone(zd.KeyDB, zd.ZoneName, zd.DnssecPolicy, time.Now())
			if err != nil {
				return zd.abandonZonemdLocked(prevSerial,
					fmt.Errorf("resolving clamp parameters to sign the ZONEMD: %w", err))
			}
		}
		if _, err := zd.SignRRset(&rs, zd.ZoneName, dak, true, clamp); err != nil {
			return zd.abandonZonemdLocked(prevSerial, fmt.Errorf("signing the ZONEMD: %w", err))
		}
	}

	zd.stageRRsetLocked(zd.ZoneName, rs)
	zd.zonemdManaged = true
	zd.zonemdDigests = digests
	zd.zonemdDigestSerial = serial
	zd.noteZonemdStateLocked("")
	return true
}

// abandonZonemdLocked drops the ZONEMD from a publish that cannot produce a
// correct one, and repairs the apex NSEC bitmap that was written on the
// assumption it could.
//
// Removing rather than keeping the previous value is the whole point. A stale
// digest is not a lesser version of a correct one: it is a zone whose contents
// do not match its own attestation, which is what a verifier reports when a
// zone has been tampered with. Absent is a state RFC 8976 defines and a
// verifier handles; wrong is not.
//
// Publishing WITHOUT a digest is the ordinary outcome, and the publish
// continues: an unrepairable NSEC chain is refused because a secondary answers
// denial from whatever chain it is handed and cannot fix it, whereas a missing
// ZONEMD costs the zone nothing but its digest, and taking a zone off the air
// over that would be the larger failure.
//
// Returns false only when the chain cannot be brought back into agreement with
// the zone, which is the one case where publishing anyway would put the very
// inconsistency this function exists to avoid onto the wire.
func (zd *ZoneData) abandonZonemdLocked(prevSerial uint32, err error) bool {
	zd.removeZonemdLocked()
	zd.noteZonemdStateLocked(err.Error())

	// The apex NSEC was rewritten by the restitch with ZONEMD in its bitmap,
	// because ensureZonemdPresenceLocked had staged the RRset by then. Left
	// alone it would assert a type the apex no longer owns, and the NXRRSET
	// proof for ZONEMD would fail. A second restitch is O(zone) and this is a
	// path that should never run twice in a row.
	rerr := zd.restitchNsecLocked()
	if rerr == nil {
		return true
	}

	// Dropping the ZONEMD has left the apex NSEC claiming a type the zone does
	// not carry, and the chain cannot be repaired. Publishing now would serve a
	// signed proof that contradicts the zone -- which is exactly what
	// refuseUnrepairableChainLocked refuses on the primary restitch path, and
	// there is no reason for this path to be laxer about the same defect.
	//
	// The previous snapshot goes on being served, self-consistent, and the
	// change stays staged for the next publish to retry.
	zd.refuseUnrepairableChainLocked(prevSerial,
		fmt.Errorf("the ZONEMD could not be computed (%v) and the apex NSEC could"+
			" not be repaired after dropping it: %w", err, rerr))
	return false
}

// removeZonemdLocked drops the apex ZONEMD RRset and forgets everything
// derived from it.
func (zd *ZoneData) removeZonemdLocked() {
	if zd.workingSet == nil {
		return
	}
	if zd.stagedOwner(zd.ZoneName) != nil {
		zd.stageDeleteLocked(zd.ZoneName, dns.TypeZONEMD)
	}
	zd.zonemdManaged = false
	zd.zonemdDigests = nil
	zd.zonemdDigestSerial = 0
	// Nothing is going to read the rendered blocks again until the zone
	// publishes a digest once more, and by then every owner will have been
	// re-rendered anyway. Holding them meanwhile is memory for nothing.
	zd.dropZonemdCacheLocked()
}

// noteZonemdStateLocked logs a change in whether the zone can publish a
// ZONEMD, and only a change.
//
// A publish runs at least every publish-cadence (5s by default), so an
// unconditional error line for a persistent failure is a log the operator
// stops reading. Reporting the transitions -- and the recovery -- is what
// makes the failure findable.
func (zd *ZoneData) noteZonemdStateLocked(errmsg string) {
	if zd.zonemdLastErr == errmsg {
		return
	}
	switch {
	case errmsg == "":
		lg.Info("the zone is publishing a ZONEMD again", "zone", zd.ZoneName)
	default:
		lg.Error("this zone is configured to publish a ZONEMD and cannot;"+
			" it is being published WITHOUT one",
			"zone", zd.ZoneName, "error", errmsg)
	}
	zd.zonemdLastErr = errmsg
}

// zonemdAlgName renders an RFC 8976 hash algorithm for a log line.
func zonemdAlgName(alg uint8) string {
	switch alg {
	case ZonemdAlgSHA384:
		return "SHA-384"
	case ZonemdAlgSHA512:
		return "SHA-512"
	default:
		return fmt.Sprintf("algorithm %d", alg)
	}
}

// cachedZonemdDigest returns the digest this zone published for alg at the
// given serial, and whether it has one.
//
// The caller is the zone-file write path. ZoneDigest excludes the apex ZONEMD
// and its RRSIG, so the value in the published ZONEMD RR is bit-for-bit the
// value ZoneFileState wants for the same (scheme, algorithm) -- digesting the
// zone a second time to obtain it would produce the identical string at full
// cost.
func (zd *ZoneData) cachedZonemdDigest(serial uint32, scheme, alg uint8) (string, bool) {
	if zd == nil {
		return "", false
	}
	zd.mu.Lock()
	defer zd.mu.Unlock()
	return zd.cachedZonemdDigestLocked(serial, scheme, alg)
}

func (zd *ZoneData) cachedZonemdDigestLocked(serial uint32, scheme, alg uint8) (string, bool) {
	if zd.zonemdDigests == nil || zd.zonemdDigestSerial != serial {
		return "", false
	}
	if zd.zonemdSchemeLocked() != scheme {
		return "", false
	}
	d, ok := zd.zonemdDigests[alg]
	return d, ok && d != ""
}

// resolveZonemdConf validates a zone's `zonemd` config block and returns the
// parameters to publish with.
//
// An empty block is SIMPLE/SHA-384. Everything else is checked: SIMPLE is the
// only scheme RFC 8976 defines, the hash registry has exactly two entries, and
// duplicates are rejected rather than deduplicated -- two ZONEMD RRs with the
// same (scheme, algorithm) pair is a malformed RRset, and silently collapsing
// it would hide a config the operator got wrong.
// zonemdSettings is a zone's validated ZONEMD configuration.
type zonemdSettings struct {
	Scheme            uint8
	Algorithms        []uint8
	OnVerifyFailure   string
	WireCacheMaxBytes int
}

func resolveZonemdConf(zc ZonemdConf) (zonemdSettings, error) {
	out := zonemdSettings{
		Scheme:            zc.Scheme,
		OnVerifyFailure:   zc.OnVerifyFailure,
		WireCacheMaxBytes: zc.WireCacheMaxBytes,
	}
	if out.Scheme == 0 {
		out.Scheme = ZonemdSchemeSimple
	}
	if out.Scheme != ZonemdSchemeSimple {
		return zonemdSettings{}, fmt.Errorf(
			"scheme %d is not implemented (only SIMPLE=%d is defined)",
			out.Scheme, ZonemdSchemeSimple)
	}

	switch out.OnVerifyFailure {
	case "":
		out.OnVerifyFailure = ZonemdOnFailureRefuse
	case ZonemdOnFailureRefuse, ZonemdOnFailureWarn:
	default:
		return zonemdSettings{}, fmt.Errorf("on-verify-failure %q is not one of %q or %q",
			zc.OnVerifyFailure, ZonemdOnFailureRefuse, ZonemdOnFailureWarn)
	}

	// wire-cache-max-bytes takes any value: 0 is the default, negative
	// disables, and a positive figure too small to hold one owner's records
	// simply caches nothing -- which is a legitimate way to say "off" and not
	// worth a separate error for.

	if len(zc.Algorithms) == 0 {
		out.Algorithms = []uint8{ZonemdAlgSHA384}
		return out, nil
	}
	seen := map[uint8]bool{}
	for _, alg := range zc.Algorithms {
		switch alg {
		case ZonemdAlgSHA384, ZonemdAlgSHA512:
		default:
			return zonemdSettings{}, fmt.Errorf("hash algorithm %d is not implemented"+
				" (%d=SHA-384, %d=SHA-512)", alg, ZonemdAlgSHA384, ZonemdAlgSHA512)
		}
		if seen[alg] {
			return zonemdSettings{}, fmt.Errorf("hash algorithm %d (%s) is listed twice",
				alg, zonemdAlgName(alg))
		}
		seen[alg] = true
		out.Algorithms = append(out.Algorithms, alg)
	}
	return out, nil
}

// zonemdSettingsDiffer reports whether two resolved configurations would
// publish a different apex ZONEMD RRset.
func zonemdSettingsDiffer(onA bool, schemeA uint8, algsA []uint8, onB bool, schemeB uint8, algsB []uint8) bool {
	if onA != onB {
		return true
	}
	if !onA {
		return false // both off: nothing to publish either way
	}
	if schemeA != schemeB || len(algsA) != len(algsB) {
		return true
	}
	for i := range algsA {
		if algsA[i] != algsB[i] {
			return true
		}
	}
	return false
}

// filterManagedZonemdActions removes attempts to write the apex ZONEMD RRset
// of a zone that maintains its own.
//
// While publish-zonemd is on, that RRset is derived: every publish recomputes
// it from the zone's contents. An update that wrote one would be overwritten
// in the same breath, so accepting it and discarding the result would report
// success for a change that never happened -- the silent no-op DELNAME used to
// be, and the reason the update path now says no out loud.
//
// A REPLAY is filtered rather than refused. The journal can hold a ZONEMD
// written while the option was off, or before it existed, and failing the
// whole replay over one record the server is about to recompute anyway would
// cost the operator every other change in it.
func (zd *ZoneData) filterManagedZonemdActions(actions []dns.RR, replay bool) ([]dns.RR, error) {
	if !zd.zoneManagesZonemd() {
		return actions, nil
	}
	dropped := 0
	out := make([]dns.RR, 0, len(actions))
	for _, rr := range actions {
		if rr != nil {
			hdr := rr.Header()
			if hdr.Rrtype == dns.TypeZONEMD && core.EqualNames(hdr.Name, zd.ZoneName) {
				if !replay {
					return nil, fmt.Errorf("zone %s: the apex ZONEMD RRset is maintained"+
						" by the server while the publish-zonemd option is set, and cannot"+
						" be changed by an update", zd.ZoneName)
				}
				dropped++
				continue
			}
		}
		out = append(out, rr)
	}
	if dropped == 0 {
		return actions, nil
	}
	lg.Debug("replay: skipped journalled apex ZONEMD records; the server recomputes them",
		"zone", zd.ZoneName, "dropped", dropped)
	return out, nil
}
