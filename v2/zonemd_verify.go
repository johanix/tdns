/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Verifying ZONEMD (RFC 8976).
//
// One function answers the question for every caller that asks it: the gate on
// a secondary's inbound zone, `tdns-cli zone zonemd verify` against a live
// zone, and `dog` against somebody else's. They differ only in where the
// records come from.
//
// The distinction that matters throughout is between a digest that FAILS and
// one that cannot be CHECKED. A zone whose ZONEMD uses a scheme or hash this
// build does not implement is not a zone in trouble -- RFC 8976 reserves
// codepoints precisely so a publisher can say "this is not for you" -- and
// treating unsupported as invalid would make every future algorithm an outage.

// ZonemdVerdict is the outcome of verifying a zone's apex ZONEMD RRset.
type ZonemdVerdict int

const (
	// ZonemdAbsent: the apex has no ZONEMD. Not a failure; most zones do not
	// publish one.
	ZonemdAbsent ZonemdVerdict = iota
	// ZonemdValid: every ZONEMD this build can check was checked, and all of
	// them describe the zone.
	ZonemdValid
	// ZonemdInvalid: a ZONEMD this build can check does not describe the zone.
	ZonemdInvalid
	// ZonemdUnsupported: the zone publishes a ZONEMD, but not with any
	// (scheme, algorithm) pair this build implements. Nothing was checked and
	// nothing is known to be wrong.
	ZonemdUnsupported
)

func (v ZonemdVerdict) String() string {
	switch v {
	case ZonemdAbsent:
		return "absent"
	case ZonemdValid:
		return "valid"
	case ZonemdInvalid:
		return "invalid"
	default:
		return "unsupported"
	}
}

// ZonemdCheck is what came of one apex ZONEMD RR.
type ZonemdCheck struct {
	Scheme        uint8  `json:"scheme"`
	Algorithm     uint8  `json:"algorithm"`
	AlgorithmName string `json:"algorithm_name"`
	Serial        uint32 `json:"serial"`
	Published     string `json:"published"`
	Computed      string `json:"computed,omitempty"`
	Supported     bool   `json:"supported"`
	SerialMatch   bool   `json:"serial_match"`
	DigestMatch   bool   `json:"digest_match"`
	Reason        string `json:"reason,omitempty"`
}

// OK reports whether this ZONEMD was checked and describes the zone.
func (c ZonemdCheck) OK() bool {
	return c.Supported && c.SerialMatch && c.DigestMatch
}

// ZonemdReport is the verdict plus everything needed to explain it.
type ZonemdReport struct {
	Zone      string        `json:"zone"`
	Verdict   string        `json:"verdict"`
	SoaSerial uint32        `json:"soa_serial"`
	Checks    []ZonemdCheck `json:"checks,omitempty"`
	// Duration is how long recomputing the digests took, which for a large
	// zone is the number an operator wants before turning verification on for
	// a whole fleet.
	Duration time.Duration `json:"duration"`
	// IgnoredSerial records that the digests were computed against the serial
	// each ZONEMD NAMES rather than the one the SOA carries. See
	// VerifyZonemdOpts.IgnoreSerial.
	IgnoredSerial bool `json:"ignored_serial,omitempty"`
}

func (r *ZonemdReport) verdict() ZonemdVerdict {
	switch r.Verdict {
	case "valid":
		return ZonemdValid
	case "invalid":
		return ZonemdInvalid
	case "unsupported":
		return ZonemdUnsupported
	default:
		return ZonemdAbsent
	}
}

// Summary renders the report as one line per ZONEMD, for a CLI or a log.
func (r *ZonemdReport) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: ZONEMD %s (SOA serial %d, %s)",
		r.Zone, r.Verdict, r.SoaSerial, r.Duration.Round(time.Millisecond))
	if r.IgnoredSerial {
		b.WriteString(" [serial ignored]")
	}
	for _, c := range r.Checks {
		fmt.Fprintf(&b, "\n   scheme %d %s serial %d: ", c.Scheme, c.AlgorithmName, c.Serial)
		switch {
		case c.OK():
			b.WriteString("OK")
		default:
			b.WriteString(c.Reason)
		}
	}
	return b.String()
}

// VerifyZonemdOpts tunes what verification means for one caller.
type VerifyZonemdOpts struct {
	// IgnoreSerial computes each digest against the serial the ZONEMD RR
	// names, substituted into the SOA, rather than the serial the SOA carries.
	//
	// It answers a different question from verification: "was this digest
	// correct for the zone at the serial it claims?" -- which is what an
	// operator wants when a pipeline digests a zone and then bumps its serial,
	// and is how labstuff's `axfr-cli zone verify --ignore-serial` behaves.
	//
	// It is NOT a laxer verification. A zone that only passes with this set is
	// a zone whose published digest does not describe what it is serving, and
	// no RFC 8976 verifier will accept it.
	IgnoreSerial bool
}

// VerifyZonemd checks the apex ZONEMD RRset of the zone described by rrs.
//
// rrs is the whole zone as flat records -- the RR list a parse, an AXFR or a
// snapshot flattens to. The apex SOA must be among them: RFC 8976 binds the
// digest to a serial, and a zone with no SOA is not a zone.
func VerifyZonemd(apex string, rrs []dns.RR, opts VerifyZonemdOpts) (*ZonemdReport, error) {
	apex = dns.CanonicalName(apex)
	report := &ZonemdReport{Zone: apex, Verdict: ZonemdAbsent.String()}

	var soa *dns.SOA
	var zonemds []*dns.ZONEMD
	for _, rr := range rrs {
		if rr == nil || dns.CanonicalName(rr.Header().Name) != apex {
			continue
		}
		switch x := rr.(type) {
		case *dns.SOA:
			if soa == nil {
				soa = x
			}
		case *dns.ZONEMD:
			zonemds = append(zonemds, x)
		}
	}
	if soa == nil {
		return nil, fmt.Errorf("zone %s: no apex SOA, so there is no serial to bind a digest to", apex)
	}
	report.SoaSerial = soa.Serial
	if len(zonemds) == 0 {
		return report, nil
	}

	// A duplicate (scheme, algorithm) pair is a malformed RRset: the pair is
	// what identifies which digest a verifier is looking at, so two RRs
	// sharing one leave a verifier unable to say which it checked.
	seen := map[[2]uint8]bool{}

	started := time.Now()
	// One digest per (scheme, algorithm, effective serial), because two ZONEMD
	// RRs can name the same pair of parameters and, under IgnoreSerial,
	// different serials.
	type digestKey struct {
		scheme, alg uint8
		serial      uint32
	}
	cache := map[digestKey]string{}

	anyChecked, anyFailed := false, false
	for _, z := range zonemds {
		c := ZonemdCheck{
			Scheme:        z.Scheme,
			Algorithm:     z.Hash,
			AlgorithmName: zonemdAlgName(z.Hash),
			Serial:        z.Serial,
			Published:     strings.ToLower(z.Digest),
			SerialMatch:   z.Serial == soa.Serial,
		}

		pair := [2]uint8{z.Scheme, z.Hash}
		if seen[pair] {
			c.Reason = fmt.Sprintf("a second ZONEMD with scheme %d and %s is present;"+
				" the pair must be unique within the RRset", z.Scheme, c.AlgorithmName)
			anyFailed = true
			report.Checks = append(report.Checks, c)
			continue
		}
		seen[pair] = true

		// Unsupported is not invalid. RFC 8976 §5 reserves scheme 0 and hash
		// algorithm 0, and a publisher uses a reserved or unimplemented
		// codepoint to say that this digest is not one we can act on -- which
		// is a statement about us, not about the zone.
		if z.Scheme != ZonemdSchemeSimple {
			c.Reason = fmt.Sprintf("scheme %d is not implemented", z.Scheme)
			report.Checks = append(report.Checks, c)
			continue
		}
		if _, herr := zonemdHasher(z.Hash); herr != nil {
			c.Reason = fmt.Sprintf("hash algorithm %d is not implemented", z.Hash)
			report.Checks = append(report.Checks, c)
			continue
		}
		c.Supported = true

		effSerial := soa.Serial
		if !c.SerialMatch {
			if !opts.IgnoreSerial {
				c.Reason = fmt.Sprintf("the ZONEMD names serial %d but the SOA carries %d,"+
					" so the digest does not describe this zone", z.Serial, soa.Serial)
				anyChecked, anyFailed = true, true
				report.Checks = append(report.Checks, c)
				continue
			}
			effSerial = z.Serial
			report.IgnoredSerial = true
		}

		key := digestKey{z.Scheme, z.Hash, effSerial}
		computed, ok := cache[key]
		if !ok {
			var derr error
			computed, derr = zoneDigestAtSerial(apex, rrs, soa, effSerial, z.Scheme, z.Hash)
			if derr != nil {
				c.Reason = derr.Error()
				anyChecked, anyFailed = true, true
				report.Checks = append(report.Checks, c)
				continue
			}
			cache[key] = computed
		}
		c.Computed = computed
		c.DigestMatch = strings.EqualFold(computed, z.Digest)
		anyChecked = true
		if !c.DigestMatch {
			c.Reason = "the digest does not describe this zone"
			anyFailed = true
		}
		// Under IgnoreSerial a digest that matches still did not describe the
		// zone as served; say so rather than reporting a bare OK.
		if c.DigestMatch && !c.SerialMatch {
			c.Reason = fmt.Sprintf("the digest is correct for serial %d, but the zone"+
				" is serving serial %d", z.Serial, soa.Serial)
		}
		report.Checks = append(report.Checks, c)
	}
	report.Duration = time.Since(started)

	switch {
	case anyFailed:
		report.Verdict = ZonemdInvalid.String()
	case anyChecked:
		report.Verdict = ZonemdValid.String()
	default:
		report.Verdict = ZonemdUnsupported.String()
	}
	return report, nil
}

// zoneDigestAtSerial computes the digest of rrs with the apex SOA's serial set
// to serial.
//
// When the serial already matches it is ZoneDigest unchanged. It differs only
// under IgnoreSerial, and then it rebuilds the SOA rather than mutating it: the
// caller's records may be a published snapshot that queries are being answered
// from right now, and rewriting a serial in place would tear it.
func zoneDigestAtSerial(apex string, rrs []dns.RR, soa *dns.SOA, serial uint32,
	scheme, alg uint8) (string, error) {

	if soa.Serial == serial {
		return ZoneDigestHex(apex, rrs, scheme, alg)
	}
	adjusted := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		if rr == soa {
			c := dns.Copy(soa).(*dns.SOA)
			c.Serial = serial
			adjusted = append(adjusted, c)
			continue
		}
		adjusted = append(adjusted, rr)
	}
	return ZoneDigestHex(apex, adjusted, scheme, alg)
}

// VerifyZonemdOfPublished verifies the zone as it is being served.
func (zd *ZoneData) VerifyZonemdOfPublished(opts VerifyZonemdOpts) (*ZonemdReport, error) {
	if zd == nil {
		return nil, fmt.Errorf("no zone")
	}
	snap := zd.publishedSnapshot()
	if snap == nil {
		return nil, fmt.Errorf("zone %s: nothing published to verify", zd.ZoneName)
	}
	return VerifyZonemd(zd.ZoneName, zoneRRsFromSnapshot(snap), opts)
}

// verifyZonemdOfWorkingData verifies a zone that has been parsed or
// transferred but not yet published -- the scratch ZoneData the refresh path
// builds, which is the only moment at which an incoming zone can still be
// refused.
func (zd *ZoneData) verifyZonemdOfWorkingData(opts VerifyZonemdOpts) (*ZonemdReport, error) {
	if zd == nil || zd.Data == nil {
		return nil, fmt.Errorf("no zone data")
	}
	var rrs []dns.RR
	for tuple := range zd.Data.Iter() {
		od := tuple.Val
		rrs = append(rrs, ownerRRsForDigest(&od)...)
	}
	return VerifyZonemd(zd.ZoneName, rrs, opts)
}

// gateIncomingZonemd is the `verify-zonemd` check, run against a zone that has
// been parsed or transferred but not yet adopted.
//
// The placement is the whole feature. It runs on the scratch ZoneData, before
// the pre-refresh callbacks and before the hard flip, because that is the last
// moment at which the answer can still change what the server does. Verifying
// after adoption would produce a log line about a zone already being served.
//
// Returns an error when the zone must be refused; the caller restores the
// previous status and keeps serving what it had. A refusal is not the end of
// the matter: the refresh engine turns the error into a RefreshError and tries
// again on the next interval, so a primary that fixes its digest is picked up
// without intervention.
//
// zd is the LIVE zone (whose options and failure mode apply); incoming is the
// scratch zone being considered.
func (zd *ZoneData) gateIncomingZonemd(incoming *ZoneData, source string) error {
	if zd == nil || incoming == nil || !zd.Options[OptVerifyZonemd] {
		return nil
	}

	report, err := incoming.verifyZonemdOfWorkingData(VerifyZonemdOpts{})
	if err != nil {
		// The check could not be RUN -- a zone with no apex SOA, which the
		// parse and transfer paths reject on their own account anyway. Not a
		// verification failure, and not something to refuse a zone over twice.
		lg.Warn("verify-zonemd: the check could not be run",
			"zone", zd.ZoneName, "source", source, "error", err)
		return nil
	}

	switch report.verdict() {
	case ZonemdValid:
		lg.Info("verify-zonemd: the incoming zone's digest describes it",
			"zone", zd.ZoneName, "source", source, "serial", report.SoaSerial,
			"took", report.Duration.Round(time.Millisecond))
		return nil

	case ZonemdAbsent:
		// A zone with no ZONEMD is not a zone that failed verification. The
		// option says "check the digest if there is one"; making it mean "and
		// refuse a zone that publishes none" would turn it into a policy about
		// the upstream's configuration, which is a different setting and one
		// nobody asked for here.
		lg.Debug("verify-zonemd: the incoming zone publishes no ZONEMD; nothing to check",
			"zone", zd.ZoneName, "source", source, "serial", report.SoaSerial)
		return nil

	case ZonemdUnsupported:
		// Reserved and unimplemented codepoints exist so a publisher can say
		// "not for you". Refusing here would make every algorithm this build
		// does not yet implement an outage for every zone that adopts it.
		lg.Warn("verify-zonemd: the incoming zone's ZONEMD uses no scheme or algorithm"+
			" this build implements, so it could not be checked; adopting the zone",
			"zone", zd.ZoneName, "source", source, "serial", report.SoaSerial,
			"detail", report.Summary())
		return nil
	}

	// Invalid.
	if zd.zonemdVerifyFailureMode() == ZonemdOnFailureWarn {
		lg.Error("verify-zonemd: the incoming zone's ZONEMD does not describe it;"+
			" adopting it anyway because on-verify-failure is \"warn\"",
			"zone", zd.ZoneName, "source", source, "serial", report.SoaSerial,
			"detail", report.Summary())
		return nil
	}
	lg.Error("verify-zonemd: REFUSING the incoming zone, whose ZONEMD does not describe it;"+
		" the previously loaded content is still being served",
		"zone", zd.ZoneName, "source", source, "serial", report.SoaSerial,
		"detail", report.Summary())
	return fmt.Errorf("zone %s: refusing the zone received from %s: its ZONEMD does not"+
		" describe it (serial %d); set zonemd.on-verify-failure: warn to adopt it anyway",
		zd.ZoneName, source, report.SoaSerial)
}

// zonemdVerifyFailureMode returns the resolved on-verify-failure setting,
// defaulting to refuse for a zone whose config never set one.
func (zd *ZoneData) zonemdVerifyFailureMode() string {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	if zd.zonemdOnVerifyFailure == "" {
		return ZonemdOnFailureRefuse
	}
	return zd.zonemdOnVerifyFailure
}

// ZonemdStatusReport builds the API/CLI view of a zone's ZONEMD.
//
// verify decides whether the digests are recomputed. Without it this reads the
// published RRset and reports what it says, which costs nothing; with it the
// zone is digested, which for a large zone is the expensive part of the
// feature and is why it is a separate verb.
func (zd *ZoneData) ZonemdStatusReport(verify bool, opts VerifyZonemdOpts) (*ZonemdStatus, error) {
	if zd == nil {
		return nil, fmt.Errorf("no zone")
	}
	st := &ZonemdStatus{
		Zone:       zd.ZoneName,
		Publishing: zd.Options[OptPublishZonemd],
		Verifying:  zd.Options[OptVerifyZonemd],
	}
	zd.mu.Lock()
	st.Scheme, st.Algorithms = zd.zonemdSchemeLocked(), zd.zonemdAlgsLocked()
	st.OnVerifyFailure = zd.zonemdOnVerifyFailure
	// Reported for a zone that has actually digested something. A zone that
	// publishes no ZONEMD has no cache and saying "0 of 0" about it would be
	// noise dressed as information.
	if zd.zonemdCacheStats.Owners > 0 {
		cs := zd.zonemdCacheStats
		st.Cache = &cs
	}
	zd.mu.Unlock()
	if st.OnVerifyFailure == "" {
		st.OnVerifyFailure = ZonemdOnFailureRefuse
	}

	snap := zd.publishedSnapshot()
	if snap == nil {
		return nil, fmt.Errorf("zone %s: nothing published", zd.ZoneName)
	}
	if verify {
		report, err := VerifyZonemd(zd.ZoneName, zoneRRsFromSnapshot(snap), opts)
		if err != nil {
			return nil, err
		}
		st.Report = report
		return st, nil
	}

	// Status without a recomputation: describe what is published and say
	// nothing about whether it is right. Reporting "valid" here on the
	// strength of not having looked would be the worst answer available.
	report := &ZonemdReport{Zone: zd.ZoneName, SoaSerial: snap.Serial,
		Verdict: ZonemdAbsent.String()}
	apex := getOwnerFrom(snap, zd.ZoneName)
	if apex != nil {
		for _, rr := range apex.RRtypes.GetOnlyRRSet(dns.TypeZONEMD).RRs {
			z, ok := rr.(*dns.ZONEMD)
			if !ok {
				continue
			}
			report.Verdict = "" // "published, not checked"
			report.Checks = append(report.Checks, ZonemdCheck{
				Scheme:        z.Scheme,
				Algorithm:     z.Hash,
				AlgorithmName: zonemdAlgName(z.Hash),
				Serial:        z.Serial,
				Published:     strings.ToLower(z.Digest),
				SerialMatch:   z.Serial == snap.Serial,
			})
		}
	}
	st.Report = report
	return st, nil
}
