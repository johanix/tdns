/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// The five zone-content statements. One frontend, two transports: the same
// spec is turned into RFC 2136 update-section records here, and those records
// are either put on the wire (--via ddns) or carried in an UpdateRequest to
// the ZoneUpdater (--via api). Keeping the translation in one place is what
// makes the two channels behave identically -- the alternative, encoding the
// verbs separately per transport, is how they drift.
const (
	VerbAddRR        = "addrr"
	VerbDelRR        = "delrr"
	VerbDelRRset     = "delrrset"
	VerbDelName      = "delname"
	VerbReplaceRRset = "replacerrset"
)

// ZoneUpdateVerbs lists the statements in the order they are documented.
var ZoneUpdateVerbs = []string{VerbAddRR, VerbDelRR, VerbDelRRset, VerbDelName, VerbReplaceRRset}

// ZoneUpdateSpec is one statement. RRs carry presentation-form records for the
// verbs that take them; Name and Rrtype carry the owner/type for the verbs that
// address an RRset or a name rather than specific records.
type ZoneUpdateSpec struct {
	Verb   string
	RRs    []string // addrr, delrr, replacerrset
	Name   string   // delrrset, delname
	Rrtype string   // delrrset
}

// BuildZoneUpdateActions turns a statement into the update-section records for
// zone. The result is exactly what goes into UpdateRequest.Actions, and equally
// what goes into the Ns section of a DNS UPDATE message.
//
// Every owner name is checked to be in bailiwick: a statement that addresses a
// name outside the zone is a client error, not something to hand to the applier
// and hope it declines.
func BuildZoneUpdateActions(zone string, spec ZoneUpdateSpec) ([]dns.RR, error) {
	zone = dns.Fqdn(strings.TrimSpace(zone))
	if zone == "." || zone == "" {
		return nil, fmt.Errorf("no zone given")
	}

	inBailiwick := func(owner string) error {
		if !dns.IsSubDomain(zone, owner) {
			return fmt.Errorf("owner %q is not in zone %s", owner, zone)
		}
		return nil
	}

	switch strings.ToLower(strings.TrimSpace(spec.Verb)) {

	case VerbAddRR, VerbDelRR:
		rrs, err := parseSpecRRs(spec.RRs)
		if err != nil {
			return nil, err
		}
		if len(rrs) == 0 {
			return nil, fmt.Errorf("%s requires at least one RR", spec.Verb)
		}
		class := uint16(dns.ClassINET)
		if strings.EqualFold(spec.Verb, VerbDelRR) {
			// RFC 2136 §2.5.4: delete an individual RR by giving it in
			// CLASS=NONE. The TTL is not part of RR identity and is ignored.
			class = dns.ClassNONE
		}
		var actions []dns.RR
		for _, rr := range rrs {
			if err := inBailiwick(rr.Header().Name); err != nil {
				return nil, err
			}
			rr.Header().Class = class
			if class == dns.ClassNONE {
				rr.Header().Ttl = 0
			}
			actions = append(actions, rr)
		}
		return actions, nil

	case VerbDelRRset:
		owner, err := specOwner(spec.Name)
		if err != nil {
			return nil, err
		}
		if err := inBailiwick(owner); err != nil {
			return nil, err
		}
		rrtype, err := specRrtype(spec.Rrtype)
		if err != nil {
			return nil, err
		}
		// The apex SOA and NS RRsets are what make the zone a zone. Deleting
		// either leaves something that cannot be served, and the applier's
		// apex guard would then refuse the entire publish -- taking any other
		// change in the same update down with it. Refuse here, where the error
		// can name the problem. (delname protects these too, plus the DNSSEC
		// and signalling RRsets, because it is a wholesale statement.)
		if strings.EqualFold(owner, zone) && (rrtype == dns.TypeSOA || rrtype == dns.TypeNS) {
			return nil, fmt.Errorf(
				"refusing to delete the apex %s RRset of %s: the zone cannot be served without it",
				dns.TypeToString[rrtype], zone)
		}
		// RFC 2136 §2.5.2: CLASS=ANY, the type to delete, empty RDATA.
		return []dns.RR{&dns.ANY{Hdr: dns.RR_Header{
			Name: owner, Rrtype: rrtype, Class: dns.ClassANY, Ttl: 0,
		}}}, nil

	case VerbDelName:
		owner, err := specOwner(spec.Name)
		if err != nil {
			return nil, err
		}
		if err := inBailiwick(owner); err != nil {
			return nil, err
		}
		// RFC 2136 §2.5.3: CLASS=ANY, TYPE=ANY. At the apex the applier
		// retains SOA and NS; see ApplyZoneUpdateToZoneData.
		return []dns.RR{&dns.ANY{Hdr: dns.RR_Header{
			Name: owner, Rrtype: dns.TypeANY, Class: dns.ClassANY, Ttl: 0,
		}}}, nil

	case VerbReplaceRRset:
		rrs, err := parseSpecRRs(spec.RRs)
		if err != nil {
			return nil, err
		}
		if len(rrs) == 0 {
			// Deliberately an error rather than silently meaning DELRRSET.
			// The owner and type are inferred from the supplied records, so
			// with none supplied there is nothing to infer and the operator
			// cannot have meant anything specific. delrrset says it plainly.
			return nil, fmt.Errorf("replacerrset requires at least one RR (use delrrset to remove an RRset)")
		}

		// The RRset to replace is inferred from the records, so they must all
		// describe the same one. Mixed input is a mistake worth refusing: the
		// alternative is silently replacing whichever RRset happened to come
		// first and dropping the rest into it.
		owner := rrs[0].Header().Name
		rrtype := rrs[0].Header().Rrtype
		for _, rr := range rrs[1:] {
			if !strings.EqualFold(rr.Header().Name, owner) {
				return nil, fmt.Errorf(
					"replacerrset: all RRs must share one owner; got %q and %q",
					owner, rr.Header().Name)
			}
			if rr.Header().Rrtype != rrtype {
				return nil, fmt.Errorf(
					"replacerrset: all RRs must share one type; got %s and %s",
					dns.TypeToString[rrtype], dns.TypeToString[rr.Header().Rrtype])
			}
		}
		if err := inBailiwick(owner); err != nil {
			return nil, err
		}

		// The apex SOA is not replaceable through this channel: tdns owns the
		// serial, and a client-supplied SOA would fight the serial machinery
		// on every update. Refused here so it fails at the client with a
		// reason, rather than in the applier -- which drops the delete half of
		// the replacement and would silently leave the old SOA in place.
		//
		// The apex NS IS replaceable, and must be: moving to a new set of
		// nameservers is exactly what an operator uses this for. The applier
		// recognises a replacement and permits that delete (see
		// updateReplacesRRset).
		if strings.EqualFold(owner, zone) && rrtype == dns.TypeSOA {
			return nil, fmt.Errorf(
				"refusing to replace the apex SOA of %s: the serial is maintained by the server", zone)
		}

		// Delete the RRset, then add the replacements, in ONE action list.
		// The applier walks the list in a single pass under one zd.mu and
		// publishes once at the end, so the empty intermediate RRset is never
		// visible to a reader and never reaches a secondary as its own serial.
		// This is why REPLACE needs no dedicated applier support.
		actions := []dns.RR{&dns.ANY{Hdr: dns.RR_Header{
			Name: owner, Rrtype: rrtype, Class: dns.ClassANY, Ttl: 0,
		}}}
		for _, rr := range rrs {
			rr.Header().Class = dns.ClassINET
			actions = append(actions, rr)
		}
		return actions, nil

	default:
		return nil, fmt.Errorf("unknown zone update verb %q (want one of %s)",
			spec.Verb, strings.Join(ZoneUpdateVerbs, ", "))
	}
}

func parseSpecRRs(in []string) ([]dns.RR, error) {
	var out []dns.RR
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		rr, err := dns.NewRR(s)
		if err != nil {
			return nil, fmt.Errorf("cannot parse %q: %v", s, err)
		}
		if rr == nil {
			// dns.NewRR returns (nil, nil) for input that is only a comment
			// or blank after parsing -- not an RR, and not an error either.
			return nil, fmt.Errorf("%q is not a resource record", s)
		}
		out = append(out, rr)
	}
	return out, nil
}

func specOwner(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("no owner name given")
	}
	return dns.Fqdn(name), nil
}

func specRrtype(s string) (uint16, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	if s == "" {
		return 0, fmt.Errorf("no rrtype given")
	}
	if s == "ANY" {
		// Would be DELNAME by another name, but via a path that does not carry
		// its apex protections. Refuse and point at the verb that does.
		return 0, fmt.Errorf("delrrset does not accept type ANY (use delname)")
	}
	rrtype, ok := dns.StringToType[s]
	if !ok {
		return 0, fmt.Errorf("unknown rrtype %q", s)
	}
	// Meta and query types never exist as RRsets in a zone, so a delete
	// targeting one can only ever be a mistake -- but dns.StringToType happily
	// resolves them, so without this the statement is built, queued and
	// silently does nothing. OPT is a pseudo-RR that lives in the additional
	// section; 128-255 covers TKEY, TSIG, IXFR, AXFR, MAILB and MAILA (ANY is
	// caught above with a more useful message).
	if rrtype == dns.TypeOPT || (rrtype >= 128 && rrtype <= 255) {
		return 0, fmt.Errorf("%q is a meta type and never exists as an RRset in a zone", s)
	}
	return rrtype, nil
}
