/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// ApiZoneGetName answers "what does this zone publish at this name" over the
// management API.
//
// WHY IT EXISTS. A client that maintains records in a zone through this API has
// to be able to read them back, or it cannot tell "already correct" from "not
// there yet" -- and then it either republishes on every pass, which on a signed
// zone bumps the serial and re-signs forever, or it keeps a private copy of
// what it believes it wrote, which drifts from the zone the moment anyone
// touches it by hand.
//
// get-delegation answers the same shape of question for a delegated child, and
// deliberately routes through the DelegationBackend because delegation data may
// live somewhere other than the zone. This one is about ordinary names in the
// zone itself -- glue for out-of-bailiwick nameservers, service addresses,
// anything a client provisions -- so it reads the zone.
//
// READS THE PUBLISHED VIEW, not staged data. The question is what the server
// currently serves, which is what a client comparing against it means; an
// in-flight update is not yet an answer to that.
//
// RRSIGs and NSEC are deliberately absent. They are derived: the signer owns
// them, no client may author them, and returning them would invite a
// read-modify-write that tries. A client wanting to see signatures should query
// the zone over DNS, where they belong to the answer rather than to the
// inventory.
func (zd *ZoneData) ApiZoneGetName(zp ZonePost) (*ZoneNameReport, error) {
	if zd.ZoneStore != MapZone {
		// Naming the store rather than "unsupported": a SliceZone is a
		// perfectly good zone, it just cannot answer a question keyed by owner
		// name, and an operator seeing this needs to know which of the two
		// they have.
		return nil, fmt.Errorf("zone %s is a %s; get-name needs a map store",
			zd.ZoneName, ZoneStoreToString[zd.ZoneStore])
	}

	name := dns.Fqdn(strings.TrimSpace(zp.UpdateName))
	if name == "." || name == "" {
		return nil, fmt.Errorf("get-name: no name given (set updatename)")
	}
	if !dns.IsSubDomain(zd.ZoneName, name) {
		// Answering "nothing" for a name the zone could never hold reads as
		// "that name has no records", which is a different and wrong answer.
		return nil, fmt.Errorf("%s is not in zone %s", name, zd.ZoneName)
	}

	out := &ZoneNameReport{
		Zone:   zd.ZoneName,
		Name:   name,
		RRsets: map[string][]string{},
	}

	owner, err := zd.GetOwner(name)
	if err != nil {
		return nil, err
	}
	if owner == nil || owner.RRtypes == nil {
		// An empty report, not an error: "this zone publishes nothing at that
		// name" is a legitimate and useful answer, and is exactly what a
		// client provisioning the name for the first time expects to get.
		return out, nil
	}

	for _, rrtype := range owner.RRtypes.Keys() {
		if rrtype == dns.TypeRRSIG || rrtype == dns.TypeNSEC || rrtype == dns.TypeNSEC3 {
			continue // derived; see the doc comment
		}
		rrset, ok := owner.RRtypes.Get(rrtype)
		if !ok || len(rrset.RRs) == 0 {
			continue
		}
		strs := make([]string, 0, len(rrset.RRs))
		for _, rr := range rrset.RRs {
			if rr != nil {
				strs = append(strs, rr.String())
			}
		}
		if len(strs) == 0 {
			continue
		}
		// Sorted so two reads of unchanged data compare equal. A client
		// diffing against this must not see a difference that is only map
		// iteration order -- that is the republish-forever bug this command
		// exists to prevent.
		sort.Strings(strs)
		out.RRsets[rrTypeName(rrtype)] = strs
	}
	return out, nil
}

// rrTypeName renders an RR type the way presentation format does, falling back
// to TYPEnnn for types this build has no mnemonic for. Both halves matter: a
// client re-parsing these with dns.NewRR needs a spelling the parser accepts.
func rrTypeName(rrtype uint16) string {
	if name := dns.TypeToString[rrtype]; name != "" {
		return name
	}
	return fmt.Sprintf("TYPE%d", rrtype)
}
