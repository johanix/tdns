/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"

	"github.com/miekg/dns"
)

// DSIntent is what a zone's own key material says its parent's DS RRset should
// contain -- together with whether that is an answer at all.
//
// The second half is the point. An empty DS set is ambiguous unless something
// says which kind of empty it is: "this zone is not signed, remove the DS" and
// "I have no opinion about DS" are opposite instructions that look identical as
// a nil slice. Deriving one from the other has gone wrong in this codebase
// before, so the two travel together and callers must read Known before Set.
type DSIntent struct {
	// Set is the DS RRset the parent should hold. Meaningful only when Known.
	Set []dns.RR
	// Known reports whether Set is an answer. When false the caller must leave
	// the parent's DS RRset alone; it is not a claim that the parent holds
	// nothing.
	Known bool
}

// dsBelongsAtParent reports whether a key in the given keystore state should
// have its DS published at the parent right now.
//
// A predicate rather than a list of state names, because the question is about
// a key, not about a label. Under the multi-DS rollover the engine implements,
// a KSK acquires its DS at the parent BEFORE its DNSKEY is published:
//
//	created -> ds-published -> published -> standby -> active
//
// so every state from ds-published onward has, or should have, a DS. created
// has not had one placed yet, and retired and removed are on their way out.
//
// mpdist is a multi-provider zone's own key, served while it is distributed to
// the other providers and before its owner promotes it to published. Its DS does
// not belong at the parent until then.
//
// foreign (another provider's key) and mpremove (tdns-mp's state for a key on
// its way out of a multi-provider zone) are not classified here. tdns does not
// act on either -- a foreign key's DS is not this zone's decision, and mpremove
// is tdns-mp's to manage -- so DSIntentForZone declines for a zone holding one.
//
// Written this way so that a state added later has to be classified explicitly
// rather than silently defaulting to "no DS", which would express itself as a
// DS deletion.
func dsBelongsAtParent(state string) (belongs, recognised bool) {
	switch state {
	case DnskeyStateDsPublished, DnskeyStatePublished, DnskeyStateStandby, DnskeyStateActive:
		return true, true
	case DnskeyStateCreated, DnskeyStateMpdist, DnskeyStateRetired, DnskeyStateRemoved:
		return false, true
	default:
		return false, false
	}
}

const dsIntentKeysSql = `
SELECT state, keyrr
FROM DnssecKeyStore
WHERE zonename = ? AND (CAST(flags AS INTEGER) & ?) != 0`

// DSIntentForZone reads the zone's own KSKs and reports what DS the parent
// should hold.
//
// This replaces deriving the DS set from the published DNSKEY RRset. That
// derivation cannot be correct for a zone that rolls its KSK: a multi-DS
// rollover places the new DS at the parent before the matching DNSKEY is
// published, so a set derived from published keys is missing exactly the record
// the rollover just added, and reports it for deletion. The keystore knows the
// difference because the rollover is its own state machine.
//
// Known is false when the keystore holds no SEP key for the zone at all. That
// is not "this zone is unsigned" -- it is "tdns does not manage this zone's
// keys", which is the case for a zone signed elsewhere and merely served here.
// Withdrawing the DS of such a zone would break it, so the absence of rows
// means the DS is not ours to have an opinion about.
//
// Known is also false when the zone holds a KSK tdns does not act on: another
// provider's key (state foreign), whose DS is not this zone's decision, or a
// key tdns-mp is removing from a multi-provider zone (state mpremove). Every
// consumer of the intent acts on the parent's whole DS set: replace mode
// rewrites it, and delta mode removes whatever the set lacks. No set tdns could
// state would leave such a key's DS alone; declining does.
//
// Known is true with an empty Set when tdns does hold keys for the zone and
// none of them should have a DS -- a zone that has been un-signed. That is a
// real instruction to withdraw, and the distinction from the cases above is the
// whole reason Known exists.
//
// An mpdist key does not make that answer. It gets no DS of its own, but it is
// served: a zone whose only DS-less keys include one is signed, with a key on
// its way to promotion, not un-signed. If nothing else gives the set a member,
// the intent is unknown rather than an instruction to withdraw the parent's DS.
func DSIntentForZone(kdb *KeyDB, zonename string, digest uint8) (DSIntent, error) {
	var out DSIntent
	if kdb == nil {
		return out, nil
	}
	zonename = dns.Fqdn(zonename)

	rows, err := kdb.Query(dsIntentKeysSql, zonename, int(dns.SEP))
	if err != nil {
		return out, fmt.Errorf("DSIntentForZone: query keystore for %s: %w", zonename, err)
	}
	defer rows.Close()

	seen, sawMpdist := false, false
	for rows.Next() {
		var state, keyrr string
		if err := rows.Scan(&state, &keyrr); err != nil {
			return DSIntent{}, fmt.Errorf("DSIntentForZone: scan key row for %s: %w", zonename, err)
		}
		seen = true
		if state == DnskeyStateMpdist {
			sawMpdist = true
		}

		if state == DnskeyStateForeign || state == DnskeyStateMpremove {
			lgDns.Debug("DSIntentForZone: the zone holds a KSK tdns does not act on; declining to state a DS intent",
				"zone", zonename, "state", state)
			return DSIntent{}, nil
		}
		belongs, recognised := dsBelongsAtParent(state)
		if !recognised {
			// A state this code does not know about makes the whole answer
			// unsafe, not merely incomplete. Excluding the key from Set while
			// still reporting Known would present an empty or short set as
			// authoritative, and replace mode would delete DS records on the
			// strength of a state nobody has classified yet. Refusing to have
			// an opinion is the only outcome that cannot turn a schema addition
			// into a DS removal.
			lgDns.Warn("DSIntentForZone: unrecognised DNSKEY state; declining to state a DS intent for this zone",
				"zone", zonename, "state", state)
			return DSIntent{}, nil
		}
		if !belongs {
			continue
		}
		rr, perr := dns.NewRR(keyrr)
		if perr != nil {
			return DSIntent{}, fmt.Errorf("DSIntentForZone: parse DNSKEY for %s: %w", zonename, perr)
		}
		dk, ok := rr.(*dns.DNSKEY)
		if !ok {
			return DSIntent{}, fmt.Errorf("DSIntentForZone: %s: keystore row is a %T, not a DNSKEY", zonename, rr)
		}
		if ds := dk.ToDS(digest); ds != nil {
			out.Set = append(out.Set, ds)
		}
	}
	if err := rows.Err(); err != nil {
		return DSIntent{}, fmt.Errorf("DSIntentForZone: iterate key rows for %s: %w", zonename, err)
	}

	if len(out.Set) == 0 && sawMpdist {
		lgDns.Debug("DSIntentForZone: no key warrants a DS but an mpdist key is served; declining to state a DS intent",
			"zone", zonename)
		return DSIntent{}, nil
	}

	out.Known = seen
	return out, nil
}
