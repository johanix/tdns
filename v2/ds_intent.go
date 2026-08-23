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
// Written this way so that a state added later has to be classified explicitly
// rather than silently defaulting to "no DS", which would express itself as a
// DS deletion.
func dsBelongsAtParent(state string) bool {
	switch state {
	case DnskeyStateDsPublished, DnskeyStatePublished, DnskeyStateStandby, DnskeyStateActive:
		return true
	case DnskeyStateCreated, DnskeyStateRetired, DnskeyStateRemoved:
		return false
	default:
		// An unrecognised state is not evidence that the key's DS should go.
		// Treating it as "no DS" would turn a schema addition into a removal.
		lgDns.Warn("dsBelongsAtParent: unrecognised DNSKEY state; not counting it toward the DS set",
			"state", state)
		return false
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
// Known is true with an empty Set when tdns does hold keys for the zone and
// none of them should have a DS -- a zone that has been un-signed. That is a
// real instruction to withdraw, and the distinction from the case above is the
// whole reason Known exists.
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

	seen := false
	for rows.Next() {
		var state, keyrr string
		if err := rows.Scan(&state, &keyrr); err != nil {
			return DSIntent{}, fmt.Errorf("DSIntentForZone: scan key row for %s: %w", zonename, err)
		}
		seen = true
		if !dsBelongsAtParent(state) {
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

	out.Known = seen
	return out, nil
}
