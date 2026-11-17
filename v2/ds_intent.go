/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"database/sql"
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

const dsIntentKeysSql = `
SELECT state, keyrr, ds
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
// The answer is the ds column of the zone's SEP rows (design §3.3, §3.4): the
// state machine that owns a zone writes ds at its transitions, and this reader
// never needs to know the zone's DS model or the names of an owner's states.
// Known is false as soon as one SEP row has ds unset: a row in a state an
// owner stages, whose ds the owner has not written, a row written before the
// column, a zone whose policy is not bound yet. Every consumer of the intent
// acts on the parent's whole DS set -- replace mode rewrites it, and delta
// mode removes whatever the set lacks -- so no set tdns could state would
// leave an undecided key's DS alone; declining does.
//
// Known is true with an empty Set when tdns does hold SEP keys for the zone
// and every one of them has ds=0 -- a zone that has been un-signed. That is a
// real instruction to withdraw, and the distinction from the cases above is
// the whole reason Known exists.
func DSIntentForZone(kdb *KeyDB, zonename string, digest uint8) (DSIntent, error) {
	// An owned zone's DS is its owner's answer (§4): the rows here are one
	// provider's view, the owner's covers every signing provider.
	if zd, owned := zoneOwnedByName(zonename); owned {
		in, err := currentKeyLifecycleOwner().DSIntent(zd, digest)
		if err != nil {
			return DSIntent{}, fmt.Errorf("DSIntentForZone: the owner of %s: %w", zonename, err)
		}
		return in, nil
	}
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
		var ds sql.NullInt64
		if err := rows.Scan(&state, &keyrr, &ds); err != nil {
			return DSIntent{}, fmt.Errorf("DSIntentForZone: scan key row for %s: %w", zonename, err)
		}
		seen = true

		// The ds column is the answer (design §3.3). A row whose ds is unset
		// is one nobody has decided: a row in an owner's state whose ds the
		// owner has not written yet, a row written before the column, a zone
		// whose policy has not bound yet. Excluding it while still reporting Known would present
		// a short set as authoritative, and replace mode would delete DS
		// records on the strength of a decision nobody made. Refusing to have
		// an opinion is the only outcome that cannot turn "unknown" into a DS
		// removal.
		if !ds.Valid {
			lgDns.Debug("DSIntentForZone: a KSK's ds is unset; declining to state a DS intent for this zone",
				"zone", zonename, "state", state)
			return DSIntent{}, nil
		}
		if ds.Int64 == 0 {
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
