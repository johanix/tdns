/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * DBDelegationBackend stores child delegation data in the ChildDelegationData
 * SQLite table. Extracts and replaces the existing ApplyChildUpdateToDB logic.
 */
package tdns

import (
	"fmt"

	"github.com/miekg/dns"
)

type DBDelegationBackend struct {
	kdb *KeyDB
}

func (b *DBDelegationBackend) Name() string { return "db" }

func (b *DBDelegationBackend) ApplyChildUpdate(parentZone string, ur UpdateRequest) error {
	const (
		adddelsql   = `INSERT OR REPLACE INTO ChildDelegationData (parent, child, owner, rrtype, rr) VALUES (?, ?, ?, ?, ?)`
		delrrsql    = `DELETE FROM ChildDelegationData WHERE parent=? AND owner=? AND rrtype=? AND rr=?`
		delrrsetsql = `DELETE FROM ChildDelegationData WHERE parent=? AND owner=? AND rrtype=?`
	)

	tx, err := b.kdb.Begin("DBDelegationBackend.ApplyChildUpdate")
	if err != nil {
		return err
	}

	defer func() {
		if err == nil {
			err1 := tx.Commit()
			if err1 != nil {
				lg.Error("DBDelegationBackend: tx.Commit failed", "error", err1)
			}
		} else {
			lg.Error("DBDelegationBackend: rolling back", "error", err)
			err1 := tx.Rollback()
			if err1 != nil {
				lg.Error("DBDelegationBackend: tx.Rollback failed", "error", err1)
			}
		}
	}()

	for _, rr := range ur.Actions {
		class := rr.Header().Class
		owner := rr.Header().Name
		rrtype := rr.Header().Rrtype
		rrtypestr := dns.TypeToString[rrtype]

		// Determine child zone: the immediate child of the parent zone
		childZone := childZoneFromOwner(owner, parentZone)

		rrcopy := dns.Copy(rr)
		rrcopy.Header().Ttl = 0
		rrcopy.Header().Class = dns.ClassINET

		switch class {
		case dns.ClassNONE:
			lg.Debug("DBDelegationBackend: Remove RR", "owner", owner, "rrtype", rrtypestr)
			_, err = tx.Exec(delrrsql, parentZone, owner, rrtypestr, rrcopy.String())
			if err != nil {
				return fmt.Errorf("delete RR failed: %w", err)
			}

		case dns.ClassANY:
			lg.Debug("DBDelegationBackend: Remove RRset", "owner", owner, "rrtype", rrtypestr)
			_, err = tx.Exec(delrrsetsql, parentZone, owner, rrtypestr)
			if err != nil {
				return fmt.Errorf("delete RRset failed: %w", err)
			}

		case dns.ClassINET:
			lg.Debug("DBDelegationBackend: Add RR", "owner", owner, "rrtype", rrtypestr, "rr", rrcopy.String())
			_, err = tx.Exec(adddelsql, parentZone, childZone, owner, rrtypestr, rrcopy.String())
			if err != nil {
				return fmt.Errorf("add RR failed: %w", err)
			}

		default:
			lg.Warn("DBDelegationBackend: unknown class, skipping", "rr", rr.String())
		}
	}

	return nil
}

func (b *DBDelegationBackend) GetDelegationData(parentZone, childZone string) (map[string]map[uint16][]dns.RR, error) {
	const query = `SELECT owner, rrtype, rr FROM ChildDelegationData WHERE parent=? AND child=?`

	rows, err := b.kdb.Query(query, parentZone, childZone)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}
	defer rows.Close()

	result := map[string]map[uint16][]dns.RR{}
	for rows.Next() {
		var owner, rrtypestr, rrstr string
		if err := rows.Scan(&owner, &rrtypestr, &rrstr); err != nil {
			return nil, fmt.Errorf("scan failed: %w", err)
		}
		rr, err := dns.NewRR(rrstr)
		if err != nil {
			lg.Warn("DBDelegationBackend: bad RR in DB, skipping", "rr", rrstr, "error", err)
			continue
		}
		rrtype := rr.Header().Rrtype
		if result[owner] == nil {
			result[owner] = map[uint16][]dns.RR{}
		}
		result[owner][rrtype] = append(result[owner][rrtype], rr)
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no delegation data for %s in zone %s", childZone, parentZone)
	}
	return result, nil
}

func (b *DBDelegationBackend) ListChildren(parentZone string) ([]string, error) {
	const query = `SELECT DISTINCT child FROM ChildDelegationData WHERE parent=?`

	rows, err := b.kdb.Query(query, parentZone)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}
	defer rows.Close()

	var children []string
	for rows.Next() {
		var child string
		if err := rows.Scan(&child); err != nil {
			return nil, fmt.Errorf("scan failed: %w", err)
		}
		children = append(children, child)
	}
	return children, nil
}

// childZoneFromOwner extracts the immediate child zone name from an owner name.
// E.g. owner="ns1.whisky.dnslab.", parent="dnslab." → "whisky.dnslab."
// If owner is already a direct child, returns owner itself.
func childZoneFromOwner(owner, parentZone string) string {
	if owner == parentZone {
		return owner
	}
	// Walk labels from the right until we have parentZone + one more label
	labels := dns.SplitDomainName(owner)
	parentLabels := dns.SplitDomainName(parentZone)
	if len(labels) <= len(parentLabels) {
		return owner
	}
	// The child zone is the label just above the parent
	childIdx := len(labels) - len(parentLabels) - 1
	childName := dns.Fqdn(joinLabels(labels[childIdx:]))
	return childName
}

func joinLabels(labels []string) string {
	result := ""
	for i, l := range labels {
		if i > 0 {
			result += "."
		}
		result += l
	}
	return result
}
