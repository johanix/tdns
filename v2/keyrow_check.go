/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// The key invariants of the key lifecycle ownership test plan (§3), checked by
// every test layer, by "keystore dnssec check", and on demand:
//
//	I1 sign implies pub
//	I2 sign implies a private key
//	I3 ds only on SEP keys
//	I4 at most one signing key per role and algorithm
//	I5 the served DNSKEY RRset equals the pub=1 rows
//	I6 the keys that signed the zone are the sign=1 keys, and each of them signed
//	I7 the served CDS, when there is one and every SEP row has ds set, equals the ds=1 rows
//	I8 no row has pub or sign unset
//	I9 the flags match the flag table for the row's state
//
// I5, I6 and I7 look at the served zone, so they hold outside a transition in
// progress: between a state write and the re-sign that follows it, an RRSIG
// by a key that no longer signs is expected for a moment.

// KeyInvariantViolation is one finding of CheckKeyInvariants: which invariant
// (I1..I9 of the test plan), in which zone, for which key.
type KeyInvariantViolation struct {
	Invariant string
	Zone      string
	KeyID     uint16
	Detail    string
}

func (v KeyInvariantViolation) String() string {
	if v.KeyID != 0 {
		return fmt.Sprintf("%s %s keyid %d: %s", v.Invariant, v.Zone, v.KeyID, v.Detail)
	}
	return fmt.Sprintf("%s %s: %s", v.Invariant, v.Zone, v.Detail)
}

// keyRowView is one keystore row as the checker reads it.
type keyRowView struct {
	Keyid   uint16
	Flags   uint16
	Alg     uint8
	AlgName string
	State   string
	HasPriv bool
	Pub     sql.NullInt64
	Sign    sql.NullInt64
	DS      sql.NullInt64
	DNSKEY  *dns.DNSKEY
}

func (r keyRowView) sep() bool   { return r.Flags&dns.SEP != 0 }
func (r keyRowView) signs() bool { return r.Sign.Valid && r.Sign.Int64 != 0 }
func (r keyRowView) pub() bool   { return r.Pub.Valid && r.Pub.Int64 != 0 }
func (r keyRowView) role() string {
	if r.sep() {
		return "KSK"
	}
	return "ZSK"
}

func loadKeyRowViews(kdb *KeyDB, zone string) ([]keyRowView, error) {
	rows, err := kdb.DB.Query(`SELECT keyid, flags, algorithm, state, COALESCE(privatekey, ''), COALESCE(keyrr, ''), pub, sign, ds
FROM DnssecKeyStore WHERE zonename=? ORDER BY keyid`, zone)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []keyRowView
	for rows.Next() {
		var r keyRowView
		var keyid, flags int
		var priv, keyrr string
		if err := rows.Scan(&keyid, &flags, &r.AlgName, &r.State, &priv, &keyrr, &r.Pub, &r.Sign, &r.DS); err != nil {
			return nil, err
		}
		r.Keyid, r.Flags, r.HasPriv = uint16(keyid), uint16(flags), priv != ""
		r.Alg = dns.StringToAlgorithm[r.AlgName]
		if rr, err := dns.NewRR(keyrr); err == nil {
			if dk, ok := rr.(*dns.DNSKEY); ok {
				r.DNSKEY = dk
				if r.Alg == 0 {
					r.Alg = dk.Algorithm
				}
			}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CheckKeyRowInvariants checks the row-level invariants (I1-I4, I8, I9) of a
// zone's keystore rows: for a zone that is not loaded, or before it is.
func CheckKeyRowInvariants(kdb *KeyDB, zone string) []KeyInvariantViolation {
	zone = dns.Fqdn(zone)
	rows, err := loadKeyRowViews(kdb, zone)
	if err != nil {
		return []KeyInvariantViolation{{Invariant: "error", Zone: zone, Detail: fmt.Sprintf("reading the keystore: %v", err)}}
	}
	return checkKeyRows(zone, rows)
}

// CheckKeyInvariants checks I1-I9 for one zone: the row-level invariants
// against the keystore, and the served-zone ones (I5, I6, I7) against zd's
// snapshot when the zone holds one.
func CheckKeyInvariants(kdb *KeyDB, zd *ZoneData) []KeyInvariantViolation {
	if zd == nil {
		return nil
	}
	zone := dns.Fqdn(zd.ZoneName)
	rows, err := loadKeyRowViews(kdb, zone)
	if err != nil {
		return []KeyInvariantViolation{{Invariant: "error", Zone: zone, Detail: fmt.Sprintf("reading the keystore: %v", err)}}
	}
	out := checkKeyRows(zone, rows)
	if apex, err := zd.OwnerForAnalysis(zone); err != nil || apex == nil {
		return out // nothing served yet
	}
	out = append(out, checkServedDnskeys(zd, zone, rows)...)
	out = append(out, checkSignatures(zd, zone, rows)...)
	out = append(out, checkServedCds(zd, zone, rows)...)
	return out
}

func checkKeyRows(zone string, rows []keyRowView) []KeyInvariantViolation {
	var out []KeyInvariantViolation
	add := func(inv string, keyid uint16, detail string) {
		out = append(out, KeyInvariantViolation{Invariant: inv, Zone: zone, KeyID: keyid, Detail: detail})
	}
	signers := map[string][]uint16{} // "role alg" -> keyids with sign=1
	for _, r := range rows {
		if !r.Pub.Valid || !r.Sign.Valid {
			add("I8", r.Keyid, fmt.Sprintf("pub or sign unset (state %s)", r.State))
		}
		if r.signs() && !r.pub() {
			add("I1", r.Keyid, "sign is set but pub is not")
		}
		if r.signs() && !r.HasPriv {
			add("I2", r.Keyid, fmt.Sprintf("sign is set on a row without a private key (state %s)", r.State))
		}
		if r.DS.Valid && r.DS.Int64 != 0 && !r.sep() {
			add("I3", r.Keyid, "ds is set on a key without the SEP bit")
		}
		if r.signs() {
			k := r.role() + " " + r.AlgName
			signers[k] = append(signers[k], r.Keyid)
		}
		if f, ok := keyFlagsForState(r.State); !ok {
			add("I9", r.Keyid, fmt.Sprintf("state %q is not in the flag table", r.State))
		} else if r.Pub.Valid && r.Sign.Valid && (r.pub() != f.Pub || r.signs() != f.Sign) {
			add("I9", r.Keyid, fmt.Sprintf("state %s has pub=%d sign=%d, the table says pub=%d sign=%d",
				r.State, r.Pub.Int64, r.Sign.Int64, boolInt(f.Pub), boolInt(f.Sign)))
		} else if f.DS.Valid && r.DS.Valid && (r.DS.Int64 != 0) != f.DS.Bool {
			add("I9", r.Keyid, fmt.Sprintf("state %s has ds=%d, the table says ds=%d", r.State, r.DS.Int64, boolInt(f.DS.Bool)))
		}
	}
	var groups []string
	for k := range signers {
		groups = append(groups, k)
	}
	sort.Strings(groups)
	for _, k := range groups {
		if ids := signers[k]; len(ids) > 1 {
			add("I4", 0, fmt.Sprintf("%d signing %s keys: %v", len(ids), k, ids))
		}
	}
	return out
}

// checkServedDnskeys is I5: the served DNSKEY RRset equals the pub=1 rows.
func checkServedDnskeys(zd *ZoneData, zone string, rows []keyRowView) []KeyInvariantViolation {
	var out []KeyInvariantViolation
	want := map[string]uint16{}
	for _, r := range rows {
		if r.pub() && r.DNSKEY != nil {
			want[dnskeyIdentity(r.DNSKEY)] = r.Keyid
		}
	}
	served := map[string]*dns.DNSKEY{}
	if rs, err := zd.RRsetForAnalysis(zone, dns.TypeDNSKEY); err == nil && rs != nil {
		for _, rr := range rs.RRs {
			if dk, ok := rr.(*dns.DNSKEY); ok {
				served[dnskeyIdentity(dk)] = dk
			}
		}
	}
	for id, keyid := range want {
		if _, ok := served[id]; !ok {
			out = append(out, KeyInvariantViolation{Invariant: "I5", Zone: zone, KeyID: keyid, Detail: "pub is set but the key is not in the served DNSKEY RRset"})
		}
	}
	for id, dk := range served {
		if _, ok := want[id]; !ok {
			out = append(out, KeyInvariantViolation{Invariant: "I5", Zone: zone, KeyID: dk.KeyTag(), Detail: "served in the DNSKEY RRset without a pub=1 row"})
		}
	}
	return out
}

// checkSignatures is I6: every RRSIG in the zone is by a sign=1 key, every
// sign=1 SEP key signs the DNSKEY RRset, and every other sign=1 key signs
// something. The second and third parts apply only to a zone that carries
// signatures at all.
func checkSignatures(zd *ZoneData, zone string, rows []keyRowView) []KeyInvariantViolation {
	var out []KeyInvariantViolation
	type sigKey struct {
		tag uint16
		alg uint8
	}
	signing := map[sigKey]keyRowView{}
	for _, r := range rows {
		if r.signs() {
			signing[sigKey{r.Keyid, r.Alg}] = r
		}
	}
	names, err := zd.GetOwnerNames()
	if err != nil {
		return out
	}
	signedSomething := map[sigKey]bool{}
	signedDnskey := map[sigKey]bool{}
	anySig := false
	reported := map[string]bool{}
	for _, name := range names {
		owner, err := zd.OwnerForAnalysis(name)
		if err != nil || owner == nil || owner.RRtypes == nil {
			continue
		}
		for _, rrt := range owner.RRtypes.Keys() {
			rrset := owner.RRtypes.GetOnlyRRSet(rrt)
			for _, sig := range rrset.RRSIGs {
				rrsig, ok := sig.(*dns.RRSIG)
				if !ok {
					continue
				}
				anySig = true
				k := sigKey{rrsig.KeyTag, rrsig.Algorithm}
				if _, ok := signing[k]; !ok {
					key := fmt.Sprintf("%d/%s", rrsig.KeyTag, dns.TypeToString[rrt])
					if !reported[key] {
						reported[key] = true
						out = append(out, KeyInvariantViolation{Invariant: "I6", Zone: zone, KeyID: rrsig.KeyTag,
							Detail: fmt.Sprintf("RRSIG over %s at %s by a key that does not sign", dns.TypeToString[rrt], name)})
					}
					continue
				}
				signedSomething[k] = true
				if rrt == dns.TypeDNSKEY && name == zone {
					signedDnskey[k] = true
				}
			}
		}
	}
	if !anySig {
		return out
	}
	var keys []sigKey
	for k := range signing {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].tag < keys[j].tag })
	for _, k := range keys {
		r := signing[k]
		switch {
		case r.sep() && !signedDnskey[k]:
			out = append(out, KeyInvariantViolation{Invariant: "I6", Zone: zone, KeyID: r.Keyid, Detail: "sign is set on a SEP key that does not sign the DNSKEY RRset"})
		case !r.sep() && !signedSomething[k]:
			out = append(out, KeyInvariantViolation{Invariant: "I6", Zone: zone, KeyID: r.Keyid, Detail: "sign is set on a key that signed nothing"})
		}
	}
	return out
}

// checkServedCds is I7: when the zone serves a CDS RRset and every SEP row
// has ds set, the served CDS names exactly the ds=1 keys. A zone that serves
// no CDS is not judged (it may not publish one at all), and neither is a zone
// with a SEP row whose ds is unknown.
func checkServedCds(zd *ZoneData, zone string, rows []keyRowView) []KeyInvariantViolation {
	rs, err := zd.RRsetForAnalysis(zone, dns.TypeCDS)
	if err != nil || rs == nil || len(rs.RRs) == 0 {
		return nil
	}
	want := map[string]uint16{}
	for _, r := range rows {
		if !r.sep() {
			continue
		}
		if !r.DS.Valid {
			return nil
		}
		if r.DS.Int64 != 0 {
			want[fmt.Sprintf("%d/%d", r.Keyid, r.Alg)] = r.Keyid
		}
	}
	served := map[string]uint16{}
	for _, rr := range rs.RRs {
		cds, ok := rr.(*dns.CDS)
		if !ok || cds.Algorithm == 0 { // the delete sentinel names no key
			continue
		}
		served[fmt.Sprintf("%d/%d", cds.KeyTag, cds.Algorithm)] = cds.KeyTag
	}
	var out []KeyInvariantViolation
	for k, keyid := range want {
		if _, ok := served[k]; !ok {
			out = append(out, KeyInvariantViolation{Invariant: "I7", Zone: zone, KeyID: keyid, Detail: "ds is set but the served CDS has no record for the key"})
		}
	}
	for k, keyid := range served {
		if _, ok := want[k]; !ok {
			out = append(out, KeyInvariantViolation{Invariant: "I7", Zone: zone, KeyID: keyid, Detail: "the served CDS names a key whose ds is not set"})
		}
	}
	return out
}

// checkKeystoreZones runs the checker over the named zone, or over every zone
// in the keystore, using the loaded zone where there is one.
func (kdb *KeyDB) checkKeystoreZones(zone string) ([]KeyInvariantViolation, int, error) {
	var zones []string
	if strings.TrimSpace(zone) != "" {
		zones = []string{dns.Fqdn(zone)}
	} else {
		var err error
		if zones, err = kdb.keystoreZones(); err != nil {
			return nil, 0, err
		}
	}
	var out []KeyInvariantViolation
	for _, z := range zones {
		if zd, ok := Zones.Get(z); ok && zd != nil {
			out = append(out, CheckKeyInvariants(kdb, zd)...)
		} else {
			out = append(out, CheckKeyRowInvariants(kdb, z)...)
		}
	}
	return out, len(zones), nil
}
