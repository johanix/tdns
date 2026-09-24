/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"log"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// CDNSKEY alongside CDS (#753; design
// docs/2026-09-24-cds-publication-and-rfc-conformance.md §4).
//
// The child: RFC 7344 §4 says to publish both, and they must agree. Every CDS
// tdns publishes gets the CDNSKEY of the keys it names, in the same update:
// the CDNSKEY is derived from the CDS, by matching each record against the
// keys tdns holds, so the two agree by construction. A CDS naming a key tdns
// holds no copy of is published alone, as before, and the log says so.
//
// The parent: RFC 9975 §3.1 makes a key named in the CDS but not in the
// CDNSKEY, or the other way round, an inconsistency, and the scan changes
// nothing on one. A child that serves no CDNSKEY at any nameserver is taken
// as CDS-only: local policy, not RFC 9975.

// cdnskeyOf is the CDNSKEY record for key at zone's apex, with the CDS's TTL.
func cdnskeyOf(zone string, key *dns.DNSKEY) dns.RR {
	c := &dns.CDNSKEY{DNSKEY: *key}
	c.Hdr = dns.RR_Header{
		Name:   dns.Fqdn(zone),
		Rrtype: dns.TypeCDNSKEY,
		Class:  dns.ClassINET,
		Ttl:    120,
	}
	return c
}

// cdnskeyDeleteRR is the class-ANY record that removes the whole CDNSKEY RRset
// at zone's apex (RFC 2136 section 2.5.2).
func cdnskeyDeleteRR(zone string) dns.RR {
	anti := &dns.CDNSKEY{}
	anti.Hdr = dns.RR_Header{
		Name:   dns.Fqdn(zone),
		Rrtype: dns.TypeCDNSKEY,
		Class:  dns.ClassANY,
		Ttl:    0,
	}
	return anti
}

// servedCdnskeyRRs returns the CDNSKEY RRset the zone serves at its apex, if
// any.
func servedCdnskeyRRs(zd *ZoneData) ([]dns.RR, error) {
	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return nil, fmt.Errorf("zone %s: reading the served CDNSKEY: %w", zd.ZoneName, err)
	}
	if apex == nil || apex.RRtypes == nil {
		return nil, nil
	}
	return apex.RRtypes.GetOnlyRRSet(dns.TypeCDNSKEY).RRs, nil
}

// keyIdentities is the set of keys in a DNSKEY or CDNSKEY RRset, keyed on what
// makes a key that key: flags, protocol, algorithm and public key.
func keyIdentities(rrs []dns.RR) map[string]struct{} {
	out := make(map[string]struct{})
	for _, rr := range rrs {
		var k *dns.DNSKEY
		switch v := rr.(type) {
		case *dns.DNSKEY:
			k = v
		case *dns.CDNSKEY:
			k = &v.DNSKEY
		default:
			continue
		}
		out[fmt.Sprintf("%d %d %d %s", k.Flags, k.Protocol, k.Algorithm, k.PublicKey)] = struct{}{}
	}
	return out
}

// publishesCdnskey reports whether the zone's policy lets the DS engine publish
// a CDNSKEY: `cdnskey: false` does not. A zone with no policy does.
func (zd *ZoneData) publishesCdnskey() bool {
	return zd.DnssecPolicy == nil || !zd.DnssecPolicy.SuppressCDNSKEY
}

const dsSignalKeysSql = `SELECT keyrr FROM DnssecKeyStore WHERE zonename = ?`

// dsSignalKeys is every key a CDS for zd may name: the keystore's rows for the
// zone, in any state -- a multi-DS rollover's next KSK has its DS at the parent
// before its DNSKEY is published, and an owned zone's DS set names other
// providers' keys, whose rows are foreign -- and the DNSKEY RRset the zone
// serves.
func (zd *ZoneData) dsSignalKeys(kdb *KeyDB) []*dns.DNSKEY {
	var out []*dns.DNSKEY
	if kdb != nil {
		rows, err := kdb.Query(dsSignalKeysSql, dns.Fqdn(zd.ZoneName))
		if err != nil {
			lgDSEngine.Debug("could not read the keystore for the CDNSKEY", "zone", zd.ZoneName, "err", err)
		} else {
			for rows.Next() {
				var keyrr string
				if rows.Scan(&keyrr) != nil {
					continue
				}
				if rr, err := dns.NewRR(keyrr); err == nil {
					if k, ok := rr.(*dns.DNSKEY); ok {
						out = append(out, k)
					}
				}
			}
			rows.Close()
		}
	}
	if apex, err := zd.GetOwner(zd.ZoneName); err == nil && apex != nil && apex.RRtypes != nil {
		for _, rr := range apex.RRtypes.GetOnlyRRSet(dns.TypeDNSKEY).RRs {
			if k, ok := rr.(*dns.DNSKEY); ok {
				out = append(out, k)
			}
		}
	}
	return out
}

// cdnskeyForCDS is the CDNSKEY RRset to publish with cds: for each CDS record,
// the key among keys whose DS it is. When a record names no key among them,
// the CDNSKEY is empty and unmatched lists the key tags that had none.
func cdnskeyForCDS(zone string, cds []dns.RR, keys []*dns.DNSKEY) (cdnskey []dns.RR, unmatched []uint16) {
	seen := map[string]bool{}
	for _, rr := range cds {
		c, ok := rr.(*dns.CDS)
		if !ok {
			continue
		}
		want := newCdsTuple(c.KeyTag, c.Algorithm, c.DigestType, c.Digest)
		var found *dns.DNSKEY
		for _, k := range keys {
			if ds := k.ToDS(c.DigestType); ds != nil && newCdsTuple(ds.KeyTag, ds.Algorithm, ds.DigestType, ds.Digest) == want {
				found = k
				break
			}
		}
		if found == nil {
			unmatched = append(unmatched, c.KeyTag)
			continue
		}
		id := fmt.Sprintf("%d %d %d %s", found.Flags, found.Protocol, found.Algorithm, found.PublicKey)
		if !seen[id] {
			seen[id] = true
			cdnskey = append(cdnskey, cdnskeyOf(zone, found))
		}
	}
	if len(unmatched) > 0 {
		return nil, unmatched
	}
	return cdnskey, nil
}

// cdnskeyFor is the CDNSKEY RRset zd publishes with cds: none under
// `cdnskey: false`, and none when the CDS names a key tdns holds no copy of.
func (zd *ZoneData) cdnskeyFor(kdb *KeyDB, cds []dns.RR) (cdnskey []dns.RR, unmatched []uint16) {
	if !zd.publishesCdnskey() {
		return nil, nil
	}
	return cdnskeyForCDS(zd.ZoneName, cds, zd.dsSignalKeys(kdb))
}

// cdnskeyInStep reports whether the zone serves the CDNSKEY RRset that goes
// with cds. The DS engine's "already in step" checks ask it as well as
// comparing the CDS: a zone that serves the right CDS and no CDNSKEY -- one
// signed by a build from before #753 -- would otherwise never get one until
// its keys changed.
func (zd *ZoneData) cdnskeyInStep(kdb *KeyDB, cds []dns.RR) (bool, error) {
	served, err := servedCdnskeyRRs(zd)
	if err != nil {
		return false, err
	}
	want, _ := zd.cdnskeyFor(kdb, cds)
	return sameKeyIdentities(keyIdentities(want), keyIdentities(served)), nil
}

// isCdnskeyDelete reports whether a CDNSKEY RRset is exactly the RFC 8078 §4
// delete: one record, 0 3 0 AA== (the key a single zero octet).
func isCdnskeyDelete(rrs []dns.RR) bool {
	var keys []*dns.CDNSKEY
	for _, rr := range rrs {
		if k, ok := rr.(*dns.CDNSKEY); ok {
			keys = append(keys, k)
		}
	}
	if len(keys) != 1 {
		return false
	}
	k := keys[0]
	if k.Flags != 0 || k.Protocol != 3 || k.Algorithm != 0 {
		return false
	}
	b, err := base64.StdEncoding.DecodeString(k.PublicKey)
	return err == nil && bytes.Equal(b, deleteDigest)
}

// cdnskeyAgreesWithCDS applies RFC 9975 §3.1 to a CDS RRset and a non-empty
// CDNSKEY RRset: the keys the CDNSKEY names, as SHA-256 DS, must be exactly the
// keys the SHA-256 CDS records name. CDS records of other digest types take no
// part; 9975 checks only the digest types marked MUST. The RFC 8078 delete
// agrees only with the delete.
func cdnskeyAgreesWithCDS(cds, cdnskey []dns.RR) (bool, string) {
	kind, why := classifyCDS(cds)
	cdnskeyDelete := isCdnskeyDelete(cdnskey)
	switch {
	case kind == cdsMalformed:
		return false, "the CDS RRset is malformed: " + why
	case kind == cdsDelete && cdnskeyDelete:
		return true, ""
	case kind == cdsDelete:
		return false, "the CDS is the RFC 8078 delete and the CDNSKEY is not"
	case cdnskeyDelete:
		return false, "the CDNSKEY is the RFC 8078 delete and the CDS is not"
	}
	fromCDS := map[cdsTuple]struct{}{}
	for _, rr := range cds {
		if c, ok := rr.(*dns.CDS); ok && c.DigestType == dns.SHA256 {
			fromCDS[newCdsTuple(c.KeyTag, c.Algorithm, c.DigestType, c.Digest)] = struct{}{}
		}
	}
	fromCDNSKEY := map[cdsTuple]struct{}{}
	for _, rr := range cdnskey {
		k, ok := rr.(*dns.CDNSKEY)
		if !ok {
			continue
		}
		if k.Algorithm == 0 {
			return false, "a CDNSKEY record has algorithm 0, but the RRset is not the RFC 8078 delete"
		}
		ds := k.ToDS(dns.SHA256)
		if ds == nil {
			return false, fmt.Sprintf("no DS can be computed for the CDNSKEY record with key tag %d", k.KeyTag())
		}
		fromCDNSKEY[newCdsTuple(ds.KeyTag, ds.Algorithm, ds.DigestType, ds.Digest)] = struct{}{}
	}
	if !cdsTupleSetsEqual(fromCDS, fromCDNSKEY) {
		return false, fmt.Sprintf("the SHA-256 CDS records name keys %v and the CDNSKEY keys %v",
			tupleKeyids(fromCDS), tupleKeyids(fromCDNSKEY))
	}
	return true, ""
}

// checkCdnskey fetches the child's CDNSKEY from the nameservers the CDS came
// from and checks it against the CDS. A refusal is an inconsistency RFC 9975
// §3.1 says to act on by changing nothing: nameservers that do not agree, a
// CDNSKEY that could not be fetched, or one that names other keys than the
// CDS. No CDNSKEY at any nameserver is accepted, by local policy.
func (scanner *Scanner) checkCdnskey(ctx context.Context, childZone string, nsRRset, cds *core.RRset, scanLog *log.Logger) error {
	rrset, inSync, err := scanner.askChild(ctx, childZone, dns.TypeCDNSKEY, nsRRset, scanLog)
	if err != nil {
		return refusef("RFC 9975 §3.1: the CDNSKEY could not be fetched from the child's nameservers: %v", err)
	}
	if !inSync {
		return refusef("RFC 9975 §3.1: the child's nameservers do not agree on the CDNSKEY RRset")
	}
	if rrset == nil || len(rrset.RRs) == 0 {
		scanLog.Printf("ProcessCDSNotify: %s: no CDNSKEY at any nameserver; accepted as a CDS-only child"+
			" (local policy, an exception to RFC 9975 §3.1)", childZone)
		return nil
	}
	if ok, why := cdnskeyAgreesWithCDS(cds.RRs, rrset.RRs); !ok {
		return refusef("RFC 9975 §3.1: the CDS and CDNSKEY RRsets are inconsistent: %s", why)
	}
	return nil
}
