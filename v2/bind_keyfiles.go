/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Reading the metadata bind9 keeps beside a key.
 *
 * A bind9 key is up to three files sharing a basename:
 *
 *   Kzone.+013+12345.key       the public DNSKEY/KEY RR (zone-file text)
 *   Kzone.+013+12345.private   the private key, plus timing metadata
 *   Kzone.+013+12345.state     KASP key states (bind 9.16+ dnssec-policy only)
 *
 * tdns never reads these at run time. They are parsed by `keystore <class>
 * bulk-convert`, which turns a directory of bind9-generated keys into an export
 * directory tdns can pre-load: the private half re-encoded as PKCS#8 PEM, and a
 * manifest carrying the state and timestamps that would otherwise be lost.
 *
 * Both files are "Tag: value" lines with ';' comments. The tag sets are NOT the
 * same in the two files -- .private says "Created:/Publish:/Activate:" where
 * .state says "Generated:/Published:/Active:" for the same instants -- which is
 * why they get separate parsers rather than one shared map lookup.
 */

package tdns

import (
	"fmt"
	"strings"
	"time"
)

// bindTimeLayout is how bind9 writes every timestamp in both files
// (dns_time32_totext): UTC, no separators.
const bindTimeLayout = "20060102150405"

// BindKeyTimes are the timing fields bind9 records in a .private file. Empty
// string means the tag was absent, which is normal -- dnssec-keygen writes only
// the ones that apply.
type BindKeyTimes struct {
	Created     string
	Publish     string
	Activate    string
	Revoke      string
	Inactive    string
	Delete      string
	DSPublish   string
	SyncPublish string
}

// BindKeyState is the content of a .state file. The four per-record states each
// hold "hidden", "rumoured", "omnipresent" or "unretentive"; an empty string
// means the tag was absent (bind's NA).
type BindKeyState struct {
	KSK, ZSK bool

	DNSKEY string
	ZRRSIG string
	KRRSIG string
	DS     string
	Goal   string

	Generated string
	Published string
	Active    string
	Retired   string
	Removed   string
}

// parseBindTagFile turns "Tag: value" lines into a map, dropping ';' comments
// and blank lines. Tags keep their trailing colon off; values are trimmed.
//
// Deliberately lenient about unknown tags: bind adds fields between releases,
// and a converter that refused a file because it carried a tag this binary had
// never heard of would be useless the first time bind9 gained one.
func parseBindTagFile(data []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		tag, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		out[strings.TrimSpace(tag)] = strings.TrimSpace(value)
	}
	return out
}

// ParseBindKeyTimes reads the timing metadata out of a .private file. It does
// NOT parse the key material -- that is PrepareKeyCache's job, and keeping the
// two apart means a key whose algorithm this binary cannot load still yields
// usable metadata.
func ParseBindKeyTimes(data []byte) BindKeyTimes {
	t := parseBindTagFile(data)
	return BindKeyTimes{
		Created:     t["Created"],
		Publish:     t["Publish"],
		Activate:    t["Activate"],
		Revoke:      t["Revoke"],
		Inactive:    t["Inactive"],
		Delete:      t["Delete"],
		DSPublish:   t["DSPublish"],
		SyncPublish: t["SyncPublish"],
	}
}

// ParseBindKeyState reads a .state file. A file with no recognisable key-state
// tag is an error rather than an empty result: it means we were handed
// something that is not a .state file, and silently treating that as "no states
// recorded" would send the caller down the no-state path with a wrong reason.
func ParseBindKeyState(data []byte) (*BindKeyState, error) {
	t := parseBindTagFile(data)
	st := &BindKeyState{
		KSK:       strings.EqualFold(t["KSK"], "yes"),
		ZSK:       strings.EqualFold(t["ZSK"], "yes"),
		DNSKEY:    strings.ToLower(t["DNSKEYState"]),
		ZRRSIG:    strings.ToLower(t["ZRRSIGState"]),
		KRRSIG:    strings.ToLower(t["KRRSIGState"]),
		DS:        strings.ToLower(t["DSState"]),
		Goal:      strings.ToLower(t["GoalState"]),
		Generated: t["Generated"],
		Published: t["Published"],
		Active:    t["Active"],
		Retired:   t["Retired"],
		Removed:   t["Removed"],
	}
	if st.DNSKEY == "" && st.ZRRSIG == "" && st.KRRSIG == "" && st.DS == "" && st.Goal == "" {
		return nil, fmt.Errorf("no key-state tags found; not a bind9 .state file")
	}
	for tag, v := range map[string]string{
		"DNSKEYState": st.DNSKEY, "ZRRSIGState": st.ZRRSIG,
		"KRRSIGState": st.KRRSIG, "DSState": st.DS, "GoalState": st.Goal,
	} {
		switch v {
		case "", "hidden", "rumoured", "omnipresent", "unretentive":
		default:
			return nil, fmt.Errorf("%s has unknown value %q", tag, v)
		}
	}
	return st, nil
}

// BindTimeToRFC3339 converts one bind timestamp to the form the keystore's
// *_at columns hold. An empty input stays empty: "not recorded" must not become
// an epoch, which would read as a real event at the dawn of 1970.
func BindTimeToRFC3339(s string) (string, error) {
	if strings.TrimSpace(s) == "" {
		return "", nil
	}
	t, err := time.Parse(bindTimeLayout, strings.TrimSpace(s))
	if err != nil {
		return "", fmt.Errorf("unparsable bind timestamp %q: %v", s, err)
	}
	return t.UTC().Format(time.RFC3339), nil
}

// BindStateToDnssecState maps bind's KASP key states onto tdns's single linear
// DNSSEC key state.
//
// The two models do not correspond. bind tracks four INDEPENDENT records
// (DNSKEY, ZRRSIG, KRRSIG, DS), each moving hidden -> rumoured -> omnipresent
// and back out through unretentive; tdns has one ordered state per key. So this
// is a lossy projection, and it is written out explicitly rather than inferred,
// because a plausible-but-wrong answer here publishes a DNSKEY set containing
// keys bind had already retired.
//
// isKSK selects which signing record speaks for the key: a KSK signs the DNSKEY
// RRset (KRRSIG), a ZSK signs everything else (ZRRSIG). Taken from the RR's
// flags rather than the .state file's KSK:/ZSK: booleans, so the public key and
// the state file disagreeing is caught by the caller instead of silently
// resolved here.
//
// Order matters and is not the table's reading order: "active" is checked
// before "dspublished" because a fully rolled-in KSK satisfies both, and active
// is the later state.
func BindStateToDnssecState(st *BindKeyState, isKSK bool) (string, error) {
	if st == nil {
		return "", fmt.Errorf("no key state")
	}
	signing := st.ZRRSIG
	if isKSK {
		signing = st.KRRSIG
	}

	// On the way out, in any record: the key is being withdrawn.
	if st.DNSKEY == "unretentive" || st.ZRRSIG == "unretentive" ||
		st.KRRSIG == "unretentive" || st.DS == "unretentive" {
		return DnskeyStateRetired, nil
	}

	// Nothing anywhere. Two very different keys look identical in the state
	// tags -- one that has not been published yet, and one whose withdrawal has
	// completed -- so the timestamps break the tie. Without them, "created" is
	// the safe reading: it publishes nothing.
	if st.DNSKEY == "hidden" || st.DNSKEY == "" {
		if st.Removed != "" || st.Retired != "" {
			return DnskeyStateRemoved, nil
		}
		return DnskeyStateCreated, nil
	}

	if signing == "omnipresent" {
		return DnskeyStateActive, nil
	}
	if isKSK && (st.DS == "rumoured" || st.DS == "omnipresent") {
		return DnskeyStateDsPublished, nil
	}
	if st.DNSKEY == "rumoured" || st.DNSKEY == "omnipresent" {
		return DnskeyStatePublished, nil
	}

	return "", fmt.Errorf("cannot map key state (DNSKEY=%q ZRRSIG=%q KRRSIG=%q DS=%q) to a tdns state",
		st.DNSKEY, st.ZRRSIG, st.KRRSIG, st.DS)
}
