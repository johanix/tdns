/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Resolver-side name handling: what comes back from OTHER servers.
 *
 * A resolver controls neither the case an authoritative server stores its names
 * in nor, once it randomises query case (0x20), the case it gets back. Records
 * in one response need not agree with each other either: a parent whose zone
 * file spells a delegation's NS owner and its DS owner differently serves them
 * back exactly that way. tdns itself does that as of the boundary work in
 * #417, which preserves the spelling a zone file used instead of folding it.
 */
package tdns

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// referral builds a parent's authority section for child, spelling the NS owner
// and the DS/RRSIG owners independently. zonename is derived from the NS owner,
// so those two spellings are precisely what gets compared.
func referral(t *testing.T, child string, nsSpell, dsSpell func(string) string) []dns.RR {
	t.Helper()
	nsOwner, dsOwner := nsSpell(child), dsSpell(child)
	var out []dns.RR
	for _, text := range []string{
		nsOwner + " 3600 IN NS ns1." + child,
		nsOwner + " 3600 IN NS ns2." + child,
		dsOwner + " 3600 IN DS 12345 15 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
		dsOwner + " 3600 IN RRSIG DS 15 2 3600 20260911000000 20260828000000 54321 example. " +
			"c29tZXNpZ25hdHVyZWJ5dGVzaGVyZXNvbWVzaWduYXR1cmVieXRlc2hlcmVzb21lc2lnbmF0dXJlYnl0ZXNoZXJlYWFhYWE9",
	} {
		rr, err := dns.NewRR(text)
		if err != nil {
			t.Fatalf("building %q: %v", text, err)
		}
		out = append(out, rr)
	}
	return out
}

func same(s string) string  { return s }
func upper(s string) string { return strings.ToUpper(s) }

// A referral whose DS owner is spelled differently from its NS owner must still
// yield the DS records AND their signatures. Dropping the DS makes a signed
// child look unsigned to the resolver. Keeping the DS while dropping the RRSIGs
// is worse -- a DS RRset that cannot be proven, which is bogus rather than
// merely insecure -- and the two comparisons used to be able to disagree.
func TestReferralDSSurvivesAnyOwnerSpelling(t *testing.T) {
	const child = "child.example."

	for _, tc := range []struct {
		what             string
		nsSpell, dsSpell func(string) string
	}{
		{"both as asked", same, same},
		{"DS owner upper", same, upper},
		{"NS owner upper", upper, same},
		{"DS owner zone part upper", same, func(string) string { return "child.EXAMPLE." }},
		{"DS owner left label upper", same, func(string) string { return "CHILD.example." }},
		{"both mixed, differently", func(string) string { return "ChIlD.eXaMpLe." },
			func(string) string { return "cHiLd.ExAmPlE." }},
	} {
		t.Run(tc.what, func(t *testing.T) {
			authority := referral(t, child, tc.nsSpell, tc.dsSpell)

			msg := new(dns.Msg)
			msg.Ns = authority
			nsRRset, zonename, nsMap := extractReferral(msg, child, dns.TypeA)
			if len(nsRRset.RRs) != 2 || len(nsMap) != 2 {
				t.Fatalf("referral lost its NS records: %d RRs, %d in nsMap", len(nsRRset.RRs), len(nsMap))
			}

			dsRRs, dsSigs := collectDSFromAuthority(authority, zonename)
			if len(dsRRs) != 1 {
				t.Errorf("got %d DS records for zonename %q, want 1: a signed child looks unsigned",
					len(dsRRs), zonename)
			}
			if len(dsSigs) != 1 {
				t.Errorf("got %d DS RRSIGs for zonename %q, want 1: the DS RRset cannot be validated",
					len(dsSigs), zonename)
			}
		})
	}
}

// A DS for a different name in the same authority section must not be picked
// up, or "fixing" the comparison by accepting everything would pass this.
func TestReferralDSIgnoresAnotherName(t *testing.T) {
	authority := referral(t, "child.example.", same, same)
	stray, err := dns.NewRR("other.example. 3600 IN DS 999 15 2 " +
		"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")
	if err != nil {
		t.Fatalf("building the stray DS: %v", err)
	}
	authority = append(authority, stray)

	if dsRRs, _ := collectDSFromAuthority(authority, "child.example."); len(dsRRs) != 1 {
		t.Errorf("got %d DS records, want only the one for child.example.", len(dsRRs))
	}
	// And not a name that merely ends with the zone name.
	if got, _ := collectDSFromAuthority(authority, "hild.example."); len(got) != 0 {
		t.Error("a DS for child.example. was collected for zone hild.example.")
	}
}

// Out-of-bailiwick transport signals live under a "_dns." owner prefix. The
// prefix TEST was folded and the STRIP was not, so _DNS.ns1.example. cleared
// the test and then kept its prefix: baseName stayed the whole owner, every
// lookup keyed on it missed, and the transport signal was silently dropped.
//
// The base name keeps the case it arrived with -- it is a nameserver name and
// the server map now folds its own keys, so there is nothing to gain by
// flattening it here and a spelling to lose.
func TestParseOwnerNameStripsThePrefixItMatched(t *testing.T) {
	for _, tc := range []struct {
		owner    string
		wantBase string
		wantOOTS bool
	}{
		{"_dns.ns1.example.", "ns1.example.", true},
		{"_DNS.ns1.example.", "ns1.example.", true},
		{"_Dns.NS1.Example.", "NS1.Example.", true},
		{"_DNS.NS1.EXAMPLE.", "NS1.EXAMPLE.", true},

		// Not a signal owner: left alone entirely.
		{"ns1.example.", "ns1.example.", false},
		{"_dnsx.ns1.example.", "_dnsx.ns1.example.", false},
		{"x_dns.ns1.example.", "x_dns.ns1.example.", false},
	} {
		t.Run(tc.owner, func(t *testing.T) {
			base, isOOTS, orig := parseOwnerName(tc.owner)
			if isOOTS != tc.wantOOTS {
				t.Errorf("parseOwnerName(%q) isOOTSOwner = %v, want %v",
					tc.owner, isOOTS, tc.wantOOTS)
			}
			if base != tc.wantBase {
				t.Errorf("parseOwnerName(%q) baseName = %q, want %q -- a base name "+
					"that still carries its prefix matches no server",
					tc.owner, base, tc.wantBase)
			}
			if orig != tc.owner {
				t.Errorf("parseOwnerName(%q) originalOwner = %q, want the input", tc.owner, orig)
			}
		})
	}
}

// ZoneMatchesSelector is the one predicate both IMR dump handlers filter with.
// It became load-bearing for case when ZoneMap started folding its keys: the
// zone-backoff dump was still comparing a now-canonical key against the filter
// as the operator typed it, so a mixed-case zone argument returned an empty
// dump. Both handlers go through here now, so the two cannot drift again.
func TestZoneMatchesSelectorIgnoresCase(t *testing.T) {
	for _, tc := range []struct {
		zone, exact, suffix string
		want                bool
		why                 string
	}{
		{"example.com.", "example.com.", "", true, "exact match"},
		{"example.com.", "EXAMPLE.COM.", "", true, "filter in another case"},
		{"EXAMPLE.COM.", "example.com.", "", true, "key in another case"},
		{"example.com.", "example.org.", "", false, "different zone"},

		{"www.example.com.", "", "example.com.", true, "suffix match"},
		{"www.example.com.", "", "EXAMPLE.COM.", true, "suffix in another case"},
		{"example.com.", "", "example.com.", true, "suffix matches the zone itself"},
		{"dsync.se.", "", "sync.se.", false, "never a partial label"},

		{"example.com.", "", "", true, "no filter selects everything"},
		{"example.com.", "example.com.", "other.", true, "exact wins over suffix"},
	} {
		if got := ZoneMatchesSelector(tc.zone, tc.exact, tc.suffix); got != tc.want {
			t.Errorf("ZoneMatchesSelector(%q, %q, %q) = %v, want %v -- %s",
				tc.zone, tc.exact, tc.suffix, got, tc.want, tc.why)
		}
	}
}
