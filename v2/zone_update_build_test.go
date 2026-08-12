/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestBuildZoneUpdateActionsAddAndDelRR(t *testing.T) {
	add, err := BuildZoneUpdateActions("alpha.dnslab.", ZoneUpdateSpec{
		Verb: VerbAddRR,
		RRs:  []string{"foo.alpha.dnslab. 3600 IN A 1.2.3.4"},
	})
	if err != nil {
		t.Fatalf("addrr: %v", err)
	}
	if len(add) != 1 {
		t.Fatalf("addrr produced %d actions, want 1", len(add))
	}
	if add[0].Header().Class != dns.ClassINET {
		t.Errorf("addrr class = %d, want ClassINET", add[0].Header().Class)
	}

	del, err := BuildZoneUpdateActions("alpha.dnslab.", ZoneUpdateSpec{
		Verb: VerbDelRR,
		RRs:  []string{"foo.alpha.dnslab. 3600 IN A 1.2.3.4"},
	})
	if err != nil {
		t.Fatalf("delrr: %v", err)
	}
	if del[0].Header().Class != dns.ClassNONE {
		t.Errorf("delrr class = %d, want ClassNONE (RFC 2136 §2.5.4)", del[0].Header().Class)
	}
	// The TTL is not part of RR identity; carrying the caller's TTL into a
	// delete invites "why did my delete not match" reports.
	if del[0].Header().Ttl != 0 {
		t.Errorf("delrr TTL = %d, want 0", del[0].Header().Ttl)
	}
}

func TestBuildZoneUpdateActionsDelRRsetAndDelName(t *testing.T) {
	drs, err := BuildZoneUpdateActions("alpha.dnslab.", ZoneUpdateSpec{
		Verb: VerbDelRRset, Name: "foo.alpha.dnslab", Rrtype: "a",
	})
	if err != nil {
		t.Fatalf("delrrset: %v", err)
	}
	if drs[0].Header().Class != dns.ClassANY || drs[0].Header().Rrtype != dns.TypeA {
		t.Errorf("delrrset = class %d type %d, want ClassANY/A",
			drs[0].Header().Class, drs[0].Header().Rrtype)
	}
	// An unqualified name must be made absolute, not left to match nothing.
	if drs[0].Header().Name != "foo.alpha.dnslab." {
		t.Errorf("owner = %q, want it qualified to foo.alpha.dnslab.", drs[0].Header().Name)
	}

	dn, err := BuildZoneUpdateActions("alpha.dnslab.", ZoneUpdateSpec{
		Verb: VerbDelName, Name: "foo.alpha.dnslab.",
	})
	if err != nil {
		t.Fatalf("delname: %v", err)
	}
	if dn[0].Header().Class != dns.ClassANY || dn[0].Header().Rrtype != dns.TypeANY {
		t.Errorf("delname = class %d type %d, want ClassANY/ANY (RFC 2136 §2.5.3)",
			dn[0].Header().Class, dn[0].Header().Rrtype)
	}

	// delrrset with type ANY would be delname without delname's apex
	// protections, so it is refused rather than quietly reinterpreted.
	if _, err := BuildZoneUpdateActions("alpha.dnslab.", ZoneUpdateSpec{
		Verb: VerbDelRRset, Name: "alpha.dnslab.", Rrtype: "ANY",
	}); err == nil {
		t.Error("delrrset accepted type ANY; expected a refusal pointing at delname")
	}
}

// TestBuildZoneUpdateActionsReplaceInfersRRset covers the CLI shape:
// several --rr flags, with the RRset to replace inferred from their owner and
// type rather than named separately.
func TestBuildZoneUpdateActionsReplaceInfersRRset(t *testing.T) {
	actions, err := BuildZoneUpdateActions("alpha.dnslab.", ZoneUpdateSpec{
		Verb: VerbReplaceRRset,
		RRs: []string{
			"foo.alpha.dnslab. IN A 1.2.3.4",
			"foo.alpha.dnslab. IN A 2.3.4.5",
		},
	})
	if err != nil {
		t.Fatalf("replacerrset: %v", err)
	}
	if len(actions) != 3 {
		t.Fatalf("replacerrset produced %d actions, want 3 (one delete + two adds)", len(actions))
	}

	// The delete must come first, and must name the inferred RRset.
	if actions[0].Header().Class != dns.ClassANY || actions[0].Header().Rrtype != dns.TypeA {
		t.Errorf("action[0] = class %d type %d, want the ClassANY A-RRset delete",
			actions[0].Header().Class, actions[0].Header().Rrtype)
	}
	if actions[0].Header().Name != "foo.alpha.dnslab." {
		t.Errorf("delete owner = %q, want foo.alpha.dnslab.", actions[0].Header().Name)
	}
	for _, rr := range actions[1:] {
		if rr.Header().Class != dns.ClassINET {
			t.Errorf("replacement RR is class %d, want ClassINET: %v", rr.Header().Class, rr)
		}
	}
}

func TestBuildZoneUpdateActionsReplaceRejectsMixedRRsets(t *testing.T) {
	for _, tc := range []struct {
		name string
		rrs  []string
		want string
	}{
		{
			"mixed owners",
			[]string{"foo.alpha.dnslab. IN A 1.2.3.4", "bar.alpha.dnslab. IN A 2.3.4.5"},
			"owner",
		},
		{
			"mixed types",
			[]string{"foo.alpha.dnslab. IN A 1.2.3.4", "foo.alpha.dnslab. IN TXT \"x\""},
			"type",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := BuildZoneUpdateActions("alpha.dnslab.", ZoneUpdateSpec{
				Verb: VerbReplaceRRset, RRs: tc.rrs,
			})
			if err == nil {
				t.Fatal("expected a refusal: the RRset is inferred, so mixed input is ambiguous")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}

	// Zero RRs leaves nothing to infer from. Silently treating it as DELRRSET
	// would delete an RRset the operator never named.
	if _, err := BuildZoneUpdateActions("alpha.dnslab.", ZoneUpdateSpec{
		Verb: VerbReplaceRRset,
	}); err == nil {
		t.Error("replacerrset with no RRs was accepted; expected a refusal pointing at delrrset")
	}
}

// The apex SOA and NS RRsets are what make the zone a zone; deleting either
// leaves something unservable, and the applier's apex guard would then refuse
// the whole publish, taking any other change in the same update with it.
func TestBuildZoneUpdateActionsRefusesApexSoaNsDelete(t *testing.T) {
	for _, rrtype := range []string{"SOA", "NS"} {
		if _, err := BuildZoneUpdateActions("alpha.dnslab.", ZoneUpdateSpec{
			Verb: VerbDelRRset, Name: "alpha.dnslab.", Rrtype: rrtype,
		}); err == nil {
			t.Errorf("delrrset accepted deleting the apex %s RRset", rrtype)
		}
	}

	// The same types below the apex are ordinary data: an NS RRset at a
	// delegation point is exactly what delegation management edits.
	if _, err := BuildZoneUpdateActions("alpha.dnslab.", ZoneUpdateSpec{
		Verb: VerbDelRRset, Name: "child.alpha.dnslab.", Rrtype: "NS",
	}); err != nil {
		t.Errorf("delrrset refused a non-apex NS RRset: %v", err)
	}
}

// Meta and query types never exist as RRsets in a zone, but dns.StringToType
// resolves them happily -- so without a check the statement is built, queued,
// and silently does nothing.
func TestBuildZoneUpdateActionsRefusesMetaTypes(t *testing.T) {
	for _, rrtype := range []string{"TSIG", "TKEY", "AXFR", "IXFR", "OPT", "MAILB"} {
		if _, err := BuildZoneUpdateActions("alpha.dnslab.", ZoneUpdateSpec{
			Verb: VerbDelRRset, Name: "foo.alpha.dnslab.", Rrtype: rrtype,
		}); err == nil {
			t.Errorf("delrrset accepted meta type %s", rrtype)
		}
	}
}

func TestBuildZoneUpdateActionsRefusesOutOfBailiwick(t *testing.T) {
	for _, spec := range []ZoneUpdateSpec{
		{Verb: VerbAddRR, RRs: []string{"foo.beta.dnslab. IN A 1.2.3.4"}},
		{Verb: VerbDelRRset, Name: "foo.beta.dnslab.", Rrtype: "A"},
		{Verb: VerbDelName, Name: "foo.beta.dnslab."},
		{Verb: VerbReplaceRRset, RRs: []string{"foo.beta.dnslab. IN A 1.2.3.4"}},
	} {
		if _, err := BuildZoneUpdateActions("alpha.dnslab.", spec); err == nil {
			t.Errorf("%s accepted an owner outside the zone", spec.Verb)
		}
	}
}

func TestBuildZoneUpdateActionsRejectsGarbage(t *testing.T) {
	if _, err := BuildZoneUpdateActions("alpha.dnslab.", ZoneUpdateSpec{
		Verb: "frobnicate", RRs: []string{"foo.alpha.dnslab. IN A 1.2.3.4"},
	}); err == nil {
		t.Error("unknown verb was accepted")
	}
	if _, err := BuildZoneUpdateActions("alpha.dnslab.", ZoneUpdateSpec{
		Verb: VerbAddRR, RRs: []string{"this is not a resource record"},
	}); err == nil {
		t.Error("unparseable RR was accepted")
	}
}
