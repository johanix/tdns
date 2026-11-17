package tdns

import (
	"strings"
	"testing"

	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// mustGrants parses grants for zone, failing the test on an error.
func mustGrants(t *testing.T, zone string, confs ...TsigGrantConf) []TsigGrant {
	t.Helper()
	g, err := parseTsigGrants(zone, confs)
	if err != nil {
		t.Fatalf("parseTsigGrants: %v", err)
	}
	return g
}

// A grant that cannot mean what it says is refused at load, with a reason.
func TestParseTsigGrants_Refusals(t *testing.T) {
	cases := []struct {
		conf TsigGrantConf
		want string
	}{
		{TsigGrantConf{NameType: "zonesub", RRtypes: []string{"A"}}, "no key"},
		{TsigGrantConf{Key: "*", NameType: "self", RRtypes: []string{"A"}}, `key "*" is not supported`},
		{TsigGrantConf{Key: "k.", RRtypes: []string{"A"}}, "no nametype"},
		{TsigGrantConf{Key: "k.", NameType: "wildcard", RRtypes: []string{"A"}}, "unknown nametype"},
		{TsigGrantConf{Key: "k.", NameType: "zonesub", Name: "x.example.", RRtypes: []string{"A"}}, "takes no name"},
		{TsigGrantConf{Key: "h.example.", NameType: "self", Name: "h.example.", RRtypes: []string{"A"}}, "takes no name"},
		{TsigGrantConf{Key: "k.other.", NameType: "self", RRtypes: []string{"A"}}, "could never match"},
		{TsigGrantConf{Key: "k.", NameType: "subdomain", RRtypes: []string{"A"}}, "needs a name"},
		{TsigGrantConf{Key: "k.", NameType: "name", RRtypes: []string{"A"}}, "needs a name"},
		{TsigGrantConf{Key: "k.", NameType: "subdomain", Name: "example.org.", RRtypes: []string{"A"}}, "not in zone"},
		{TsigGrantConf{Key: "k.", NameType: "name", Name: "badexample.", RRtypes: []string{"A"}}, "not in zone"},
		{TsigGrantConf{Key: "k.", NameType: "zonesub"}, "no rrtypes"},
		{TsigGrantConf{Key: "k.", NameType: "zonesub", RRtypes: []string{"A", "BOGUS"}}, `unknown rrtype "BOGUS"`},
	}
	for _, c := range cases {
		_, err := parseTsigGrants("example.", []TsigGrantConf{c.conf})
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: err = %v, want it to contain %q", c.conf, err, c.want)
		}
	}
}

// Keys and names are canonicalised, name types and types are case-insensitive.
func TestParseTsigGrants_Normalises(t *testing.T) {
	g := mustGrants(t, "Example.",
		TsigGrantConf{Key: " DDNS-Key ", NameType: "ZoneSub", RRtypes: []string{"any"}},
		TsigGrantConf{Key: "acme", NameType: "subdomain", Name: "_ACME-challenge.example", RRtypes: []string{"txt"}},
		TsigGrantConf{Key: "H1.example", NameType: "self", RRtypes: []string{"A", "aaaa"}},
	)
	if g[0].Key != "ddns-key." || g[0].NameType != TsigNameZonesub || g[0].Name != "example." || !g[0].Any {
		t.Errorf("zonesub grant: %+v", g[0])
	}
	if g[1].Name != "_acme-challenge.example." || !g[1].RRtypes[dns.TypeTXT] || g[1].Any {
		t.Errorf("subdomain grant: %+v", g[1])
	}
	if g[2].Key != "h1.example." || g[2].Name != "" || !g[2].RRtypes[dns.TypeAAAA] {
		t.Errorf("self grant: %+v", g[2])
	}
}

// The grant check over every name type, case, label boundaries, narrow ANY
// and a TYPE ANY delete.
func TestTsigGrantsAllow(t *testing.T) {
	grants := mustGrants(t, "example.",
		TsigGrantConf{Key: "ddns.", NameType: "zonesub", RRtypes: []string{"ANY"}},
		TsigGrantConf{Key: "acme.", NameType: "subdomain", Name: "_acme-challenge.example.", RRtypes: []string{"TXT"}},
		TsigGrantConf{Key: "h1.example.", NameType: "self", RRtypes: []string{"A", "TXT"}},
		TsigGrantConf{Key: "ms.", NameType: "name", Name: "example.", RRtypes: []string{"DNSKEY", "CDS", "NS"}},
		TsigGrantConf{Key: "full.", NameType: "zonesub", RRtypes: []string{"ANY", "CDS"}},
	)
	cases := []struct {
		key, owner string
		t          uint16
		want       bool
	}{
		// zonesub + ANY: ordinary data anywhere, apex included
		{"ddns.", "host.example.", dns.TypeA, true},
		{"ddns.", "a.b.example.", dns.TypeSSHFP, true},
		{"ddns.", "example.", dns.TypeMX, true},
		{"DDNS.", "HOST.Example.", dns.TypeTXT, true}, // case carries no meaning
		{"ddns.", "host.example.org.", dns.TypeA, false},
		// narrow ANY: none of these unless named
		{"ddns.", "example.", dns.TypeSOA, false},
		{"ddns.", "example.", dns.TypeDNSKEY, false},
		{"ddns.", "x.example.", dns.TypeRRSIG, false},
		{"ddns.", "x.example.", dns.TypeNSEC, false},
		{"ddns.", "x.example.", dns.TypeNSEC3, false},
		{"ddns.", "example.", dns.TypeNSEC3PARAM, false},
		{"ddns.", "example.", dns.TypeCDS, false},
		{"ddns.", "example.", dns.TypeCDNSKEY, false},
		{"ddns.", "example.", dns.TypeCSYNC, false},
		{"ddns.", "example.", dns.TypeZONEMD, false},
		{"full.", "example.", dns.TypeCDS, true}, // ANY plus a named excluded type
		{"full.", "example.", dns.TypeDNSKEY, false},
		// a DELNAME (TYPE ANY) needs a grant of ANY
		{"ddns.", "host.example.", dns.TypeANY, true},
		{"acme.", "_acme-challenge.example.", dns.TypeANY, false},
		// subdomain: the name and below, label-aligned
		{"acme.", "_acme-challenge.example.", dns.TypeTXT, true},
		{"acme.", "www._acme-challenge.example.", dns.TypeTXT, true},
		{"acme.", "x_acme-challenge.example.", dns.TypeTXT, false},
		{"acme.", "_acme-challenge.example.", dns.TypeA, false},
		// self: exactly the key's name
		{"h1.example.", "h1.example.", dns.TypeA, true},
		{"h1.example.", "sub.h1.example.", dns.TypeA, false},
		{"h1.example.", "h2.example.", dns.TypeA, false},
		// name: exactly the name, with the listed types only
		{"ms.", "example.", dns.TypeDNSKEY, true},
		{"ms.", "example.", dns.TypeNS, true},
		{"ms.", "x.example.", dns.TypeNS, false},
		{"ms.", "example.", dns.TypeTXT, false},
		// a key with no grant
		{"other.", "host.example.", dns.TypeA, false},
	}
	for _, c := range cases {
		if got := tsigGrantsAllow(grants, c.key, c.owner, c.t); got != c.want {
			t.Errorf("key %s owner %s type %s: got %v, want %v", c.key, c.owner, dns.TypeToString[c.t], got, c.want)
		}
	}
}

// A refusal says why: no grant for the key, the type, or the owner.
func TestEvalTsigGrants_RefusalReasons(t *testing.T) {
	grants := mustGrants(t, "example.",
		TsigGrantConf{Key: "acme.", NameType: "subdomain", Name: "_acme-challenge.example.", RRtypes: []string{"TXT"}},
	)
	rr := func(s string) dns.RR {
		r, err := dns.NewRR(s)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	cases := []struct {
		key  string
		rr   dns.RR
		ok   bool
		want uint16
	}{
		{"acme.", rr("_acme-challenge.example. 60 IN TXT \"x\""), true, 0},
		{"other.", rr("_acme-challenge.example. 60 IN TXT \"x\""), false, edns0.EDEZoneUpdatesNotAllowed},
		{"acme.", rr("_acme-challenge.example. 60 IN A 192.0.2.1"), false, edns0.EDEZoneUpdateRRtypeNotAllowed},
		{"acme.", rr("www.example. 60 IN TXT \"x\""), false, edns0.EDEZoneUpdateOwnerOutsidePolicy},
	}
	for _, c := range cases {
		ok, ede := evalTsigGrants(grants, c.key, c.rr)
		if ok != c.ok || ede != c.want {
			t.Errorf("key %s rr %s: got (%v, %d), want (%v, %d)", c.key, c.rr, ok, ede, c.ok, c.want)
		}
	}
}

// Activation carries the grants into the policy and leaves allow-updates alone.
func TestActivateUpdatePolicy_TsigGrants(t *testing.T) {
	zconf := &ZoneConf{Name: "example."}
	zconf.UpdatePolicy.Zone.Tsig = []TsigGrantConf{{Key: "k.", NameType: "zonesub", RRtypes: []string{"A"}}}
	options := map[ZoneOption]bool{OptAllowTsigUpdates: true}
	policy, err := activateUpdatePolicy(zconf, options)
	if err != nil {
		t.Fatalf("activateUpdatePolicy: %v", err)
	}
	if len(policy.TsigGrants) != 1 || policy.TsigGrants[0].Key != "k." {
		t.Errorf("grants not carried into the policy: %+v", policy.TsigGrants)
	}
	// TSIG grants do not touch the SIG(0) switch, and type none still turns
	// allow-updates off.
	if options[OptAllowUpdates] {
		t.Error("TSIG grants turned allow-updates on")
	}
	if !options[OptAllowTsigUpdates] {
		t.Error("allow-tsig-updates was turned off")
	}

	zconf.UpdatePolicy.Zone.Tsig = []TsigGrantConf{{Key: "*", NameType: "self", RRtypes: []string{"A"}}}
	if _, err := activateUpdatePolicy(zconf, map[ZoneOption]bool{}); err == nil {
		t.Error("a grant for \"*\" was accepted")
	}
}

// A config reload replaces the zone's update policy even when the new policy
// is empty. The case that went wrong: a zone whose only policy is its TSIG
// grants (no SIG(0) type) has its last grant removed from the config. Every
// field of the reloaded policy is then empty, and the old condition, which
// copied the policy only when some field was set, kept the removed grants in
// effect. A refresher that is not a reload still must not wipe a policy it
// does not carry.
func TestRefresherReplacesUpdatePolicy(t *testing.T) {
	grants := mustGrants(t, "example.", TsigGrantConf{Key: "k.", NameType: "zonesub", RRtypes: []string{"A"}})
	cases := []struct {
		name string
		zr   ZoneRefresher
		want bool
	}{
		{"reload removing the last TSIG grants", ZoneRefresher{ConfigUpdate: true, UpdatePolicySet: true}, true},
		{"reload with grants", ZoneRefresher{ConfigUpdate: true, UpdatePolicySet: true, UpdatePolicy: UpdatePolicy{TsigGrants: grants}}, true},
		{"reload with a SIG(0) type", ZoneRefresher{ConfigUpdate: true, UpdatePolicySet: true, UpdatePolicy: UpdatePolicy{Zone: UpdatePolicyDetail{Type: "selfsub"}}}, true},
		// config-bearing but carrying no policy (a persisted dynamic secondary)
		{"config-bearing, no policy carried", ZoneRefresher{ConfigUpdate: true}, false},
		{"not a reload, no policy", ZoneRefresher{}, false},
		{"not a reload, grants", ZoneRefresher{UpdatePolicy: UpdatePolicy{TsigGrants: grants}}, true},
		{"not a reload, a SIG(0) type", ZoneRefresher{UpdatePolicy: UpdatePolicy{Zone: UpdatePolicyDetail{Type: "self"}}}, true},
	}
	for _, c := range cases {
		if got := refresherReplacesUpdatePolicy(c.zr); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
