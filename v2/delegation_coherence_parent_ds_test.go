/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"net/http"
	"strings"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// #838: a child that already has a DS may change it only on a DNSKEY RRset
// that is authenticated. The resolver's Secure is one way. At a parent that is
// unsigned, or that no trust anchor of its resolver covers, the answer is never
// Secure, and every DS change after the first was refused for good. The DS the
// parent itself publishes is the other way: the child's DNSKEY RRset must be
// signed by a key matching it.

// fetcherAnswer returns a fetcher that answers with rrset, and state as the
// resolver's verdict on it.
func fetcherAnswer(state cache.ValidationState, rrset *core.RRset) dnskeyFetcher {
	return func(string) (*core.RRset, cache.ValidationState, error) { return rrset, state, nil }
}

// dsForKey is the SHA-256 DS for k.
func dsForKey(t *testing.T, k *signerTestKey) *dns.DS {
	t.Helper()
	ds := k.dnskey.ToDS(dns.SHA256)
	if ds == nil {
		t.Fatal("ToDS returned nil")
	}
	return ds
}

// testKeys is shorthand for a list of test keys.
func testKeys(k ...*signerTestKey) []*signerTestKey { return k }

// A KSK rollover at a parent whose resolver cannot validate the child: the new
// KSK's DS is added, and later the old one's is withdrawn. Both are accepted,
// because each time the DNSKEY RRset is signed by a key the parent already
// holds a DS for.
func TestCoherenceTheParentsDSAuthenticatesAnUnvalidatedAnswer(t *testing.T) {
	oldKSK := newSignerTestKey(t, cohChild, 257)
	newKSK := newSignerTestKey(t, cohChild, 257)
	oldDS, newDS := dsForKey(t, oldKSK), dsForKey(t, newKSK)
	now := time.Now()
	inc, exp := now.Add(-time.Hour), now.Add(time.Hour)

	for _, state := range []cache.ValidationState{
		cache.ValidationStateInsecure, cache.ValidationStateIndeterminate, 0,
	} {
		t.Run(validationStateName(state), func(t *testing.T) {
			// Both KSKs published, the RRset signed by both; the new one's
			// signature comes first and names a key the parent has no DS for
			// yet, so every signature has to be tried.
			both := signedDnskeys(t, testKeys(oldKSK, newKSK), testKeys(newKSK, oldKSK), inc, exp)
			if err := CheckDelegationCoherence(cohChild, []dns.RR{oldDS},
				[]dns.RR{addDS(newDS)}, fetcherAnswer(state, both)); err != nil {
				t.Fatalf("the new KSK's DS was refused: %v", err)
			}

			// The old KSK is gone and only the new one signs. The parent holds
			// its DS already, so withdrawing the old DS is authenticated too.
			onlyNew := signedDnskeys(t, testKeys(newKSK), testKeys(newKSK), inc, exp)
			if err := CheckDelegationCoherence(cohChild, []dns.RR{oldDS, newDS},
				[]dns.RR{delOneDS(oldDS)}, fetcherAnswer(state, onlyNew)); err != nil {
				t.Fatalf("withdrawing the old KSK's DS was refused: %v", err)
			}
		})
	}
}

// The double-DS rollover's first step: a DS for a key the child does not
// publish yet, while the live key still signs.
func TestCoherenceTheParentsDSAllowsAPrePublishedDS(t *testing.T) {
	live := newSignerTestKey(t, cohChild, 257)
	incoming := newSignerTestKey(t, cohChild, 257)
	now := time.Now()
	rrset := signedDnskeys(t, testKeys(live), testKeys(live), now.Add(-time.Hour), now.Add(time.Hour))

	if err := CheckDelegationCoherence(cohChild, []dns.RR{dsForKey(t, live)},
		[]dns.RR{addDS(dsForKey(t, incoming))},
		fetcherAnswer(cache.ValidationStateInsecure, rrset)); err != nil {
		t.Fatalf("a pre-published DS was refused: %v", err)
	}
}

// What an attacker can supply is an RRset no key matching the parent's DS has
// signed, or one whose signature is no longer (or not yet) valid. Whatever the
// resolver said short of Secure, that is refused, and the refusal says what the
// resolver said and that the parent's own DS did not validate it either.
func TestCoherenceRefusesWhatNeitherTheResolverNorTheParentsDSValidates(t *testing.T) {
	live := newSignerTestKey(t, cohChild, 257)
	rogue := newSignerTestKey(t, cohChild, 257)
	now := time.Now()
	inc, exp := now.Add(-time.Hour), now.Add(time.Hour)

	// A signature that names the live key, made with the rogue one.
	forged := signedDnskeys(t, testKeys(live, rogue), nil, inc, exp)
	sig := &dns.RRSIG{
		Algorithm:  live.dnskey.Algorithm,
		Inception:  uint32(inc.Unix()),
		Expiration: uint32(exp.Unix()),
		KeyTag:     live.dnskey.KeyTag(),
		SignerName: cohChild,
	}
	if err := sig.Sign(rogue.priv, forged.RRs); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	forged.RRSIGs = []dns.RR{sig}

	for _, tc := range []struct {
		name  string
		state cache.ValidationState
		rrset *core.RRset
		want  string
	}{
		{"a key the parent has no DS for, signing itself", cache.ValidationStateInsecure,
			signedDnskeys(t, testKeys(rogue), testKeys(rogue), inc, exp), "none of its 1 DNSKEY(s) matches"},
		{"the live key copied in, the RRset signed by another", cache.ValidationStateInsecure,
			signedDnskeys(t, testKeys(live, rogue), testKeys(rogue), inc, exp), "no RRSIG by key"},
		{"a signature naming the live key, made with another", cache.ValidationStateIndeterminate,
			forged, "does not verify"},
		{"the live key, unsigned", cache.ValidationStateInsecure,
			signedDnskeys(t, testKeys(live), nil, inc, exp), "no RRSIG by key"},
		{"signed by the live key, expired", cache.ValidationStateInsecure,
			signedDnskeys(t, testKeys(live), testKeys(live), now.Add(-2*time.Hour), now.Add(-time.Hour)), "validity period"},
		{"signed by the live key, not valid yet", cache.ValidationStateInsecure,
			signedDnskeys(t, testKeys(live), testKeys(live), now.Add(time.Hour), now.Add(2*time.Hour)), "validity period"},
		{"bogus, and signed by a key the parent has no DS for", cache.ValidationStateBogus,
			signedDnskeys(t, testKeys(live, rogue), testKeys(rogue), inc, exp), "no RRSIG by key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The update adds a DS for the rogue key, which the RRset carries:
			// on an unauthenticated answer it would pass the matching rule.
			err := CheckDelegationCoherence(cohChild, []dns.RR{dsForKey(t, live)},
				[]dns.RR{addDS(dsForKey(t, rogue))}, fetcherAnswer(tc.state, tc.rrset))
			if err == nil {
				t.Fatal("a DS change was accepted on an answer neither the resolver nor the parent's DS validates")
			}
			for _, want := range []string{
				"did not DNSSEC-validate",
				"resolver: " + validationStateName(tc.state),
				"not signed by a key matching the DS this parent publishes",
				tc.want,
			} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("refusal does not say %q: %v", want, err)
				}
			}
		})
	}
}

// Bogus from the resolver is decided the same way. The parent's check is made
// on the RRset in hand, against the DS the parent publishes now, so a forged or
// altered RRset fails it whatever the resolver said (the Bogus case above).
// What passes it and is still Bogus to the resolver is a disagreement about the
// chain, not the keys: here, a resolver still holding the DS RRset from before
// the new KSK's DS was added, when the child has since dropped the old KSK.
func TestCoherenceABogusAnswerIsDecidedByTheParentsDS(t *testing.T) {
	oldKSK := newSignerTestKey(t, cohChild, 257)
	newKSK := newSignerTestKey(t, cohChild, 257)
	oldDS, newDS := dsForKey(t, oldKSK), dsForKey(t, newKSK)
	now := time.Now()
	onlyNew := signedDnskeys(t, testKeys(newKSK), testKeys(newKSK), now.Add(-time.Hour), now.Add(time.Hour))

	if err := CheckDelegationCoherence(cohChild, []dns.RR{oldDS, newDS},
		[]dns.RR{delOneDS(oldDS)}, fetcherAnswer(cache.ValidationStateBogus, onlyNew)); err != nil {
		t.Fatalf("a DNSKEY RRset signed by a key the parent holds a DS for was refused on"+
			" the resolver's Bogus: %v", err)
	}
}

// Where the parent's own DS is not asked, nothing changes: a Secure answer
// needs nothing more, and a child with no DS yet has nothing to be checked
// against (RFC 8078 bootstrap).
func TestCoherenceTheParentsDSIsAskedOnlyWhenTheResolverDidNotValidate(t *testing.T) {
	live := newSignerTestKey(t, cohChild, 257)
	incoming := newSignerTestKey(t, cohChild, 257)
	unsigned := signedDnskeys(t, testKeys(live), nil, time.Time{}, time.Time{})

	if err := CheckDelegationCoherence(cohChild, []dns.RR{dsForKey(t, live)},
		[]dns.RR{addDS(dsForKey(t, incoming))},
		fetcherAnswer(cache.ValidationStateSecure, unsigned)); err != nil {
		t.Errorf("a Secure answer was refused: %v", err)
	}
	if err := CheckDelegationCoherence(cohChild, nil, []dns.RR{addDS(dsForKey(t, live))},
		fetcherAnswer(cache.ValidationStateInsecure, unsigned)); err != nil {
		t.Errorf("a first DS was refused: %v", err)
	}
}

// childDSParent is a parent that takes child updates of DS, and publishes ds
// for child.parent.example.
func childDSParent(t *testing.T, ds ...*dns.DS) *ZoneData {
	t.Helper()
	zone := childKeyParentZone
	for _, d := range ds {
		zone += d.String() + "\n"
	}
	zd := testSnapshotZone(t, "parent.example.", zone)
	zd.Options = map[ZoneOption]bool{OptAllowChildUpdates: true}
	zd.UpdatePolicy = UpdatePolicy{
		Child: UpdatePolicyDetail{Type: "selfsub", RRtypes: map[uint16]bool{dns.TypeDS: true}, TTL: 120},
	}
	return zd
}

// resolverAnswers makes this server's resolver answer the DNSKEY query for
// child from its cache: rrset, with state as the verdict it holds.
func resolverAnswers(t *testing.T, child string, rrset *core.RRset, state cache.ValidationState) {
	t.Helper()
	imr := newTestImr(t)
	imr.Cache.Set(child, dns.TypeDNSKEY, &cache.CachedRRset{Name: child, RRtype: dns.TypeDNSKEY,
		RRset: rrset, Context: cache.ContextAnswer, State: state, Expiration: time.Now().Add(time.Hour)})
	prevImr, prevReady := Conf.Internal.ImrEngine, Conf.Internal.ImrReady
	Conf.Internal.ImrEngine, Conf.Internal.ImrReady = imr, nil
	t.Cleanup(func() { Conf.Internal.ImrEngine, Conf.Internal.ImrReady = prevImr, prevReady })
}

// The whole UPDATE path: the DS the parent publishes, the resolver's Insecure
// answer as it hands it over, and the refusal the child is sent.
func TestApproveChildUpdateTakesTheParentsDSOverAnInsecureAnswer(t *testing.T) {
	const child = "child.parent.example."
	oldKSK := newSignerTestKey(t, child, 257)
	newKSK := newSignerTestKey(t, child, 257)
	rogue := newSignerTestKey(t, child, 257)
	now := time.Now()
	inc, exp := now.Add(-time.Hour), now.Add(time.Hour)
	zd := childDSParent(t, dsForKey(t, oldKSK))

	update := func() (bool, *UpdateStatus, error) {
		r := new(dns.Msg)
		r.SetUpdate(zd.ZoneName)
		r.Ns = []dns.RR{addDS(dsForKey(t, newKSK))}
		us := &UpdateStatus{
			Type:                  "CHILD-UPDATE",
			Validated:             true,
			ValidatedByTrustedKey: true,
			SignerName:            child,
			ValidationRcode:       dns.RcodeSuccess,
		}
		approved, _, err := zd.ApproveChildUpdate(zd.ZoneName, us, r)
		return approved, us, err
	}

	resolverAnswers(t, child, signedDnskeys(t, testKeys(oldKSK, newKSK), testKeys(oldKSK), inc, exp),
		cache.ValidationStateInsecure)
	if approved, _, err := update(); !approved || err != nil {
		t.Fatalf("the roll's DS add was not approved (err %v)", err)
	}

	resolverAnswers(t, child, signedDnskeys(t, testKeys(oldKSK, newKSK), testKeys(rogue), inc, exp),
		cache.ValidationStateInsecure)
	approved, us, err := update()
	if approved || err == nil {
		t.Fatal("approved on a DNSKEY RRset no key matching the parent's DS signs")
	}
	if !strings.Contains(err.Error(), "resolver: insecure") {
		t.Errorf("the refusal does not name the resolver's verdict: %v", err)
	}
	if us.ValidationRcode != dns.RcodeRefused || us.RejectionEDE != edns0.EDEDelegationIncoherent {
		t.Errorf("rcode %s, EDE %d; want REFUSED with EDE %d",
			dns.RcodeToString[int(us.ValidationRcode)], us.RejectionEDE, edns0.EDEDelegationIncoherent)
	}
}

// The DSYNC API path runs the same check on the same DS and the same answer:
// the request as the handler builds it, the check as the handler calls it, and
// the status it answers.
func TestDsyncApiTakesTheParentsDSOverAnInsecureAnswer(t *testing.T) {
	const child = "child.parent.example."
	oldKSK := newSignerTestKey(t, child, 257)
	newKSK := newSignerTestKey(t, child, 257)
	rogue := newSignerTestKey(t, child, 257)
	now := time.Now()
	inc, exp := now.Add(-time.Hour), now.Add(time.Hour)
	zd := childDSParent(t, dsForKey(t, oldKSK))

	check := func() error {
		actions, err := dsyncApiBuildActions(zd, child, []DsyncApiRRset{{
			Owner: child, Type: "DS",
			RRs: []string{dsForKey(t, oldKSK).String(), dsForKey(t, newKSK).String()},
		}})
		if err != nil {
			t.Fatalf("dsyncApiBuildActions: %v", err)
		}
		return zd.CheckDelegationCoherenceForUpdate(actions, coherenceDnskeyFetcher(&Conf))
	}

	resolverAnswers(t, child, signedDnskeys(t, testKeys(oldKSK, newKSK), testKeys(oldKSK), inc, exp),
		cache.ValidationStateInsecure)
	if err := check(); err != nil {
		t.Fatalf("the roll's DS add was refused: %v", err)
	}

	resolverAnswers(t, child, signedDnskeys(t, testKeys(oldKSK, newKSK), testKeys(rogue), inc, exp),
		cache.ValidationStateInsecure)
	err := check()
	if err == nil {
		t.Fatal("accepted on a DNSKEY RRset no key matching the parent's DS signs")
	}
	if !strings.Contains(err.Error(), "resolver: insecure") {
		t.Errorf("the refusal does not name the resolver's verdict: %v", err)
	}
	if got := dsyncApiCoherenceStatus(err); got != http.StatusConflict {
		t.Errorf("status %d, want %d: the parent has decided, and asking again changes nothing",
			got, http.StatusConflict)
	}
}
