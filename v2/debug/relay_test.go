/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package debug

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/debug/peer"
	"github.com/miekg/dns"
)

// A stand-in for tdns-auth: a signing secondary that transfers from the rig's
// upstream and re-serves to the rig's downstream.
//
// Two behaviours. `publishCorrectly` does what the settled rules require --
// one version, signed, one NOTIFY. `publishAsTdnsDoesToday` reproduces the
// chain derived in the design's §2.3: an unsigned state announced first, then
// a signed one, then the same content re-signed, then a fourth NOTIFY for a
// serial already announced.
//
// This is what makes R5 testable at all. Without a controlled SUT there is no
// way to assert that the rig FAILS the broken case, and a rig that only ever
// reports PASS has proved nothing.
type fakeSUT struct {
	srv    *peer.Upstream // serves the zone to the rig's downstream peer
	origin string
	pull   string // the rig's upstream address
	notify string // the rig's downstream address
	tag    uint16

	mu     sync.Mutex
	serial uint32
	react  func(*fakeSUT, *peer.Zone)
	errs   []string
}

const fakeSUTKey = "3600 IN DNSKEY 257 3 15 kRBqRMzUZ6PJyDXkkyOJXHZTRlAvNRTOZUqbXkMDBHo="

func newFakeSUT(t *testing.T, origin string, react func(*fakeSUT, *peer.Zone)) *fakeSUT {
	t.Helper()
	origin = dns.Fqdn(origin)

	// A placeholder first version. The rig's prime step drives the SUT onto
	// real content, exactly as it would a real one.
	seed := peer.ZoneFromRRs(origin, []dns.RR{
		mustTestRR(t, fmt.Sprintf("%s 3600 IN SOA ns.%s hostmaster.%s 1 7200 1800 604800 3600", origin, origin, origin)),
		mustTestRR(t, fmt.Sprintf("%s 3600 IN NS ns.%s", origin, origin)),
	})
	srv, err := peer.NewUpstream(origin, "127.0.0.1:0", seed, 64)
	if err != nil {
		t.Fatalf("fake SUT: %v", err)
	}
	key := mustTestRR(t, origin+" "+fakeSUTKey).(*dns.DNSKEY)
	s := &fakeSUT{srv: srv, origin: origin, tag: key.KeyTag(), serial: 1, react: react}
	srv.OnNotify = func(string) { s.onNotify() }
	srv.Start()
	t.Cleanup(srv.Stop)
	return s
}

func (s *fakeSUT) addr() string { return s.srv.Addr() }

// wire tells the SUT where to pull from and whom to announce to. Under the
// mutex because onNotify reads both from a server goroutine.
func (s *fakeSUT) wire(pull, notify string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pull, s.notify = pull, notify
}

func (s *fakeSUT) failures() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.errs...)
}

// onNotify is the whole inbound path: transfer from upstream, then publish and
// announce according to the configured behaviour.
func (s *fakeSUT) onNotify() {
	s.mu.Lock()
	defer s.mu.Unlock()

	content, err := s.axfrFromUpstream()
	if err != nil {
		s.errs = append(s.errs, "axfr from upstream: "+err.Error())
		return
	}
	s.react(s, content)
}

func (s *fakeSUT) axfrFromUpstream() (*peer.Zone, error) {
	m := new(dns.Msg)
	m.SetAxfr(s.origin)
	tr := &dns.Transfer{DialTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second}
	ch, err := tr.In(m, s.pull)
	if err != nil {
		return nil, err
	}
	var rrs []dns.RR
	for env := range ch {
		if env.Error != nil {
			return nil, env.Error
		}
		rrs = append(rrs, env.RR...)
	}
	return peer.ZoneFromRRs(s.origin, rrs), nil
}

// publish installs one new version and announces it.
func (s *fakeSUT) publish(z *peer.Zone) {
	if _, err := s.srv.Publish(z); err != nil {
		s.errs = append(s.errs, "publish: "+err.Error())
		return
	}
	s.announce()
}

func (s *fakeSUT) announce() {
	m := new(dns.Msg)
	m.SetNotify(s.origin)
	c := &dns.Client{Timeout: 3 * time.Second}
	if _, _, err := c.Exchange(m, s.notify); err != nil {
		s.errs = append(s.errs, "notify: "+err.Error())
	}
}

func (s *fakeSUT) next() uint32 { s.serial++; return s.serial }

// publishCorrectly: one version, fully signed, one NOTIFY.
func publishCorrectly(s *fakeSUT, content *peer.Zone) {
	s.publish(signLike(s.origin, content, s.next(), s.tag, "20260901000000", true))
}

// publishAsTdnsDoesToday reproduces the design's §2.3 chain. The pauses stand
// in for a signing pass, and are what give the rig a chance to observe each
// intermediate -- a real run may not get one, which is why the verdicts are
// three-valued.
func publishAsTdnsDoesToday(s *fakeSUT, content *peer.Zone) {
	// 1. the refresh's own publish: content as transferred, unsigned, but with
	//    a signed SOA and a signed NSEC chain.
	s.publish(signLike(s.origin, content, s.next(), s.tag, "20260901000000", false))
	time.Sleep(400 * time.Millisecond)

	// 2. SetupZoneSigning -> SignZone -> publishLocked (bumps and notifies).
	s.publish(signLike(s.origin, content, s.next(), s.tag, "20260901000000", true))
	time.Sleep(400 * time.Millisecond)

	// 3. the resigner's forced pass over the very same content.
	s.publish(signLike(s.origin, content, s.next(), s.tag, "20260902000000", true))

	// 4. and the refresh engine's own tail NOTIFY, for a serial already announced.
	s.announce()
}

// signLike renders content as a signing server would publish it: a DNSKEY, an
// NSEC chain, and RRSIGs. With signContent false it signs only the SOA, the
// DNSKEY and the chain -- the state the design's §2.1 describes, where a
// validator sees a signed chain over unsigned data.
func signLike(origin string, content *peer.Zone, serial uint32, tag uint16, inception string, signContent bool) *peer.Zone {
	z := content.Clone()
	_ = z.SetSerial(serial)
	z.Add(mustParse(origin + " " + fakeSUTKey))

	owners := canonicalOwners(z, origin)
	types := map[string][]uint16{}
	for _, rr := range z.RRs() {
		n := strings.ToLower(rr.Header().Name)
		types[n] = append(types[n], rr.Header().Rrtype)
	}

	sig := func(owner string, covered uint16) {
		z.Add(mustParse(fmt.Sprintf("%s 3600 IN RRSIG %s 15 %d 3600 20270101000000 %s %d %s c2lnbmF0dXJl",
			owner, dns.TypeToString[covered], dns.CountLabel(owner), inception, tag, origin)))
	}

	for i, owner := range owners {
		next := origin
		if i+1 < len(owners) {
			next = owners[i+1]
		}

		// The NSEC type bitmap MUST be in ascending numeric type order. An
		// alphabetical list parses happily and then fails to PACK, so the
		// server answers nothing and the client sees a timeout with no clue
		// what went wrong. Sorting by name here cost an afternoon.
		present := map[uint16]bool{}
		for _, tp := range types[owner] {
			present[tp] = true
		}
		bitmap := map[uint16]bool{dns.TypeRRSIG: true, dns.TypeNSEC: true}
		for tp := range present {
			bitmap[tp] = true
		}
		codes := make([]uint16, 0, len(bitmap))
		for tp := range bitmap {
			codes = append(codes, tp)
		}
		sort.Slice(codes, func(a, b int) bool { return codes[a] < codes[b] })
		names := make([]string, 0, len(codes))
		for _, c := range codes {
			names = append(names, dns.TypeToString[c])
		}

		z.Add(mustParse(fmt.Sprintf("%s 3600 IN NSEC %s %s", owner, next, strings.Join(names, " "))))
		sig(owner, dns.TypeNSEC)

		for tp := range present {
			if signContent || tp == dns.TypeSOA || tp == dns.TypeDNSKEY {
				sig(owner, tp)
			}
		}
	}
	return z
}

// canonicalOwners orders the apex first, then its children. Every name the rig
// authors is a direct child of the apex, so a plain string sort of the whole
// name puts them in label order.
func canonicalOwners(z *peer.Zone, origin string) []string {
	set := map[string]bool{}
	for _, rr := range z.RRs() {
		set[strings.ToLower(rr.Header().Name)] = true
	}
	var kids []string
	for n := range set {
		if n != origin {
			kids = append(kids, n)
		}
	}
	sort.Strings(kids)
	return append([]string{origin}, kids...)
}

func mustParse(s string) dns.RR {
	rr, err := dns.NewRR(s)
	if err != nil {
		panic(fmt.Sprintf("fixture %q: %v", s, err))
	}
	return rr
}

func mustTestRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("fixture %q: %v", s, err)
	}
	return rr
}

// runAgainst wires the rig to a fake SUT and runs it.
func runAgainst(t *testing.T, react func(*fakeSUT, *peer.Zone), rounds int) (*Report, *RelayResult, *fakeSUT) {
	return runProfile(t, ProfileSigning, react, rounds)
}

func runProfile(t *testing.T, profile string, react func(*fakeSUT, *peer.Zone), rounds int) (*Report, *RelayResult, *fakeSUT) {
	t.Helper()
	const zone = "relay.test."
	sut := newFakeSUT(t, zone, react)

	cfg := RelayConfig{
		Zone: zone, SUT: sut.addr(), Profile: profile,
		UpstreamListen: "127.0.0.1:0", DownstreamListen: "127.0.0.1:0",
		Rounds: rounds, Settle: time.Second, RoundTimeout: 20 * time.Second,
		Seed: 1, Tool: "tdns-debug-test",
	}
	up, down, err := NewRelayPeers(cfg)
	if err != nil {
		t.Fatalf("NewRelayPeers: %v", err)
	}
	up.Start()
	down.Start()
	t.Cleanup(up.Stop)
	t.Cleanup(down.Stop)

	sut.wire(up.Addr(), down.Addr())

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	rep, res, err := RunRelay(ctx, cfg, up, down)
	if errs := sut.failures(); len(errs) > 0 {
		t.Fatalf("the fake SUT itself failed, so the verdicts mean nothing: %v (run err: %v)", errs, err)
	}
	if err != nil {
		t.Fatalf("RunRelay: %v", err)
	}
	// Always log the table: a run that passes for the wrong reason (say, every
	// verdict inconclusive) is indistinguishable from a good one otherwise.
	var b strings.Builder
	RenderRounds(&b, res)
	t.Log("\n" + b.String())
	return rep, res, sut
}

func verdicts(t *testing.T, res *RelayResult, round int) map[string]Verdict {
	t.Helper()
	if len(res.Rounds) < round {
		t.Fatalf("only %d rounds ran, wanted at least %d", len(res.Rounds), round)
	}
	return res.Rounds[round-1].Verdicts
}

func TestRelayPassesAServerThatFollowsTheRules(t *testing.T) {
	rep, res, _ := runAgainst(t, publishCorrectly, 2)

	for i := 1; i <= len(res.Rounds); i++ {
		rr := res.Rounds[i-1]
		if len(rr.NewSerials) != 1 {
			t.Fatalf("round %d: one change produced %d serials (%v), want 1", i, len(rr.NewSerials), rr.NewSerials)
		}
		if rr.Notifies != 1 {
			t.Fatalf("round %d: one change produced %d NOTIFYs, want 1", i, rr.Notifies)
		}
		for _, inv := range []string{"N1", "N2", "N3", "N4", "N5", "N6"} {
			if got := verdicts(t, res, i)[inv]; got.Result != VerdictPass {
				t.Fatalf("round %d: %s = %s (%s), want pass", i, inv, got.Result, got.Detail)
			}
		}
		// One state per round, so there is no pair to compare: inconclusive is
		// the honest answer, and claiming a pass would be the bug.
		if got := verdicts(t, res, i)["N7"]; got.Result != VerdictInconclusive {
			t.Fatalf("round %d: N7 = %s, want inconclusive with one observed state", i, got.Result)
		}
	}
	if len(rep.Violations) != 0 {
		t.Fatalf("a rule-following server produced %d violation(s): %+v", len(rep.Violations), rep.Violations)
	}
	if rep.ExitCode() != ExitOK {
		t.Fatalf("exit code = %d, want %d", rep.ExitCode(), ExitOK)
	}
}

// The instrument's whole purpose: it must report the behaviour the design
// derived. A rig that cannot see this is not finished.
func TestRelayCatchesTodaysBehaviour(t *testing.T) {
	rep, res, _ := runAgainst(t, publishAsTdnsDoesToday, 1)
	rr := res.Rounds[0]
	v := verdicts(t, res, 1)

	if len(rr.NewSerials) != 3 {
		t.Fatalf("expected one change to produce 3 serials (design §2.3), got %d: %v", len(rr.NewSerials), rr.NewSerials)
	}
	if rr.Notifies != 4 {
		t.Fatalf("expected 4 NOTIFYs (design §2.3), got %d", rr.Notifies)
	}

	if v["N1"].Result != VerdictFail {
		t.Fatalf("N1 = %s (%s); three serials for one change must fail", v["N1"].Result, v["N1"].Detail)
	}
	if !strings.Contains(v["N1"].Detail, "3 new serials") {
		t.Fatalf("N1 detail does not name the count: %q", v["N1"].Detail)
	}

	if v["N2"].Result != VerdictFail {
		t.Fatalf("N2 = %s (%s); four NOTIFYs for three serials must fail", v["N2"].Result, v["N2"].Detail)
	}
	if !strings.Contains(v["N2"].Detail, "announced twice") {
		t.Fatalf("N2 detail does not name the defect: %q", v["N2"].Detail)
	}

	if v["N3"].Result != VerdictFail {
		t.Fatalf("N3 = %s (%s); an unsigned announced state must fail", v["N3"].Result, v["N3"].Detail)
	}
	if !strings.Contains(v["N3"].Detail, "not fully signed") {
		t.Fatalf("N3 detail does not name the defect: %q", v["N3"].Detail)
	}

	if v["N7"].Result != VerdictFail {
		t.Fatalf("N7 = %s (%s); re-signing content already published must fail", v["N7"].Result, v["N7"].Detail)
	}
	if !strings.Contains(v["N7"].Detail, "re-signs") {
		t.Fatalf("N7 detail does not name the defect: %q", v["N7"].Detail)
	}

	// The content still arrives correctly -- that is what makes this hard to
	// notice without counting, and the rig must not confuse the two.
	if v["N4"].Result != VerdictPass {
		t.Fatalf("N4 = %s (%s); the content itself is correct", v["N4"].Result, v["N4"].Detail)
	}
	if v["N5"].Result != VerdictPass {
		t.Fatalf("N5 = %s (%s); the deltas do express the change", v["N5"].Result, v["N5"].Detail)
	}

	if rep.ExitCode() != ExitViolation {
		t.Fatalf("exit code = %d, want %d", rep.ExitCode(), ExitViolation)
	}
}

// Section 0 is a precondition, not a check among others: if a comparator
// cannot report a difference, nothing above it means anything.
func TestSection0Discriminates(t *testing.T) {
	if err := section0(); err != nil {
		t.Fatalf("section 0 failed on a healthy build: %v", err)
	}
}

func TestChangeGenIsReproducibleAndValid(t *testing.T) {
	a := newChangeGen("relay.test.", 42)
	b := newChangeGen("relay.test.", 42)
	kinds := map[string]bool{}
	for i := 0; i < 40; i++ {
		x, y := a.Next(), b.Next()
		if x.String() != y.String() {
			t.Fatalf("change %d differs between two generators on the same seed:\n  %s\n  %s", i, x, y)
		}
		kinds[x.Label] = true
	}
	// "grow" is the shape whose delta must carry a removal AND an addition for
	// one owner and type. A generator that never emits it leaves the case an
	// IXFR applier is most easily wrong about untested.
	for _, want := range []string{"add", "delete", "replace", "grow"} {
		if !kinds[want] {
			t.Fatalf("40 changes never produced a %q; kinds seen: %v", want, kinds)
		}
	}
}

// A generated change must be applicable to the zone it was generated against,
// every time: History.Apply refuses a removal of an RR the zone does not hold,
// so a generator that lost track of its own state would abort a run.
func TestChangeGenChangesAlwaysApply(t *testing.T) {
	z, err := buildSeedZone("relay.test.", 100)
	if err != nil {
		t.Fatalf("buildSeedZone: %v", err)
	}
	h := peer.NewHistory("relay.test.", 200)
	if err := h.Seed(z); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	g := newChangeGen("relay.test.", 7)
	for i := 0; i < 100; i++ {
		if _, err := h.Apply(g.Next()); err != nil {
			t.Fatalf("generated change %d did not apply: %v", i, err)
		}
	}
}

// --- the mirroring profile -------------------------------------------------

// mirrorVerbatim is a plain secondary doing the right thing: it publishes what
// it received, unchanged, upstream's serial included, and announces once.
func mirrorVerbatim(s *fakeSUT, content *peer.Zone) {
	s.publish(content.Clone())
}

// mirrorWithDrift reproduces the historical unconditional ++ that
// applyRefreshReplacementLocked's MUST-NOT-MODIFY branch exists to prevent:
// the content is perfect and the serial is one ahead of upstream's.
func mirrorWithDrift(s *fakeSUT, content *peer.Zone) {
	z := content.Clone()
	_ = z.SetSerial(content.Serial() + 1)
	s.publish(z)
}

// An unsigned zone through a non-signing tdns-auth: what comes out must be
// what went in, byte for byte, serial included.
func TestRelayMirrorPassesAVerbatimSecondary(t *testing.T) {
	rep, res, _ := runProfile(t, ProfileMirror, mirrorVerbatim, 2)

	for i := 1; i <= len(res.Rounds); i++ {
		rr := res.Rounds[i-1]
		v := verdicts(t, res, i)
		if rr.Notifies != 1 || len(rr.NewSerials) != 1 {
			t.Fatalf("round %d: %d NOTIFYs and %d serials for one change, want 1 and 1", i, rr.Notifies, len(rr.NewSerials))
		}
		for _, inv := range []string{"N1", "N2", "N4", "N5", "N8"} {
			if got := v[inv]; got.Result != VerdictPass {
				t.Fatalf("round %d: %s = %s (%s), want pass", i, inv, got.Result, got.Detail)
			}
		}
		// Nothing here signs, so the signing invariants are not applicable --
		// which is a different statement from "could not decide", and must not
		// read as either a pass or a failure.
		for _, inv := range []string{"N3", "N6", "N7"} {
			if got := v[inv]; got.Result != VerdictNA {
				t.Fatalf("round %d: %s = %s (%s), want n/a on an unsigned zone", i, inv, got.Result, got.Detail)
			}
		}
	}
	if len(rep.Violations) != 0 {
		t.Fatalf("a verbatim mirror produced %d violation(s): %+v", len(rep.Violations), rep.Violations)
	}
}

// The serial drift is invisible to every other check, because the CONTENT is
// right. That is exactly why it needs its own invariant.
func TestRelayMirrorCatchesSerialDrift(t *testing.T) {
	rep, res, _ := runProfile(t, ProfileMirror, mirrorWithDrift, 1)
	v := verdicts(t, res, 1)

	if v["N8"].Result != VerdictFail {
		t.Fatalf("N8 = %s (%s); a mirror that advances the serial must fail", v["N8"].Result, v["N8"].Detail)
	}
	if !strings.Contains(v["N8"].Detail, "must mirror it verbatim") {
		t.Fatalf("N8 detail does not name the rule: %q", v["N8"].Detail)
	}
	for _, inv := range []string{"N1", "N2", "N4", "N5"} {
		if got := v[inv]; got.Result != VerdictPass {
			t.Fatalf("%s = %s (%s); the content and the announcement are correct, which is what makes the drift hard to see",
				inv, got.Result, got.Detail)
		}
	}
	if rep.ExitCode() != ExitViolation {
		t.Fatalf("exit code = %d, want %d", rep.ExitCode(), ExitViolation)
	}
}

// A signing SUT must not be judged by the mirror rules, and vice versa.
func TestRelayRejectsAnUnknownProfile(t *testing.T) {
	_, _, err := RunRelay(context.Background(), RelayConfig{Zone: "relay.test.", Profile: "guess"}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "unknown profile") {
		t.Fatalf("err = %v, want an unknown-profile refusal", err)
	}
}
