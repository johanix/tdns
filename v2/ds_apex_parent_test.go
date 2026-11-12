/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"strings"
	"testing"
	"time"

	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// A DS at the apex of a zone hosted here is that zone's parent's data (RFC 4035
// section 3.1.4.1). With the parent hosted here too, the parent answers it, by
// the parent's state: the child's state is not asked, whether the child has no
// copy, is in error, is withheld or is past SOA EXPIRE. With no parent hosted,
// the answer is the child's own NODATA, from its copy, and the child's state
// decides. The root has no parent: FindParentZone(".") is the root itself, so
// its own state decides. Every reply carries an OPT when the query had one
// (RFC 6891 section 6.1.1), and none when it had none (johanix/tdns#1036).

const (
	apexParent = "example."
	dsSecure   = "secure.example."
	dsInsecure = "insecure.example."
	dsLonely   = "lonely.test."
)

// dsParentText is a parent signed elsewhere, as a secondary holds one: a
// signed delegation (DS) and an insecure one (NS only), its NSEC chain, and the
// signer's signatures (upstreamSig, by "example."), so that a DO answer from it
// carries the parent's signatures and its NSEC at the insecure cut.
var dsParentText = strings.Join([]string{
	apexParent + " 3600 IN SOA ns.example. hostmaster.example. 1 7200 1800 604800 300",
	apexParent + " 3600 IN NS ns.example.",
	"ns.example. 3600 IN A 192.0.2.1",
	dsSecure + " 3600 IN NS ns.secure.example.",
	dsSecure + " 3600 IN DS 12345 15 2 " + strings.Repeat("ab", 32),
	"ns.secure.example. 3600 IN A 192.0.2.2",
	dsInsecure + " 3600 IN NS ns.insecure.example.",
	"ns.insecure.example. 3600 IN A 192.0.2.3",
	apexParent + " 300 IN NSEC insecure.example. NS SOA RRSIG NSEC",
	dsInsecure + " 300 IN NSEC ns.example. NS RRSIG NSEC",
	"ns.example. 300 IN NSEC secure.example. A RRSIG NSEC",
	dsSecure + " 300 IN NSEC example. NS DS RRSIG NSEC",
	upstreamSig(apexParent, "SOA"),
	upstreamSig(apexParent, "NS"),
	upstreamSig(apexParent, "NSEC"),
	upstreamSig("ns.example.", "A"),
	upstreamSig("ns.example.", "NSEC"),
	upstreamSig(dsSecure, "DS"),
	upstreamSig(dsSecure, "NSEC"),
	upstreamSig(dsInsecure, "NSEC"),
}, "\n") + "\n"

const dsRootText = `. 3600 IN SOA a.root. hostmaster.root. 7 7200 1800 604800 300
. 3600 IN NS a.root.
a.root. 3600 IN A 192.0.2.53
`

func dsChildText(name string) string {
	return name + " 3600 IN SOA ns." + name + " hostmaster." + name + " 1 7200 1800 604800 300\n" +
		name + " 3600 IN NS ns." + name + "\n" +
		"ns." + name + " 3600 IN A 192.0.2.9\n"
}

// dsState is a state a zone is in, and in each of them but dsHealthy the zone
// answers no query (servesQueries).
type dsState string

const (
	dsHealthy  dsState = "healthy"
	dsNoCopy   dsState = "no copy"
	dsInError  dsState = "in error"
	dsWithheld dsState = "withheld"
	dsExpired  dsState = "expired"
	dsXfrOnly  dsState = "held only for transfer"
)

// dsNotServing is every state in which the query handler's guards SERVFAIL.
var dsNotServing = []dsState{dsNoCopy, dsInError, dsWithheld, dsExpired}

// dsZone registers zone name, built from text, in state. It needs authApp:
// only tdns-auth enforces SOA EXPIRE.
func dsZone(t *testing.T, name, text string, state dsState) *ZoneData {
	t.Helper()
	var zd *ZoneData
	if state == dsNoCopy {
		// Registered and not withheld, with nothing loaded yet: the case that
		// has nothing to do with withholding.
		zd = &ZoneData{ZoneName: name, ZoneStore: MapZone}
		registerZones(t, zd)
	} else {
		zd = testSnapshotZone(t, name, text)
	}
	switch state {
	case dsInError:
		zd.SetError(ConfigError, "a service-impacting error, for the test")
	case dsWithheld:
		zd.mu.Lock()
		zd.withheld = true
		zd.mu.Unlock()
	case dsExpired:
		zd.ZoneType = Secondary
		zd.LatestRefresh = time.Now().Add(-8 * 24 * time.Hour)
	case dsXfrOnly:
		zd.ZoneStore = XfrZone
	}
	if got := zd.servesQueries(); got != (state == dsHealthy) {
		t.Fatalf("setup: %s %s: servesQueries() is %v", name, state, got)
	}
	return zd
}

// dsWay is one way of asking: without EDNS, with EDNS and DO clear, or with DO
// set.
type dsWay struct {
	name     string
	edns, do bool
}

var dsWays = []dsWay{{"no EDNS", false, false}, {"EDNS", true, false}, {"EDNS and DO", true, true}}

// askWay asks DefaultQueryHandler for <qname, qtype> the way given, and checks
// that the reply carries an OPT exactly when the query did.
func askWay(t *testing.T, qname string, qtype uint16, way dsWay, when string) *dns.Msg {
	t.Helper()
	return askWayCtx(t, context.Background(), qname, qtype, way, when)
}

func askWayCtx(t *testing.T, ctx context.Context, qname string, qtype uint16, way dsWay, when string) *dns.Msg {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(qname, qtype)
	if way.edns {
		req.SetEdns0(dns.DefaultMsgSize, way.do)
	}
	m := askMsgCtx(t, ctx, req)
	switch opt := m.IsEdns0(); {
	case way.edns && opt == nil:
		t.Errorf("%s, %s: asked with an OPT and answered without one", when, way.name)
	case !way.edns && opt != nil:
		t.Errorf("%s, %s: asked without an OPT and answered with one", when, way.name)
	}
	return m
}

func wantEmptyServfail(t *testing.T, m *dns.Msg, when string) {
	t.Helper()
	if m.Rcode != dns.RcodeServerFailure || len(m.Answer)+len(m.Ns) != 0 {
		t.Errorf("%s: rcode %s, %d answers, %d authority: want an empty SERVFAIL",
			when, dns.RcodeToString[m.Rcode], len(m.Answer), len(m.Ns))
	}
}

// wantParentsDS: the parent's DS RRset for dsSecure, with the parent's
// signature over it when DO was set and without one when it was not.
func wantParentsDS(t *testing.T, m *dns.Msg, way dsWay, when string) {
	t.Helper()
	if m.Rcode != dns.RcodeSuccess || !m.Authoritative {
		t.Errorf("%s: rcode %s, AA %v: want the parent's authoritative DS", when, dns.RcodeToString[m.Rcode], m.Authoritative)
		return
	}
	var ds, sigs int
	for _, rr := range m.Answer {
		switch rr := rr.(type) {
		case *dns.DS:
			if rr.Hdr.Name == dsSecure {
				ds++
			}
		case *dns.RRSIG:
			if rr.TypeCovered == dns.TypeDS && rr.SignerName == apexParent {
				sigs++
			}
		}
	}
	if ds != 1 {
		t.Errorf("%s: answer %v: want the parent's one DS", when, m.Answer)
	}
	if want := map[bool]int{true: 1, false: 0}[way.do]; sigs != want {
		t.Errorf("%s: %d signatures by the parent over the DS, want %d", when, sigs, want)
	}
}

// wantParentsNODATA: the parent's NODATA for dsInsecure, under the parent's
// SOA, and with DO its NSEC at the cut, which lists NS and not DS: the proof
// that the delegation is insecure.
func wantParentsNODATA(t *testing.T, m *dns.Msg, way dsWay, when string) {
	t.Helper()
	if m.Rcode != dns.RcodeSuccess || !m.Authoritative || len(m.Answer) != 0 {
		t.Errorf("%s: rcode %s, AA %v, answer %v: want the parent's authoritative NODATA",
			when, dns.RcodeToString[m.Rcode], m.Authoritative, m.Answer)
		return
	}
	var soa bool
	var nsec *dns.NSEC
	var nsecSigs int
	for _, rr := range m.Ns {
		switch rr := rr.(type) {
		case *dns.SOA:
			soa = soa || rr.Hdr.Name == apexParent
		case *dns.NSEC:
			if rr.Hdr.Name == dsInsecure {
				nsec = rr
			}
		case *dns.RRSIG:
			if rr.TypeCovered == dns.TypeNSEC && rr.SignerName == apexParent && rr.Hdr.Name == dsInsecure {
				nsecSigs++
			}
		}
	}
	if !soa {
		t.Errorf("%s: authority %v: want the parent's SOA", when, m.Ns)
	}
	if !way.do {
		if nsec != nil {
			t.Errorf("%s: an NSEC without DO", when)
		}
		return
	}
	if nsec == nil || nsecSigs != 1 {
		t.Errorf("%s: authority %v: want the parent's signed NSEC at the cut", when, m.Ns)
		return
	}
	var hasNS, hasDS bool
	for _, t := range nsec.TypeBitMap {
		hasNS = hasNS || t == dns.TypeNS
		hasDS = hasDS || t == dns.TypeDS
	}
	if !hasNS || hasDS {
		t.Errorf("%s: NSEC bitmap %v: want NS and no DS", when, nsec.TypeBitMap)
	}
}

// wantOwnNODATA: zone's own NODATA at its apex, under its own SOA.
func wantOwnNODATA(t *testing.T, m *dns.Msg, zone, when string) {
	t.Helper()
	if m.Rcode != dns.RcodeSuccess || !m.Authoritative || len(m.Answer) != 0 || len(m.Ns) == 0 {
		t.Errorf("%s: rcode %s, AA %v, answer %v, authority %v: want an authoritative NODATA",
			when, dns.RcodeToString[m.Rcode], m.Authoritative, m.Answer, m.Ns)
		return
	}
	if soa, ok := m.Ns[0].(*dns.SOA); !ok || soa.Hdr.Name != zone {
		t.Errorf("%s: authority %v: want %s's SOA first", when, m.Ns, zone)
	}
}

// Parent hosted and serving: its answer, whatever state the child is in. And
// only the DS: the child's own names stay behind its state.
func TestADSAtAHostedChildsApexIsItsParentsToAnswerWhateverTheChildsState(t *testing.T) {
	for _, state := range append([]dsState{dsHealthy}, dsNotServing...) {
		t.Run(string(state), func(t *testing.T) {
			authApp(t)
			dsZone(t, apexParent, dsParentText, dsHealthy)
			dsZone(t, dsSecure, dsChildText(dsSecure), state)
			dsZone(t, dsInsecure, dsChildText(dsInsecure), state)
			for _, way := range dsWays {
				wantParentsDS(t, askWay(t, dsSecure, dns.TypeDS, way, "a signed delegation"), way,
					"a signed delegation, "+way.name)
				wantParentsNODATA(t, askWay(t, dsInsecure, dns.TypeDS, way, "an insecure delegation"), way,
					"an insecure delegation, "+way.name)
				if state != dsHealthy {
					wantEmptyServfail(t, askWay(t, dsSecure, dns.TypeSOA, way, "the child's SOA"), "the child's SOA, "+way.name)
				}
			}
		})
	}
}

// The handler skips the child's guards because it found the parent, and the
// answer comes from that parent: dsResponder is handed it and does not look
// again. Removed from Zones in between (RemoveDynamicZone), the parent still
// answers, as the zone of any query in flight does. A second lookup would find
// no parent and answer from the child's own copy: an authoritative NODATA from
// a zone in error, withheld or expired.
func TestADSIsAnsweredByTheParentTheHandlerFoundEvenIfItIsRemovedBeforeTheAnswer(t *testing.T) {
	for _, state := range dsNotServing {
		t.Run(string(state), func(t *testing.T) {
			authApp(t)
			parent := dsZone(t, apexParent, dsParentText, dsHealthy)
			child := dsZone(t, dsSecure, dsChildText(dsSecure), state)
			if got := FindParentZone(dsSecure); got != parent {
				t.Fatalf("setup: FindParentZone(%s) is %v, want the parent", dsSecure, got)
			}
			Zones.Remove(apexParent)
			for _, way := range dsWays {
				req := new(dns.Msg)
				req.SetQuestion(dsSecure, dns.TypeDS)
				if way.edns {
					req.SetEdns0(dns.DefaultMsgSize, way.do)
				}
				msgo, err := edns0.ExtractFlagsAndEDNS0Options(req)
				if err != nil {
					t.Fatalf("ExtractFlagsAndEDNS0Options: %v", err)
				}
				rw := &fakeRW{remote: udpAddr("127.0.0.1")}
				if err := child.dsResponder(context.Background(), rw, req, dsSecure, parent, msgo, nil); err != nil {
					t.Fatalf("dsResponder: %v", err)
				}
				if rw.written == nil {
					t.Fatalf("%s: no reply written", way.name)
				}
				wantParentsDS(t, rw.written, way, "the parent removed before the answer, "+way.name)
			}
		})
	}
}

// Parent hosted and not serving: SERVFAIL, for a healthy child too. The parent
// answers the DS no more than it answers for its own names.
func TestAParentThatDoesNotServeDoesNotAnswerADSForAHealthyChild(t *testing.T) {
	const onAnAgent dsState = "on an agent"
	for _, state := range append(append([]dsState{}, dsNotServing...), dsXfrOnly, onAnAgent) {
		t.Run(string(state), func(t *testing.T) {
			authApp(t)
			parentState := state
			if state == onAnAgent {
				parentState = dsHealthy
			}
			dsZone(t, apexParent, dsParentText, parentState)
			dsZone(t, dsSecure, dsChildText(dsSecure), dsHealthy)
			dsZone(t, dsInsecure, dsChildText(dsInsecure), dsHealthy)
			if state == onAnAgent {
				Globals.App.Type = AppTypeAgent
			}
			for _, way := range dsWays {
				for _, child := range []string{dsSecure, dsInsecure} {
					when := child + " DS, " + way.name
					wantEmptyServfail(t, askWay(t, child, dns.TypeDS, way, when), when)
				}
			}
		})
	}
}

// No parent hosted: the child's own NODATA (sendChildApexDSNodata) when it
// serves, and SERVFAIL, from its own guards, when it does not.
func TestADSAtAnApexWithNoParentHostedIsTheChildsOwnToAnswer(t *testing.T) {
	for _, state := range append([]dsState{dsHealthy}, dsNotServing...) {
		t.Run(string(state), func(t *testing.T) {
			authApp(t)
			dsZone(t, dsLonely, dsChildText(dsLonely), state)
			if pzd := FindParentZone(dsLonely); pzd != nil {
				t.Fatalf("setup: a parent is hosted: %s", pzd.ZoneName)
			}
			for _, way := range dsWays {
				m := askWay(t, dsLonely, dns.TypeDS, way, "no parent")
				if state == dsHealthy {
					wantOwnNODATA(t, m, dsLonely, "no parent, "+way.name)
				} else {
					wantEmptyServfail(t, m, "no parent, "+way.name)
				}
			}
		})
	}
}

// The root: FindParentZone(".") is the root, so the root's own state decides,
// as the parent's does for any other apex.
func TestTheRootsOwnStateDecidesItsDS(t *testing.T) {
	for _, state := range append([]dsState{dsHealthy}, dsNotServing...) {
		t.Run(string(state), func(t *testing.T) {
			authApp(t)
			root := dsZone(t, ".", dsRootText, state)
			if FindParentZone(".") != root {
				t.Fatal("setup: FindParentZone(\".\") is not the root")
			}
			for _, way := range dsWays {
				m := askWay(t, ".", dns.TypeDS, way, "the root")
				if state == dsHealthy {
					wantOwnNODATA(t, m, ".", "the root, "+way.name)
				} else {
					wantEmptyServfail(t, m, "the root, "+way.name)
				}
			}
		})
	}
}

// Every reply DefaultQueryHandler builds itself, rather than QueryResponder,
// carries an OPT when the query had one and none when it had none: the
// refusals and SERVFAILs on both of its paths, and the SERVFAIL after a failed
// QueryResponder.
func TestEveryReplyTheHandlerBuildsCarriesAnOPTIfAskedWithOne(t *testing.T) {
	healthy := func(t *testing.T) { dsZone(t, apexParent, dsParentText, dsHealthy) }
	inState := func(state dsState) func(*testing.T) {
		return func(t *testing.T) { dsZone(t, apexParent, dsParentText, state) }
	}
	for _, tc := range []struct {
		what      string
		setup     func(*testing.T)
		qname     string
		qtype     uint16
		rcode     int
		cancelled bool
	}{
		{"an error channel query without the _er. label", func(t *testing.T) { Globals.App.Type = AppTypeReporter },
			"www.example.", dns.TypeA, dns.RcodeRefused, false},

		{"the apex of a zone in error", inState(dsInError), apexParent, dns.TypeSOA, dns.RcodeServerFailure, false},
		{"the apex of a zone with no copy", inState(dsNoCopy), apexParent, dns.TypeSOA, dns.RcodeServerFailure, false},
		{"the apex of a withheld zone", inState(dsWithheld), apexParent, dns.TypeSOA, dns.RcodeServerFailure, false},
		{"the apex of an expired zone", inState(dsExpired), apexParent, dns.TypeSOA, dns.RcodeServerFailure, false},
		{"the apex, when the responder fails", healthy, apexParent, dns.TypeSOA, dns.RcodeServerFailure, true},
		{"a DS at a child's apex, when the responder fails", func(t *testing.T) {
			healthy(t)
			dsZone(t, dsSecure, dsChildText(dsSecure), dsHealthy)
		}, dsSecure, dns.TypeDS, dns.RcodeServerFailure, true},

		{"a name in no zone", func(*testing.T) {}, "nowhere.invalid.", dns.TypeA, dns.RcodeRefused, false},
		{"below the apex, on an agent", func(t *testing.T) {
			healthy(t)
			Globals.App.Type = AppTypeAgent
		}, "www.example.", dns.TypeA, dns.RcodeRefused, false},
		{"below the apex of a zone held for transfer", inState(dsXfrOnly), "www.example.", dns.TypeA, dns.RcodeRefused, false},
		{"below the apex of a zone in error", inState(dsInError), "www.example.", dns.TypeA, dns.RcodeServerFailure, false},
		{"below the apex of a zone with no copy", inState(dsNoCopy), "www.example.", dns.TypeA, dns.RcodeServerFailure, false},
		{"below the apex of a withheld zone", inState(dsWithheld), "www.example.", dns.TypeA, dns.RcodeServerFailure, false},
		{"below the apex of an expired zone", inState(dsExpired), "www.example.", dns.TypeA, dns.RcodeServerFailure, false},
	} {
		t.Run(tc.what, func(t *testing.T) {
			authApp(t)
			tc.setup(t)
			ctx := context.Background()
			if tc.cancelled {
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			}
			for _, way := range dsWays[:2] {
				if m := askWayCtx(t, ctx, tc.qname, tc.qtype, way, tc.what); m.Rcode != tc.rcode {
					t.Errorf("%s, %s: rcode %s, want %s", tc.what, way.name, dns.RcodeToString[m.Rcode], dns.RcodeToString[tc.rcode])
				}
			}
		})
	}
}
