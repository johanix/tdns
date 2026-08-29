/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Stage 1 of docs/2026-08-28-secondary-serve-until-expire.md: the query and
 * UPDATE paths decide "do we hold data" from the published snapshot, not from
 * RefreshCount.
 *
 * The zone these tests build is the shape that was broken: an API-provisioned
 * secondary in the process that added it. ProvisionDynamicZone pre-registers
 * the ZoneData with FirstZoneLoad false, so the refresh engine takes its
 * EXISTING ZONE branch and never calls initialLoadZone -- the only place that
 * increments RefreshCount. The zone holds a complete, published copy and the
 * counter sits at 0 forever, which the old guards read as "no data" (tdns#413).
 */
package tdns

import (
	"context"
	"io"
	"log"
	"testing"

	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

const expireTestZone = `example.	3600	IN	SOA	ns.example. hostmaster.example. 1 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
ns.example.	3600	IN	A	10.0.0.1
www.example.	3600	IN	A	10.0.0.3
`

// apiShapedZone is a zone that holds published data while looking, to every
// first-load field, like it never loaded: RefreshCount 0, FirstZoneLoad false.
func apiShapedZone(t *testing.T) *ZoneData {
	t.Helper()
	zd := testSnapshotZone(t, "example.", expireTestZone)
	zd.ZoneType = Secondary
	zd.FirstZoneLoad = false
	zd.RefreshCount = 0
	if zd.publishedSnapshot() == nil {
		t.Fatal("precondition: the zone should hold a published snapshot")
	}
	return zd
}

// authApp points the handler at tdns-auth with a usable KeyDB, and puts both
// back afterwards. DefaultQueryHandler reads them off the package globals.
func authApp(t *testing.T) {
	t.Helper()
	prevApp, prevKdb := Globals.App.Type, Conf.Internal.KeyDB
	t.Cleanup(func() { Globals.App.Type, Conf.Internal.KeyDB = prevApp, prevKdb })
	Globals.App.Type = AppTypeAuth
	Conf.Internal.KeyDB = newTestKeyDB(t)
}

// ask drives the full DefaultQueryHandler, which is where the Stage 1 guards
// live. Going through QueryResponder directly would skip them entirely.
func ask(t *testing.T, qname string, qtype uint16) *dns.Msg {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(qname, qtype)
	msgo, err := edns0.ExtractFlagsAndEDNS0Options(req)
	if err != nil {
		t.Fatalf("ExtractFlagsAndEDNS0Options: %v", err)
	}
	rw := &fakeRW{remote: udpAddr("127.0.0.1")}
	if err := DefaultQueryHandler(context.Background(), &DnsQueryRequest{
		ResponseWriter: rw,
		Msg:            req,
		Qname:          qname,
		Qtype:          qtype,
		Options:        msgo,
	}); err != nil {
		t.Fatalf("DefaultQueryHandler(%s): %v", qname, err)
	}
	if rw.written == nil {
		t.Fatalf("DefaultQueryHandler(%s): no response written", qname)
	}
	return rw.written
}

// TestHasPublishedDataIsNotGetSOA covers the trap the brief calls out: GetSOA
// synthesizes an SOA for a never-transferred secondary so the refresh engine
// has something to probe with. Using it as the have-data test would let a zone
// that holds nothing answer as though it were authoritative.
func TestHasPublishedDataIsNotGetSOA(t *testing.T) {
	// The never-transferred shape, exactly as GetSOA tests for it.
	empty := &ZoneData{
		ZoneName:       "empty.example.",
		ZoneStore:      MapZone,
		ZoneType:       Secondary,
		Ready:          false,
		IncomingSerial: 0,
		Logger:         discardLogger(),
	}

	soa, err := empty.GetSOA()
	if err != nil || soa == nil {
		t.Fatalf("precondition: GetSOA should synthesize an SOA for this shape, got soa=%v err=%v", soa, err)
	}
	if empty.HasPublishedData() {
		t.Error("a never-transferred secondary reports published data; " +
			"the synthetic GetSOA must not count as having a zone to serve")
	}

	if loaded := apiShapedZone(t); !loaded.HasPublishedData() {
		t.Error("a zone with a published snapshot reports no data")
	}
}

// TestQueryAnswersBelowApexWithoutRefreshCount is Symptom A. The FindZone
// guard used to fire on every sub-apex query with RefreshCount == 0 --
// unconditionally, with no error set anywhere -- so the zone answered for its
// own name and nothing inside it.
func TestQueryAnswersBelowApexWithoutRefreshCount(t *testing.T) {
	authApp(t)
	zd := apiShapedZone(t)
	registerZones(t, zd)

	if got := ask(t, "example.", dns.TypeSOA); got.Rcode != dns.RcodeSuccess {
		t.Errorf("apex SOA: rcode %s, want NOERROR", dns.RcodeToString[got.Rcode])
	}

	m := ask(t, "www.example.", dns.TypeA)
	if m.Rcode != dns.RcodeSuccess {
		t.Errorf("sub-apex A: rcode %s, want NOERROR", dns.RcodeToString[m.Rcode])
	}
	if len(m.Answer) != 1 {
		t.Fatalf("sub-apex A: %d answer RRs, want 1", len(m.Answer))
	}
	if a, ok := m.Answer[0].(*dns.A); !ok || a.A.String() != "10.0.0.3" {
		t.Errorf("sub-apex A: answer %v, want 10.0.0.3", m.Answer[0])
	}

	// The absent name is the sharper half: SERVFAIL and NXDOMAIN are both
	// "no record", so only the rcode distinguishes a working zone from a
	// broken one.
	if got := ask(t, "nosuchname.example.", dns.TypeA); got.Rcode != dns.RcodeNameError {
		t.Errorf("absent sub-apex name: rcode %s, want NXDOMAIN", dns.RcodeToString[got.Rcode])
	}
}

// TestQueryServesThroughRefreshError is Symptom B. A failed refresh does not
// invalidate the copy the zone already holds: RFC 1034 4.3.5 gives it until
// SOA EXPIRE, and serviceImpactingErrors deliberately excludes RefreshError.
func TestQueryServesThroughRefreshError(t *testing.T) {
	authApp(t)
	zd := apiShapedZone(t)
	registerZones(t, zd)

	zd.SetError(RefreshError, "SOA probe of %s failed: all upstreams unreachable", zd.ZoneName)
	if !zd.HasError(RefreshError) {
		t.Fatal("precondition: RefreshError should be set")
	}
	if zd.HasServiceImpactingError() {
		t.Fatal("precondition: RefreshError must not be service-impacting")
	}

	for _, tc := range []struct {
		what  string
		qname string
		qtype uint16
		want  int
	}{
		{"apex through Zones.Get", "example.", dns.TypeSOA, dns.RcodeSuccess},
		{"sub-apex through FindZone", "www.example.", dns.TypeA, dns.RcodeSuccess},
		{"absent name through FindZone", "nosuchname.example.", dns.TypeA, dns.RcodeNameError},
	} {
		if got := ask(t, tc.qname, tc.qtype); got.Rcode != tc.want {
			t.Errorf("%s: rcode %s, want %s", tc.what,
				dns.RcodeToString[got.Rcode], dns.RcodeToString[tc.want])
		}
	}
}

// TestQueryServfailsWithoutPublishedData is the other direction: the predicate
// must still refuse a zone that genuinely holds nothing, on both paths.
func TestQueryServfailsWithoutPublishedData(t *testing.T) {
	authApp(t)
	zd := &ZoneData{
		ZoneName:       "empty.example.",
		ZoneStore:      MapZone,
		ZoneType:       Secondary,
		IncomingSerial: 0,
		Logger:         discardLogger(),
	}
	registerZones(t, zd)

	for _, tc := range []struct {
		what  string
		qname string
	}{
		{"apex through Zones.Get", "empty.example."},
		{"sub-apex through FindZone", "www.empty.example."},
	} {
		if got := ask(t, tc.qname, dns.TypeA); got.Rcode != dns.RcodeServerFailure {
			t.Errorf("%s: rcode %s, want SERVFAIL", tc.what, dns.RcodeToString[got.Rcode])
		}
	}
}

// TestUpdateSharesTheQueryPredicate: updateresponder.go carried its own copy of
// the RefreshCount guard, so a Stage 1 that only edited the query path would
// have left UPDATE refusing zones the query path answers for.
func TestUpdateSharesTheQueryPredicate(t *testing.T) {
	authApp(t)

	update := func(t *testing.T, qname string) *dns.Msg {
		t.Helper()
		r := new(dns.Msg)
		r.SetUpdate(qname)
		msgo, err := edns0.ExtractFlagsAndEDNS0Options(r)
		if err != nil {
			t.Fatalf("ExtractFlagsAndEDNS0Options: %v", err)
		}
		rw := &fakeRW{remote: udpAddr("127.0.0.1")}
		if err := UpdateResponder(&DnsUpdateRequest{
			ResponseWriter: rw,
			Msg:            r,
			Qname:          qname,
			Options:        msgo,
			Status:         &UpdateStatus{},
		}, nil); err != nil {
			t.Fatalf("UpdateResponder(%s): %v", qname, err)
		}
		if rw.written == nil {
			t.Fatalf("UpdateResponder(%s): no response written", qname)
		}
		return rw.written
	}

	t.Run("no published data is refused", func(t *testing.T) {
		zd := &ZoneData{ZoneName: "empty.example.", ZoneStore: MapZone, ZoneType: Secondary, Logger: discardLogger()}
		registerZones(t, zd)
		if got := update(t, "empty.example."); got.Rcode != dns.RcodeServerFailure {
			t.Errorf("rcode %s, want SERVFAIL for a zone holding nothing",
				dns.RcodeToString[got.Rcode])
		}
	})

	t.Run("published data past a failed refresh is not refused by this guard", func(t *testing.T) {
		zd := apiShapedZone(t)
		registerZones(t, zd)
		zd.SetError(RefreshError, "SOA probe failed")

		// Asserted positively, on where the request ENDED UP rather than
		// on where it did not: this zone sets no allow-updates option, so
		// reaching the update-policy check answers REFUSED +
		// EDEZoneUpdatesNotAllowed, and getting that answer is proof the
		// have-data guard (SERVFAIL + EDEZoneNotFound) was passed. A
		// negative "not SERVFAIL+EDEZoneNotFound" would also accept a
		// SERVFAIL carrying some other EDE.
		//
		// The policy layer's particular answer is incidental to Stage 1.
		// If it changes, update the expectation -- the claim being made
		// here is only that the request got past the guard.
		got := update(t, "example.")
		if got.Rcode != dns.RcodeRefused || !hasEDE(got, edns0.EDEZoneUpdatesNotAllowed) {
			t.Errorf("rcode %s (EDEZoneUpdatesNotAllowed=%v), want REFUSED from the "+
				"update-policy check; a zone holding a published copy must reach it, "+
				"and the query path answers for this zone",
				dns.RcodeToString[got.Rcode], hasEDE(got, edns0.EDEZoneUpdatesNotAllowed))
		}
	})
}

// discardLogger keeps the bare fixtures from tripping over zd.Logger on paths
// that should never be reached: a regression must fail as an assertion, not as
// a nil-pointer panic that hides which guard let it through.
func discardLogger() *log.Logger { return log.New(io.Discard, "", 0) }

// hasEDE reports whether the response carries the given extended DNS error.
func hasEDE(m *dns.Msg, code uint16) bool {
	opt := m.IsEdns0()
	if opt == nil {
		return false
	}
	for _, o := range opt.Option {
		if ede, ok := o.(*dns.EDNS0_EDE); ok && ede.InfoCode == code {
			return true
		}
	}
	return false
}
