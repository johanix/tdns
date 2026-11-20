package tdns

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// A secondary past SOA EXPIRE has lost its entitlement to answer from the copy
// it holds (RFC 1034 section 4.3.5), and its queries are SERVFAILed. An
// outbound transfer is the same answer in bulk, so it is refused too. Expire is
// not a service-impacting error, because the refresh ticker skips those zones
// and an expired zone would have no way back; so the transfer asks HasExpired
// itself.

// xferServable makes the fixture a zone that a downstream may transfer: ready,
// with an ACL entry for the loopback requester.
func xferServable(zd *ZoneData) {
	zd.Ready = true
	zd.Status = ZoneStatusReady
	zd.Downstreams = []AclEntry{{Prefix: "127.0.0.0/8", Key: NOKEY}}
}

// refusedTransfer asks zd for an AXFR or IXFR (from serial, when qtype is
// IXFR) through ZoneTransferOut and returns the rcode of the reply.
func refusedTransfer(t *testing.T, zd *ZoneData, qtype uint16, serial uint32) (int, int) {
	t.Helper()
	w := &fakeRW{remote: udpAddr("127.0.0.1")}
	r := new(dns.Msg)
	if qtype == dns.TypeIXFR {
		r.SetIxfr(zd.ZoneName, serial, ".", ".")
	} else {
		r.SetAxfr(zd.ZoneName)
	}
	sent, err := zd.ZoneTransferOut(context.Background(), w, r, nil)
	if err != nil {
		t.Fatalf("ZoneTransferOut: %v", err)
	}
	if w.written == nil {
		t.Fatalf("ZoneTransferOut wrote no reply")
	}
	return w.written.Rcode, sent
}

func TestZoneTransferOut_ExpiredSecondaryRefuses(t *testing.T) {
	authApp(t)
	zd := expiredZone(t)
	xferServable(zd)

	if !zd.HasExpired() {
		t.Fatal("precondition: the zone should be past SOA EXPIRE")
	}
	if zd.HasServiceImpactingError() {
		t.Fatal("expire must stay out of the service-impacting errors: the refresh ticker skips those zones")
	}
	// The queries it answers SERVFAIL are the reference for the transfer.
	if got := ask(t, "www.example.", dns.TypeA); got.Rcode != dns.RcodeServerFailure {
		t.Fatalf("precondition: an expired zone answers %s to a query, want SERVFAIL", dns.RcodeToString[got.Rcode])
	}

	for _, tc := range []struct {
		what   string
		qtype  uint16
		serial uint32
	}{
		{"AXFR", dns.TypeAXFR, 0},
		{"IXFR from an older serial", dns.TypeIXFR, 6},
		{"IXFR from the current serial", dns.TypeIXFR, 7},
	} {
		t.Run(tc.what, func(t *testing.T) {
			rcode, sent := refusedTransfer(t, zd, tc.qtype, tc.serial)
			if sent != 0 || rcode != dns.RcodeRefused {
				t.Fatalf("an expired secondary answered %s with %d RRs, want REFUSED and none", dns.RcodeToString[rcode], sent)
			}
		})
	}
}

// TestZoneTransferOut_UnexpiredSecondaryServes: the refusal is for a zone past
// its EXPIRE and for nothing short of it; a primary has nothing to expire.
func TestZoneTransferOut_UnexpiredSecondaryServes(t *testing.T) {
	authApp(t)
	for _, tc := range []struct {
		what  string
		setup func(zd *ZoneData)
	}{
		{"a secondary refreshed an hour ago", func(zd *ZoneData) {
			zd.LatestRefresh = time.Now().Add(-time.Hour)
		}},
		{"a secondary with no confirmation on record", func(zd *ZoneData) {
			zd.LatestRefresh = time.Time{}
		}},
		{"a primary, whatever its stamp says", func(zd *ZoneData) {
			zd.ZoneType = Primary
			zd.LatestRefresh = time.Now().Add(-8 * 24 * time.Hour)
		}},
	} {
		t.Run(tc.what, func(t *testing.T) {
			zd := expiredZone(t)
			xferServable(zd)
			tc.setup(zd)
			if zd.HasExpired() {
				t.Fatal("precondition: the zone should not be past SOA EXPIRE")
			}

			srv := startTestAXFRServer(t, zd)
			defer srv.shutdown()
			rrs, err := axfrClient(t, srv.addr, zd.ZoneName)
			if err != nil {
				t.Fatalf("AXFR of a zone that has not expired was refused: %v", err)
			}
			if first, last := firstAndLastSerial(t, rrs); first != 7 || last != 7 {
				t.Errorf("AXFR bookends carry serials %d and %d, want 7", first, last)
			}
			ix, err := ixfrClient(t, srv.addr, zd.ZoneName, 7)
			if err != nil {
				t.Fatalf("IXFR of a zone that has not expired was refused: %v", err)
			}
			if got := soaSerials(ix); !serialsEqual(got, []uint32{7}) {
				t.Errorf("IXFR from the current serial answered SOA serials %v, want the single 7", got)
			}
		})
	}
}

// TestZoneTransferOut_RefreshClearsExpiry: the zone keeps being refreshed while
// expired, and the next usable SOA from its primary un-expires it, queries and
// transfers together.
func TestZoneTransferOut_RefreshClearsExpiry(t *testing.T) {
	authApp(t)
	zd := expiredZone(t)
	zd.KeyDB = newTestKeyDB(t)
	zd.IncomingSerial = 7
	xferServable(zd)

	if rcode, _ := refusedTransfer(t, zd, dns.TypeAXFR, 0); rcode != dns.RcodeRefused {
		t.Fatalf("precondition: an expired secondary answered %s, want REFUSED", dns.RcodeToString[rcode])
	}

	addr, stop := startTestSOAServer(t, "example.", 7, dns.RcodeSuccess)
	defer stop()
	zd.Upstreams = []PeerConf{{Addr: addr}}
	if _, _, err := zd.DoTransfer(context.Background(), &Config{}); err != nil {
		t.Fatalf("DoTransfer: %v", err)
	}
	if zd.HasExpired() {
		t.Fatal("still expired after a usable SOA")
	}

	srv := startTestAXFRServer(t, zd)
	defer srv.shutdown()
	rrs, err := axfrClient(t, srv.addr, zd.ZoneName)
	if err != nil {
		t.Fatalf("AXFR after the refresh succeeded was refused: %v", err)
	}
	if first, last := firstAndLastSerial(t, rrs); first != 7 || last != 7 {
		t.Errorf("AXFR bookends carry serials %d and %d, want 7", first, last)
	}
}
