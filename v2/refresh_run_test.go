package tdns

import (
	"context"
	"log"
	"testing"

	"github.com/miekg/dns"
)

// A zone whose primary comes back, but whose serial has not moved, refreshes
// successfully with updated == false. Its RefreshError must be cleared.
//
// This is a behaviour FIX, not a move. The two bodies runZoneRefresh unifies
// disagreed here: the operator path cleared the error on any successful refresh,
// the ticker only inside `if updated`. So a zone that recovered without its
// serial changing kept reporting as failed on `zone list` until the serial next
// moved -- which, for a zone whose upstream is simply quiet, can be a long time.
func TestRefreshClearsRefreshErrorOnAnUnchangedSuccess(t *testing.T) {
	zone := "example.test."
	addr, stop := startTestSOAServer(t, zone, 42, dns.RcodeSuccess)
	defer stop()

	zd := &ZoneData{
		ZoneName:       zone,
		ZoneType:       Secondary,
		Upstreams:      []PeerConf{{Addr: addr}},
		IncomingSerial: 42, // the same serial the primary is offering: no transfer
		Logger:         log.Default(),
	}
	Zones.Set(zone, zd)
	defer Zones.Remove(zone)

	zd.SetError(RefreshError, "the primary was unreachable a moment ago")
	if !zd.HasError(RefreshError) {
		t.Fatal("test setup: the error was not recorded")
	}

	updated, err := runZoneRefresh(context.Background(),
		refreshJob{zd: zd, zone: zone, gen: zd.generation.Load()}, &Config{})
	if err != nil {
		t.Fatalf("runZoneRefresh: %v", err)
	}
	if updated {
		t.Fatal("test setup: the serial was unchanged, so nothing should have been transferred")
	}

	if zd.HasError(RefreshError) {
		t.Fatal("a zone that refreshed successfully still reports RefreshError; it " +
			"recovered, and nothing else will clear this until its serial moves")
	}
}

// The operator's caller is answered exactly once, by the refresh itself.
func TestRefreshAnswersAWaitingRefresher(t *testing.T) {
	zone := "example.test."
	addr, stop := startTestSOAServer(t, zone, 7, dns.RcodeSuccess)
	defer stop()

	zd := &ZoneData{
		ZoneName:       zone,
		ZoneType:       Secondary,
		Upstreams:      []PeerConf{{Addr: addr}},
		IncomingSerial: 7,
		Logger:         log.Default(),
	}
	Zones.Set(zone, zd)
	defer Zones.Remove(zone)

	resp := make(chan RefresherResponse, 1)
	zr := ZoneRefresher{Name: zone, Wait: true, Response: resp}

	if _, err := runZoneRefresh(context.Background(),
		refreshJob{zd: zd, zone: zone, gen: zd.generation.Load(), zr: &zr}, &Config{}); err != nil {
		t.Fatalf("runZoneRefresh: %v", err)
	}

	select {
	case got := <-resp:
		if got.Error {
			t.Fatalf("a successful refresh answered with an error: %s", got.ErrorMsg)
		}
	default:
		t.Fatal("a Wait-ing caller was never answered; tdns-cli zone reload would hang")
	}
}
