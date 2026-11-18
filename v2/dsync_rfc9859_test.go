/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// #757: a DSYNC with port 0 (or the null scheme, or the root as its target)
// names nowhere to send anything, and is never selected; and the root's DSYNC
// names are the RFC 9859 ones, _dsync. and <tld>._dsync.

func parsedDsync(t *testing.T, rdata string) *core.DSYNC {
	t.Helper()
	rr := mustRR(t, "_dsync.example. 3600 IN DSYNC "+rdata)
	return rr.(*dns.PrivateRR).Data.(*core.DSYNC)
}

func TestFindDsyncSkipsUnusableRecords(t *testing.T) {
	port0 := parsedDsync(t, "ANY UPDATE 0 upd0.example.")
	rootTarget := parsedDsync(t, "ANY UPDATE 53 .")
	usable := parsedDsync(t, "ANY UPDATE 53 upd.example.")
	notify0 := parsedDsync(t, "CDS NOTIFY 0 n0.example.")
	notify := parsedDsync(t, "CDS NOTIFY 53 n.example.")

	res := DsyncResult{Rdata: []*core.DSYNC{port0, rootTarget, usable}}
	if got := findDsync(res, core.SchemeUpdate, false); got != usable {
		t.Errorf("UPDATE: found %v, want %v", got, usable)
	}
	res = DsyncResult{Rdata: []*core.DSYNC{port0, rootTarget}}
	if got := findDsync(res, core.SchemeUpdate, false); got != nil {
		t.Errorf("UPDATE with no usable record: found %v, want none", got)
	}
	res = DsyncResult{Rdata: []*core.DSYNC{notify0, notify}}
	if got := findDsync(res, core.SchemeNotify, true); got != notify {
		t.Errorf("NOTIFY: found %v, want %v", got, notify)
	}
	res = DsyncResult{Rdata: []*core.DSYNC{notify0}}
	if got := findDsync(res, core.SchemeNotify, true); got != nil {
		t.Errorf("NOTIFY with port 0 only: found %v, want none", got)
	}
}

// The DS delivery takes its schemes from the parent sync plan, so a port-0
// record is passed over there too: under "auto" the choices are the usable
// UPDATE and NOTIFY targets, an API-only parent gives the usable API target,
// and port-0 records alone give nothing to send over.
func TestDSDeliverySkipsUnusableRecords(t *testing.T) {
	zd := dsSyncTestZone(t)
	setChildApiCredentials(t, ParentSyncApiCredentialConf{Parent: "example.", Username: "u", Key: "k"})
	res := DsyncResult{Validated: true, Rdata: []*core.DSYNC{
		parsedDsync(t, "ANY UPDATE 0 upd0.example."),
		parsedDsync(t, "CDS NOTIFY 0 n0.example."),
		parsedDsync(t, "CDS API 0 api0.example."),
		parsedDsync(t, "ANY UPDATE 53 upd.example."),
		parsedDsync(t, "CDS NOTIFY 53 n.example."),
		parsedDsync(t, "CDS API 8443 api.example."),
	}}
	choices, _, _, err := rolloverSchemeChoices(dsSyncPlanFor(t, zd, res, nil), dsSyncPolicy(DsyncSchemePreferenceAuto))
	if err != nil {
		t.Fatalf("scheme choice: %v", err)
	}
	if got := dsSyncChoiceTargets(choices); !slices.Equal(got, []string{"UPDATE upd.example.", "NOTIFY n.example."}) {
		t.Errorf("choices %v, want the usable UPDATE and NOTIFY targets", got)
	}

	apiOnly := DsyncResult{Validated: true, Rdata: []*core.DSYNC{res.Rdata[2], res.Rdata[5]}}
	choices, _, _, err = rolloverSchemeChoices(dsSyncPlanFor(t, zd, apiOnly, nil), dsSyncPolicy(DsyncSchemePreferenceAuto))
	if err != nil {
		t.Fatalf("API only: scheme choice: %v", err)
	}
	if got := dsSyncChoiceTargets(choices); !slices.Equal(got, []string{"API api.example."}) {
		t.Errorf("API only: choices %v, want the usable API target", got)
	}

	res.Rdata = res.Rdata[:3]
	_, _, _, err = rolloverSchemeChoices(dsSyncPlanFor(t, zd, res, nil), dsSyncPolicy(DsyncSchemePreferenceAuto))
	if !errors.Is(err, errNoUsableScheme) {
		t.Errorf("port 0 only: err = %v, want errNoUsableScheme", err)
	}
}

// A parent whose own NOTIFY DSYNC has port 0 does not advertise NOTIFY.
func TestAdvertisesDsyncNotifyNeedsAUsableRecord(t *testing.T) {
	const zone = `example. 3600 IN SOA ns.example. hostmaster.example. 1 7200 1800 604800 7200
example. 3600 IN NS ns.example.
ns.example. 3600 IN A 192.0.2.1
_dsync.example. 7200 IN DSYNC CDS NOTIFY 0 notify.example.
_dsync.example. 7200 IN DSYNC CSYNC NOTIFY 5302 notify.example.
`
	zd := testZone(t, "example.", zone)
	if zd.advertisesDsyncNotify(dns.TypeCDS) {
		t.Error("NOTIFY(CDS) is advertised only with port 0, yet counted as advertised")
	}
	if !zd.advertisesDsyncNotify(dns.TypeCSYNC) {
		t.Error("NOTIFY(CSYNC) is advertised with a port, yet not counted")
	}
}


// A root zone publishes its DSYNC RRset at _dsync. and nothing at
// _dsync.root. A record an older build left at _dsync.root. is not the
// root's DSYNC: the scheme it names is published at _dsync. all the same.
func TestTheRootPublishesAtDsync(t *testing.T) {
	allSchemesChildSync(t)
	const root = `. 3600 IN SOA a.root. hostmaster.root. 1 7200 1800 604800 7200
. 3600 IN NS a.root.
a.root. 3600 IN A 192.0.2.1
_dsync.root. 7200 IN DSYNC ANY UPDATE 5302 updates.root.
`
	zd := testZone(t, ".", root)
	zd.KeyDB = &KeyDB{UpdateQ: make(chan UpdateRequest, 1)}
	p := DefaultDelegationPolicy()
	zd.DelegationPolicy = &p

	pub, err := zd.BuildDsyncPublication()
	if err != nil {
		t.Fatalf("BuildDsyncPublication: %v", err)
	}
	schemes := map[core.DsyncScheme]bool{}
	for _, rr := range pub.Actions() {
		if rr.Header().Rrtype != core.TypeDSYNC {
			continue
		}
		if rr.Header().Name != "_dsync." {
			t.Errorf("a DSYNC action at %q: %s", rr.Header().Name, rr)
			continue
		}
		schemes[rr.(*dns.PrivateRR).Data.(*core.DSYNC).Scheme] = true
	}
	for _, s := range []core.DsyncScheme{core.SchemeNotify, core.SchemeUpdate, core.SchemeAPI} {
		if !schemes[s] {
			t.Errorf("scheme %d is not published at _dsync.", s)
		}
	}
	for _, rr := range pub.Actions() {
		if strings.HasSuffix(strings.ToLower(rr.Header().Name), "_dsync.root.") {
			t.Errorf("an action at the old name: %s", rr)
		}
	}
}

// A root zone that still serves a DSYNC RRset at _dsync.root. is warned about
// on every build of its publication; the RRset is left alone. A root zone
// without one is not.
func TestTheRootWarnsAboutALeftoverDsyncRoot(t *testing.T) {
	allSchemesChildSync(t)
	var buf syncBuffer // the updater goroutine logs after it has answered; the read must not race its last line
	prev := lg
	lg = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	t.Cleanup(func() { lg = prev })

	const apex = `. 3600 IN SOA a.root. hostmaster.root. 1 7200 1800 604800 7200
. 3600 IN NS a.root.
a.root. 3600 IN A 192.0.2.1
`
	warnings := func(zone string) (int, *DsyncPublication) {
		t.Helper()
		buf.Reset()
		zd := testZone(t, ".", zone)
		p := DefaultDelegationPolicy()
		zd.DelegationPolicy = &p
		pub, err := zd.BuildDsyncPublication()
		if err != nil {
			t.Fatalf("BuildDsyncPublication: %v", err)
		}
		n := 0
		for _, line := range strings.Split(buf.String(), "\n") {
			if strings.Contains(line, "level=WARN") && strings.Contains(line, "_dsync.root.") {
				n++
			}
		}
		return n, pub
	}

	n, pub := warnings(apex + "_dsync.root. 7200 IN DSYNC ANY UPDATE 5302 updates.root.\n")
	if n != 1 {
		t.Errorf("a leftover _dsync.root. RRset: %d warnings, want 1\n%s", n, buf.String())
	}
	for _, rr := range pub.Actions() {
		if strings.EqualFold(rr.Header().Name, "_dsync.root.") {
			t.Errorf("the publication touches the old RRset: %s", rr)
		}
	}
	if n, _ := warnings(apex); n != 0 {
		t.Errorf("no RRset at _dsync.root.: %d warnings, want none\n%s", n, buf.String())
	}
	if n, _ := warnings(apex + "_dsync.root. 7200 IN TXT \"not a DSYNC\"\n"); n != 0 {
		t.Errorf("only a TXT at _dsync.root.: %d warnings, want none\n%s", n, buf.String())
	}
}







