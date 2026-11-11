/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// A parent that publishes no DSYNC, or none this child can use, is the
// common case (Johan, 2026-11-09): one warning per zone, no ERROR, nothing
// sent, no retry. A real failure on a usable scheme is still an error.

const (
	logNoScheme    = `level=WARN msg="delegation sync: the parent offers no scheme this zone can use; nothing is sent to it"`
	logStillNone   = `level=DEBUG msg="delegation sync: the parent still offers no scheme this zone can use"`
	logNowScheme   = `level=INFO msg="delegation sync: the parent now offers a scheme this zone can use"`
	logNoUpdate    = `level=WARN msg="DelegationSyncSetup: the parent offers no UPDATE scheme; the zone's SIG(0) key is not bootstrapped with it"`
	logNowUpdate   = `level=INFO msg="DelegationSyncSetup: the parent now offers the UPDATE scheme"`
	logErrorLevel  = `level=ERROR`
	logRefreshFail = `level=ERROR msg="DelegationSyncher: refresh sync failed; will retry"`
)

// cacheOnlyImr is a resolver that answers from its cache alone. Each name
// in dsync gets the given DSYNC rdata, or a no-data answer when there is
// none; each name in addrs an A record and a no-data AAAA answer.
func cacheOnlyImr(t *testing.T, dsync map[string][]string, addrs map[string]string) *Imr {
	t.Helper()
	imr := &Imr{Cache: cache.NewRRsetCache(log.New(io.Discard, "", 0), false, false)}
	set := func(name string, rrtype uint16, rrs ...dns.RR) {
		c := &cache.CachedRRset{Name: name, RRtype: rrtype, Context: cache.ContextNoErrNoAns,
			State: cache.ValidationStateSecure, Ttl: 3600, Expiration: time.Now().Add(time.Hour)}
		if len(rrs) > 0 {
			c.Context = cache.ContextAnswer
			c.RRset = &core.RRset{Name: name, Class: dns.ClassINET, RRtype: rrtype, RRs: rrs}
		}
		imr.Cache.Set(name, rrtype, c)
	}
	for name, rdata := range dsync {
		var rrs []dns.RR
		for _, rd := range rdata {
			rrs = append(rrs, mustRR(t, fmt.Sprintf("%s 3600 IN DSYNC %s", name, rd)))
		}
		set(name, core.TypeDSYNC, rrs...)
	}
	for name, addr := range addrs {
		set(name, dns.TypeA, mustRR(t, fmt.Sprintf("%s 3600 IN A %s", name, addr)))
		set(name, dns.TypeAAAA)
	}
	return imr
}

// noDsyncAt: both of the discovery's names for child under parent answer
// with no data, as a parent without DSYNC does.
func noDsyncAt(child, parent string) map[string][]string {
	label := dns.SplitDomainName(child)[0]
	return map[string][]string{label + "._dsync." + parent: nil, "_dsync." + parent: nil}
}

// The plan of a discovery that found nothing usable is ErrNoUsableDsync:
// one warning per zone and parent, DEBUG for the same again, INFO once when
// a usable plan follows, and a warning again for a new parent. A plan that
// could make no discovery (no IMR) is not that case.
func TestANoUsableDsyncPlanIsOneWarning(t *testing.T) {
	logs := captureDnsLog(t)
	zd := &ZoneData{ZoneName: "plan.nodsync.example."}
	none := func(parent string) *ParentSyncPlan {
		return &ParentSyncPlan{Parent: parent, discovered: true, Skipped: []SkippedScheme{
			{Scheme: "all", Reason: "parent " + parent + " publishes no DSYNC records"}}}
	}
	for i := 0; i < 4; i++ {
		if err := zd.planUsable(none("nodsync.example.")); !errors.Is(err, ErrNoUsableDsync) {
			t.Fatalf("round %d: %v, want ErrNoUsableDsync", i, err)
		}
	}
	if n := strings.Count(logs.String(), logNoScheme); n != 1 {
		t.Errorf("%d warnings over four looks, want 1\n%s", n, logs)
	}
	if n := strings.Count(logs.String(), logStillNone); n != 3 {
		t.Errorf("%d DEBUG lines, want 3\n%s", n, logs)
	}
	if !strings.Contains(logs.String(), `parent=nodsync.example.`) || !strings.Contains(logs.String(), "publishes no DSYNC records") {
		t.Errorf("the warning does not name the parent and what was found\n%s", logs)
	}

	usable := &ParentSyncPlan{Parent: "nodsync.example.", discovered: true,
		Candidates: []SyncCandidate{{Scheme: "NOTIFY", Target: &DsyncTarget{Name: "dsync.nodsync.example."}}}}
	for i := 0; i < 2; i++ {
		if err := zd.planUsable(usable); err != nil {
			t.Fatalf("a usable plan: %v", err)
		}
	}
	if n := strings.Count(logs.String(), logNowScheme); n != 1 {
		t.Errorf("%d INFO lines for the scheme that appeared, want 1\n%s", n, logs)
	}

	_ = zd.planUsable(none("nodsync.example."))
	_ = zd.planUsable(none("other.example."))
	if n := strings.Count(logs.String(), logNoScheme); n != 3 {
		t.Errorf("%d warnings, want 3: the first, again after the scheme went, and for a new parent\n%s", n, logs)
	}

	noImr := &ParentSyncPlan{Skipped: []SkippedScheme{{Scheme: "all", Reason: "no IMR available to discover the parent's DSYNC records"}}}
	if err := zd.planUsable(noImr); err == nil || errors.Is(err, ErrNoUsableDsync) {
		t.Errorf("a plan with no discovery: %v, want an error that is not ErrNoUsableDsync", err)
	}
	if n := strings.Count(logs.String(), logErrorLevel); n != 0 {
		t.Errorf("%d ERROR lines\n%s", n, logs)
	}
}

// The lookup the SIG(0) bootstrap and others make: a parent with no DSYNC,
// or one with no target of the scheme asked for, is ErrNoUsableDsync.
func TestLookupDSYNCTargetWithoutATargetIsErrNoUsableDsync(t *testing.T) {
	const child, parent = "lookup.nodsync.example.", "nodsync.example."
	imr := cacheOnlyImr(t, noDsyncAt(child, parent), nil)
	if _, err := imr.LookupDSYNCTarget(context.Background(), child, dns.TypeANY, core.SchemeUpdate); !errors.Is(err, ErrNoUsableDsync) {
		t.Errorf("no DSYNC at all: %v, want ErrNoUsableDsync", err)
	}
	notifyOnly := map[string][]string{"lookup._dsync." + parent: {"CDS NOTIFY 5300 dsync." + parent}}
	imr = cacheOnlyImr(t, notifyOnly, map[string]string{"dsync." + parent: "127.0.0.1"})
	if _, err := imr.LookupDSYNCTarget(context.Background(), child, dns.TypeANY, core.SchemeUpdate); !errors.Is(err, ErrNoUsableDsync) {
		t.Errorf("NOTIFY only, UPDATE asked for: %v, want ErrNoUsableDsync", err)
	}
	if target, err := imr.LookupDSYNCTarget(context.Background(), child, dns.TypeCDS, core.SchemeNotify); err != nil || target == nil {
		t.Errorf("the NOTIFY target the parent has: %v, %v", target, err)
	}
}

// runRealRefreshArm runs the REFRESH-SYNC-DELEGATION arm with its real
// steps, as the syncher wires them, against imr; the retries are recorded,
// not queued.
func runRealRefreshArm(t *testing.T, zd *ZoneData, imr *Imr, kdb *KeyDB) *armRecord {
	t.Helper()
	conf := &Config{}
	conf.Internal.ImrEngine = imr
	ready := NewImrReadiness()
	ready.Publish()
	rec := &armRecord{}
	steps := refreshSyncStepsFor(context.Background(), conf, nil, kdb, nil, zd)
	steps.requeue = func(next DelegationSyncRequest, delay time.Duration) {
		rec.requeued = append(rec.requeued, next)
		rec.delays = append(rec.delays, delay)
	}
	if done := handleRefreshSyncDelegationWith(context.Background(), ready,
		make(chan DelegationSyncRequest, 1), zd, refreshRequest(zd), steps); done != nil {
		rec.deferred = true
	}
	return rec
}

// A tdns-auth child whose NS differs from its parent's, and whose parent
// publishes no DSYNC: the refresh arm's sync, run three times, warns once,
// logs no ERROR and schedules no retry.
func TestRefreshSyncToAParentWithNoDsyncIsOneWarning(t *testing.T) {
	withApp(t, AppTypeAuth)
	logs := captureDnsLog(t)
	zd := childZone(t, ddcngServedZone(), OptParentSync)
	// the parent lacks the zone's second nameserver
	fakeParent(t, zd, []string{ddcngNS1, ddcngNS1A, ddcngNS1AAAA})
	imr := cacheOnlyImr(t, noDsyncAt(zd.ZoneName, zd.GetParent()), nil)
	for i := 0; i < 3; i++ {
		if rec := runRealRefreshArm(t, zd, imr, newTestKeyDB(t)); len(rec.requeued) != 0 || rec.deferred {
			t.Fatalf("round %d: %d retries (deferred %v), want none", i, len(rec.requeued), rec.deferred)
		}
	}
	if n := strings.Count(logs.String(), logNoScheme); n != 1 {
		t.Errorf("%d warnings over three syncs, want 1\n%s", n, logs)
	}
	if n := strings.Count(logs.String(), logErrorLevel); n != 0 {
		t.Errorf("%d ERROR lines for a parent with no DSYNC\n%s", n, logs)
	}
}

// The same child, with a parent that offers UPDATE and answers it NOTAUTH
// (an answer tdns does not retry within the send): a real failure, logged
// as an ERROR and retried by the arm, as before.
func TestRefreshSyncFailureOnAUsableSchemeIsStillAnError(t *testing.T) {
	withApp(t, AppTypeAuth)
	prevCS, prevPS := *ChildSyncConfig(), *ParentSyncConfig()
	t.Cleanup(func() { _ = SetDelegationSyncConfig(prevCS, prevPS) })
	if err := SetDelegationSyncConfig(ChildSyncConf{}, ParentSyncConf{Schemes: []string{"update"}}); err != nil {
		t.Fatal(err)
	}
	logs := captureDnsLog(t)
	zd := childZone(t, ddcngServedZone(), OptParentSync)
	fakeParent(t, zd, []string{ddcngNS1, ddcngNS1A, ddcngNS1AAAA})
	kdb := newTestKeyDB(t)
	zd.KeyDB = kdb
	if _, err := kdb.Sig0KeyMgmt(nil, KeystorePost{Command: "sig0-mgmt", SubCommand: "generate", Zone: zd.ZoneName,
		Keyname: zd.ZoneName, Algorithm: dns.ED25519, State: Sig0StateActive, Creator: "test"}); err != nil {
		t.Fatalf("the zone's SIG(0) key: %v", err)
	}
	refuser := startRcodeResponder(t, dns.RcodeNotAuth)
	_, port, err := net.SplitHostPort(refuser)
	if err != nil {
		t.Fatal(err)
	}
	parent := zd.GetParent()
	label := dns.SplitDomainName(zd.ZoneName)[0]
	imr := cacheOnlyImr(t, map[string][]string{label + "._dsync." + parent: {"ANY UPDATE " + port + " upd." + parent}},
		map[string]string{"upd." + parent: "127.0.0.1"})
	rec := runRealRefreshArm(t, zd, imr, kdb)
	if len(rec.requeued) != 1 {
		t.Errorf("%d retries of a failed UPDATE, want 1", len(rec.requeued))
	}
	if !strings.Contains(logs.String(), logRefreshFail) {
		t.Errorf("a failed UPDATE was not logged as an ERROR\n%s", logs)
	}
	if strings.Contains(logs.String(), logNoScheme) {
		t.Errorf("a failed UPDATE was taken for a parent that offers nothing\n%s", logs)
	}
}

// The SIG(0) bootstrap for a parent with no UPDATE target: the lookup's
// ErrNoUsableDsync reaches the setup's decision, which warns once and ends
// the setup with no error, however often it is asked. A bootstrap the
// parent takes afterwards is logged at INFO once; a refusal is still an
// error.
func TestASetupWithNoUpdateTargetIsOneWarning(t *testing.T) {
	logs := captureDnsLog(t)
	const child, parent = "setup.nodsync.example.", "nodsync.example."
	kdb := newTestKeyDB(t)
	zd := &ZoneData{ZoneName: child, KeyDB: kdb, Logger: log.New(io.Discard, "", 0)}
	zd.SetParent(parent)
	if _, err := kdb.Sig0KeyMgmt(nil, KeystorePost{Command: "sig0-mgmt", SubCommand: "generate", Zone: child,
		Keyname: child, Algorithm: dns.ED25519, State: Sig0StateActive, Creator: "test"}); err != nil {
		t.Fatalf("the zone's SIG(0) key: %v", err)
	}
	prev := Globals.ImrEngine
	Globals.ImrEngine = cacheOnlyImr(t, noDsyncAt(child, parent), nil)
	t.Cleanup(func() { Globals.ImrEngine = prev })

	for i := 0; i < 3; i++ {
		msg, ur, err := zd.bootstrapSig0KeyWithParent(context.Background(), dns.ED25519, zd.zoneChildBootstrapMethods(), false)
		if !errors.Is(err, ErrNoUsableDsync) {
			t.Fatalf("round %d: the bootstrap returned %v, want ErrNoUsableDsync", i, err)
		}
		if got := zd.finishDelegationSyncSetup(msg, ur, err); got != nil {
			t.Fatalf("round %d: the setup returned %v, want nil", i, got)
		}
	}
	if n := strings.Count(logs.String(), logNoUpdate); n != 1 {
		t.Errorf("%d warnings over three setups, want 1\n%s", n, logs)
	}
	if n := strings.Count(logs.String(), logErrorLevel); n != 0 {
		t.Errorf("%d ERROR lines for a parent with no UPDATE target\n%s", n, logs)
	}

	ok := startRcodeResponder(t, dns.RcodeSuccess)
	_, ur, err := SendUpdate(context.Background(), testUpdateMsg(t), child, []string{ok})
	if got := zd.finishDelegationSyncSetup("", ur, err); got != nil {
		t.Fatalf("an accepted bootstrap: %v", got)
	}
	if n := strings.Count(logs.String(), logNowUpdate); n != 1 {
		t.Errorf("%d INFO lines for the UPDATE target that appeared, want 1\n%s", n, logs)
	}

	refused := startRcodeResponder(t, dns.RcodeRefused)
	_, ur, err = SendUpdate(context.Background(), testUpdateMsg(t), child, []string{refused})
	if got := zd.finishDelegationSyncSetup("", ur, err); got == nil {
		t.Error("a refused bootstrap returned nil, want an error")
	}
	if !strings.Contains(logs.String(), logErrorLevel) {
		t.Errorf("a refused bootstrap was not logged as an ERROR\n%s", logs)
	}
}
