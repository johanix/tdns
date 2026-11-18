package tdns

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// The operator-authored transport signal (design 2026-11-14, section 5; plan
// step S2, as the maintainer ruled it 2026-11-15): the start-up pass leaves
// provisioned records at an identity's _dns owner alone whatever their mode,
// injection includes provisioned records by zone data alone, only AliasMode
// records are chased, and the zone loader warns about what a resolver will
// read differently from what the operator wrote. The three rules themselves
// are tested in tsignal_zone_data_rules_test.go.

func captureSignalLog(t *testing.T) *syncBuffer {
	t.Helper()
	var logs syncBuffer
	prev := lgDns
	lgDns = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	t.Cleanup(func() { lgDns = prev })
	return &logs
}

func mustRRs(t *testing.T, lines ...string) []dns.RR {
	t.Helper()
	var out []dns.RR
	for _, l := range lines {
		rr, err := dns.NewRR(l)
		if err != nil {
			t.Fatalf("%s: %v", l, err)
		}
		out = append(out, rr)
	}
	return out
}

// An operator's ServiceMode RRset at an identity's signal owner survives the
// start-up pass as written, with a target and without one, and the pass
// says it left it alone. The configuration still gives the server's other
// identity its signal: the walk goes on.
func TestAnOperatorServiceModeRRsetSurvivesTheSignalPass(t *testing.T) {
	cases := []struct {
		name, zone string
		records    []string
	}{
		{"without a target", "svc.sig.example.", []string{
			`_dns.ns1.svc.sig.example. 300 IN SVCB 1 . oots="dot:30"`,
		}},
		{"with a target", "tgt.sig.example.", []string{
			`_dns.ns1.tgt.sig.example. 300 IN SVCB 1 dot.provider.example. oots="dot:30" port=1234`,
			`_dns.ns1.tgt.sig.example. 300 IN SVCB 1 . oots="doq:10"`,
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			z := c.zone
			logs := captureSignalLog(t)
			zd, conf := signalTestZone(t, z, z+`	3600	IN	NS	ns1.`+z+`
`+z+`	3600	IN	NS	ns2.`+z+`
ns1.`+z+`	3600	IN	A	127.0.0.1
ns2.`+z+`	3600	IN	A	127.0.0.1
`+strings.Join(c.records, "\n")+"\n", "127.0.0.1:53")
			conf.Service.Identities = []string{"ns1." + z, "ns2." + z}
			conf.Service.Transport.Signal = "dot:50"
			if err := zd.CreateTransportSignalRRs(conf); err != nil {
				t.Fatal(err)
			}
			want := mustRRs(t, c.records...)
			if got := svcbRecords(zd, "_dns.ns1."+z); !sameRecords(got, want) {
				t.Fatalf("the operator's RRset was not left alone:\n got %v\nwant %v", got, want)
			}
			if !strings.Contains(logs.String(), "leaving the operator's records") {
				t.Fatalf("the pass did not say it left the operator's RRset alone:\n%s", logs.String())
			}
			own := svcbRecords(zd, "_dns.ns2."+z)
			if len(own) != 1 || !strings.Contains(own[0].String(), "dot:50") {
				t.Fatalf("the server's other identity did not get the configured signal: %v", own)
			}
		})
	}
}

// The pass's own stored signal is zone content too, so a later run must not
// take it for an operator's: a run after the configuration changed rewrites
// it. An RRset the pass has no record of storing is the operator's even
// when it is exactly what the configuration gives: a later configuration
// must not replace it.
func TestTheSignalPassTellsItsOwnSignalFromTheOperators(t *testing.T) {
	const z = "rerun.sig.example."
	logs := captureSignalLog(t)
	zd, conf := signalTestZone(t, z, z+`	3600	IN	NS	ns1.`+z+`
ns1.`+z+`	3600	IN	A	127.0.0.1
`, "127.0.0.1:53")
	conf.Service.Identities = []string{"ns1." + z}
	conf.Service.Transport.Signal = "dot:50"
	if err := zd.CreateTransportSignalRRs(conf); err != nil {
		t.Fatal(err)
	}
	conf.Service.Transport.Signal = "dot:20"
	if err := zd.CreateTransportSignalRRs(conf); err != nil {
		t.Fatal(err)
	}
	got := svcbRecords(zd, "_dns.ns1."+z)
	if len(got) != 1 || !strings.Contains(got[0].String(), "dot:20") {
		t.Fatalf("the second run took the pass's own signal for the operator's: %v", got)
	}
	if strings.Contains(logs.String(), "leaving the operator's") {
		t.Fatalf("the pass's own signal was reported as the operator's:\n%s", logs.String())
	}

	// The operator wrote exactly what the configuration gives. It is left
	// as written and not taken as the pass's own, so a configuration that
	// later says something else does not replace it.
	const z2 = "same.sig.example."
	logs2 := captureSignalLog(t)
	fresh, err := zd.buildServerSVCB(conf, "ns1."+z2, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, rr := range fresh.RRs {
		lines = append(lines, rr.String())
	}
	zd2, conf2 := signalTestZone(t, z2, z2+`	3600	IN	NS	ns1.`+z2+`
ns1.`+z2+`	3600	IN	A	127.0.0.1
`+strings.Join(lines, "\n")+"\n", "127.0.0.1:53")
	conf2.Service.Identities = []string{"ns1." + z2}
	conf2.Service.Transport.Signal = conf.Service.Transport.Signal
	if err := zd2.CreateTransportSignalRRs(conf2); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs2.String(), "leaving the operator's") {
		t.Fatalf("an operator's RRset identical to the configuration's was not left alone:\n%s", logs2.String())
	}
	if own, err := zd2.signalStoredByPass("_dns.ns1."+z2, svcbRecords(zd2, "_dns.ns1."+z2)); err != nil || own {
		t.Fatal("the pass took the operator's RRset as its own because it matched the configuration")
	}
	conf2.Service.Transport.Signal = "dot:50"
	if err := zd2.CreateTransportSignalRRs(conf2); err != nil {
		t.Fatal(err)
	}
	if got := svcbRecords(zd2, "_dns.ns1."+z2); len(got) != 1 || !strings.Contains(got[0].String(), "dot:20") {
		t.Fatalf("a later configuration replaced the operator's RRset: %v", got)
	}
}

func TestARefreshCarriesOnlyThePassOwnSignal(t *testing.T) {
	const z = "carry.sig.example."
	zd, conf := signalTestZone(t, z, z+`	3600	IN	NS	ns1.`+z+`
`+z+`	3600	IN	NS	ns2.`+z+`
ns1.`+z+`	3600	IN	A	127.0.0.1
ns2.`+z+`	3600	IN	A	127.0.0.1
_dns.ns1.`+z+`	300	IN	SVCB	1 . oots="dot:30"
`, "127.0.0.1:53")
	conf.Service.Identities = []string{"ns1." + z, "ns2." + z}
	conf.Service.Transport.Signal = "dot:50"
	if err := zd.CreateTransportSignalRRs(conf); err != nil {
		t.Fatal(err)
	}
	zd.KeyDB = newTestKeyDB(t) // CollectDynamicRRs collects nothing without one
	carried := map[string]bool{}
	for _, rs := range zd.CollectDynamicRRs(conf) {
		if rs.RRtype == dns.TypeSVCB {
			carried[core.CanonicalizeName(rs.Name)] = true
		}
	}
	if !carried["_dns.ns2."+z] {
		t.Fatal("the pass's own stored signal is not carried across a refresh")
	}
	if carried["_dns.ns1."+z] {
		t.Fatal("the operator's RRset is carried across a refresh, over the fresh data")
	}
}

// A provisioned ServiceMode RRset, with a target or without, is included by
// zone data alone: no identity is configured and the NS name's address is
// not this server's (rule 1). It also answers a direct query.
func TestAProvisionedServiceModeRRsetIsIncludedByZoneData(t *testing.T) {
	const z = "theirs-svc.sig.example."
	zd, conf := signalTestZone(t, z, z+`	3600	IN	NS	ns1.`+z+`
ns1.`+z+`	3600	IN	A	192.0.2.1
_dns.ns1.`+z+`	300	IN	SVCB	1 . oots="dot:30"
_dns.ns1.`+z+`	300	IN	SVCB	1 dot.elsewhere.example. oots="doq:30"
`, "127.0.0.1:53")
	if len(conf.Service.Identities) != 0 || len(Conf.Service.Identities) != 0 {
		t.Fatal("the test needs no identity configured")
	}
	got := zd.collectSignalRRsets(zd.publishedSnapshot())
	if len(got) != 1 || len(got[0].RRs) != 2 {
		t.Fatalf("a provisioned ServiceMode RRset was not included whole by zone data: %v", got)
	}
	if !served(zd, "_dns.ns1."+z, dns.TypeSVCB) {
		t.Fatal("the provisioned RRset must answer a direct query")
	}
}

// Only AliasMode records are chased. The TargetName of a ServiceMode record
// names an endpoint host, so a signal the server holds at that name is not
// injected with it.
func TestAServiceModeTargetIsNotChased(t *testing.T) {
	const z = "nochase.sig.example."
	const pz = "chase-provider.example."
	zd, _ := signalTestZone(t, z, z+`	3600	IN	NS	ns1.`+z+`
ns1.`+z+`	3600	IN	A	127.0.0.1
_dns.ns1.`+z+`	300	IN	SVCB	1 _dns.ns.`+pz+` oots="dot:30"
`, "127.0.0.1:53")
	provider := testZone(t, pz, pz+`	3600	IN	SOA	ns.`+pz+` hostmaster.`+pz+` 1 7200 1800 604800 7200
`+pz+`	3600	IN	NS	ns.`+pz+`
ns.`+pz+`	3600	IN	A	127.0.0.1
_dns.ns.`+pz+`	300	IN	SVCB	1 . alpn=dot
`)
	registerZones(t, provider)
	got := zd.collectSignalRRsets(zd.publishedSnapshot())
	if len(got) != 1 || got[0].RRs[0].Header().Name != "_dns.ns1."+z {
		names := []string{}
		for _, rs := range got {
			names = append(names, rs.Name)
		}
		t.Fatalf("a ServiceMode target was chased: %v", names)
	}
	if svcbHasAlias(got[0]) || len(signalChaseTargets(got[0])) != 0 {
		t.Fatal("a ServiceMode record with a target was read as an alias")
	}
}

// The zone loader warns, and refuses nothing, when a transport is named in
// two records of one RRset or an oots weight is above 100.
func TestZoneLoadWarnsAboutTheTransportSignal(t *testing.T) {
	const z = "warn.sig.example."
	logs := captureSignalLog(t)
	zd := &ZoneData{ZoneName: z, ZoneStore: MapZone, Logger: log.New(os.Stderr, "", 0)}
	_, _, err := zd.ReadZoneData(z+`	3600	IN	SOA	ns1.`+z+` hostmaster.`+z+` 1 7200 1800 604800 7200
`+z+`	3600	IN	NS	ns1.`+z+`
ns1.`+z+`	3600	IN	A	127.0.0.1
_dns.ns1.`+z+`	300	IN	SVCB	1 . oots="dot:30,doh:20"
_dns.ns1.`+z+`	300	IN	SVCB	1 dot.provider.example. oots="dot:20,doq:10" port=1234
`, false)
	if err != nil {
		t.Fatalf("the zone was refused: %v", err)
	}
	out := logs.String()
	if !strings.Contains(out, `transport \"dot\" is named in 2 records`) {
		t.Fatalf("no warning for a transport named in two records:\n%s", out)
	}
	if strings.Contains(out, `transport \"doq\"`) || strings.Contains(out, `transport \"doh\"`) {
		t.Fatalf("a warning for a transport named once:\n%s", out)
	}
}

// The checks behind the zone-load warnings. A weight above 100 is built
// here rather than parsed: the codec this module pins refuses one at parse,
// and the lossless codec (design section 8) keeps it.
func TestSvcbSignalWarnings(t *testing.T) {
	rec := func(prio uint16, target string, entries ...dns.SVCBOotsEntry) dns.RR {
		return &dns.SVCB{
			Hdr:      dns.RR_Header{Name: "_dns.ns1.example.", Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: 300},
			Priority: prio, Target: target,
			Value: []dns.SVCBKeyValue{&dns.SVCBOots{Oots: entries}},
		}
	}
	set := func(rrs ...dns.RR) core.RRset {
		return core.RRset{Name: "_dns.ns1.example.", RRtype: dns.TypeSVCB, RRs: rrs}
	}
	dot := func(w uint8) dns.SVCBOotsEntry { return dns.SVCBOotsEntry{Proto: "dot", Weight: w} }
	doq := func(w uint8) dns.SVCBOotsEntry { return dns.SVCBOotsEntry{Proto: "doq", Weight: w} }

	if w := svcbSignalWarnings(set(rec(1, ".", dot(30), doq(10)))); len(w) != 0 {
		t.Fatalf("warnings for a clean record: %v", w)
	}
	if w := svcbSignalWarnings(set(rec(1, ".", dot(150)))); len(w) != 1 || !strings.Contains(w[0], "above 100") {
		t.Fatalf("a weight above 100: %v", w)
	}
	if w := svcbSignalWarnings(set(rec(1, ".", dot(100)))); len(w) != 0 {
		t.Fatalf("a weight of 100 drew a warning: %v", w)
	}
	w := svcbSignalWarnings(set(rec(1, ".", dot(30)), rec(2, "dot.example.", dot(20)), rec(1, "doq.example.", doq(10))))
	if len(w) != 1 || !strings.Contains(w[0], `"dot" is named in 2 records`) {
		t.Fatalf("a transport in two records: %v", w)
	}
	// An AliasMode record carries no signal (RFC 9460 section 2.4.2).
	if w := svcbSignalWarnings(set(rec(0, "_dns.ns.example.", dot(30)), rec(1, ".", dot(30)))); len(w) != 0 {
		t.Fatalf("an AliasMode record was counted: %v", w)
	}
}

// The pass's record of what it stored outlives the process when the zone has
// a KeyDB: a stored signal that comes back as content after a restart (a
// journal replay, a persisted copy) is still the pass's own, and a changed
// configuration replaces it. Without a KeyDB the record is gone after the
// restart, and an old signal that differs from the configuration reads as
// the operator's and is left alone, with the info line.
func TestTheSignalPassKnowsItsOwnSignalAcrossARestart(t *testing.T) {
	const z = "restart2.sig.example."
	const body = z + `	3600	IN	NS	ns1.` + z + `
ns1.` + z + `	3600	IN	A	127.0.0.1
`
	// Before the restart: the pass stores its signal for "dot:50".
	before := func(t *testing.T, kdb *KeyDB) []string {
		zd, conf := signalTestZone(t, z, body, "127.0.0.1:53")
		zd.KeyDB = kdb
		conf.Service.Identities = []string{"ns1." + z}
		conf.Service.Transport.Signal = "dot:50"
		if err := zd.CreateTransportSignalRRs(conf); err != nil {
			t.Fatal(err)
		}
		var lines []string
		for _, rr := range svcbRecords(zd, "_dns.ns1."+z) {
			lines = append(lines, rr.String())
		}
		return lines
	}
	// After it: a new process loads the zone with that signal in it and a
	// configuration that now says "dot:20".
	after := func(t *testing.T, kdb *KeyDB, persisted []string) (*ZoneData, *syncBuffer) {
		logs := captureSignalLog(t)
		zd, conf := signalTestZone(t, z, body+strings.Join(persisted, "\n")+"\n", "127.0.0.1:53")
		zd.KeyDB = kdb
		conf.Service.Identities = []string{"ns1." + z}
		conf.Service.Transport.Signal = "dot:20"
		if err := zd.CreateTransportSignalRRs(conf); err != nil {
			t.Fatal(err)
		}
		return zd, logs
	}

	t.Run("with a KeyDB", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		persisted := before(t, kdb)
		zd, logs := after(t, kdb, persisted)
		got := svcbRecords(zd, "_dns.ns1."+z)
		if len(got) != 1 || !strings.Contains(got[0].String(), "dot:20") {
			t.Fatalf("the pass's own signal from before the restart was not replaced: %v", got)
		}
		if strings.Contains(logs.String(), "leaving the operator's") {
			t.Fatalf("the pass's own signal was taken for the operator's after a restart:\n%s", logs.String())
		}
	})

	t.Run("without a KeyDB", func(t *testing.T) {
		persisted := before(t, nil)
		zd, logs := after(t, nil, persisted)
		got := svcbRecords(zd, "_dns.ns1."+z)
		if len(got) != 1 || !strings.Contains(got[0].String(), "dot:50") {
			t.Fatalf("without a record the old signal should be left as it is: %v", got)
		}
		if !strings.Contains(logs.String(), "leaving the operator's") {
			t.Fatalf("no info line for the RRset left alone:\n%s", logs.String())
		}
	})
}

// The pass stores a signal into the working set; it reaches the zone file
// only when the zone is next written. A restart before that loads an earlier
// signal of the pass's, not the last one, and that is still the pass's own:
// replaced with what the configuration gives, not kept as the operator's.
func TestAnEarlierSignalOfThePassIsStillItsOwnAfterARestart(t *testing.T) {
	const z = "unwritten.sig.example."
	const body = z + `	3600	IN	NS	ns1.` + z + `
ns1.` + z + `	3600	IN	A	127.0.0.1
`
	kdb := newTestKeyDB(t)
	// run starts a process with the zone file holding persisted and the
	// configuration giving signal, and returns the signal it serves.
	run := func(persisted []string, signal string) ([]dns.RR, *syncBuffer) {
		logs := captureSignalLog(t)
		zd, conf := signalTestZone(t, z, body+strings.Join(persisted, "\n")+"\n", "127.0.0.1:53")
		zd.KeyDB = kdb
		conf.Service.Identities = []string{"ns1." + z}
		conf.Service.Transport.Signal = signal
		if err := zd.CreateTransportSignalRRs(conf); err != nil {
			t.Fatal(err)
		}
		return svcbRecords(zd, "_dns.ns1."+z), logs
	}
	// The first process stores "dot:50", and the zone is written with it.
	first, _ := run(nil, "dot:50")
	var written []string
	for _, rr := range first {
		written = append(written, rr.String())
	}
	// The second stores "dot:20"; the zone is not written again.
	if got, _ := run(written, "dot:20"); len(got) != 1 || !strings.Contains(got[0].String(), "dot:20") {
		t.Fatalf("the second process did not replace the pass's signal: %v", got)
	}
	// The third loads "dot:50" from the file once more.
	got, logs := run(written, "dot:20")
	if len(got) != 1 || !strings.Contains(got[0].String(), "dot:20") {
		t.Fatalf("an earlier signal of the pass's was not replaced after a restart: %v", got)
	}
	if strings.Contains(logs.String(), "leaving the operator's") {
		t.Fatalf("an earlier signal of the pass's was taken for the operator's:\n%s", logs.String())
	}
	if d, _, _ := kdb.GetTransportSignalStored(z, "_dns.ns1."+z); len(d) != 2 {
		t.Fatalf("the record should hold the last digest and the one before it: %v", d)
	}
}

// An RRset the operator now owns is forgotten: the record goes, so the pass
// does not later take that RRset, or an identical one, for its own.
func TestTheSignalPassForgetsAnOwnerTheOperatorTookOver(t *testing.T) {
	const z = "takeover.sig.example."
	kdb := newTestKeyDB(t)
	zd, conf := signalTestZone(t, z, z+`	3600	IN	NS	ns1.`+z+`
ns1.`+z+`	3600	IN	A	127.0.0.1
`, "127.0.0.1:53")
	zd.KeyDB = kdb
	conf.Service.Identities = []string{"ns1." + z}
	conf.Service.Transport.Signal = "dot:50"
	if err := zd.CreateTransportSignalRRs(conf); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := kdb.GetTransportSignalStored(z, "_dns.ns1."+z); !ok {
		t.Fatal("the stored signal was not recorded in the KeyDB")
	}
	// The operator replaces it.
	op := mustRRs(t, `_dns.ns1.`+z+` 300 IN SVCB 1 . oots="doq:10"`)
	zd.mu.Lock()
	zd.stageRRsetLocked("_dns.ns1."+z, core.RRset{Name: "_dns.ns1." + z, RRtype: dns.TypeSVCB, RRs: op})
	zd.publishWorkingSetLocked(zd.generation.Load(), false)
	zd.mu.Unlock()
	if err := zd.CreateTransportSignalRRs(conf); err != nil {
		t.Fatal(err)
	}
	if got := svcbRecords(zd, "_dns.ns1."+z); !sameRecords(got, op) {
		t.Fatalf("the operator's RRset was not left alone: %v", got)
	}
	if _, ok, _ := kdb.GetTransportSignalStored(z, "_dns.ns1."+z); ok {
		t.Fatal("the record of the pass's signal outlived the operator's takeover")
	}
}

// A forget whose KeyDB delete fails is not undone by the KeyDB's record
// (CodeRabbit on #1051, 2026-11-15). The operator adds a TXT RRset beside
// the pass's signal, so the RRset there is the operator's and the pass
// forgets it, but the KeyDB refuses the delete. The operator then removes
// the TXT: the SVCB alone is the same bytes the pass stored, and without
// the revocation held in memory the KeyDB's record would make it the
// pass's again, to be rewritten. Once the KeyDB takes the delete, the next
// run drops the record.
func TestAFailedForgetIsNotUndoneByTheKeyDBRecord(t *testing.T) {
	const z = "forgetfail.sig.example."
	const owner = "_dns.ns1." + z
	kdb := newTestKeyDB(t)
	zd, conf := signalTestZone(t, z, z+`	3600	IN	NS	ns1.`+z+`
ns1.`+z+`	3600	IN	A	127.0.0.1
`, "127.0.0.1:53")
	zd.KeyDB = kdb
	conf.Service.Identities = []string{"ns1." + z}
	conf.Service.Transport.Signal = "dot:50"
	if err := zd.CreateTransportSignalRRs(conf); err != nil {
		t.Fatal(err)
	}
	stored := svcbRecords(zd, owner)
	if len(stored) != 1 {
		t.Fatalf("the pass stored %v", stored)
	}

	// The operator adds a TXT RRset at the owner; the KeyDB refuses deletes.
	zd.mu.Lock()
	zd.stageRRsetLocked(owner, core.RRset{Name: owner, RRtype: dns.TypeTXT, RRs: mustRRs(t, owner+` 300 IN TXT "operator"`)})
	zd.publishWorkingSetLocked(zd.generation.Load(), false)
	zd.mu.Unlock()
	if _, err := kdb.DB.Exec(`CREATE TRIGGER refuse_delete BEFORE DELETE ON TransportSignalStored
BEGIN SELECT RAISE(ABORT, 'delete refused by the test'); END`); err != nil {
		t.Fatal(err)
	}
	logs := captureSignalLog(t)
	if err := zd.CreateTransportSignalRRs(conf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "could not drop the stored-signal record") {
		t.Fatalf("no warning for the failed delete:\n%s", logs.String())
	}
	if _, ok, _ := kdb.GetTransportSignalStored(z, owner); !ok {
		t.Fatal("the refused delete should have left the KeyDB record")
	}

	// The operator removes the TXT. The SVCB alone is the pass's old bytes,
	// and the configuration changes: the pass must not rewrite it.
	zd.mu.Lock()
	zd.stageDeleteLocked(owner, dns.TypeTXT)
	zd.publishWorkingSetLocked(zd.generation.Load(), false)
	zd.mu.Unlock()
	conf.Service.Transport.Signal = "dot:60"
	if err := zd.CreateTransportSignalRRs(conf); err != nil {
		t.Fatal(err)
	}
	if got := svcbRecords(zd, owner); !sameRecords(got, stored) {
		t.Fatalf("the KeyDB record undid the revocation: the pass rewrote the operator's SVCB to %v", got)
	}
	if own, err := zd.signalStoredByPass(owner, stored); err != nil || own {
		t.Fatal("the revoked SVCB is known as the pass's own again")
	}

	// The KeyDB takes deletes again: the next run drops the record.
	if _, err := kdb.DB.Exec(`DROP TRIGGER refuse_delete`); err != nil {
		t.Fatal(err)
	}
	if err := zd.CreateTransportSignalRRs(conf); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := kdb.GetTransportSignalStored(z, owner); ok {
		t.Fatal("the record outlived a run after the KeyDB took deletes again")
	}
	if zd.signalRevocationPending(owner) {
		t.Fatal("the revocation is still pending after the delete succeeded")
	}
	if got := svcbRecords(zd, owner); !sameRecords(got, stored) {
		t.Fatalf("the operator's SVCB changed: %v", got)
	}
}

// service.transport.type none synthesizes nothing and withdraws what the
// pass stored before, under svcb (CodeRabbit on #1051, 2026-11-15).
// Records provisioned in the zone stay. The record of the withdrawn signal
// stays too, as after any withdrawal.
func TestTypeNoneWithdrawsThePassSignal(t *testing.T) {
	const z = "typenone.sig.example."
	kdb := newTestKeyDB(t)
	zd, conf := signalTestZone(t, z, z+`	3600	IN	NS	ns1.`+z+`
`+z+`	3600	IN	NS	ns2.`+z+`
ns1.`+z+`	3600	IN	A	127.0.0.1
ns2.`+z+`	3600	IN	A	192.0.2.2
_dns.ns2.`+z+`	300	IN	SVCB	1 . oots="doq:10"
`, "127.0.0.1:53")
	zd.KeyDB = kdb
	conf.Service.Identities = []string{"ns1." + z}
	conf.Service.Transport.Signal = "dot:50"
	if err := zd.CreateTransportSignalRRs(conf); err != nil {
		t.Fatal(err)
	}
	if len(svcbRecords(zd, "_dns.ns1."+z)) != 1 {
		t.Fatal("the pass stored no signal under svcb")
	}
	provisioned := svcbRecords(zd, "_dns.ns2."+z)

	conf.Service.Transport.Type = "none"
	if err := zd.CreateTransportSignalRRs(conf); err != nil {
		t.Fatal(err)
	}
	if getOwnerFrom(zd.publishedSnapshot(), "_dns.ns1."+z) != nil {
		t.Fatalf("type none left the pass's signal in place: %v", svcbRecords(zd, "_dns.ns1."+z))
	}
	if got := svcbRecords(zd, "_dns.ns2."+z); !sameRecords(got, provisioned) {
		t.Fatalf("type none touched a provisioned signal: %v", got)
	}
	if _, ok, _ := kdb.GetTransportSignalStored(z, "_dns.ns1."+z); !ok {
		t.Fatal("the record of the withdrawn signal was dropped")
	}
}

// A reload whose file now holds an operator's SVCB RRset at an owner where
// the pass had stored its signal: the old signal is not carried over and
// merged into the operator's RRset. The operator's RRset alone is served.
func TestAReloadDoesNotMergeTheOldSignalIntoTheOperators(t *testing.T) {
	const head = `example.	3600	IN	SOA	ns1.example. hostmaster.example. %d 7200 1800 604800 7200
example.	3600	IN	NS	ns1.example.
ns1.example.	3600	IN	A	127.0.0.1
`
	zd := reloadZone(t, newTestKeyDB(t), fmt.Sprintf(head, 1))
	zd.Options[OptAddTransportSignal] = true
	prevSVCB, prevListeners := Globals.ServerSVCB, Conf.Listeners.Addresses
	Globals.ServerSVCB = &dns.SVCB{Hdr: dns.RR_Header{Name: "_dns.server.example.", Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: 300}, Priority: 1, Target: "."}
	Conf.Listeners.Addresses = []string{"127.0.0.1:53"}
	t.Cleanup(func() { Globals.ServerSVCB, Conf.Listeners.Addresses = prevSVCB, prevListeners })
	conf := &Config{}
	conf.Service.Transport.Type = "svcb"
	conf.Service.Identities = []string{"ns1.example."}
	conf.Service.Transport.Signal = "dot:50"
	conf.Listeners.Addresses = Conf.Listeners.Addresses
	if err := zd.CreateTransportSignalRRs(conf); err != nil {
		t.Fatal(err)
	}
	if got := svcbRecords(zd, "_dns.ns1.example."); len(got) != 1 || !strings.Contains(got[0].String(), "dot:50") {
		t.Fatalf("the pass did not store its signal: %v", got)
	}

	operatorEdit(t, zd, fmt.Sprintf(head, 2)+`_dns.ns1.example.	300	IN	SVCB	1 . oots="doq:30"
`)
	if _, err := zd.Refresh(context.Background(), false, false, true, conf); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if got := svcbRecords(zd, "_dns.ns1.example."); len(got) != 1 || !strings.Contains(got[0].String(), "doq:30") {
		t.Fatalf("the reload merged the old signal into the operator's RRset: %v", got)
	}
}

// A reload whose file now holds an operator's CNAME at the owner where the
// pass had stored its signal: the old signal is not carried over beside it
// (RFC 1034 section 3.6.2). The CNAME alone is served.
func TestAReloadDoesNotCarryTheOldSignalBesideAnOperatorsCNAME(t *testing.T) {
	const head = `example.	3600	IN	SOA	ns1.example. hostmaster.example. %d 7200 1800 604800 7200
example.	3600	IN	NS	ns1.example.
ns1.example.	3600	IN	A	127.0.0.1
`
	zd := reloadZone(t, newTestKeyDB(t), fmt.Sprintf(head, 1))
	zd.Options[OptAddTransportSignal] = true
	prevSVCB, prevListeners := Globals.ServerSVCB, Conf.Listeners.Addresses
	Globals.ServerSVCB = &dns.SVCB{Hdr: dns.RR_Header{Name: "_dns.server.example.", Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: 300}, Priority: 1, Target: "."}
	Conf.Listeners.Addresses = []string{"127.0.0.1:53"}
	t.Cleanup(func() { Globals.ServerSVCB, Conf.Listeners.Addresses = prevSVCB, prevListeners })
	conf := &Config{}
	conf.Service.Transport.Type = "svcb"
	conf.Service.Identities = []string{"ns1.example."}
	conf.Service.Transport.Signal = "dot:50"
	conf.Listeners.Addresses = Conf.Listeners.Addresses
	if err := zd.CreateTransportSignalRRs(conf); err != nil {
		t.Fatal(err)
	}
	if got := svcbRecords(zd, "_dns.ns1.example."); len(got) != 1 {
		t.Fatalf("the pass did not store its signal: %v", got)
	}

	operatorEdit(t, zd, fmt.Sprintf(head, 2)+`_dns.ns1.example.	300	IN	CNAME	_dns.ns.provider.example.
`)
	if _, err := zd.Refresh(context.Background(), false, false, true, conf); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	od := getOwnerFrom(zd.publishedSnapshot(), "_dns.ns1.example.")
	if od == nil || ownerRRsetCount(od) != 1 || len(od.RRtypes.GetOnlyRRSet(dns.TypeCNAME).RRs) != 1 {
		t.Fatalf("the reload carried the old signal beside the operator's CNAME: %v", od)
	}
}

// A signal is read at its home, the most specific zone hosted here that
// holds it: under a co-hosted child, the child's RRset, not a copy below the
// parent's zone cut.
func TestASignalIsReadAtItsHomeNotBelowTheParentsCut(t *testing.T) {
	const parent = "cohost.sig.example."
	const child = "child." + parent
	const ns = "ns1." + child
	zp, _ := signalTestZone(t, parent, parent+`	3600	IN	NS	`+ns+`
`+child+`	3600	IN	NS	`+ns+`
`+ns+`	3600	IN	A	192.0.2.1
_dns.`+ns+`	300	IN	SVCB	1 . oots="dot:1"
`, "127.0.0.1:53")
	signalTestZone(t, child, child+`	3600	IN	NS	`+ns+`
`+ns+`	3600	IN	A	192.0.2.1
_dns.`+ns+`	300	IN	SVCB	1 . oots="dot:2"
`, "127.0.0.1:53")
	got := zp.collectSignalRRsets(zp.publishedSnapshot())
	if len(got) != 1 || len(got[0].RRs) != 1 || !strings.Contains(got[0].RRs[0].String(), "dot:2") {
		t.Fatalf("the parent's responses did not carry the child's signal: %v", got)
	}
}

// Below a zone cut to a child not hosted here the parent holds only glue and
// occluded data. A signal stored there is not served: not in the parent's
// own responses, and not in those of another zone that names the name.
func TestASignalBelowACutToAChildNotHostedIsNotServed(t *testing.T) {
	noIdentities(t)
	const parent = "cut.sig.example."
	const child = "child." + parent
	const ns = "ns1." + child
	const cz = "cut-customer.sig.example."
	zp, _ := signalTestZone(t, parent, parent+`	3600	IN	NS	`+ns+`
`+child+`	3600	IN	NS	`+ns+`
`+ns+`	3600	IN	A	192.0.2.1
_dns.`+ns+`	300	IN	SVCB	1 . oots="dot:1"
`, "127.0.0.1:53")
	customer, _ := signalTestZone(t, cz, cz+`	3600	IN	NS	`+ns+`
`, "127.0.0.1:53")
	for _, zd := range []*ZoneData{zp, customer} {
		if got := zd.collectSignalRRsets(zd.publishedSnapshot()); len(got) != 0 {
			t.Fatalf("%s: a signal below the cut to %s was served: %v", zd.ZoneName, child, got)
		}
	}
}
