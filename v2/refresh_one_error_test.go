/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// A failed refresh logs exactly one ERROR, at noteRefreshFailure, and that line
// names every upstream tried with its own error. The lines that said the same
// thing beside it are DEBUG now; these tests hold both halves on each path a
// refresh fails on: the ticker's (runZoneRefresh), the first load, and the
// first load's retry.

// capturedRecord is one log record as the tests read it: level, message and
// fields, with no text format in between.
type capturedRecord struct {
	level slog.Level
	msg   string
	attrs map[string]string
}

type recordCapture struct {
	mu   sync.Mutex
	recs []capturedRecord
}

func (c *recordCapture) Enabled(context.Context, slog.Level) bool { return true }

func (c *recordCapture) Handle(_ context.Context, r slog.Record) error {
	rec := capturedRecord{level: r.Level, msg: r.Message, attrs: map[string]string{}}
	r.Attrs(func(a slog.Attr) bool {
		rec.attrs[a.Key] = a.Value.String()
		return true
	})
	c.mu.Lock()
	c.recs = append(c.recs, rec)
	c.mu.Unlock()
	return nil
}

func (c *recordCapture) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *recordCapture) WithGroup(string) slog.Handler      { return c }

// mentioning returns the records at level that name zone anywhere: in the
// message or in any field. Wider than the zone field on purpose, so an ERROR
// that names the zone under some other key is still counted.
func (c *recordCapture) mentioning(zone string, level slog.Level) []capturedRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []capturedRecord
	for _, r := range c.recs {
		if r.level != level {
			continue
		}
		hit := strings.Contains(r.msg, zone)
		for _, v := range r.attrs {
			hit = hit || strings.Contains(v, zone)
		}
		if hit {
			out = append(out, r)
		}
	}
	return out
}

// withMsg returns the records at level with message msg for zone.
func (c *recordCapture) withMsg(zone string, level slog.Level, msg string) []capturedRecord {
	var out []capturedRecord
	for _, r := range c.mentioning(zone, level) {
		if r.msg == msg {
			out = append(out, r)
		}
	}
	return out
}

// captureRefreshLogs sends every record to the returned capture for the rest
// of the test, DEBUG included for the two subsystems a refresh logs in.
func captureRefreshLogs(t *testing.T) *recordCapture {
	t.Helper()
	c := &recordCapture{}
	prev := slog.Default()
	slog.SetDefault(slog.New(c))
	t.Cleanup(func() { slog.SetDefault(prev) })
	for _, sub := range []string{"zones", "engine"} {
		lv := getOrCreateLevel(sub)
		was := lv.Level()
		lv.Set(slog.LevelDebug)
		t.Cleanup(func() { lv.Set(was) })
	}
	return c
}

// closedUDPPorts returns n distinct loopback addresses with nothing bound on
// them. All n are held until the last is chosen, so none is handed out twice.
func closedUDPPorts(t *testing.T, n int) []string {
	t.Helper()
	var addrs []string
	var held []net.PacketConn
	for range n {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		held = append(held, pc)
		addrs = append(addrs, pc.LocalAddr().String())
	}
	for _, pc := range held {
		_ = pc.Close()
	}
	return addrs
}

// upstreamErrorFor is the entry upstream_errors holds for addr.
func upstreamErrorFor(rec capturedRecord, addr string) string {
	for _, entry := range strings.Split(rec.attrs["upstream_errors"], " | ") {
		if strings.HasPrefix(entry, addr+": ") {
			return entry
		}
	}
	return ""
}

// startRefusingPrimary answers the SOA probe over UDP with serial and every
// transfer over TCP with REFUSED: a primary whose allow-transfer ACL does not
// list us.
func startRefusingPrimary(t *testing.T, zone string, serial uint32) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	pc, err := net.ListenPacket("udp", ln.Addr().String())
	if err != nil {
		ln.Close()
		t.Fatalf("listen udp on the tcp port: %v", err)
	}
	mux := dns.NewServeMux()
	mux.HandleFunc(zone, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Qtype == dns.TypeAXFR || r.Question[0].Qtype == dns.TypeIXFR {
			m.Rcode = dns.RcodeRefused
		} else {
			m.Answer = append(m.Answer, &dns.SOA{
				Hdr:    dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
				Ns:     "ns." + zone,
				Mbox:   "hostmaster." + zone,
				Serial: serial, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 60,
			})
		}
		_ = w.WriteMsg(m)
	})
	var started sync.WaitGroup
	started.Add(2)
	tcpSrv := &dns.Server{Listener: ln, Handler: mux, NotifyStartedFunc: started.Done}
	udpSrv := &dns.Server{PacketConn: pc, Handler: mux, NotifyStartedFunc: started.Done}
	go func() { _ = tcpSrv.ActivateAndServe() }()
	go func() { _ = udpSrv.ActivateAndServe() }()
	started.Wait()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = tcpSrv.ShutdownContext(ctx)
		_ = udpSrv.ShutdownContext(ctx)
	})
	return ln.Addr().String()
}

// wantOneError holds the one ERROR of a failed refresh to its fields: it
// names every upstream with a kind, and every upstream's own error.
func wantOneError(t *testing.T, rec capturedRecord, stage string, upstreams map[string][]string) {
	t.Helper()
	if got := rec.attrs["stage"]; got != stage {
		t.Errorf("stage=%q, want %q", got, stage)
	}
	kinds := map[string]string{}
	for _, pair := range strings.Split(rec.attrs["upstreams"], ",") {
		if i := strings.LastIndex(pair, "="); i > 0 {
			kinds[pair[:i]] = pair[i+1:]
		}
	}
	for addr, allowed := range upstreams {
		kind, ok := kinds[addr]
		if !ok {
			t.Errorf("upstream %s is missing from upstreams=%q", addr, rec.attrs["upstreams"])
			continue
		}
		okKind := false
		for _, k := range allowed {
			okKind = okKind || kind == k
		}
		if !okKind {
			t.Errorf("upstream %s has kind %q, want one of %v", addr, kind, allowed)
		}
		if upstreamErrorFor(rec, addr) == "" {
			t.Errorf("upstream %s has no error in upstream_errors=%q", addr, rec.attrs["upstream_errors"])
		}
	}
	if len(kinds) != len(upstreams) {
		t.Errorf("upstreams=%q names %d upstreams, want %d", rec.attrs["upstreams"], len(kinds), len(upstreams))
	}
	if n := strings.Count(rec.attrs["upstream_errors"], " | ") + 1; n != len(upstreams) {
		t.Errorf("upstream_errors=%q holds %d errors, want %d", rec.attrs["upstream_errors"], n, len(upstreams))
	}
	if rec.attrs["since"] == "" || rec.attrs["error"] == "" {
		t.Errorf("since and error must be set: %v", rec.attrs)
	}
}

// The ticker path, failing at the probe: no upstream answers. One ERROR per
// refresh, naming both upstreams; the failure count and its start carry over
// from one refresh to the next.
func TestAFailedProbeOnTheTickerPathLogsOneError(t *testing.T) {
	withRefreshBudgets(t, 1, 5)
	logs := captureRefreshLogs(t)
	quiet, stop := startBlackholeUDP(t)
	defer stop()
	closed := closedUDPPorts(t, 1)[0]

	const zone = "probe.one-error.test."
	zd := &ZoneData{
		ZoneName:  zone,
		ZoneType:  Secondary,
		Upstreams: []PeerConf{{Addr: quiet}, {Addr: closed}},
		Logger:    discardLogger(),
	}
	for i := 1; i <= 2; i++ {
		if _, err := runZoneRefresh(context.Background(),
			refreshJob{zd: zd, zone: zone, gen: zd.generation.Load()}, &Config{}); err == nil {
			t.Fatal("the refresh succeeded with no upstream answering")
		}
	}

	errs := logs.mentioning(zone, slog.LevelError)
	if len(errs) != 2 {
		t.Fatalf("two failed refreshes logged %d ERRORs, want 2: %+v", len(errs), errs)
	}
	for i, rec := range errs {
		if rec.msg != "zone refresh failed" {
			t.Errorf("ERROR %d is %q, want the refresh failure", i, rec.msg)
		}
		wantOneError(t, rec, refreshStageProbe, map[string][]string{
			quiet:  {"timeout", "closed"},
			closed: {"connrefused", "timeout", "closed"},
		})
		if got, want := rec.attrs["attempts"], fmt.Sprint(i+1); got != want {
			t.Errorf("ERROR %d: attempts=%s, want %s", i, got, want)
		}
	}
	if errs[0].attrs["since"] != errs[1].attrs["since"] {
		t.Errorf("since moved within one run of failures: %s, then %s",
			errs[0].attrs["since"], errs[1].attrs["since"])
	}
	if n := len(logs.withMsg(zone, slog.LevelDebug, "DoTransfer: SOA probe failed on all upstreams (unreachable)")); n != 2 {
		t.Errorf("the probe's own summary was logged %d times at DEBUG, want once per refresh", n)
	}
}

// The ticker path, failing at the transfer: the probe answers, one upstream
// refuses the transfer and the other is not listening on TCP. One ERROR, with
// the REFUSED read from the rcode and not the text.
func TestAFailedTransferOnTheTickerPathLogsOneError(t *testing.T) {
	withRefreshBudgets(t, 1, 5)
	logs := captureRefreshLogs(t)

	const zone = "xfr.one-error.test."
	refusing := startRefusingPrimary(t, zone, 10)
	soaOnly, stop := startTestSOAServer(t, zone, 10, dns.RcodeSuccess) // UDP only: TCP is refused
	defer stop()

	zd := &ZoneData{
		ZoneName:       zone,
		ZoneType:       Secondary,
		ZoneStore:      MapZone,
		Upstreams:      []PeerConf{{Addr: refusing}, {Addr: soaOnly}},
		IncomingSerial: 5,
		Logger:         discardLogger(),
	}
	if _, err := runZoneRefresh(context.Background(),
		refreshJob{zd: zd, zone: zone, gen: zd.generation.Load()}, &Config{}); err == nil {
		t.Fatal("the refresh succeeded with no upstream giving the zone")
	}

	errs := logs.mentioning(zone, slog.LevelError)
	if len(errs) != 1 {
		t.Fatalf("one failed refresh logged %d ERRORs, want 1: %+v", len(errs), errs)
	}
	wantOneError(t, errs[0], refreshStageTransfer, map[string][]string{
		refusing: {"refused"},
		soaOnly:  {"connrefused"},
	})
	if got := errs[0].attrs["kind"]; got != refreshKindMixed {
		t.Errorf("kind=%q for two upstreams failing differently, want %q", got, refreshKindMixed)
	}
	// Each error under its own upstream, not merely somewhere on the line.
	if e := upstreamErrorFor(errs[0], refusing); !strings.Contains(e, "REFUSED") {
		t.Errorf("the refusing upstream's entry %q lost the rcode text", e)
	}
	if e := upstreamErrorFor(errs[0], soaOnly); !strings.Contains(e, "connection refused") || strings.Contains(e, "REFUSED") {
		t.Errorf("the TCP-less upstream's entry is %q, want its own connection refusal", e)
	}
	for _, msg := range []string{"FetchFromUpstream: AXFR failed on all upstreams", "FetchZone failed"} {
		if n := len(logs.withMsg(zone, slog.LevelDebug, msg)); n != 1 {
			t.Errorf("%q was logged %d times at DEBUG, want 1", msg, n)
		}
	}
}

// The first load and its retry, through the engine: a pre-registered zone
// whose primaries are down. Each attempt logs one ERROR, the first as a
// refresh failure and the next as the retry's, and the count runs on across
// them though the retry clears RefreshError first.
func TestAFailedFirstLoadAndItsRetryLogOneErrorEach(t *testing.T) {
	authApp(t)
	withRefreshBudgets(t, 1, 5)
	prevRetry := firstLoadRetrySeconds
	firstLoadRetrySeconds = 1
	t.Cleanup(func() { firstLoadRetrySeconds = prevRetry })
	logs := captureRefreshLogs(t)

	const zone = "first.one-error.test."
	ups := closedUDPPorts(t, 2)
	up1, up2 := ups[0], ups[1]
	zd := &ZoneData{
		ZoneName:      zone,
		ZoneType:      Secondary,
		ZoneStore:     MapZone,
		Upstreams:     []PeerConf{{Addr: up1}, {Addr: up2}},
		FirstZoneLoad: true,
		Logger:        discardLogger(),
	}
	Zones.Set(zone, zd)
	t.Cleanup(func() { Zones.Remove(zone) })

	conf := &Config{}
	conf.Internal.KeyDB = Conf.Internal.KeyDB
	conf.Internal.RefreshZoneCh = make(chan ZoneRefresher, 1)
	conf.Internal.BumpZoneCh = make(chan BumperData, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); RefreshEngine(ctx, conf) }()
	stopEngine := func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("RefreshEngine did not shut down")
		}
	}
	t.Cleanup(stopEngine)

	conf.Internal.RefreshZoneCh <- ZoneRefresher{Name: zone}
	deadline := time.Now().Add(15 * time.Second)
	for len(logs.withMsg(zone, slog.LevelError, "initial load retry failed")) == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("no retry of the first load within 15s; ERRORs so far: %+v",
				logs.mentioning(zone, slog.LevelError))
		}
		time.Sleep(50 * time.Millisecond)
	}
	stopEngine()

	errs := logs.mentioning(zone, slog.LevelError)
	probes := logs.withMsg(zone, slog.LevelDebug, "DoTransfer: SOA probe failed on all upstreams (unreachable)")
	if len(errs) != len(probes) {
		t.Fatalf("%d failed attempts logged %d ERRORs, want one each: %+v", len(probes), len(errs), errs)
	}
	if errs[0].msg != "zone refresh failed" || errs[1].msg != "initial load retry failed" {
		t.Errorf("ERRORs are %q then %q, want the first load's then the retry's", errs[0].msg, errs[1].msg)
	}
	for i, rec := range errs {
		wantOneError(t, rec, refreshStageProbe, map[string][]string{
			up1: {"connrefused", "timeout", "closed"},
			up2: {"connrefused", "timeout", "closed"},
		})
		if got, want := rec.attrs["attempts"], fmt.Sprint(i+1); got != want {
			t.Errorf("ERROR %d (%s): attempts=%s, want %s", i, rec.msg, got, want)
		}
		if rec.attrs["since"] != errs[0].attrs["since"] {
			t.Errorf("ERROR %d: since=%s, want the first failure's %s", i, rec.attrs["since"], errs[0].attrs["since"])
		}
	}
}

// A refresh that sees a usable SOA ends the run of failures: the next failure
// is attempts=1 with a new since. One whose primaries all answer REFUSED
// proves nothing, so the run goes on through it.
func TestOnlyAUsableSOAEndsARunOfFailures(t *testing.T) {
	withRefreshBudgets(t, 1, 5)
	logs := captureRefreshLogs(t)
	const zone = "run.one-error.test."
	down := closedUDPPorts(t, 1)[0]
	usable, stopUsable := startTestSOAServer(t, zone, 42, dns.RcodeSuccess)
	defer stopUsable()
	refusing, stopRefusing := startTestSOAServer(t, zone, 42, dns.RcodeRefused)
	defer stopRefusing()

	zd := &ZoneData{
		ZoneName:       zone,
		ZoneType:       Secondary,
		IncomingSerial: 42, // what the usable primary offers: no transfer
		Logger:         discardLogger(),
	}
	refreshFrom := func(addr string) error {
		zd.Upstreams = []PeerConf{{Addr: addr}}
		_, err := runZoneRefresh(context.Background(),
			refreshJob{zd: zd, zone: zone, gen: zd.generation.Load()}, &Config{})
		return err
	}
	lastError := func() capturedRecord {
		errs := logs.withMsg(zone, slog.LevelError, "zone refresh failed")
		if len(errs) == 0 {
			t.Fatal("no refresh failure logged")
		}
		return errs[len(errs)-1]
	}

	if refreshFrom(down) == nil {
		t.Fatal("refresh from a down primary succeeded")
	}
	// Back-date the run, so a since that carried over is told from a new one.
	zd.refreshRun.mu.Lock()
	zd.refreshRun.failingSince = time.Now().Add(-time.Hour)
	zd.refreshRun.mu.Unlock()
	old := zd.refreshRun.failingSince.UTC().Format(time.RFC3339)

	if err := refreshFrom(refusing); err != nil {
		t.Fatalf("an all-REFUSED refresh is a quiet back-off, not an error: %v", err)
	}
	if refreshFrom(down) == nil {
		t.Fatal("refresh from a down primary succeeded")
	}
	if rec := lastError(); rec.attrs["attempts"] != "2" || rec.attrs["since"] != old {
		t.Errorf("after an all-REFUSED refresh: attempts=%s since=%s, want 2 and %s: it proved nothing",
			rec.attrs["attempts"], rec.attrs["since"], old)
	}
	if n := len(logs.withMsg(zone, slog.LevelInfo, "zone refresh recovered")); n != 0 {
		t.Errorf("an all-REFUSED refresh logged a recovery (%d)", n)
	}

	if err := refreshFrom(usable); err != nil {
		t.Fatalf("refresh from a usable primary: %v", err)
	}
	rec := logs.withMsg(zone, slog.LevelInfo, "zone refresh recovered")
	if len(rec) != 1 || rec[0].attrs["failed_attempts"] != "2" {
		t.Errorf("the recovery was logged as %+v, want once with failed_attempts=2", rec)
	}
	if refreshFrom(down) == nil {
		t.Fatal("refresh from a down primary succeeded")
	}
	if rec := lastError(); rec.attrs["attempts"] != "1" || rec.attrs["since"] == old {
		t.Errorf("after a usable SOA: attempts=%s since=%s, want 1 and a new since",
			rec.attrs["attempts"], rec.attrs["since"])
	}
}

// A first bind that restores a confirmation stamp off disk has not seen a
// usable SOA, so a refresh that does that and then gets only REFUSED leaves
// the run of failures open. Keyed on LatestRefresh, the restore read as a
// confirmation and logged a false recovery.
func TestARestoredStampIsNoConfirmation(t *testing.T) {
	logs := captureRefreshLogs(t)
	kdb := newTestKeyDB(t)
	conf, dir := persistentConf(t, kdb)
	hourAgo := time.Now().Add(-time.Hour).UTC().Truncate(time.Millisecond)
	if err := kdb.SetZoneRefreshState("example.", 7, hourAgo); err != nil {
		t.Fatalf("seed the stamp: %v", err)
	}
	refusing, stop := startTestSOAServer(t, "example.", 7, dns.RcodeRefused)
	defer stop()
	zd := persistedSecondary(t, kdb, dir, refusing)

	noteRefreshFailure(zd, "example.", errors.New("the primary was down"), "zone refresh failed")
	if _, err := runZoneRefresh(context.Background(),
		refreshJob{zd: zd, zone: "example.", gen: zd.generation.Load()}, conf); err != nil {
		t.Fatalf("an all-REFUSED refresh is a quiet back-off, not an error: %v", err)
	}
	if !zd.lastRefresh().Equal(hourAgo) {
		t.Fatalf("test setup: the stamp was not restored (LatestRefresh %v, want %v)", zd.lastRefresh(), hourAgo)
	}
	if n := len(logs.withMsg("example.", slog.LevelInfo, "zone refresh recovered")); n != 0 {
		t.Error("a restored stamp and an all-REFUSED refresh logged a recovery")
	}
	zd.refreshRun.mu.Lock()
	failures := zd.refreshRun.failures
	zd.refreshRun.mu.Unlock()
	if failures != 1 {
		t.Errorf("the run of failures is %d after a refresh that proved nothing, want it kept at 1", failures)
	}
}

// A primary's forced reload that cannot read its zone file opens a run of
// failures, and the unforced refresh after it, which skips the file because
// its stat has not moved, does not close it. Only a read does. The bad file
// has the good one's length and mtime, so the skip sees nothing new; no chmod,
// so it holds for root too.
func TestASkippedFileReadIsNoConfirmation(t *testing.T) {
	logs := captureRefreshLogs(t)
	zd, _ := firstLoadFileZone(t, newTestKeyDB(t), s2Zone)
	firstLoadFromFile(t, zd)
	st, err := os.Stat(zd.Zonefile)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	writeKeepingStat := func(content string) {
		t.Helper()
		if err := os.WriteFile(zd.Zonefile, []byte(content), 0644); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := os.Chtimes(zd.Zonefile, st.ModTime(), st.ModTime()); err != nil {
			t.Fatalf("chtimes: %v", err)
		}
	}
	refresh := func(force bool) error {
		_, err := runZoneRefresh(context.Background(),
			refreshJob{zd: zd, zone: "example.", gen: zd.generation.Load(), force: force}, &Config{})
		return err
	}

	writeKeepingStat(strings.Repeat("x", len(s2Zone)-1) + "\n")
	if refresh(true) == nil {
		t.Fatal("a forced reload read a zone file that does not parse")
	}
	if err := refresh(false); err != nil {
		t.Fatalf("test setup: the unforced refresh read the file instead of skipping it: %v", err)
	}
	if n := len(logs.withMsg("example.", slog.LevelInfo, "zone refresh recovered")); n != 0 {
		t.Error("a refresh that skipped the bad file logged a recovery")
	}

	writeKeepingStat(s2Zone)
	if err := refresh(true); err != nil {
		t.Fatalf("a forced reload of the readable file: %v", err)
	}
	rec := logs.withMsg("example.", slog.LevelInfo, "zone refresh recovered")
	if len(rec) != 1 || rec[0].attrs["failed_attempts"] != "1" {
		t.Errorf("the recovery was logged as %+v, want once, after the read, with failed_attempts=1", rec)
	}
}

// A refresh that was not deferred ends a deferral run even when it proves
// nothing, and leaves the run of failures as it was. Left open, the deferral
// run would measure a later hold from this one and reach ERROR at once.
func TestARefreshThatProvesNothingStillEndsADeferral(t *testing.T) {
	captureRefreshLogs(t)
	const zone = "defer.one-error.test."
	refusing, stop := startTestSOAServer(t, zone, 42, dns.RcodeRefused)
	defer stop()
	zd := &ZoneData{ZoneName: zone, ZoneType: Secondary, Upstreams: []PeerConf{{Addr: refusing}},
		Logger: discardLogger()}

	noteRefreshFailure(zd, zone, errors.New("the primary was down"), "zone refresh failed")
	noteRefreshFailure(zd, zone, fmt.Errorf("zone %s: %w", zone, ErrRefreshHeld), "zone refresh failed")
	if _, err := runZoneRefresh(context.Background(),
		refreshJob{zd: zd, zone: zone, gen: zd.generation.Load()}, &Config{}); err != nil {
		t.Fatalf("an all-REFUSED refresh is a quiet back-off, not an error: %v", err)
	}
	zd.refreshRun.mu.Lock()
	deferrals, failures := zd.refreshRun.deferrals, zd.refreshRun.failures
	zd.refreshRun.mu.Unlock()
	if deferrals != 0 {
		t.Errorf("the deferral run is still open (%d) after a refresh that was not deferred", deferrals)
	}
	if failures != 1 {
		t.Errorf("the run of failures is %d, want it kept at 1: the refresh proved nothing", failures)
	}
}

// A secondary whose persisted copy cannot be read at first bind logs one
// ERROR for it, from the adoption: the refresh path's summary does not see a
// failure the transfer may yet make good. Its primary answers REFUSED, a quiet
// back-off with no error, so that ERROR is the only one.
func TestAnUnreadablePersistedCopyLogsOneError(t *testing.T) {
	logs := captureRefreshLogs(t)
	kdb := newTestKeyDB(t)
	conf, dir := persistentConf(t, kdb)
	refusing, stop := startTestSOAServer(t, "example.", 7, dns.RcodeRefused)
	defer stop()
	zd := persistedSecondary(t, kdb, dir, refusing)
	if err := os.WriteFile(filepath.Join(dir, "example.zone"), []byte("not a zone file\n"), 0644); err != nil {
		t.Fatalf("corrupt the copy: %v", err)
	}

	if _, err := runZoneRefresh(context.Background(),
		refreshJob{zd: zd, zone: "example.", gen: zd.generation.Load()}, conf); err != nil {
		t.Fatalf("an all-REFUSED refresh is a quiet back-off, not an error: %v", err)
	}
	errs := logs.mentioning("example.", slog.LevelError)
	if len(errs) != 1 || errs[0].msg != "could not read persisted zone copy at first bind, continuing to transfer" {
		t.Errorf("an unreadable persisted copy logged %+v, want exactly one ERROR, from the adoption", errs)
	}
}

// A persisted copy that cannot be reached is a storage fault and logs one
// ERROR, from the adoption; a copy that is simply not there logs none. The
// primary answers REFUSED, a quiet back-off with no error, so the adoption's
// line is the only ERROR there can be.
func TestAnUnreachablePersistedCopyLogsOneError(t *testing.T) {
	const unreachable = "could not reach persisted zone copy at first bind, continuing to transfer"
	for _, c := range []struct {
		what   string
		break_ func(t *testing.T, conf *Config, dir string)
		want   int
	}{
		{"no copy on disk", func(t *testing.T, _ *Config, dir string) {
			if err := os.Remove(filepath.Join(dir, "example.zone")); err != nil {
				t.Fatalf("remove: %v", err)
			}
		}, 0},
		{"a directory that may not be searched", func(t *testing.T, _ *Config, dir string) {
			if os.Geteuid() == 0 {
				t.Skip("root searches a mode-000 directory")
			}
			if err := os.Chmod(dir, 0); err != nil {
				t.Fatalf("chmod: %v", err)
			}
			t.Cleanup(func() { _ = os.Chmod(dir, 0755) })
		}, 1},
		{"a path through a regular file", func(t *testing.T, conf *Config, dir string) {
			file := filepath.Join(dir, "not-a-directory")
			if err := os.WriteFile(file, nil, 0644); err != nil {
				t.Fatalf("write: %v", err)
			}
			conf.DynamicZones.ZoneDirectory = file
		}, 1},
	} {
		t.Run(c.what, func(t *testing.T) {
			kdb := newTestKeyDB(t)
			conf, dir := persistentConf(t, kdb)
			refusing, stop := startTestSOAServer(t, "example.", 7, dns.RcodeRefused)
			defer stop()
			zd := persistedSecondary(t, kdb, dir, refusing)
			c.break_(t, conf, dir)
			logs := captureRefreshLogs(t)

			if _, err := runZoneRefresh(context.Background(),
				refreshJob{zd: zd, zone: "example.", gen: zd.generation.Load()}, conf); err != nil {
				t.Fatalf("an all-REFUSED refresh is a quiet back-off, not an error: %v", err)
			}
			errs := logs.mentioning("example.", slog.LevelError)
			if len(errs) != c.want {
				t.Fatalf("logged %d ERRORs, want %d: %+v", len(errs), c.want, errs)
			}
			for _, rec := range errs {
				if rec.msg != unreachable || rec.attrs["file"] == "" || rec.attrs["err"] == "" {
					t.Errorf("the ERROR is %q with %v, want the adoption's, naming the file and the error", rec.msg, rec.attrs)
				}
			}
		})
	}
}

// A primary that read its zone file and then could not apply it -- here the
// published serial cannot be read -- fails at stage other, not file. Through
// the engine, as the first load runs it.
func TestAnApplyFailureOnAPrimaryIsStageOther(t *testing.T) {
	zd, _, load := persistPrimary(t, s2Zone, 1000)
	kdb := Conf.Internal.KeyDB
	if _, err := kdb.DB.Exec(`ALTER TABLE OutgoingSerials RENAME TO OutgoingSerialsAway`); err != nil {
		t.Fatalf("hide the table: %v", err)
	}
	t.Cleanup(func() {
		if _, err := kdb.DB.Exec(`ALTER TABLE OutgoingSerialsAway RENAME TO OutgoingSerials`); err != nil {
			t.Errorf("restore the table: %v", err)
		}
	})
	logs := captureRefreshLogs(t)
	load()
	deadline := time.Now().Add(5 * time.Second)
	for !zd.HasError(RefreshError) {
		if time.Now().After(deadline) {
			t.Fatal("the first load did not fail with the published serial unreadable")
		}
		time.Sleep(20 * time.Millisecond)
	}
	errs := logs.withMsg("example.", slog.LevelError, "zone refresh failed")
	if len(errs) != 1 || errs[0].attrs["stage"] != refreshStageOther {
		t.Errorf("an apply failure logged %+v, want one failure at stage other", errs)
	}
}

// A peer whose TLS or TSIG setup fails at the transfer is kind config, read
// off the error ZoneTransferIn returns. Neither case reaches the network.
func TestPeerSetupFailuresAtTheTransferAreConfig(t *testing.T) {
	zd := &ZoneData{ZoneName: "cfg.one-error.test.", ZoneStore: MapZone, Logger: discardLogger()}
	conf := &Config{}
	conf.Internal.TsigKeyStore = NewTsigKeyStore()
	for _, c := range []struct {
		what string
		up   PeerConf
	}{
		{"TLS, a ca-file that is gone", PeerConf{Addr: "127.0.0.1:853", Transport: TransportDoT,
			TLSAuth: TLSAuthPKIX, CAFile: t.TempDir() + "/gone.pem"}},
		{"TSIG, a key not in the store", PeerConf{Addr: closedUDPPorts(t, 1)[0], Key: "no-such-key."}},
	} {
		_, err := zd.ZoneTransferIn(context.Background(), c.up, 0, "axfr", conf)
		if err == nil {
			t.Errorf("%s: the transfer was set up", c.what)
			continue
		}
		if got := refreshErrorKind(err); got != refreshKindConfig {
			t.Errorf("%s: kind %q, want %q (err: %v)", c.what, got, refreshKindConfig, err)
		}
	}
}

// The stage comes with the error. A primary whose zone file cannot be read
// fails at stage file; anything else not an upstream's is other, a primary's
// included.
func TestTheStageComesWithTheError(t *testing.T) {
	logs := captureRefreshLogs(t)
	const zone = "file.one-error.test."
	zd := &ZoneData{
		ZoneName:  zone,
		ZoneType:  Primary,
		ZoneStore: MapZone,
		Zonefile:  t.TempDir() + "/missing.zone",
		Logger:    discardLogger(),
	}
	if _, err := runZoneRefresh(context.Background(),
		refreshJob{zd: zd, zone: zone, gen: zd.generation.Load()}, &Config{}); err == nil {
		t.Fatal("a primary with no zone file refreshed")
	}
	// Every ERROR that names the zone, not only the summary: the read failure
	// itself is DEBUG.
	errs := logs.mentioning(zone, slog.LevelError)
	if len(errs) != 1 || errs[0].msg != "zone refresh failed" || errs[0].attrs["stage"] != refreshStageFile {
		t.Errorf("an unreadable zone file logged %+v, want exactly one ERROR, the summary, at stage file", errs)
	}
	if n := len(logs.withMsg(zone, slog.LevelDebug, "ReadZoneFile failed")); n != 1 {
		t.Errorf("the read failure was logged %d times at DEBUG, want 1", n)
	}

	stageOf := func(err error) string {
		attrs := refreshFailureAttrs(zone, err, 1, time.Now())
		for i := 0; i+1 < len(attrs); i += 2 {
			if attrs[i] == "stage" {
				return attrs[i+1].(string)
			}
		}
		return ""
	}
	if got := stageOf(fmt.Errorf("x: %w", &refreshStageError{stage: refreshStageFile, err: io.EOF})); got != refreshStageFile {
		t.Errorf("a wrapped file failure has stage %q", got)
	}
	if got := stageOf(errors.New("read the published serial: database is locked")); got != refreshStageOther {
		t.Errorf("a failure after the file was read has stage %q, want other", got)
	}
}

// A staged change that keeps the zone from refreshing reaches ERROR: after
// refreshStagedErrorAfter deferrals, again every refreshDeferralReminder, and
// with WARN between. Its end says so. None of it marks the zone failed.
func TestAStagedDeferralReachesError(t *testing.T) {
	logs := captureRefreshLogs(t)
	const zone = "staged.one-error.test."
	zd := &ZoneData{ZoneName: zone, ZoneType: Secondary}
	staged := fmt.Errorf("zone %s: %w", zone, ErrRefreshStaged)

	for i := 1; i <= refreshStagedErrorAfter+1; i++ {
		if noteRefreshFailure(zd, zone, staged, "zone refresh failed") {
			t.Fatalf("deferral %d was counted as a failure", i)
		}
	}
	info := logs.withMsg(zone, slog.LevelInfo, "zone refresh deferred")
	errs := logs.mentioning(zone, slog.LevelError)
	warns := logs.withMsg(zone, slog.LevelWarn, "zone refresh deferred")
	if len(info) != refreshStagedErrorAfter-1 || len(errs) != 1 || len(warns) != 1 {
		t.Fatalf("%d deferrals logged %d INFO, %d ERROR and %d WARN; want %d, 1 and 1",
			refreshStagedErrorAfter+1, len(info), len(errs), len(warns), refreshStagedErrorAfter-1)
	}
	if got, want := errs[0].attrs["deferrals"], fmt.Sprint(refreshStagedErrorAfter); got != want {
		t.Errorf("the ERROR came at deferrals=%s, want %s", got, want)
	}
	if !strings.Contains(errs[0].attrs["reason"], ErrRefreshStaged.Error()) || errs[0].attrs["since"] == "" {
		t.Errorf("the ERROR lost its reason or start: %v", errs[0].attrs)
	}

	// The reminder.
	zd.refreshRun.mu.Lock()
	zd.refreshRun.escalatedAt = time.Now().Add(-refreshDeferralReminder)
	zd.refreshRun.mu.Unlock()
	noteRefreshFailure(zd, zone, staged, "zone refresh failed")
	if n := len(logs.mentioning(zone, slog.LevelError)); n != 2 {
		t.Errorf("%d ERRORs after the reminder interval, want 2", n)
	}

	noteRefreshSuccess(zd, zone, true)
	if n := len(logs.withMsg(zone, slog.LevelWarn, "zone refresh no longer deferred")); n != 1 {
		t.Errorf("the end of an escalated deferral run was logged %d times, want 1", n)
	}
	if zd.HasError(RefreshError) {
		t.Error("a deferral marked the zone failed")
	}
}

// An escalated staged run that ends on a refresh proving nothing still logs
// its end: the WARN does not wait for a confirmation. The run of failures is
// left as it was, with no recovery line.
func TestAnUnconfirmedRefreshEndsAnEscalatedStagedDeferral(t *testing.T) {
	logs := captureRefreshLogs(t)
	const zone = "staged-unconfirmed.one-error.test."
	zd := &ZoneData{ZoneName: zone, ZoneType: Secondary}
	staged := fmt.Errorf("zone %s: %w", zone, ErrRefreshStaged)

	noteRefreshFailure(zd, zone, errors.New("the primary was down"), "zone refresh failed")
	for i := 1; i <= refreshStagedErrorAfter; i++ {
		noteRefreshFailure(zd, zone, staged, "zone refresh failed")
	}
	escalation := "zone refresh deferred too long; the zone is taking no refreshes"
	if n := len(logs.withMsg(zone, slog.LevelError, escalation)); n != 1 {
		t.Fatalf("%d deferrals escalated %d times, want 1", refreshStagedErrorAfter, n)
	}

	noteRefreshSuccess(zd, zone, false)
	ends := logs.withMsg(zone, slog.LevelWarn, "zone refresh no longer deferred")
	if len(ends) != 1 {
		t.Fatalf("an unconfirmed refresh logged the end of an escalated staged run %d times, want 1", len(ends))
	}
	if got, want := ends[0].attrs["deferrals"], fmt.Sprint(refreshStagedErrorAfter); got != want {
		t.Errorf("the end gave deferrals=%s, want %s", got, want)
	}
	if n := len(logs.withMsg(zone, slog.LevelInfo, "zone refresh recovered")); n != 0 {
		t.Errorf("an unconfirmed refresh logged a recovery %d times", n)
	}
	zd.refreshRun.mu.Lock()
	deferrals, escalated, failures := zd.refreshRun.deferrals, zd.refreshRun.escalated, zd.refreshRun.failures
	zd.refreshRun.mu.Unlock()
	if deferrals != 0 || escalated {
		t.Errorf("the deferral run is still open: deferrals=%d escalated=%v", deferrals, escalated)
	}
	if failures != 1 {
		t.Errorf("the run of failures is %d, want it kept at 1: the refresh proved nothing", failures)
	}
}

// A staged deferral is overdue past txHoldLimit whatever its count; an open
// transaction's only past txHoldAgeCap, never by count.
func TestDeferralOverdueBounds(t *testing.T) {
	staged := fmt.Errorf("x: %w", ErrRefreshStaged)
	held := fmt.Errorf("x: %w", ErrRefreshHeld)
	for _, c := range []struct {
		what string
		err  error
		n    int
		held time.Duration
		want bool
	}{
		{"staged, early", staged, 1, time.Second, false},
		{"staged, by count", staged, refreshStagedErrorAfter, time.Second, true},
		{"staged, by time", staged, 2, txHoldLimit + time.Second, true},
		{"held, many retries within the cap", held, 50, txHoldLimit, false},
		{"held, past the cap", held, 2, txHoldAgeCap + time.Second, true},
	} {
		if got := refreshDeferralOverdue(c.err, c.n, c.held); got != c.want {
			t.Errorf("%s: overdue=%v, want %v", c.what, got, c.want)
		}
	}
}

// The kinds are read from the error's type. Each case is the shape the
// transport actually returns, wrapped as the refresh wraps it.
func TestRefreshErrorKind(t *testing.T) {
	op := func(err error) error {
		return fmt.Errorf("192.0.2.1:53: %w", &net.OpError{Op: "read", Net: "udp", Err: os.NewSyscallError("read", err)})
	}
	for _, c := range []struct {
		err  error
		want string
	}{
		{op(syscall.ECONNREFUSED), "connrefused"},
		{op(syscall.ENETUNREACH), "unreachable"},
		{op(syscall.EHOSTUNREACH), "unreachable"},
		{op(syscall.ECONNRESET), "reset"},
		{op(syscall.EPIPE), "reset"},
		{fmt.Errorf("x: %w", &net.OpError{Op: "read", Net: "udp", Err: os.ErrDeadlineExceeded}), "timeout"},
		{fmt.Errorf("x: %w", context.DeadlineExceeded), "timeout"},
		{fmt.Errorf("x: %w", &net.OpError{Op: "read", Net: "udp", Err: net.ErrClosed}), "closed"},
		{fmt.Errorf("x: %w", io.EOF), "eof"},
		{&xfrRcodeError{zone: "z.", upstream: "u", rcode: dns.RcodeServerFailure}, "servfail"},
		{&xfrRcodeError{zone: "z.", upstream: "u", rcode: dns.RcodeRefused}, "refused"},
		{&xfrRcodeError{zone: "z.", upstream: "u", rcode: dns.RcodeNotAuth}, "notauth"},
		{fmt.Errorf("x: %w", dns.ErrSig), "tsig"},
		{fmt.Errorf("x: %w", dns.ErrTime), "tsig"},
		{fmt.Errorf("x: %w", &peerConfigError{err: fmt.Errorf("TLS setup: %w", &os.PathError{Op: "open", Path: "/ca.pem", Err: syscall.ENOENT})}), "config"},
		{errors.New("something else"), "other"},
	} {
		if got := refreshErrorKind(c.err); got != c.want {
			t.Errorf("refreshErrorKind(%v) = %q, want %q", c.err, got, c.want)
		}
	}
}

// The typed rcode error keeps the text clarifyXfrError always produced.
func TestClarifyXfrErrorKeepsItsText(t *testing.T) {
	err := clarifyXfrError("z.", "192.0.2.1:53", errors.New("dns: bad xfr rcode: 5"))
	if got, want := err.Error(), "inbound zone transfer of z. from 192.0.2.1:53 failed: REFUSED"; got != want {
		t.Errorf("text %q, want %q", got, want)
	}
	var rc *xfrRcodeError
	if !errors.As(err, &rc) || rc.rcode != dns.RcodeRefused {
		t.Errorf("not typed with its rcode: %#v", err)
	}
}
