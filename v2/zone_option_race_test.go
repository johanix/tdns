/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// johanix/tdns#981: a zone's options are replaced, never written in place
// (SetRuntimeOption, a config reload, a config-bearing refresh), and a reader
// that holds no lock sees the new map or the old one whole. The replacement is
// still a write to the zone's Options field, and a reader's look at that
// field is a read of it: without something between the two, that is a data
// race, which `go test -race` reports and which no amount of copying the map
// removes.
//
// These tests run a writer against readers that take no lock, on the paths the
// daemon reads options on: the multi-provider ownership test, the tests of
// whether this server signs the zone, may originate its content, takes updates
// for it and keeps ZONEMD for it, and whether the resolver treats the copy as
// the zone the world sees. They fail under `go test -race` when a reader looks
// at zd.Options directly and pass when every one goes through the zone's
// accessor. Without -race they only check that the readers end up seeing what
// the writer wrote.

// optionReaders are read paths that look at a zone's options holding no lock.
// Only paths that read options and nothing else a writer here changes.
var optionReaders = map[string]func(zd *ZoneData) bool{
	"zoneOwned":           zoneOwned,
	"signsHere":           (*ZoneData).signsHere,
	"zoneUpdatesAdmitted": func(zd *ZoneData) bool { return zoneUpdatesAdmitted(zd, false) },
	"modifiedDownstream":  (*ZoneData).modifiedDownstream,
	"zoneManagesZonemd":   (*ZoneData).zoneManagesZonemd,
}

// readOptionsUntil runs a goroutine per reader path, and per extra reader the
// caller adds, that calls it in a loop until the returned func stops them. That
// func waits for them and returns how many reads they made. It returns only
// once every reader has made a read, so that a writer that finishes before a
// reader is scheduled does not stop it unread.
func readOptionsUntil(t *testing.T, zd *ZoneData, extra ...func(*ZoneData) bool) (stop func() int64) {
	t.Helper()
	readers := make([]func(*ZoneData) bool, 0, len(optionReaders)+len(extra))
	for _, read := range optionReaders {
		readers = append(readers, read)
	}
	readers = append(readers, extra...)
	done := make(chan struct{})
	var wg, started sync.WaitGroup
	var reads atomic.Int64
	for _, read := range readers {
		wg.Add(1)
		started.Add(1)
		go func() {
			defer wg.Done()
			// The first read comes before the done check and is announced:
			// the caller waits for it below.
			_ = read(zd)
			reads.Add(1)
			started.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				_ = read(zd)
				reads.Add(1)
			}
		}()
	}
	started.Wait()
	return func() int64 {
		close(done)
		wg.Wait()
		return reads.Load()
	}
}

// TestReadOptionsUntilHasEveryReaderReadBeforeItReturns: readOptionsUntil
// returns only once every reader has made a read. Without that, a writer that
// finishes before a reader is scheduled stops it unread, and a test of correct
// code fails with "the readers never ran" (johanix/tdns#981 review). One P makes
// the case certain: the readers do not run until the caller blocks, so a
// readOptionsUntil that did not wait for them returns with nothing read.
func TestReadOptionsUntilHasEveryReaderReadBeforeItReturns(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	zd := &ZoneData{ZoneName: "example.", Options: map[ZoneOption]bool{OptAllowUpdates: true}}
	var extra [8]atomic.Int64
	readers := make([]func(*ZoneData) bool, len(extra))
	for i := range extra {
		readers[i] = func(*ZoneData) bool { extra[i].Add(1); return false }
	}
	stop := readOptionsUntil(t, zd, readers...)
	// Looked at here, before stop: stop joins the workers, and a worker reads
	// once before it looks at done, so after it every reader has read whatever
	// readOptionsUntil did. What is claimed is that they had when it returned.
	for i := range extra {
		if extra[i].Load() == 0 {
			t.Errorf("reader %d had not read when readOptionsUntil returned", i)
		}
	}
	stop()
}

// optionOn reads an option the way the tests' own assertions may: under the
// zone's lock, which every writer of the field holds.
func optionOn(zd *ZoneData, opt ZoneOption) bool {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	return zd.Options[opt]
}

// The writer is SetRuntimeOption, as tdns-mp's signer switch calls it at a
// hand-over, and the readers are the paths above.
func TestSettingARuntimeOptionRacesNoUnlockedReader(t *testing.T) {
	zd := &ZoneData{ZoneName: "example.", Options: map[ZoneOption]bool{OptAllowUpdates: true}}
	stop := readOptionsUntil(t, zd)

	opts := []ZoneOption{OptInlineSigning, OptMultiProvider, OptModifiedDownstream, OptPublishZonemd, OptAllowTsigUpdates}
	const rounds = 2000
	for i := 0; i < rounds; i++ {
		zd.SetRuntimeOption(opts[i%len(opts)], i%2 == 0)
	}
	// Leave a known state, and let the readers see it before they stop.
	for _, opt := range opts {
		zd.SetRuntimeOption(opt, true)
	}
	if reads := stop(); reads == 0 {
		t.Fatal("the readers never ran")
	}
	for _, opt := range opts {
		if !optionOn(zd, opt) {
			t.Errorf("%v reads off after the daemon set it on", opt)
		}
	}
	if !optionOn(zd, OptAllowUpdates) {
		t.Error("the configured option was lost")
	}
}

// The other writer of the field: ParseZones, which reads the configuration of
// a zone that is already loaded and replaces its options under the zone's
// lock, keeping what the daemon set by itself.
func TestAReloadOfTheZoneConfigurationRacesNoUnlockedReader(t *testing.T) {
	withAppType(t, derivedSignerApp)
	registerTestOriginationRuleApp(t, derivedSignerApp)
	zd := testSnapshotZone(t, ovZone, ovUpstreamZone(40))
	zd.Options = map[ZoneOption]bool{}
	zd.SetRuntimeOption(OptInlineSigning, true)

	stop := readOptionsUntil(t, zd)
	conf := &Config{Zones: []ZoneConf{{Name: ovZone, Type: "primary", Store: "map",
		Zonefile: "/nonexistent", OptionsStrs: []string{"fold-case"}}}}
	const rounds = 50
	// No refresh engine runs here: the channel holds every refresher a parse
	// queues, and ParseZones would block on a full one.
	conf.Internal.RefreshZoneCh = make(chan ZoneRefresher, rounds+1)
	for i := 0; i < rounds; i++ {
		if _, _, err := conf.ParseZones(context.Background(), true); err != nil {
			stop()
			t.Fatalf("reload %d: %v", i, err)
		}
	}
	if reads := stop(); reads == 0 {
		t.Fatal("the readers never ran")
	}
	if !optionOn(zd, OptInlineSigning) || !optionOn(zd, OptFoldCase) {
		zd.mu.Lock()
		defer zd.mu.Unlock()
		t.Fatalf("after the reloads the zone's options are %v, want the option the daemon set beside the configured ones",
			zd.Options)
	}
}

// The third: the refresh engine, which replaces a zone's options when a
// config-bearing refresher reaches it, with the run-time option laid over the
// configured ones, and builds a forced refetch's incoming zone on the same
// map. The zone is loaded and refreshed through a running engine, as a daemon
// does, and a derived app sets its option at every refresh.
func TestAConfigUpdateThroughTheRefreshEngineRacesNoUnlockedReader(t *testing.T) {
	kdb := asDerivedApp(t, derivedSignerApp)
	registerTestOriginationRuleApp(t, derivedSignerApp)
	prepare := func(zd *ZoneData) {
		zd.OnZonePreRefresh = append(zd.OnZonePreRefresh, func(served, _ *ZoneData) {
			served.SetRuntimeOption(OptInlineSigning, true)
		})
	}
	up := startRelayUpstream(t, 40)
	z := startRelayedZone(t, kdb, up, map[ZoneOption]bool{OptFoldCase: true}, prepare)

	stop := readOptionsUntil(t, z.zd)
	const rounds = 20
	for i := 0; i < rounds; i++ {
		zr := z.configRefresher()
		zr.Force = i%5 == 4 // every fifth is a forced refetch, as `config reload-zones` sends
		runUntilTheEngineIsFree(t, z, zr)
	}
	if reads := stop(); reads == 0 {
		t.Fatal("the readers never ran")
	}
	if !optionOn(z.zd, OptInlineSigning) || !optionOn(z.zd, OptFoldCase) {
		t.Fatal("after the config updates the zone lost the option the daemon set or the one the configuration gave")
	}
}

// runUntilTheEngineIsFree is z.run for a caller that sends refreshers one
// after the other: the engine answers a refresher before it has taken the
// zone off its in-flight list, and a refresher that arrives in between is
// refused, so it is sent again.
func runUntilTheEngineIsFree(t *testing.T, z *relayedZone, zr ZoneRefresher) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		zr.Wait = true
		zr.Response = make(chan RefresherResponse, 1)
		z.conf.Internal.RefreshZoneCh <- zr
		select {
		case resp := <-zr.Response:
			if !resp.Error {
				return
			}
			if !strings.Contains(resp.ErrorMsg, "already in progress") || time.Now().After(deadline) {
				t.Fatalf("refresh: %s", resp.ErrorMsg)
			}
			time.Sleep(5 * time.Millisecond)
		case <-time.After(10 * time.Second):
			t.Fatal("the refresh was not answered")
		}
	}
}

// CollectDynamicRRs gates on three options at once, and every zd.Option is a
// look at the zone's options of its own: a config update between two looks
// answers from the old set and the new together. With one set that allows
// updates and another that signs inline, a gate that mixes them sees neither
// and returns nothing, though either alone would collect the zone's SIG(0) key
// (johanix/tdns#981 review). The config update here is a writer that swaps
// between the two sets as fast as it can; the collector must find the key
// every time. The mix is a window of a few instructions, so on code that
// reads the options one look at a time this fails often, not every run.
func TestCollectDynamicRRsGatesOnOneSetOfOptions(t *testing.T) {
	zd, kdb, _ := newSig0KeyPrepZone(t, sig0KeyPrepZone, Primary)
	zd.Options = map[ZoneOption]bool{OptParentSync: true}
	if err := zd.Sig0KeyPreparation("example.", dns.ED25519, kdb); err != nil {
		t.Fatalf("Sig0KeyPreparation: %v", err)
	}
	collectsKey := func() bool {
		for _, rs := range zd.CollectDynamicRRs(&Config{}) {
			if rs.RRtype == dns.TypeKEY {
				return true
			}
		}
		return false
	}
	sets := [2]map[ZoneOption]bool{{OptAllowUpdates: true}, {OptInlineSigning: true}}
	for i, set := range sets {
		zd.mu.Lock()
		zd.setOptionsLocked(set)
		zd.mu.Unlock()
		if !collectsKey() {
			t.Fatalf("precondition: set %d alone does not collect the SIG(0) key", i)
		}
	}

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-done:
				return
			default:
			}
			zd.mu.Lock()
			zd.setOptionsLocked(sets[i%2])
			zd.mu.Unlock()
		}
	}()
	defer func() { close(done); wg.Wait() }()

	deadline := time.Now().Add(3 * time.Second)
	for i := 0; i < 20000 && time.Now().Before(deadline); i++ {
		if !collectsKey() {
			t.Fatalf("collection %d found nothing while the options swapped between two sets that each allow it", i)
		}
	}
}
