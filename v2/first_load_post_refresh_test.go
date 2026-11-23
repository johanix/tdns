package tdns

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// T-B (B-MP): a first load runs its OnZonePostRefresh callbacks once the zone
// is Ready, from the first-load completion, instead of straight after the
// pre-Ready publish. The callbacks of every later refresh already ran on a
// Ready zone; this makes a first load's do the same, for every consumer.

// postRefreshProbe is what a post-refresh consumer sees when it runs.
type postRefreshProbe struct {
	runs      int
	ready     bool
	ownerErr  error
	owner     *OwnerData
	soaSigned bool
}

func (p *postRefreshProbe) callback(zd *ZoneData) {
	p.runs++
	p.ready = zd.Ready
	p.owner, p.ownerErr = zd.GetOwner("www.example.")
	if snap := zd.publishedSnapshot(); snap != nil && snap.Apex != nil {
		p.soaSigned = len(snap.Apex.RRtypes.GetOnlyRRSet(dns.TypeSOA).RRSIGs) > 0
	}
}

// firstLoadFileZone builds a zone as ParseZones leaves it BEFORE its first
// load: a file on disk, FirstZoneLoad set, nothing read, nothing published.
func firstLoadFileZone(t *testing.T, kdb *KeyDB, zoneText string) (*ZoneData, *postRefreshProbe) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "example.zone")
	if err := os.WriteFile(path, []byte(zoneText), 0644); err != nil {
		t.Fatalf("writing the zone file: %v", err)
	}
	zd := &ZoneData{
		ZoneName:      "example.",
		ZoneStore:     MapZone,
		ZoneType:      Primary,
		Zonefile:      path,
		Logger:        log.New(os.Stderr, "", 0),
		Options:       map[ZoneOption]bool{},
		KeyDB:         kdb,
		FirstZoneLoad: true,
	}
	registerZones(t, zd)
	t.Cleanup(zd.stopPublisher)
	p := &postRefreshProbe{}
	zd.OnZonePostRefresh = append(zd.OnZonePostRefresh, p.callback)
	return zd, p
}

func firstLoadFromFile(t *testing.T, zd *ZoneData) {
	t.Helper()
	updated, err := zd.FetchFromFile(context.Background(), false, false, true, nil)
	if err != nil {
		t.Fatalf("FetchFromFile (first load): %v", err)
	}
	if !updated {
		t.Fatal("the first load did not adopt the file")
	}
	if zd.FirstZoneLoad {
		t.Fatal("FirstZoneLoad is still set after the first load")
	}
}

func TestFirstLoadPostRefreshRunsOnceReadyOnAnUnsignedZone(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd, p := firstLoadFileZone(t, kdb, reloadBase)

	firstLoadFromFile(t, zd)

	// The publish happened and the callbacks did NOT run with it. (An unsigned
	// zone's first publish already makes it Ready -- publishWorkingSetLocked
	// flips Ready on any servable snapshot -- so for this zone the deferral
	// only moves the callbacks past the journal replay; the signing case
	// below is the one where it moves them past the Ready flip.)
	if !zd.HasPublishedData() {
		t.Fatal("the first load published nothing")
	}
	if p.runs != 0 {
		t.Fatalf("post-refresh callbacks ran %d times at the first-load publish", p.runs)
	}
	zd.mu.Lock()
	owed := zd.postRefreshOwed
	zd.mu.Unlock()
	if !owed {
		t.Fatal("the first load did not record the deferred callbacks")
	}

	conf := &Config{}
	conf.Internal.KeyDB = kdb
	if err := completeFirstZonePolicyAndLoad(context.Background(), zd, conf, ""); err != nil {
		t.Fatalf("completeFirstZonePolicyAndLoad: %v", err)
	}

	if p.runs != 1 {
		t.Fatalf("post-refresh callbacks ran %d times at first-load completion, want 1", p.runs)
	}
	if !p.ready {
		t.Fatal("the callback saw a zone that was not Ready")
	}
	if p.ownerErr != nil || p.owner == nil {
		t.Fatalf("GetOwner inside the callback: owner=%v err=%v", p.owner, p.ownerErr)
	}
	zd.mu.Lock()
	owed = zd.postRefreshOwed
	zd.mu.Unlock()
	if owed {
		t.Fatal("the debt was not cleared by the run that paid it")
	}

	// A later refresh is unchanged: its callbacks run straight after its
	// publish, once.
	operatorEdit(t, zd, reloadBase+"more.example.\t3600\tIN\tA\t192.0.2.9\n")
	if _, err := zd.FetchFromFile(context.Background(), false, false, true, nil); err != nil {
		t.Fatalf("FetchFromFile (reload): %v", err)
	}
	if p.runs != 2 || !p.ready {
		t.Fatalf("after a reload: runs=%d ready=%v, want 2 and true", p.runs, p.ready)
	}
}

// The signing case, which is the one the landing site was moved for: on a
// signing zone Ready arrives with the publish that signs it, inside the
// policy apply, after InstallInitialSnapshot. The callbacks must run after
// THAT, and see a signed zone.
func TestFirstLoadPostRefreshRunsAfterTheSignOnASigningZone(t *testing.T) {
	kdb := newTestKeyDB(t)
	pol := kskzsk(dns.ED25519, dns.ED25519)
	withLivePolicies(t, map[string]DnssecPolicy{"base": pol})
	zd, p := firstLoadFileZone(t, kdb, reloadBase)
	zd.Options[OptOnlineSigning] = true
	zd.DnssecPolicyName = "base"
	// DnssecPolicy stays nil: binding is post-Ready, the production first-load
	// shape.
	if _, _, err := kdb.GenerateKeypair(zd.ZoneName, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "KSK", nil); err != nil {
		t.Fatalf("KSK: %v", err)
	}
	if _, _, err := kdb.GenerateKeypair(zd.ZoneName, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "ZSK", nil); err != nil {
		t.Fatalf("ZSK: %v", err)
	}

	firstLoadFromFile(t, zd)

	if zd.Ready {
		t.Fatal("a signing zone became Ready on its unsigned first publish")
	}
	if p.runs != 0 {
		t.Fatalf("post-refresh callbacks ran %d times before the zone was signed", p.runs)
	}

	conf := &Config{}
	conf.Internal.KeyDB = kdb
	if err := completeFirstZonePolicyAndLoad(context.Background(), zd, conf, "base"); err != nil {
		t.Fatalf("completeFirstZonePolicyAndLoad: %v", err)
	}
	if !zd.Ready {
		t.Fatal("the zone did not become Ready at first-load completion")
	}
	if zd.DnssecPolicy == nil {
		t.Fatal("the policy did not bind")
	}
	if p.runs != 1 {
		t.Fatalf("post-refresh callbacks ran %d times, want 1", p.runs)
	}
	if !p.ready {
		t.Fatal("the callback saw a zone that was not Ready")
	}
	if p.ownerErr != nil || p.owner == nil {
		t.Fatalf("GetOwner inside the callback: owner=%v err=%v", p.owner, p.ownerErr)
	}
	if !p.soaSigned {
		t.Fatal("the callback ran before the sign: the apex SOA it saw carried no RRSIG")
	}
}

// A completion that leaves the zone not Ready leaves the callbacks owed, and
// the retry that makes it Ready runs them. Modelled on the ticker's retry
// path, finishFirstLoadPolicy, which has no replay: there the drain follows
// the sign directly.
func TestFirstLoadPostRefreshStaysOwedUntilReady(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd, p := firstLoadFileZone(t, kdb, reloadBase)
	zd.Options[OptOnlineSigning] = true
	firstLoadFromFile(t, zd)

	// No policy anywhere: the sign is skipped, the zone stays not Ready.
	conf := &Config{}
	conf.Internal.KeyDB = kdb
	withLivePolicies(t, map[string]DnssecPolicy{})
	if err := finishFirstLoadPolicy(context.Background(), zd, conf, ""); err != nil {
		t.Fatalf("finishFirstLoadPolicy: %v", err)
	}
	if zd.Ready {
		t.Fatal("a signing zone with no policy became Ready")
	}
	if p.runs != 0 {
		t.Fatalf("post-refresh callbacks ran %d times on a not-Ready zone", p.runs)
	}
	zd.mu.Lock()
	owed := zd.postRefreshOwed
	zd.mu.Unlock()
	if !owed {
		t.Fatal("a completion that left the zone not Ready cleared the debt")
	}

	// The retry that succeeds: a policy appears, the sign makes the zone
	// Ready, the owed callbacks run once.
	pol := kskzsk(dns.ED25519, dns.ED25519)
	withLivePolicies(t, map[string]DnssecPolicy{"base": pol})
	zd.DnssecPolicyName = "base"
	if _, _, err := kdb.GenerateKeypair(zd.ZoneName, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "KSK", nil); err != nil {
		t.Fatalf("KSK: %v", err)
	}
	if _, _, err := kdb.GenerateKeypair(zd.ZoneName, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "ZSK", nil); err != nil {
		t.Fatalf("ZSK: %v", err)
	}
	if err := finishFirstLoadPolicy(context.Background(), zd, conf, "base"); err != nil {
		t.Fatalf("finishFirstLoadPolicy (retry): %v", err)
	}
	if !zd.Ready {
		t.Fatal("the retry did not make the zone Ready")
	}
	if p.runs != 1 || !p.ready || !p.soaSigned {
		t.Fatalf("after the retry: runs=%d ready=%v signed=%v, want 1/true/true", p.runs, p.ready, p.soaSigned)
	}
	zd.mu.Lock()
	owed = zd.postRefreshOwed
	zd.mu.Unlock()
	if owed {
		t.Fatal("the debt survived the run that paid it")
	}
	// And a second completion does not run them again.
	if err := finishFirstLoadPolicy(context.Background(), zd, conf, "base"); err != nil {
		t.Fatalf("finishFirstLoadPolicy (again): %v", err)
	}
	if p.runs != 1 {
		t.Fatalf("a second completion re-ran the callbacks: runs=%d", p.runs)
	}
}

// A pre-registered secondary whose first successful load is NOTIFY-driven:
// the refresher names only the zone, the policy comes from what the zone
// recorded at registration.
func TestFirstLoadBindsTheRegisteredPolicyWhenTheRefresherNamesNone(t *testing.T) {
	zd := &ZoneData{ZoneName: "late.example.", DnssecPolicyName: "base"}
	if got := firstLoadPolicyName(zd, ZoneRefresher{Name: "late.example."}); got != "base" {
		t.Fatalf("NOTIFY-built refresher: bound %q, want the registered %q", got, "base")
	}
	if got := firstLoadPolicyName(zd, ZoneRefresher{Name: "late.example.", DnssecPolicy: "other"}); got != "other" {
		t.Fatalf("config-driven refresher: bound %q, want its own %q", got, "other")
	}
	if got := firstLoadPolicyName(&ZoneData{ZoneName: "plain.example."}, ZoneRefresher{Name: "plain.example."}); got != "" {
		t.Fatalf("no policy anywhere: bound %q, want none", got)
	}
}

// The engine-level shape of the same: a pre-registered secondary that signs
// its own content, first tried while its primary is down, then loaded by the
// refresher a NOTIFY builds -- what a signer sees when a customer's zone is
// published after the signer started. The policy the zone recorded at
// registration is bound, keys are minted, the zone is signed and Ready.
func TestNotifyDrivenFirstLoadBindsTheRegisteredPolicy(t *testing.T) {
	authApp(t)
	kdb := Conf.Internal.KeyDB
	withLivePolicies(t, map[string]DnssecPolicy{"base": kskzsk(dns.ED25519, dns.ED25519)})
	conf := &Config{}
	conf.Internal.KeyDB = kdb
	conf.Internal.RefreshZoneCh = make(chan ZoneRefresher, 1)
	conf.Internal.BumpZoneCh = make(chan BumperData, 1)

	// the primary's address, decided before anything listens on it
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := probe.Addr().String()
	probe.Close()

	// pre-registered, the way ParseZones leaves a zone before its first load
	zd := &ZoneData{ZoneName: "example.", Logger: discardLogger(), FirstZoneLoad: true}
	zd.registerStandardRefreshHooks(conf.Internal.DelegationSyncQ)
	Zones.Set("example.", zd)
	t.Cleanup(func() { Zones.Remove("example.") })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); RefreshEngine(ctx, conf) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("RefreshEngine did not shut down")
		}
	})

	// the config-driven refresher, primary down: registration, no data
	conf.Internal.RefreshZoneCh <- ZoneRefresher{
		Name:          "example.",
		ZoneType:      Secondary,
		ZoneStore:     MapZone,
		PrimariesConf: []PeerConf{{Addr: addr}},
		Primaries:     []PeerConf{{Addr: addr}},
		Options:       map[ZoneOption]bool{OptInlineSigning: true},
		DnssecPolicy:  "base",
		ConfigUpdate:  true,
	}
	deadline := time.Now().Add(5 * time.Second)
	for !zd.HasError(RefreshError) {
		if time.Now().After(deadline) {
			t.Fatal("the first attempt against the down primary did not fail")
		}
		time.Sleep(20 * time.Millisecond)
	}
	zd.mu.Lock()
	first, name := zd.FirstZoneLoad, zd.DnssecPolicyName
	zd.mu.Unlock()
	if !first || name != "base" {
		t.Fatalf("after the failed attempt: FirstZoneLoad=%v policy name %q, want true and base", first, name)
	}

	// the primary comes up and NOTIFYs; the refresher a NOTIFY builds
	pzd := &ZoneData{ZoneName: "example.", ZoneStore: MapZone, ZoneType: Primary, Logger: discardLogger(),
		Ready: true, Status: ZoneStatusReady, Downstreams: []AclEntry{{Prefix: "127.0.0.0/8", Key: NOKEY}}}
	if _, _, err := pzd.ReadZoneData(s2Zone, true); err != nil {
		t.Fatalf("primary ReadZoneData: %v", err)
	}
	pzd.InstallInitialSnapshot()
	t.Cleanup(pzd.stopPublisher)
	_, stop := serveTestPrimaryOn(t, pzd, addr)
	t.Cleanup(stop)
	conf.Internal.RefreshZoneCh <- ZoneRefresher{Name: "example.", ZoneStore: MapZone}

	// Ready and the binding are not the end of the load: the apply binds,
	// signs -- the publish that flips Ready -- and only then records the
	// applied policy. Wait for the record as well, not just look once.
	deadline = time.Now().Add(10 * time.Second)
	for {
		zd.mu.Lock()
		ready, pol, name := zd.Ready, zd.DnssecPolicy, zd.DnssecPolicyName
		zd.mu.Unlock()
		bound := ready && pol != nil && name == "base"
		if bound {
			_, _, applied, aerr := GetZoneAppliedPolicy(kdb, "example.")
			if aerr != nil {
				t.Fatalf("GetZoneAppliedPolicy: %v", aerr)
			}
			if applied {
				break
			}
		}
		if time.Now().After(deadline) {
			if bound {
				t.Fatal("applied policy not recorded")
			}
			t.Fatalf("after the NOTIFY-driven load: Ready=%v policy bound=%v name=%q; the load bound the "+
				"refresher's empty policy name instead of the zone's", ready, pol != nil, name)
		}
		time.Sleep(20 * time.Millisecond)
	}
	apex, err := zd.GetOwner("example.")
	if err != nil || apex == nil {
		t.Fatalf("apex: %v", err)
	}
	if soa, ok := apex.RRtypes.Get(dns.TypeSOA); !ok || len(soa.RRSIGs) == 0 {
		t.Fatal("the apex SOA is served unsigned after the policy bound")
	}
}

// A pre-registered secondary in an application that originates content (a
// combiner: not tdns-auth) with a persisted outbound serial ahead of the
// upstream's: the first load restores the persisted serial, one past it,
// so the serial the zone publishes never goes backwards across a restart
// and a downstream holding the saved serial fetches what may have changed.
// The first publish used to persist the upstream's serial over the saved
// one before the engine's restore looked, so a combiner came back from a
// restart at a lower serial and its signer ignored its NOTIFYs.
func TestFirstLoadRestoresThePersistedSerialForAnOriginatingSecondary(t *testing.T) {
	firstLoadWithPersistedSerial(t, appTypeUngated, 1001,
		"the persisted 1000 restored over the upstream's 7, one past it")
}

// The same first load in tdns-agent (#1157): a secondary that writes nothing
// into the zone serves what it received, at the upstream's serial, whatever
// serial it served before the restart.
func TestFirstLoadAgentSecondaryServesTheUpstreamSerial(t *testing.T) {
	firstLoadWithPersistedSerial(t, AppTypeAgent, 7,
		"the upstream's 7: an agent secondary with no option that writes content relays")
}

// firstLoadWithPersistedSerial loads a secondary of example. from a primary
// at serial 7, as app type app, with outbound-soa-serial=persist and a saved
// outgoing serial of 1000, and waits for it to serve want.
func firstLoadWithPersistedSerial(t *testing.T, app AppType, want uint32, why string) {
	t.Helper()
	authApp(t)
	Globals.App.Type = app
	kdb := Conf.Internal.KeyDB
	if err := applyOutboundSoaSerial(kdb, OutboundSoaSerialPersist); err != nil {
		t.Fatalf("persist mode: %v", err)
	}
	if err := kdb.SaveOutgoingSerial("example.", 1000); err != nil {
		t.Fatalf("seed the persisted serial: %v", err)
	}
	conf := &Config{}
	conf.Internal.KeyDB = kdb
	conf.Internal.RefreshZoneCh = make(chan ZoneRefresher, 1)
	conf.Internal.BumpZoneCh = make(chan BumperData, 1)

	addr, stop := startTestPrimary(t, s2Zone) // serial 7
	t.Cleanup(stop)

	zd := &ZoneData{ZoneName: "example.", Logger: discardLogger(), FirstZoneLoad: true}
	zd.registerStandardRefreshHooks(conf.Internal.DelegationSyncQ)
	Zones.Set("example.", zd)
	t.Cleanup(func() { Zones.Remove("example.") })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); RefreshEngine(ctx, conf) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("RefreshEngine did not shut down")
		}
	})
	conf.Internal.RefreshZoneCh <- ZoneRefresher{
		Name:          "example.",
		ZoneType:      Secondary,
		ZoneStore:     MapZone,
		PrimariesConf: []PeerConf{{Addr: addr}},
		Primaries:     []PeerConf{{Addr: addr}},
		Options:       map[ZoneOption]bool{},
		ConfigUpdate:  true,
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		zd.mu.Lock()
		ready, cur := zd.Ready, zd.CurrentSerial
		zd.mu.Unlock()
		if ready && cur == want {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after the first load: Ready=%v CurrentSerial=%d, want %d: %s", ready, cur, want, why)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if snap := zd.publishedSnapshot(); snap == nil || snap.Serial != want {
		t.Fatalf("the served snapshot is not at %d: %+v", want, snap)
	}
}

// persistPrimary starts a RefreshEngine with outbound-soa-serial=persist, a
// saved outgoing serial when saved is non-zero, and a pre-registered primary
// for example. that is to load zoneStr from a file. load sends the config
// refresher that starts the first load.
func persistPrimary(t *testing.T, zoneStr string, saved uint32) (zd *ZoneData, conf *Config, load func()) {
	t.Helper()
	return modePrimary(t, OutboundSoaSerialPersist, zoneStr, saved)
}

// modePrimary is persistPrimary for any outbound-soa-serial mode.
func modePrimary(t *testing.T, mode, zoneStr string, saved uint32) (zd *ZoneData, conf *Config, load func()) {
	t.Helper()
	authApp(t)
	kdb := Conf.Internal.KeyDB
	if err := applyOutboundSoaSerial(kdb, mode); err != nil {
		t.Fatalf("%s mode: %v", mode, err)
	}
	if saved != 0 {
		if err := kdb.SaveOutgoingSerial("example.", saved); err != nil {
			t.Fatalf("seed the persisted serial: %v", err)
		}
	}
	zf := filepath.Join(t.TempDir(), "example.zone")
	if err := os.WriteFile(zf, []byte(zoneStr), 0644); err != nil {
		t.Fatalf("write zone file: %v", err)
	}
	conf = &Config{}
	conf.Internal.KeyDB = kdb
	conf.Internal.RefreshZoneCh = make(chan ZoneRefresher, 1)
	conf.Internal.BumpZoneCh = make(chan BumperData, 1)

	zd = &ZoneData{ZoneName: "example.", Logger: discardLogger(), FirstZoneLoad: true}
	zd.registerStandardRefreshHooks(conf.Internal.DelegationSyncQ)
	Zones.Set("example.", zd)
	t.Cleanup(func() { Zones.Remove("example.") })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); RefreshEngine(ctx, conf) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("RefreshEngine did not shut down")
		}
	})
	load = func() {
		conf.Internal.RefreshZoneCh <- ZoneRefresher{
			Name:         "example.",
			ZoneType:     Primary,
			ZoneStore:    MapZone,
			Zonefile:     zf,
			Options:      map[ZoneOption]bool{},
			ConfigUpdate: true,
		}
	}
	return zd, conf, load
}

// waitServing waits for the zone to be Ready and to serve want, in its
// CurrentSerial and in the published snapshot.
func waitServing(t *testing.T, zd *ZoneData, want uint32) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		zd.mu.Lock()
		ready, cur := zd.Ready, zd.CurrentSerial
		zd.mu.Unlock()
		snap := zd.publishedSnapshot()
		if ready && cur == want && snap != nil && snap.Serial == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("after the first load: Ready=%v CurrentSerial=%d, want %d served", ready, cur, want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// soaSerial is s2Zone with its SOA serial (7) replaced.
func soaSerial(serial uint32) string {
	return strings.Replace(s2Zone, "hostmaster.example. 7 ", fmt.Sprintf("hostmaster.example. %d ", serial), 1)
}

// A file-backed primary under tdns-auth never restored its persisted serial
// either: with a file at serial 7 and 1000 persisted, the zone comes up
// serving 1001.
func TestFirstLoadRestoresThePersistedSerialForAPrimary(t *testing.T) {
	zd, _, load := persistPrimary(t, s2Zone, 1000)
	load()
	waitServing(t, zd, 1001)
}

// Newer is RFC 1982 order, not a numeric compare: a saved serial that has
// wrapped past zero is newer than a file serial just below the wrap, and one
// just below the wrap is older than a file serial past it.
func TestFirstLoadComparesThePersistedSerialInRFC1982Order(t *testing.T) {
	t.Run("saved past the wrap is restored", func(t *testing.T) {
		zd, _, load := persistPrimary(t, soaSerial(4294967290), 5)
		load()
		waitServing(t, zd, 6)
	})
	t.Run("saved before the wrap is not", func(t *testing.T) {
		zd, _, load := persistPrimary(t, soaSerial(5), 4294967290)
		load()
		waitServing(t, zd, 5)
	})
}

// A persisted serial that cannot be read fails the first load rather than
// letting the first publish overwrite it, and leaves nothing behind that
// would stop the retry: once the read works, the next attempt loads and
// restores.
func TestFirstLoadFailsWhenThePersistedSerialCannotBeRead(t *testing.T) {
	zd, conf, load := persistPrimary(t, s2Zone, 1000)
	kdb := Conf.Internal.KeyDB
	if _, err := kdb.DB.Exec(`ALTER TABLE OutgoingSerials RENAME TO OutgoingSerialsAway`); err != nil {
		t.Fatalf("hide the table: %v", err)
	}
	load()
	deadline := time.Now().Add(5 * time.Second)
	for !zd.HasError(RefreshError) {
		if time.Now().After(deadline) {
			t.Fatal("the first load did not fail with the persisted serial unreadable")
		}
		time.Sleep(20 * time.Millisecond)
	}
	zd.mu.Lock()
	first, incoming := zd.FirstZoneLoad, zd.IncomingSerial
	zd.mu.Unlock()
	if zd.publishedSnapshot() != nil || !first || incoming != 0 {
		t.Fatalf("a failed first load left state behind: published=%v FirstZoneLoad=%v IncomingSerial=%d",
			zd.publishedSnapshot() != nil, first, incoming)
	}
	if _, err := kdb.DB.Exec(`ALTER TABLE OutgoingSerialsAway RENAME TO OutgoingSerials`); err != nil {
		t.Fatalf("restore the table: %v", err)
	}
	conf.Internal.RefreshZoneCh <- ZoneRefresher{Name: "example.", ZoneStore: MapZone} // a retry, as the ticker sends
	waitServing(t, zd, 1001)
}

// An agent upgraded from before #1157 holds a zone copy on disk at a serial it
// counted itself (100), ahead of the upstream's (40). DoTransfer's serialNewer
// test asks for no transfer, so the relay served 100, and missed every upstream
// change until the upstream's serial passed it. The relay replaces such a copy
// at the first upstream answer: at first bind, or at a later refresh when the
// upstream was down at first bind. tdns-auth is unchanged: its secondary keeps
// the copy, as the serial comparison says.
//
// The copy's serial names none of the upstream's versions, so no serial
// comparison may stand in for the transfer. An upstream newer than the copy
// must not be asked for a delta from the copy's serial: the copy stays out of
// IXFR until a transfer replaces it. An upstream at the copy's own serial must
// still replace it, and so must a fallback upstream at that serial when the
// first upstream's transfer fails, rather than be discarded as unchanged.
func TestAgentRelayReplacesAPersistedCopyAheadOfTheUpstream(t *testing.T) {
	const ahead = `example.	3600	IN	SOA	ns.example. hostmaster.example. 100 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
ns.example.	3600	IN	A	10.0.0.1
stale.example.	3600	IN	A	10.0.0.100
`
	upstreamAt := func(serial uint32) string {
		return fmt.Sprintf(`example.	3600	IN	SOA	ns.example. hostmaster.example. %d 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
ns.example.	3600	IN	A	10.0.0.1
fresh.example.	3600	IN	A	10.0.0.40
`, serial)
	}
	for _, tc := range []struct {
		name      string
		app       AppType
		upstream  uint32
		firstDown bool
		soaOnly   uint32 // a first upstream that answers this SOA serial, but no transfer
		want      uint32
		replaced  bool
	}{
		{"agent, upstream up at first bind", AppTypeAgent, 40, false, 0, 40, true},
		{"agent, upstream down at first bind", AppTypeAgent, 40, true, 0, 40, true},
		{"agent, upstream newer than the copy", AppTypeAgent, 150, true, 0, 150, true},
		{"agent, upstream at the copy's serial", AppTypeAgent, 100, false, 0, 100, true},
		{"agent, fallback upstream at the copy's serial", AppTypeAgent, 100, false, 150, 100, true},
		{"auth keeps its copy", AppTypeAuth, 40, false, 0, 100, false},
		// Confirmed (tdns-auth never marks a copy): an unchanged transfer is
		// still discarded, so the copy at that serial stays.
		{"auth, fallback upstream at the copy's serial", AppTypeAuth, 100, false, 150, 100, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kdb := newTestKeyDB(t)
			conf, dir := persistentConf(t, kdb)
			withAppType(t, tc.app)

			addr, stop := startTestPrimary(t, upstreamAt(tc.upstream))
			defer stop()
			if err := os.WriteFile(filepath.Join(dir, "example.zone"), []byte(ahead), 0644); err != nil {
				t.Fatalf("write zone file: %v", err)
			}
			first := addr
			if tc.firstDown {
				first = "127.0.0.1:1" // nothing listening
			}
			upstreams := []PeerConf{{Addr: first}}
			if tc.soaOnly != 0 {
				// UDP only: its SOA starts the transfer, its AXFR (TCP) fails,
				// and the transfer falls back to the primary behind it.
				soaAddr, stopSOA := startTestSOAServer(t, "example.", tc.soaOnly, dns.RcodeSuccess)
				defer stopSOA()
				upstreams = []PeerConf{{Addr: soaAddr}, {Addr: addr}}
			}
			zd := &ZoneData{
				ZoneName: "example.", ZoneStore: MapZone, ZoneType: Secondary,
				Logger: discardLogger(), KeyDB: kdb,
				Options:   map[ZoneOption]bool{OptApiManagedZone: true},
				Upstreams: upstreams,
			}
			registerZones(t, zd)
			t.Cleanup(zd.stopPublisher)
			if zoneMayOriginateContent(zd) {
				t.Fatal("setup: the zone should relay")
			}

			_, err := zd.Refresh(context.Background(), false, false, false, conf)
			if tc.firstDown {
				if err == nil {
					t.Fatal("expected the refresh against a dead primary to fail")
				}
				if zd.IncomingSerial != 100 {
					t.Fatalf("IncomingSerial = %d, want 100: the adopted copy serves while the upstream is down", zd.IncomingSerial)
				}
				if zd.shouldRequestIxfr(false) {
					t.Fatal("an unconfirmed relay copy is IXFR-eligible: a delta from its serial would apply to the wrong base")
				}
				zd.Upstreams = []PeerConf{{Addr: addr}}
				_, err = zd.Refresh(context.Background(), false, false, false, conf)
			}
			if err != nil {
				t.Fatalf("Refresh: %v", err)
			}

			if zd.IncomingSerial != tc.want || zd.CurrentSerial != tc.want {
				t.Fatalf("IncomingSerial %d, CurrentSerial %d, want %d", zd.IncomingSerial, zd.CurrentSerial, tc.want)
			}
			fresh, _ := zd.GetOwner("fresh.example.")
			stale, _ := zd.GetOwner("stale.example.")
			if tc.replaced && (fresh == nil || stale != nil) {
				t.Errorf("the upstream's copy is not the one served (fresh %v, stale %v)", fresh != nil, stale != nil)
			}
			if !tc.replaced && (fresh != nil || stale == nil) {
				t.Errorf("the copy was replaced (fresh %v, stale %v)", fresh != nil, stale != nil)
			}
			if zd.relayCopyUnconfirmed {
				t.Error("the copy is still unconfirmed after the refresh")
			}
			if !zd.shouldRequestIxfr(false) {
				t.Error("a confirmed copy is not IXFR-eligible")
			}
		})
	}
}

// A primary that answers without a usable SOA (every one REFUSED) gives
// DoTransfer's placeholder serial 0, which is no serial: it must neither force
// a transfer of an unconfirmed relay copy nor confirm it.
func TestAgentRelayCopyIsLeftAloneWithoutAUsableSOA(t *testing.T) {
	const ahead = `example.	3600	IN	SOA	ns.example. hostmaster.example. 100 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
ns.example.	3600	IN	A	10.0.0.1
`
	kdb := newTestKeyDB(t)
	conf, dir := persistentConf(t, kdb)
	withAppType(t, AppTypeAgent)

	addr, stop := startTestSOAServer(t, "example.", 0, dns.RcodeRefused)
	defer stop()
	if err := os.WriteFile(filepath.Join(dir, "example.zone"), []byte(ahead), 0644); err != nil {
		t.Fatalf("write zone file: %v", err)
	}
	zd := &ZoneData{
		ZoneName: "example.", ZoneStore: MapZone, ZoneType: Secondary,
		Logger: discardLogger(), KeyDB: kdb,
		Options:   map[ZoneOption]bool{OptApiManagedZone: true},
		Upstreams: []PeerConf{{Addr: addr}},
	}
	registerZones(t, zd)
	t.Cleanup(zd.stopPublisher)

	if _, err := zd.Refresh(context.Background(), false, false, false, conf); err != nil {
		t.Fatalf("Refresh: %v (a refused probe backs off quietly; it must not force a transfer)", err)
	}
	if zd.IncomingSerial != 100 {
		t.Errorf("IncomingSerial = %d, want 100: the adopted copy stands", zd.IncomingSerial)
	}
	if !zd.relayCopyUnconfirmed {
		t.Error("the copy was confirmed with no usable SOA")
	}
}
