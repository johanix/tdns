package tdns

import (
	"context"
	"log"
	"net"
	"os"
	"path/filepath"
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

	deadline = time.Now().Add(10 * time.Second)
	for {
		zd.mu.Lock()
		ready, pol, name := zd.Ready, zd.DnssecPolicy, zd.DnssecPolicyName
		zd.mu.Unlock()
		if ready && pol != nil && name == "base" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after the NOTIFY-driven load: Ready=%v policy bound=%v name=%q; the load bound the "+
				"refresher's empty policy name instead of the zone's", ready, pol != nil, name)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, _, ok, err := GetZoneAppliedPolicy(kdb, "example."); err != nil || !ok {
		t.Fatalf("applied policy not recorded: ok=%v err=%v", ok, err)
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
// upstream's: the first load restores the persisted serial, so the serial
// the zone publishes never goes backwards across a restart. The first
// publish used to persist the upstream's serial over the saved one before
// the engine's restore looked, so a combiner came back from a restart at a
// lower serial and its signer ignored its NOTIFYs.
func TestFirstLoadRestoresThePersistedSerialForAnOriginatingSecondary(t *testing.T) {
	authApp(t)
	Globals.App.Type = AppTypeAgent // any originating role but tdns-auth
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
		if ready && cur == 1000 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after the first load: Ready=%v CurrentSerial=%d RefreshCount=%d mode=%q keydb=%v, want the persisted 1000 restored over the upstream's 7", ready, cur, zd.RefreshCount, zd.EffectiveOutboundSoaSerial(), zd.KeyDB != nil)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
