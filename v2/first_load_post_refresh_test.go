package tdns

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"testing"

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
