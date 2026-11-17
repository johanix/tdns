/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// A config reload has to record the DNSSEC policy its configuration names for a
// zone that is already loaded and does not sign (neither online- nor inline-
// signing), whatever the zone had before: none, another policy, or a binding a
// derived app made with BindPolicyWithoutSigning. The record is what a signing
// role learned later resolves its policy from, so a reload that drops it leaves
// the zone unable to start signing until the daemon restarts (#1000).
//
// Every zone here is loaded and reloaded through a running RefreshEngine, by
// the refresher ParseZones builds (relayedZone.configRefresher).

// otherPolicy is a second policy, of other algorithms than "base".
func otherPolicy() DnssecPolicy {
	return kskzsk(dns.ECDSAP256SHA256, dns.ECDSAP256SHA256)
}

func reloadPolicySetup(t *testing.T) *KeyDB {
	t.Helper()
	kdb, _ := roleSetup(t)
	withLivePolicies(t, map[string]DnssecPolicy{
		"base":  kskzsk(dns.ED25519, dns.ED25519),
		"other": otherPolicy(),
	})
	return kdb
}

// loadedWithPolicy is a loaded zone that does not sign, whose first load's
// configuration named policy (or none).
func loadedWithPolicy(t *testing.T, kdb *KeyDB, policy string) *relayedZone {
	t.Helper()
	up := startRelayUpstream(t, 40)
	z := startRelayedZoneWith(t, kdb, up, &relayedZone{policy: policy}, nil)
	if z.zd.signsItsOwnContent() {
		t.Fatal("the zone signs from its first load; the test has lost its point")
	}
	if z.zd.DnssecPolicyName != policy {
		t.Fatalf("the first load recorded policy %q, want %q", z.zd.DnssecPolicyName, policy)
	}
	return z
}

// reloadedWithPolicy is a config reload whose configuration names policy.
//
// The engine records the policy before it dispatches the refresh, so a reload
// that finds the previous one's refresh still marked in flight has recorded it
// already and is answered with an error. The answer to a refresh comes from its
// worker, a moment before the engine clears the mark. So that refusal is the
// harness's, and the reload is sent again (recording is idempotent).
func reloadedWithPolicy(t *testing.T, z *relayedZone, policy string) {
	t.Helper()
	z.policy = policy
	for try := 0; ; try++ {
		zr := z.configRefresher()
		zr.Force, zr.Wait = true, true
		zr.Response = make(chan RefresherResponse, 1)
		z.conf.Internal.RefreshZoneCh <- zr
		select {
		case resp := <-zr.Response:
			if !resp.Error {
				return
			}
			if !strings.Contains(resp.ErrorMsg, "refresh already in progress") || try >= 100 {
				t.Fatalf("reload: %s", resp.ErrorMsg)
			}
			time.Sleep(10 * time.Millisecond)
		case <-time.After(10 * time.Second):
			t.Fatal("the reload was not answered")
		}
	}
}

// wantPolicyRecord: the name the zone records, and the policy bound to it.
// bound is the name of the policy struct that is bound; "" says none is.
func wantPolicyRecord(t *testing.T, zd *ZoneData, name, bound, when string) {
	t.Helper()
	zd.mu.Lock()
	gotName, pol := zd.DnssecPolicyName, zd.DnssecPolicy
	zd.mu.Unlock()
	if gotName != name {
		t.Errorf("%s: the zone records policy %q, want %q", when, gotName, name)
	}
	switch {
	case bound == "" && pol != nil:
		t.Errorf("%s: a policy is bound (KSK algorithm %d), want none", when, pol.KSKAlgorithm)
	case bound != "" && pol == nil:
		t.Errorf("%s: no policy is bound, want %q", when, bound)
	case bound != "":
		want := ConfLive().DnssecPolicies[bound]
		if pol.KSKAlgorithm != want.KSKAlgorithm {
			t.Errorf("%s: the bound policy has KSK algorithm %d, want that of %q (%d)", when, pol.KSKAlgorithm, bound, want.KSKAlgorithm)
		}
	}
}

// The issue's case: a policy added to a loaded zone that has none. The zone then
// starts signing at once, with no restart.
func TestAReloadThatAddsAPolicyLetsTheZoneStartSigning(t *testing.T) {
	kdb := reloadPolicySetup(t)
	z := loadedWithPolicy(t, kdb, "")
	own := genActiveKeys(t, kdb)

	reloadedWithPolicy(t, z, "base")

	wantPolicyRecord(t, z.zd, "base", "", "after the reload")
	if z.zd.signsItsOwnContent() {
		t.Fatal("the reload switched signing on")
	}
	if err := z.zd.StartSigning(context.Background(), 0); err != nil {
		t.Fatalf("StartSigning after a reload that named a policy: %v", err)
	}
	wantReady(t, z.zd, "after the start")
	wantPolicyRecord(t, z.zd, "base", "base", "after the start")
	wantOnlyOwnSignatures(t, z.zd, own, "after the start")
	if name, _, ok, err := GetZoneAppliedPolicy(kdb, ovZone); err != nil || !ok || name != "base" {
		t.Errorf("last-applied record: %q %v %v, want base", name, ok, err)
	}
}

// A zone that does not sign has no binding for a reload to move: the name is the
// whole record, changed or removed.
func TestAReloadChangesOrRemovesThePolicyOfAZoneThatIsNotBound(t *testing.T) {
	kdb := reloadPolicySetup(t)
	z := loadedWithPolicy(t, kdb, "base")
	wantPolicyRecord(t, z.zd, "base", "", "before the reload")

	reloadedWithPolicy(t, z, "other")
	wantPolicyRecord(t, z.zd, "other", "", "after the policy was changed")

	reloadedWithPolicy(t, z, "")
	wantPolicyRecord(t, z.zd, "", "", "after the policy was removed")
	err := z.zd.StartSigning(context.Background(), 0)
	if err == nil || !strings.Contains(err.Error(), "names no DNSSEC policy") {
		t.Fatalf("StartSigning on a zone whose configuration names none: %v", err)
	}

	reloadedWithPolicy(t, z, "base")
	wantPolicyRecord(t, z.zd, "base", "", "after the policy was added again")
}

// A zone a derived app bound a policy to without signing keeps the name and the
// policy together: the policy a later start signs under is the one the
// configuration names.
func TestAReloadMovesTheBindingOfAZoneBoundWithoutSigning(t *testing.T) {
	kdb := reloadPolicySetup(t)
	z := loadedWithPolicy(t, kdb, "base")
	if err := z.zd.BindPolicyWithoutSigning(); err != nil {
		t.Fatalf("BindPolicyWithoutSigning: %v", err)
	}
	wantPolicyRecord(t, z.zd, "base", "base", "after the bind")

	reloadedWithPolicy(t, z, "base")
	wantPolicyRecord(t, z.zd, "base", "base", "after a reload that changed nothing")

	reloadedWithPolicy(t, z, "other")
	wantPolicyRecord(t, z.zd, "other", "other", "after the policy was changed")
	if z.zd.signsItsOwnContent() {
		t.Fatal("the reload switched signing on")
	}

	reloadedWithPolicy(t, z, "")
	wantPolicyRecord(t, z.zd, "", "", "after the policy was removed")
	if z.zd.signsItsOwnContent() {
		t.Fatal("the reload switched signing on")
	}

	// And a policy named again binds nothing by itself: the owner binds.
	reloadedWithPolicy(t, z, "base")
	wantPolicyRecord(t, z.zd, "base", "", "after the policy was added again")
}

// A bound zone that a reload points at a policy that does not exist keeps its
// binding, as a signing zone does, and says so. Naming the bound policy again
// takes the warning away, and with it the zone's error state.
func TestAReloadToAPolicyThatDoesNotExistKeepsTheBinding(t *testing.T) {
	kdb := reloadPolicySetup(t)
	z := loadedWithPolicy(t, kdb, "base")
	if err := z.zd.BindPolicyWithoutSigning(); err != nil {
		t.Fatalf("BindPolicyWithoutSigning: %v", err)
	}
	warned := func() (warning, zoneError bool) {
		z.zd.mu.Lock()
		defer z.zd.mu.Unlock()
		_, warning = z.zd.Errors[DnssecPolicyWarning]
		return warning, z.zd.Error
	}

	reloadedWithPolicy(t, z, "gone")

	wantPolicyRecord(t, z.zd, "base", "base", "after a reload to a policy that does not exist")
	if w, _ := warned(); !w {
		t.Error("no DNSSEC policy warning on the zone")
	}

	// The bound policy named again: nothing to move, and the warning goes.
	reloadedWithPolicy(t, z, "base")
	wantPolicyRecord(t, z.zd, "base", "base", "after a reload that names the bound policy again")
	if w, e := warned(); w || e {
		t.Errorf("after naming the bound policy again: DNSSEC policy warning %v, zone in an error state %v", w, e)
	}

	// Pointed at a policy that exists, the zone follows.
	reloadedWithPolicy(t, z, "gone")
	reloadedWithPolicy(t, z, "other")
	wantPolicyRecord(t, z.zd, "other", "other", "after a reload to a policy that exists")
	if w, e := warned(); w || e {
		t.Errorf("after a reload to a policy that exists: DNSSEC policy warning %v, zone in an error state %v", w, e)
	}
}

// A reload that changes a policy's definition under its own name moves a bound
// zone to the new definition: what a later start signs under is what the config
// says now, not what it said when the zone was bound.
func TestAReloadThatChangesAPoliciesDefinitionRebindsTheBoundZone(t *testing.T) {
	kdb := reloadPolicySetup(t)
	z := loadedWithPolicy(t, kdb, "base")
	if err := z.zd.BindPolicyWithoutSigning(); err != nil {
		t.Fatalf("BindPolicyWithoutSigning: %v", err)
	}
	wantPolicyRecord(t, z.zd, "base", "base", "after the bind")

	// "base" now has other algorithms; the new snapshot is published before
	// the reload, as the engine resolves against it.
	withLivePolicies(t, map[string]DnssecPolicy{"base": otherPolicy(), "other": otherPolicy()})
	reloadedWithPolicy(t, z, "base")
	wantPolicyRecord(t, z.zd, "base", "base", "after the definition of the policy changed")
	if got := z.zd.DnssecPolicy.KSKAlgorithm; got != dns.ECDSAP256SHA256 {
		t.Errorf("the bound policy has KSK algorithm %d, want the new definition's %d", got, dns.ECDSAP256SHA256)
	}

	if err := z.zd.StartSigning(context.Background(), 0); err != nil {
		t.Fatalf("StartSigning: %v", err)
	}
	for _, rr := range servedRRset(t, z.zd, ovZone, dns.TypeSOA).RRSIGs {
		if sig, ok := rr.(*dns.RRSIG); ok && sig.Algorithm != dns.ECDSAP256SHA256 {
			t.Errorf("the SOA is signed with algorithm %d, want the new definition's %d", sig.Algorithm, dns.ECDSAP256SHA256)
		}
	}
	if len(keytagsOf(servedRRset(t, z.zd, ovZone, dns.TypeSOA).RRSIGs)) == 0 {
		t.Error("the SOA is unsigned after the start")
	}
}

// On an owned zone the algorithms, lifetimes, standby counts and rollover method
// of a bound policy are the owner's: a reload follows a policy that differs from
// the bound one in mechanism fields only, and keeps the binding, with a warning,
// for any other. The same for a changed name and for a changed definition.
func TestAReloadLeavesTheOwnersFieldsOfABoundZoneAlone(t *testing.T) {
	kdb := newTestKeyDB(t)
	base := kskzsk(dns.ED25519, dns.ED25519)
	base.Name = "base"
	mech := base
	mech.Name = "mech"
	mech.SigValidity.Default = 12345 // a mechanism field
	alg := base
	alg.Name = "alg"
	alg.KSKAlgorithm, alg.ZSKAlgorithm = dns.ECDSAP256SHA256, dns.ECDSAP256SHA256
	withLivePolicies(t, map[string]DnssecPolicy{"base": base, "mech": mech, "alg": alg})

	const zone = "owned.example."
	zd := testZone(t, zone, zone+" 3600 IN SOA ns."+zone+" hostmaster."+zone+" 1 7200 1800 604800 7200\n"+zone+" 3600 IN NS ns."+zone+"\n")
	registerZones(t, zd)
	zd.KeyDB = kdb
	zd.Options = map[ZoneOption]bool{OptMultiProvider: true}
	installOwner(t, &testOwner{owns: map[string]bool{zone: true}})
	zd.DnssecPolicyName = "base"
	if err := zd.BindPolicyWithoutSigning(); err != nil {
		t.Fatalf("BindPolicyWithoutSigning: %v", err)
	}

	step := func(name, wantName string, wantWarning bool, when string) {
		t.Helper()
		if !zd.recordPolicyOfNonSigningZone(name, nil) {
			t.Fatalf("%s: the zone was not handled", when)
		}
		zd.mu.Lock()
		defer zd.mu.Unlock()
		_, warned := zd.Errors[DnssecPolicyWarning]
		if zd.DnssecPolicyName != wantName || zd.DnssecPolicy == nil || zd.DnssecPolicy.Name != wantName {
			t.Errorf("%s: the zone records %q bound to %v, want %q bound to it", when, zd.DnssecPolicyName, zd.DnssecPolicy != nil, wantName)
		}
		if warned != wantWarning {
			t.Errorf("%s: DNSSEC policy warning %v, want %v", when, warned, wantWarning)
		}
	}
	step("mech", "mech", false, "a name that differs in a mechanism field")
	step("alg", "mech", true, "a name that differs in an algorithm")
	step("mech", "mech", false, "the bound policy named again")

	// the same names, defined otherwise
	mech2 := mech
	mech2.SigValidity.Default = 54321
	alg2 := mech
	alg2.KSKAlgorithm, alg2.ZSKAlgorithm = dns.ECDSAP256SHA256, dns.ECDSAP256SHA256
	withLivePolicies(t, map[string]DnssecPolicy{"base": base, "mech": mech2, "alg": alg})
	step("mech", "mech", false, "a changed mechanism field under the same name")
	if got := zd.DnssecPolicy.SigValidity.Default; got != 54321 {
		t.Errorf("the bound policy's signature validity is %v, want the new definition's", got)
	}
	withLivePolicies(t, map[string]DnssecPolicy{"base": base, "mech": alg2, "alg": alg})
	step("mech", "mech", true, "a changed algorithm under the same name")
	if got := zd.DnssecPolicy.KSKAlgorithm; got != dns.ED25519 {
		t.Errorf("the bound policy's KSK algorithm is %d, want the owner's %d kept", got, dns.ED25519)
	}
}

// A zone that signs is not touched by any of this: its policy goes through the
// policy sync, whose result a reload that changes nothing leaves as it was.
func TestAReloadLeavesTheRecordOfASigningZoneToThePolicySync(t *testing.T) {
	kdb := reloadPolicySetup(t)
	up := startRelayUpstream(t, 40)
	z := startRelayedZoneWith(t, kdb, up, &relayedZone{
		opts:   map[ZoneOption]bool{OptInlineSigning: true},
		policy: "base",
	}, nil)
	wantPolicyRecord(t, z.zd, "base", "base", "after the first load")
	if !z.zd.signsItsOwnContent() {
		t.Fatal("the zone does not sign; the test has lost its point")
	}

	z.reloaded(t)

	wantPolicyRecord(t, z.zd, "base", "base", "after a reload")
	if !z.zd.signsItsOwnContent() {
		t.Fatal("a reload took signing away")
	}
}

// ReloadZoneConfig publishes the new runtime-config snapshot only after
// ParseZones has queued the refreshers, so the engine can handle a zone's
// refresher while ConfLive still holds the previous config's policies. A bound
// zone must follow the policies of the reload being applied all the same: one
// defined and selected in that reload, and one edited under its own name. Each
// reload here is parsed by ParseZones against the new policies
// (conf.Internal.DnssecPolicies) and handled by the engine with the snapshot
// still the old one, which is published only after the engine has finished.
func TestAReloadFollowsThePoliciesOfTheReloadNotTheRunningSnapshot(t *testing.T) {
	authApp(t)
	kdb := Conf.Internal.KeyDB
	named := func(p DnssecPolicy, name string) DnssecPolicy { p.Name = name; return p }
	oldBase := named(kskzsk(dns.ED25519, dns.ED25519), "base")
	other := named(kskzsk(dns.ECDSAP256SHA256, dns.ECDSAP256SHA256), "other")
	other2 := named(kskzsk(dns.RSASHA256, dns.RSASHA256), "other") // "other", edited

	const zone = "snap.config.example."
	file := filepath.Join(t.TempDir(), "zone")
	body := zone + "\t3600\tIN\tSOA\tns1." + zone + " hostmaster." + zone + " 1 7200 1800 604800 7200\n" +
		zone + "\t3600\tIN\tNS\tns1." + zone + "\n" +
		"ns1." + zone + "\t3600\tIN\tA\t192.0.2.53\n"
	if err := os.WriteFile(file, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	// Registered before the engine starts, so it runs after the engine stops.
	t.Cleanup(func() {
		if zd, ok := Zones.Get(zone); ok {
			zd.stopPublisher()
		}
		Zones.Remove(zone)
	})

	// ParseZones queues its refreshers on parsed, and the test hands them on to
	// the engine, which is the only way to wait for the refresh a refresher
	// starts: ParseZones builds them with nobody waiting.
	engineConf := &Config{}
	engineConf.Internal.KeyDB = kdb
	engineConf.Internal.RefreshZoneCh = make(chan ZoneRefresher, 4)
	engineConf.Internal.BumpZoneCh = make(chan BumperData, 1)
	runRefreshEngine(t, engineConf)
	conf := &Config{}
	conf.Internal.KeyDB = kdb
	parsed := make(chan ZoneRefresher, 4)
	conf.Internal.RefreshZoneCh = parsed

	// The running daemon's snapshot, which the reloads below do not replace.
	withLivePolicies(t, map[string]DnssecPolicy{"base": oldBase})
	livePolicies := func(pols map[string]DnssecPolicy) {
		t.Helper()
		liveConfig.Store(&RuntimeConfig{DnssecPolicies: pols})
	}

	// answered sends zr to the engine and waits for its answer, which a
	// refresher with Wait set gets when its refresh is done.
	answered := func(zr ZoneRefresher) {
		t.Helper()
		resp := make(chan RefresherResponse, 1)
		zr.Wait, zr.Response = true, resp
		engineConf.Internal.RefreshZoneCh <- zr
		select {
		case r := <-resp:
			if r.Error {
				t.Fatalf("the engine's answer: %s", r.ErrorMsg)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("the engine did not answer")
		}
	}
	// reload is a ParseZones of the zone naming policy, against the policies
	// the reload has parsed, and the engine's handling of what it queued, its
	// refresh included.
	reload := func(isReload bool, policy string, policies map[string]DnssecPolicy) *ZoneData {
		t.Helper()
		conf.Internal.DnssecPolicies = policies
		conf.Zones = []ZoneConf{{Name: zone, Type: "primary", Store: "map", Zonefile: file, DnssecPolicy: policy}}
		if _, broken, err := conf.ParseZones(context.Background(), isReload); err != nil || len(broken) > 0 {
			t.Fatalf("ParseZones(reload=%v): err=%v broken=%v", isReload, err, broken)
		}
		zr := <-parsed
		if isReload {
			answered(zr)
		} else {
			// a first load answers when it fails, and when it is done goes on to
			// the next request
			engineConf.Internal.RefreshZoneCh <- zr
			answered(ZoneRefresher{Name: zone, ZoneStore: MapZone})
		}
		zd, ok := Zones.Get(zone)
		if !ok {
			t.Fatalf("zone %s is not held", zone)
		}
		return zd
	}
	state := func(zd *ZoneData) (name string, alg uint8, warned bool) {
		zd.mu.Lock()
		defer zd.mu.Unlock()
		if zd.DnssecPolicy != nil {
			alg = zd.DnssecPolicy.KSKAlgorithm
		}
		_, warned = zd.Errors[DnssecPolicyWarning]
		return zd.DnssecPolicyName, alg, warned
	}

	zd := reload(false, "base", map[string]DnssecPolicy{"base": oldBase})
	if err := zd.BindPolicyWithoutSigning(); err != nil {
		t.Fatalf("BindPolicyWithoutSigning: %v", err)
	}
	if n, a, w := state(zd); n != "base" || a != dns.ED25519 || w {
		t.Fatalf("after the bind: %q, KSK algorithm %d, warning %v", n, a, w)
	}

	// "other" is defined in this reload and selected for the zone. The snapshot
	// does not have it.
	zd = reload(true, "other", map[string]DnssecPolicy{"base": oldBase, "other": other})
	if n, a, w := state(zd); n != "other" || a != dns.ECDSAP256SHA256 || w {
		t.Errorf("a policy defined in the reload: the zone records %q bound with KSK algorithm %d, warning %v; want %q, %d, no warning",
			n, a, w, "other", dns.ECDSAP256SHA256)
	}

	// "other" is in the snapshot now, and the next reload edits it: the zone
	// follows the edit, not the definition the snapshot still holds.
	livePolicies(map[string]DnssecPolicy{"base": oldBase, "other": other})
	zd = reload(true, "other", map[string]DnssecPolicy{"base": oldBase, "other": other2})
	if n, a, w := state(zd); n != "other" || a != dns.RSASHA256 || w {
		t.Errorf("a policy edited in the reload: the zone records %q bound with KSK algorithm %d, warning %v; want %q, %d, no warning",
			n, a, w, "other", dns.RSASHA256)
	}
}
