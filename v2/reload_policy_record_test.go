/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	// The reload signed nothing, so it recorded nothing as applied: the record
	// is what the start writes.
	if name, _, ok, err := GetZoneAppliedPolicy(kdb, ovZone); err != nil || ok {
		t.Errorf("last-applied record after the reload: %q %v %v, want none", name, ok, err)
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

// A reload as ReloadZoneConfig makes it, for a zone of a running RefreshEngine.
//
// ReloadZoneConfig publishes the new runtime-config snapshot only after
// ParseZones has queued the refreshers, so the engine can handle a zone's
// refresher while ConfLive still holds the previous config's policies. Each
// reload here is parsed by ParseZones against the policies of the reload
// (conf.Internal.DnssecPolicies) and handled by the engine with the snapshot
// left as it was, which is how the engine meets it when it gets there first.
type reloadHarness struct {
	t          *testing.T
	zone       string
	file       string
	options    []string
	conf       *Config // what ParseZones is given
	engineConf *Config // what the engine runs on
	parsed     chan ZoneRefresher
}

// newReloadHarness starts an engine on kdb and makes the zone's file. options
// are the zone's configured options, as the config names them.
func newReloadHarness(t *testing.T, kdb *KeyDB, zone string, options ...string) *reloadHarness {
	t.Helper()
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

	// ParseZones queues its refreshers on parsed, and the test hands them on
	// to the engine, which is the only way to wait for the refresh a refresher
	// starts: ParseZones builds them with nobody waiting.
	h := &reloadHarness{t: t, zone: zone, file: file, options: options, parsed: make(chan ZoneRefresher, 4)}
	h.engineConf = &Config{}
	h.engineConf.Internal.KeyDB = kdb
	h.engineConf.Internal.RefreshZoneCh = make(chan ZoneRefresher, 4)
	h.engineConf.Internal.BumpZoneCh = make(chan BumperData, 1)
	runRefreshEngine(t, h.engineConf)
	h.conf = &Config{}
	h.conf.Internal.KeyDB = kdb
	h.conf.Internal.RefreshZoneCh = h.parsed
	return h
}

// answered sends zr to the engine and waits for its answer, which a refresher
// with Wait set gets when its refresh is done.
//
// The answer to a refresh comes from its worker, a moment before the engine
// clears the zone's in-flight mark, so a refresher sent right behind another is
// sometimes refused for that. That refusal is the harness's, as in
// reloadedWithPolicy: the refresher is sent again, up to a bound, and no other
// refusal is retried.
func (h *reloadHarness) answered(zr ZoneRefresher) {
	h.t.Helper()
	for try := 0; ; try++ {
		resp := make(chan RefresherResponse, 1)
		zr.Wait, zr.Response = true, resp
		h.engineConf.Internal.RefreshZoneCh <- zr
		select {
		case r := <-resp:
			if !r.Error {
				return
			}
			if !strings.Contains(r.ErrorMsg, "refresh already in progress") || try >= 100 {
				h.t.Fatalf("the engine's answer: %s", r.ErrorMsg)
			}
			time.Sleep(10 * time.Millisecond)
		case <-time.After(10 * time.Second):
			h.t.Fatal("the engine did not answer")
		}
	}
}

// reload is a ParseZones of the zone naming policy, against the policies the
// reload has parsed, and the engine's handling of what it queued, its refresh
// included.
func (h *reloadHarness) reload(isReload bool, policy string, policies map[string]DnssecPolicy) *ZoneData {
	h.t.Helper()
	h.conf.Internal.DnssecPolicies = policies
	h.conf.Zones = []ZoneConf{{Name: h.zone, Type: "primary", Store: "map", Zonefile: h.file, DnssecPolicy: policy, OptionsStrs: h.options}}
	if _, broken, err := h.conf.ParseZones(context.Background(), isReload); err != nil || len(broken) > 0 {
		h.t.Fatalf("ParseZones(reload=%v): err=%v broken=%v", isReload, err, broken)
	}
	zr := <-h.parsed
	if isReload {
		h.answered(zr)
	} else {
		// a first load answers when it fails, and when it is done goes on to
		// the next request
		h.engineConf.Internal.RefreshZoneCh <- zr
		h.answered(ZoneRefresher{Name: h.zone, ZoneStore: MapZone})
	}
	zd, ok := Zones.Get(h.zone)
	if !ok {
		h.t.Fatalf("zone %s is not held", h.zone)
	}
	return zd
}

// named is the policy with its name set, as the config parse leaves it.
func named(p DnssecPolicy, name string) DnssecPolicy { p.Name = name; return p }

// validFor is p with signature validities the sig-validity floor accepts, so
// that a zone signing under it is not put in an error state the engine skips.
func validFor(p DnssecPolicy, secs uint32) DnssecPolicy {
	p.SigValidity = PolicySigValidity{Default: secs, DNSKEY: secs, DS: secs}
	return p
}

// policyState is what a zone records of its policy, and whether it carries a
// DNSSEC policy warning.
func policyState(zd *ZoneData) (name string, pol *DnssecPolicy, warned bool) {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	_, warned = zd.Errors[DnssecPolicyWarning]
	return zd.DnssecPolicyName, zd.DnssecPolicy, warned
}

// validityOf and kskAlgOf read a bound policy for a failure message: 0 for none.
func validityOf(p *DnssecPolicy) uint32 {
	if p == nil {
		return 0
	}
	return p.SigValidity.Default
}

func kskAlgOf(p *DnssecPolicy) uint8 {
	if p == nil {
		return 0
	}
	return p.KSKAlgorithm
}

func zskAlgOf(p *DnssecPolicy) uint8 {
	if p == nil {
		return 0
	}
	return p.ZSKAlgorithm
}

// A bound zone follows the policies of the reload being applied: one defined
// and selected in that reload, and one edited under its own name.
func TestAReloadFollowsThePoliciesOfTheReloadNotTheRunningSnapshot(t *testing.T) {
	authApp(t)
	h := newReloadHarness(t, Conf.Internal.KeyDB, "snap.config.example.")
	oldBase := named(kskzsk(dns.ED25519, dns.ED25519), "base")
	other := named(kskzsk(dns.ECDSAP256SHA256, dns.ECDSAP256SHA256), "other")
	other2 := named(kskzsk(dns.RSASHA256, dns.RSASHA256), "other") // "other", edited

	// The running daemon's snapshot, which the reloads below do not replace.
	withLivePolicies(t, map[string]DnssecPolicy{"base": oldBase})

	zd := h.reload(false, "base", map[string]DnssecPolicy{"base": oldBase})
	if err := zd.BindPolicyWithoutSigning(); err != nil {
		t.Fatalf("BindPolicyWithoutSigning: %v", err)
	}
	if n, p, w := policyState(zd); n != "base" || p.KSKAlgorithm != dns.ED25519 || w {
		t.Fatalf("after the bind: %q, KSK algorithm %d, warning %v", n, p.KSKAlgorithm, w)
	}

	// "other" is defined in this reload and selected for the zone. The snapshot
	// does not have it.
	zd = h.reload(true, "other", map[string]DnssecPolicy{"base": oldBase, "other": other})
	if n, p, w := policyState(zd); n != "other" || p == nil || p.KSKAlgorithm != dns.ECDSAP256SHA256 || w {
		t.Errorf("a policy defined in the reload: the zone records %q bound to %v, warning %v; want %q bound to KSK algorithm %d, no warning",
			n, p != nil, w, "other", dns.ECDSAP256SHA256)
	}

	// "other" is in the snapshot now, and the next reload edits it: the zone
	// follows the edit, not the definition the snapshot still holds.
	liveConfig.Store(&RuntimeConfig{DnssecPolicies: map[string]DnssecPolicy{"base": oldBase, "other": other}})
	zd = h.reload(true, "other", map[string]DnssecPolicy{"base": oldBase, "other": other2})
	if n, p, w := policyState(zd); n != "other" || p == nil || p.KSKAlgorithm != dns.RSASHA256 || w {
		t.Errorf("a policy edited in the reload: the zone records %q bound to %v, warning %v; want %q bound to KSK algorithm %d, no warning",
			n, p != nil, w, "other", dns.RSASHA256)
	}
}

// The same for a zone that signs, whose policy goes through the policy sync: a
// policy edited under its own name is bound by the sync, and a policy defined
// and selected in the reload is applied (a rename with the same algorithms
// re-signs under it), where the previous snapshot would give the old definition
// or none at all, and the zone would keep its policy with a warning.
func TestAReloadOfASigningZoneFollowsThePoliciesOfTheReloadNotTheRunningSnapshot(t *testing.T) {
	authApp(t)
	kdb := Conf.Internal.KeyDB
	h := newReloadHarness(t, kdb, "snapsign.config.example.", "online-signing")
	const month = 30 * 86400
	base := named(validFor(kskzsk(dns.ED25519, dns.ED25519), month), "base")
	base2 := named(validFor(kskzsk(dns.ED25519, dns.ED25519), 2*month), "base") // "base", edited
	other := named(validFor(kskzsk(dns.ED25519, dns.ED25519), 3*month), "other")
	withLivePolicies(t, map[string]DnssecPolicy{"base": base})

	zd := h.reload(false, "base", map[string]DnssecPolicy{"base": base})
	if !zd.signsItsOwnContent() {
		t.Fatal("the zone does not sign; the test has lost its point")
	}
	if n, p, w := policyState(zd); n != "base" || p == nil || p.SigValidity.Default != month || w {
		t.Fatalf("after the first load: %q bound to signature validity %d, warning %v", n, validityOf(p), w)
	}
	if name, _, ok, err := GetZoneAppliedPolicy(kdb, h.zone); err != nil || !ok || name != "base" {
		t.Fatalf("after the first load the last-applied record is %q %v %v, want base", name, ok, err)
	}

	// "base" is edited in this reload; the snapshot still holds the old one.
	zd = h.reload(true, "base", map[string]DnssecPolicy{"base": base2})
	if n, p, w := policyState(zd); n != "base" || p == nil || p.SigValidity.Default != 2*month || w {
		t.Errorf("a policy edited in the reload: the zone records %q bound to signature validity %d, warning %v; want %q bound to %d, no warning",
			n, validityOf(p), w, "base", 2*month)
	}

	// "other" is defined in this reload and selected for the zone: not in the
	// snapshot, which holds the policies before the reload.
	zd = h.reload(true, "other", map[string]DnssecPolicy{"base": base2, "other": other})
	if n, p, w := policyState(zd); n != "other" || p == nil || p.SigValidity.Default != 3*month || w {
		t.Errorf("a policy defined in the reload: the zone records %q bound to signature validity %d, warning %v; want %q bound to %d, no warning",
			n, validityOf(p), w, "other", 3*month)
	}
	if name, _, ok, err := GetZoneAppliedPolicy(kdb, h.zone); err != nil || !ok || name != "other" {
		t.Errorf("after the reload the last-applied record is %q %v %v, want other", name, ok, err)
	}
	if len(keytagsOf(servedRRset(t, zd, h.zone, dns.TypeSOA).RRSIGs)) == 0 {
		t.Error("the SOA is unsigned after the reload")
	}
}

// A keystore override of the zone's policy is resolved against the policies of
// the reload too: the policy it names is the one that was edited, not the one
// the config names for the zone, and the reload follows it all the same.
func TestAReloadFollowsAnOverridesPolicyInTheReloadNotTheRunningSnapshot(t *testing.T) {
	authApp(t)
	kdb := Conf.Internal.KeyDB
	h := newReloadHarness(t, kdb, "snapovr.config.example.")
	base := named(kskzsk(dns.ED25519, dns.ED25519), "base")
	ovr := named(kskzsk(dns.ED25519, dns.ED25519), "ovr")
	ovr2 := named(kskzsk(dns.ECDSAP256SHA256, dns.ECDSAP256SHA256), "ovr") // "ovr", edited
	withLivePolicies(t, map[string]DnssecPolicy{"base": base, "ovr": ovr})

	zd := h.reload(false, "base", map[string]DnssecPolicy{"base": base, "ovr": ovr})
	if err := SetZonePolicyOverride(kdb, h.zone, "ovr"); err != nil {
		t.Fatalf("SetZonePolicyOverride: %v", err)
	}
	if err := zd.BindPolicyWithoutSigning(); err != nil {
		t.Fatalf("BindPolicyWithoutSigning: %v", err)
	}
	if n, p, w := policyState(zd); n != "ovr" || p == nil || p.KSKAlgorithm != dns.ED25519 || w {
		t.Fatalf("after the bind: %q bound to KSK algorithm %d, warning %v; want the override's policy", n, kskAlgOf(p), w)
	}

	// The config still names "base" for the zone; "ovr" is what the reload edits.
	zd = h.reload(true, "base", map[string]DnssecPolicy{"base": base, "ovr": ovr2})
	if n, p, w := policyState(zd); n != "ovr" || p == nil || p.KSKAlgorithm != dns.ECDSAP256SHA256 || w {
		t.Errorf("an override's policy edited in the reload: the zone records %q bound to KSK algorithm %d, warning %v; want %q bound to %d, no warning",
			n, kskAlgOf(p), w, "ovr", dns.ECDSAP256SHA256)
	}
}

// A reload that changes the algorithms of the policy a signing zone is bound to,
// under the policy's own name, is an algorithm change like any other. The
// applied record and the intent both name "base", and both resolve to the
// definition the reload carries, so only the definition the zone is bound to
// still says what its keys were made under. The change is refused, as a change
// of the zone to another policy of other algorithms is, and the zone keeps
// signing under the definition it has keys for. An edit that keeps the
// algorithms is followed as before.
func TestAReloadThatChangesTheAlgorithmsOfASigningZonesPolicyUnderItsNameIsRefused(t *testing.T) {
	authApp(t)
	kdb := Conf.Internal.KeyDB
	h := newReloadHarness(t, kdb, "algedit.config.example.", "online-signing")
	const month = 30 * 86400
	base := named(validFor(kskzsk(dns.ED25519, dns.ED25519), month), "base")
	baseAlg := named(validFor(kskzsk(dns.ECDSAP256SHA256, dns.ECDSAP256SHA256), month), "base") // "base", other algorithms
	base2 := named(validFor(kskzsk(dns.ED25519, dns.ED25519), 2*month), "base")                 // "base", same algorithms, edited
	withLivePolicies(t, map[string]DnssecPolicy{"base": base})

	zd := h.reload(false, "base", map[string]DnssecPolicy{"base": base})
	if !zd.signsItsOwnContent() {
		t.Fatal("the zone does not sign; the test has lost its point")
	}
	if n, p, w := policyState(zd); n != "base" || p == nil || p.KSKAlgorithm != dns.ED25519 || w {
		t.Fatalf("after the first load: %q bound to KSK algorithm %d, warning %v", n, kskAlgOf(p), w)
	}
	soaSignedWith := func(when string, want uint8) {
		t.Helper()
		sigs := servedRRset(t, zd, h.zone, dns.TypeSOA).RRSIGs
		if len(sigs) == 0 {
			t.Errorf("%s: the SOA is unsigned", when)
		}
		for _, rr := range sigs {
			if sig, ok := rr.(*dns.RRSIG); ok && sig.Algorithm != want {
				t.Errorf("%s: the SOA is signed with algorithm %d, want %d", when, sig.Algorithm, want)
			}
		}
	}
	soaSignedWith("after the first load", dns.ED25519)

	// "base" has other algorithms in this reload. The zone has no keys of them.
	zd = h.reload(true, "base", map[string]DnssecPolicy{"base": baseAlg})
	n, p, _ := policyState(zd)
	if n != "base" || p == nil || p.KSKAlgorithm != dns.ED25519 || p.ZSKAlgorithm != dns.ED25519 {
		t.Errorf("an algorithm change under the policy's name: the zone records %q bound to KSK/ZSK algorithms %d/%d; want %q bound to the %d it has keys of",
			n, kskAlgOf(p), zskAlgOf(p), "base", dns.ED25519)
	}
	if zd.HasServiceImpactingError() {
		t.Errorf("an algorithm change under the policy's name left the zone in an error state: %s", zd.ErrorMsg)
	}
	soaSignedWith("after the refused algorithm change", dns.ED25519)
	if name, _, ok, err := GetZoneAppliedPolicy(kdb, h.zone); err != nil || !ok || name != "base" {
		t.Errorf("after the refused change the last-applied record is %q %v %v, want base", name, ok, err)
	}

	// An edit that keeps the algorithms is followed, the refusal behind it.
	zd = h.reload(true, "base", map[string]DnssecPolicy{"base": base2})
	if n, p, w := policyState(zd); n != "base" || p == nil || p.SigValidity.Default != 2*month || w {
		t.Errorf("an edit that keeps the algorithms: the zone records %q bound to signature validity %d, warning %v; want %q bound to %d, no warning",
			n, validityOf(p), w, "base", 2*month)
	}
	soaSignedWith("after an edit that keeps the algorithms", dns.ED25519)
}

// A reload that names a policy the config does not define or cannot use, for a
// zone that is loaded and does not sign, does not take the zone out of service,
// and does not remove its policy: the zone keeps the binding it has, with a
// warning. This goes through the parse, which is where it was decided, and which
// the tests that hand the engine a refresher do not reach.
func TestAReloadToAnUnresolvedPolicyDoesNotQuarantineAZoneThatDoesNotSign(t *testing.T) {
	authApp(t)
	kdb := Conf.Internal.KeyDB
	h := newReloadHarness(t, kdb, "unresolved.config.example.")
	base := named(kskzsk(dns.ED25519, dns.ED25519), "base")
	broken := DnssecPolicy{Name: "broken", Error: "a test policy that did not parse"}
	pols := map[string]DnssecPolicy{"base": base, "broken": broken}
	withLivePolicies(t, pols)

	zd := h.reload(false, "base", pols)
	if zd.signsItsOwnContent() {
		t.Fatal("the zone signs; the test has lost its point")
	}
	if err := zd.BindPolicyWithoutSigning(); err != nil {
		t.Fatalf("BindPolicyWithoutSigning: %v", err)
	}
	// wantKept: the zone serves, still records and is bound to "base", and says
	// that the policy the config names is not usable. The warning is the
	// engine's, which only the engine writes: the refresh was not refused.
	wantKept := func(when string) {
		t.Helper()
		if zd.HasServiceImpactingError() {
			t.Errorf("%s: the zone is quarantined: %s", when, zd.ErrorMsg)
		}
		n, p, w := policyState(zd)
		if n != "base" || p == nil || p.KSKAlgorithm != dns.ED25519 {
			t.Errorf("%s: the zone records %q bound to KSK algorithm %d, want %q kept", when, n, kskAlgOf(p), "base")
		}
		zd.mu.Lock()
		warning := zd.Errors[DnssecPolicyWarning].Msg
		zd.mu.Unlock()
		if !w || !strings.Contains(warning, "keeping bound policy") {
			t.Errorf("%s: DNSSEC policy warning %q (set %v), want the engine's, that the bound policy is kept", when, warning, w)
		}
	}

	zd = h.reload(true, "gone", pols)
	wantKept("a policy the config does not define")

	zd = h.reload(true, "broken", pols)
	wantKept("a policy that is broken")

	// The bound policy named again: the warning goes, and nothing else changes.
	zd = h.reload(true, "base", pols)
	if n, p, w := policyState(zd); n != "base" || p == nil || w || zd.Error {
		t.Errorf("after naming the bound policy again: %q bound %v, warning %v, zone in an error state %v", n, p != nil, w, zd.Error)
	}
}

// The same reload for a zone with no policy bound: it serves, and the name it
// records is what the config says, as for any other name, so that a signing
// role learned later says that the policy does not exist rather than that the
// zone names none.
func TestAReloadToAnUnresolvedPolicyDoesNotQuarantineAnUnboundZoneThatDoesNotSign(t *testing.T) {
	authApp(t)
	kdb := Conf.Internal.KeyDB
	h := newReloadHarness(t, kdb, "unresolvedunbound.config.example.")
	base := named(kskzsk(dns.ED25519, dns.ED25519), "base")
	pols := map[string]DnssecPolicy{"base": base}
	withLivePolicies(t, pols)

	zd := h.reload(false, "base", pols)
	zd = h.reload(true, "gone", pols)
	if zd.HasServiceImpactingError() {
		t.Errorf("the zone is quarantined: %s", zd.ErrorMsg)
	}
	n, p, w := policyState(zd)
	if n != "gone" || p != nil || !w {
		t.Errorf("the zone records %q, bound %v, warning %v; want %q recorded, nothing bound, a warning", n, p != nil, w, "gone")
	}
	err := zd.StartSigning(context.Background(), 0)
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("StartSigning on a zone whose config names a policy that does not exist: %v", err)
	}
}

// What a reload to an unresolved policy still does to the zones it was always
// meant for: a zone that signs is quarantined with the reason, and so is a zone
// that is not loaded yet.
func TestAReloadToAnUnresolvedPolicyStillQuarantinesAZoneThatSigns(t *testing.T) {
	authApp(t)
	kdb := Conf.Internal.KeyDB
	base := named(validFor(kskzsk(dns.ED25519, dns.ED25519), 30*86400), "base")
	pols := map[string]DnssecPolicy{"base": base}
	withLivePolicies(t, pols)

	h := newReloadHarness(t, kdb, "unresolvedsigns.config.example.", "online-signing")
	zd := h.reload(false, "base", pols)
	if !zd.signsItsOwnContent() {
		t.Fatal("the zone does not sign; the test has lost its point")
	}
	zd = h.reload(true, "gone", pols)
	if !zd.HasError(DnssecError) {
		t.Error("a zone that signs, reloaded to a policy that does not exist, is not in the DNSSEC error state")
	}

	h2 := newReloadHarness(t, kdb, "unresolvedfirst.config.example.")
	zd = h2.reload(false, "gone", pols)
	if !zd.HasError(DnssecError) {
		t.Error("a zone loaded for the first time with a policy that does not exist is not in the DNSSEC error state")
	}
}

// An operator's override is the zone's policy whatever the config names, so a
// reload that takes the config's policy away from a bound zone that does not
// sign does not take its binding away while an override is there to be bound:
// a start binds the override (EffectiveDnssecPolicyName), and so does a reload
// that keeps the config's policy. The binding goes when neither the config nor
// an override names a policy. An override that names a policy that is not
// defined is a name that does not resolve: the binding is kept, with a warning.
func TestAReloadThatRemovesThePolicyKeepsTheOverrideOfABoundZone(t *testing.T) {
	kdb := reloadPolicySetup(t)
	z := loadedWithPolicy(t, kdb, "base")
	if err := SetZonePolicyOverride(kdb, ovZone, "other"); err != nil {
		t.Fatalf("SetZonePolicyOverride: %v", err)
	}
	if err := z.zd.BindPolicyWithoutSigning(); err != nil {
		t.Fatalf("BindPolicyWithoutSigning: %v", err)
	}
	wantPolicyRecord(t, z.zd, "other", "other", "after the bind")
	warned := func() bool {
		z.zd.mu.Lock()
		defer z.zd.mu.Unlock()
		_, w := z.zd.Errors[DnssecPolicyWarning]
		return w
	}

	reloadedWithPolicy(t, z, "")
	wantPolicyRecord(t, z.zd, "other", "other", "after the config's policy was removed, with an override")
	if warned() {
		t.Error("a DNSSEC policy warning on a zone that follows its override")
	}

	if err := SetZonePolicyOverride(kdb, ovZone, "gone"); err != nil {
		t.Fatalf("SetZonePolicyOverride: %v", err)
	}
	reloadedWithPolicy(t, z, "")
	wantPolicyRecord(t, z.zd, "other", "other", "after the config's policy was removed, with an override that does not exist")
	if !warned() {
		t.Error("no DNSSEC policy warning for an override that names a policy that does not exist")
	}

	if err := ClearZonePolicyOverride(kdb, ovZone); err != nil {
		t.Fatalf("ClearZonePolicyOverride: %v", err)
	}
	reloadedWithPolicy(t, z, "")
	wantPolicyRecord(t, z.zd, "", "", "after the config's policy was removed, with no override")
	if warned() {
		t.Error("a DNSSEC policy warning on a zone with no policy at all")
	}
}

// The first load of a zone a reload adds meets the reload's policies, not the
// runtime snapshot's: the snapshot is published after the refreshers are
// queued, so a zone that signs and a policy that the same config defines can
// reach the engine while the snapshot has neither. The zone binds the policy
// its config names and signs under it, and is not quarantined for a policy it
// "does not exist".
func TestAFirstLoadBindsAPolicyThatOnlyTheReloadDefines(t *testing.T) {
	authApp(t)
	kdb := Conf.Internal.KeyDB
	h := newReloadHarness(t, kdb, "firstpols.config.example.", "online-signing")
	const month = 30 * 86400
	base := named(validFor(kskzsk(dns.ED25519, dns.ED25519), month), "base")
	withLivePolicies(t, map[string]DnssecPolicy{}) // the running config has no policies

	zd := h.reload(false, "base", map[string]DnssecPolicy{"base": base})
	if !zd.signsItsOwnContent() {
		t.Fatal("the zone does not sign; the test has lost its point")
	}
	if zd.HasServiceImpactingError() {
		t.Errorf("the zone is quarantined after its first load: %s", zd.ErrorMsg)
	}
	if n, p, w := policyState(zd); n != "base" || p == nil || p.KSKAlgorithm != dns.ED25519 || w {
		t.Errorf("after the first load: %q bound to KSK algorithm %d, warning %v; want %q bound to %d, no warning",
			n, kskAlgOf(p), w, "base", dns.ED25519)
	}
	if len(keytagsOf(servedRRset(t, zd, h.zone, dns.TypeSOA).RRSIGs)) == 0 {
		t.Error("the SOA is unsigned after the first load")
	}
	if name, _, ok, err := GetZoneAppliedPolicy(kdb, h.zone); err != nil || !ok || name != "base" {
		t.Errorf("after the first load the last-applied record is %q %v %v, want base", name, ok, err)
	}
}

// A command-source apply (policy-change, policy-set) cannot land between the
// policy sync's reads and what it does with them. The sync reads the zone's
// last-applied record and bound definition, classifies the change and, for an
// algorithm change nothing can carry, refuses it by putting the applied policy
// back. A command that completed in between had bound and persisted another
// policy, and the refusal then put the pre-command one back in memory while the
// command's override stayed in the keystore: the zone and its keystore
// disagreed until the next restart. The sync holds the zone's policy apply lock
// for that span, so the command waits for it and lands after.
//
// The probe sees the sync at three points: before its first read, once it has
// classified, and just before it refuses. The lock has to be held at each of
// them, which a lock taken after the first read, or let go before the refusal,
// would not be. At the second a command is landed: if the lock is free there,
// the command runs to completion in the probe, as it could; if the sync holds
// it, the command is started and waits.
func TestACommandApplyCannotLandBetweenThePolicySyncsReadAndItsRefusal(t *testing.T) {
	authApp(t)
	kdb := Conf.Internal.KeyDB
	// Registered before the harness, so that it runs after the harness has
	// stopped the engine: the engine reads the probe, and clearing it first
	// would race with a read on a failure.
	t.Cleanup(func() { policySyncProbe = nil })
	h := newReloadHarness(t, kdb, "interleave.config.example.", "online-signing")
	const month = 30 * 86400
	base := named(validFor(kskzsk(dns.ED25519, dns.ED25519), month), "base")
	baseAlg := named(validFor(kskzsk(dns.ECDSAP256SHA256, dns.ECDSAP256SHA256), month), "base") // "base", other algorithms
	cmd := named(validFor(kskzsk(dns.ED25519, dns.ED25519), 2*month), "cmd")                    // the operator's, of the algorithms the zone has keys of
	withLivePolicies(t, map[string]DnssecPolicy{"base": base, "cmd": cmd})

	zd := h.reload(false, "base", map[string]DnssecPolicy{"base": base, "cmd": cmd})
	if !zd.signsItsOwnContent() {
		t.Fatal("the zone does not sign; the test has lost its point")
	}

	// What the probe saw. Written on the engine's goroutine and read here after
	// the reload has been answered, which orders them.
	var seen [3]bool
	var free [3]bool
	var heldBySync bool
	done := make(chan error, 1)
	runCommand := func() error {
		pol := cmd
		_, err := applyZonePolicyTransactional(context.Background(), zd, kdb, &pol, "cmd", PolicyApplySourceCommand)
		return err
	}
	policySyncProbe = func(z *ZoneData, stage policySyncStage) {
		if z != zd || seen[stage] {
			return
		}
		seen[stage] = true
		if z.policyApplyMu.TryLock() { // the sync does not hold it
			z.policyApplyMu.Unlock()
			free[stage] = true
		}
		if stage != policySyncClassified {
			return
		}
		if free[stage] { // the command can land here
			done <- runCommand()
			return
		}
		heldBySync = true
		go func() { done <- runCommand() }()
	}

	// "base" has other algorithms in this reload: refused, and the zone is put
	// back on the definition it has keys of.
	h.reload(true, "base", map[string]DnssecPolicy{"base": baseAlg, "cmd": cmd})
	for stage, name := range map[policySyncStage]string{
		policySyncRead:       "before its first read",
		policySyncClassified: "once it has classified",
		policySyncActing:     "just before it refuses",
	} {
		if !seen[stage] {
			t.Fatalf("the policy sync did not get as far as %s; the test has lost its point", name)
		}
		if free[stage] {
			t.Errorf("the policy sync does not hold the zone's policy apply lock %s", name)
		}
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the command's apply: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the command's apply did not finish")
	}

	if !heldBySync {
		t.Error("a command's apply completed between the policy sync's reads and its refusal")
	}
	override, ok, err := GetZonePolicyOverride(kdb, h.zone)
	if err != nil || !ok || override != "cmd" {
		t.Fatalf("the persisted override is %q %v %v, want cmd", override, ok, err)
	}
	if applied, _, ok, err := GetZoneAppliedPolicy(kdb, h.zone); err != nil || !ok || applied != "cmd" {
		t.Errorf("the persisted last-applied record is %q %v %v, want cmd", applied, ok, err)
	}
	if n, p, _ := policyState(zd); n != override || p == nil || p.SigValidity.Default != 2*month {
		t.Errorf("the zone is bound to %q (signature validity %d) and its keystore says %q: memory and keystore disagree",
			n, validityOf(p), override)
	}
}

// The first load that adopts a persisted copy meets the reload's policies too.
// A secondary that signs, whose primary is down at its first bind, serves the
// copy it persisted, and initialLoadZone binds its policy there, on the failed
// refresh's way out. That is the same first load as any other: the refresher a
// reload queued carries the policies the config defines, the snapshot may not
// hold them yet, and a zone quarantined for a policy that "does not exist" is
// the wrong answer for a config that names a valid one.
func TestAFirstLoadThatAdoptsAPersistedCopyBindsAPolicyThatOnlyTheReloadDefines(t *testing.T) {
	kdb := newTestKeyDB(t)
	conf, dir := persistentConf(t, kdb)
	kdb = Conf.Internal.KeyDB // the one the signing paths of the daemon-wide config use
	conf.Internal.KeyDB = kdb
	conf.Internal.RefreshZoneCh = make(chan ZoneRefresher, 1)
	conf.Internal.BumpZoneCh = make(chan BumperData, 1)
	if err := os.WriteFile(filepath.Join(dir, "example.zone"), []byte(s2Zone), 0644); err != nil {
		t.Fatalf("write zone file: %v", err)
	}
	const month = 30 * 86400
	base := named(validFor(kskzsk(dns.ED25519, dns.ED25519), month), "base")
	withLivePolicies(t, map[string]DnssecPolicy{}) // the running config has no policies
	t.Cleanup(func() {
		if z, ok := Zones.Get("example."); ok {
			z.stopPublisher()
		}
		Zones.Remove("example.")
	})
	runRefreshEngine(t, conf)

	conf.Internal.RefreshZoneCh <- ZoneRefresher{
		Name:           "example.",
		ZoneType:       Secondary,
		ZoneStore:      MapZone,
		Primaries:      []PeerConf{{Addr: "127.0.0.1:1"}}, // nothing listening
		ConfigUpdate:   true,
		Options:        map[ZoneOption]bool{OptApiManagedZone: true, OptInlineSigning: true},
		DnssecPolicy:   "base",
		DnssecPolicies: map[string]DnssecPolicy{"base": base},
	}

	// The copy is adopted and the policy bound inside the refresh; the engine
	// records the failed transfer after that, last.
	deadline := time.Now().Add(10 * time.Second)
	var zd *ZoneData
	for time.Now().Before(deadline) {
		if z, ok := Zones.Get("example."); ok && z.HasError(RefreshError) {
			zd = z
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if zd == nil {
		t.Fatal("the zone never recorded the failed transfer")
	}
	if !zd.signsItsOwnContent() {
		t.Fatal("the zone does not sign; the test has lost its point")
	}
	if zd.publishedSnapshot() == nil {
		t.Fatal("the persisted copy was not adopted; the test has lost its point")
	}
	if zd.HasError(DnssecError) {
		zd.mu.Lock()
		msg := zd.Errors[DnssecError].Msg
		zd.mu.Unlock()
		t.Errorf("the zone is quarantined after adopting its persisted copy: %s", msg)
	}
	if n, p, _ := policyState(zd); n != "base" || p == nil || p.KSKAlgorithm != dns.ED25519 {
		t.Errorf("after the first load: %q bound to KSK algorithm %d; want %q bound to %d", n, kskAlgOf(p), "base", dns.ED25519)
	}
	if len(keytagsOf(servedRRset(t, zd, "example.", dns.TypeSOA).RRSIGs)) == 0 {
		t.Error("the SOA is unsigned after the first load")
	}
	if name, _, ok, err := GetZoneAppliedPolicy(kdb, "example."); err != nil || !ok || name != "base" {
		t.Errorf("after the first load the last-applied record is %q %v %v, want base", name, ok, err)
	}
}

// The first load of a zone that a reload reaches while its first load is still
// pending takes the policy name from that reload's config, not from the first
// attempt's. A secondary whose transfer fails has no copy to adopt the first
// time; the reload, which drops that policy and names another, comes after a
// copy has been persisted, and the retry adopts it. The name the first attempt
// stored is not in the reload's policies, and the zone would be quarantined for
// a policy "that does not exist" with the adopted copy neither bound nor
// signed. The ticker's retries carry no refresher and go on with the stored
// name, so the reload's name is stored too.
func TestAFirstLoadStillPendingTakesThePolicyOfTheReloadThatReachesIt(t *testing.T) {
	kdb := newTestKeyDB(t)
	conf, dir := persistentConf(t, kdb)
	kdb = Conf.Internal.KeyDB
	conf.Internal.KeyDB = kdb
	conf.Internal.RefreshZoneCh = make(chan ZoneRefresher, 2)
	conf.Internal.BumpZoneCh = make(chan BumperData, 1)
	const month = 30 * 86400
	oldPol := named(validFor(kskzsk(dns.ED25519, dns.ED25519), month), "old")
	newPol := named(validFor(kskzsk(dns.ED25519, dns.ED25519), 2*month), "new")
	withLivePolicies(t, map[string]DnssecPolicy{}) // the running config has neither
	t.Cleanup(func() {
		if z, ok := Zones.Get("example."); ok {
			z.stopPublisher()
		}
		Zones.Remove("example.")
	})
	runRefreshEngine(t, conf)

	refresher := func(policy string, pols map[string]DnssecPolicy) ZoneRefresher {
		return ZoneRefresher{
			Name:           "example.",
			ZoneType:       Secondary,
			ZoneStore:      MapZone,
			Primaries:      []PeerConf{{Addr: "127.0.0.1:1"}}, // nothing listening
			ConfigUpdate:   true,
			Options:        map[ZoneOption]bool{OptApiManagedZone: true, OptInlineSigning: true},
			DnssecPolicy:   policy,
			DnssecPolicies: pols,
		}
	}
	// send is a refresher for the zone as it is waiting for its first load,
	// which the engine answers when its load fails.
	send := func(policy string, pols map[string]DnssecPolicy) RefresherResponse {
		t.Helper()
		zr := refresher(policy, pols)
		zr.Wait, zr.Response = true, make(chan RefresherResponse, 1)
		conf.Internal.RefreshZoneCh <- zr
		select {
		case resp := <-zr.Response:
			return resp
		case <-time.After(10 * time.Second):
			t.Fatal("the refresher was not answered")
		}
		return RefresherResponse{}
	}

	// The first load, with no copy on disk and no primary: nothing is adopted,
	// nothing is bound, and the name "old" is what the zone has stored. The
	// engine does not answer the load of a zone it creates; the failure is the
	// sign that it is through.
	conf.Internal.RefreshZoneCh <- refresher("old", map[string]DnssecPolicy{"old": oldPol})
	var zd *ZoneData
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if z, ok := Zones.Get("example."); ok && z.HasError(RefreshError) {
			zd = z
			break
		}
	}
	if zd == nil || !zd.FirstZoneLoad || zd.publishedSnapshot() != nil {
		t.Fatal("the zone is not waiting for its first load; the test has lost its point")
	}

	// A copy is persisted, and a reload names "new" and no longer defines "old".
	if err := os.WriteFile(filepath.Join(dir, "example.zone"), []byte(s2Zone), 0644); err != nil {
		t.Fatalf("write zone file: %v", err)
	}
	if resp := send("new", map[string]DnssecPolicy{"new": newPol}); !resp.Error {
		t.Fatal("the transfer succeeded; the test has lost its point")
	}

	if zd.publishedSnapshot() == nil {
		t.Fatal("the persisted copy was not adopted; the test has lost its point")
	}
	if zd.HasError(DnssecError) {
		zd.mu.Lock()
		msg := zd.Errors[DnssecError].Msg
		zd.mu.Unlock()
		t.Errorf("the zone is quarantined after adopting its persisted copy: %s", msg)
	}
	if n, p, _ := policyState(zd); n != "new" || p == nil || p.SigValidity.Default != 2*month {
		t.Errorf("after the first load: %q bound with signature validity %d; want %q bound to the reload's definition", n, validityOf(p), "new")
	}
	if len(keytagsOf(servedRRset(t, zd, "example.", dns.TypeSOA).RRSIGs)) == 0 {
		t.Error("the SOA is unsigned after the first load")
	}
}

// A reload that does not parse queues no refreshers. ParseZones used to queue
// each zone's refresher as the zone was parsed, so when a later zone failed its
// validation the earlier zones' refreshers were still queued, and the engine
// went on to apply the policy of a config that the reload had rejected. That is
// all this holds: the parse of the zones before the failing one has already
// changed what the live zones hold (a zone file path, say), and a failed parse
// does not undo it.
func TestAReloadThatDoesNotParseQueuesNoRefreshers(t *testing.T) {
	authApp(t)
	dir := t.TempDir()
	zoneFile := func(name string) string {
		file := filepath.Join(dir, name+"zone")
		body := name + "\t3600\tIN\tSOA\tns1." + name + " hostmaster." + name + " 1 7200 1800 604800 7200\n" +
			name + "\t3600\tIN\tNS\tns1." + name + "\n" +
			"ns1." + name + "\t3600\tIN\tA\t192.0.2.53\n"
		if err := os.WriteFile(file, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return file
	}
	const a, b = "parsefirst.config.example.", "parselater.config.example."
	t.Cleanup(func() {
		for _, name := range []string{a, b} {
			if zd, ok := Zones.Get(name); ok {
				zd.stopPublisher()
			}
			Zones.Remove(name)
		}
	})
	conf := &Config{}
	conf.Internal.KeyDB = Conf.Internal.KeyDB
	conf.Internal.RefreshZoneCh = make(chan ZoneRefresher, 10)
	conf.Internal.BumpZoneCh = make(chan BumperData, 1)
	conf.Internal.DnssecPolicies = map[string]DnssecPolicy{"base": named(kskzsk(dns.ED25519, dns.ED25519), "base")}
	conf.Zones = []ZoneConf{
		{Name: a, Type: "primary", Store: "map", Zonefile: zoneFile(a), DnssecPolicy: "base"},
		// The second does not validate: transfer-src is an address.
		{Name: b, Type: "primary", Store: "map", Zonefile: zoneFile(b), DnssecPolicy: "base", TransferSrc: []string{"not-an-address"}},
	}

	if _, _, err := conf.ParseZones(context.Background(), true); err == nil {
		t.Fatal("ParseZones accepted a zone that does not validate; the test has lost its point")
	}
	if n := len(conf.Internal.RefreshZoneCh); n != 0 {
		t.Errorf("%d refresher(s) queued by a reload that did not parse, want none", n)
	}

	// The same reload with the zone corrected queues both, after the parse.
	conf.Zones[1].TransferSrc = nil
	if _, _, err := conf.ParseZones(context.Background(), true); err != nil {
		t.Fatalf("ParseZones: %v", err)
	}
	if n := len(conf.Internal.RefreshZoneCh); n != 2 {
		t.Errorf("%d refresher(s) queued by a reload that parsed, want 2", n)
	}
}

// A reload hands its refreshers to the engine only after it has published its
// runtime-config snapshot. The engine reads the snapshot for the policies, the
// multi-signer config and the refresh limits it applies a refresher with, so a
// refresher that arrives first is applied against the previous config: a zone
// that starts signing between a reload's record of its policy and the reload's
// publish signs under the definition the config no longer has, and persists its
// name as applied.
//
// The refreshers go to a channel the test reads, which is unbuffered: a send
// completes when the test takes it, so the reload is still in the middle of
// whatever it does around the send while the test looks. The second zone's
// refresher is left unsent while the test looks at the first. What the test
// compares is the snapshot as the reload's own goroutine finds it just before it
// sends the first refresher, which does not depend on when the test gets to look.
func TestAReloadHandsItsRefreshersToTheEngineOnlyAfterPublishingItsSnapshot(t *testing.T) {
	authApp(t)
	kdb := Conf.Internal.KeyDB
	// Registered before the harness, so that it runs after the engine has stopped.
	t.Cleanup(func() { zoneRefresherSendProbe = nil })
	const month = 30 * 86400
	oldBase := named(validFor(kskzsk(dns.ED25519, dns.ED25519), month), "base")
	h := newReloadHarness(t, kdb, "ordering.config.example.")
	withLivePolicies(t, map[string]DnssecPolicy{"base": oldBase})
	prevSync := delegationSyncConf.Load()
	t.Cleanup(func() { delegationSyncConf.Store(prevSync) })

	zd := h.reload(false, "base", map[string]DnssecPolicy{"base": oldBase})
	if zd.signsItsOwnContent() {
		t.Fatal("the zone signs; the test has lost its point")
	}

	const second = "orderingsecond.config.example."
	secondFile := filepath.Join(t.TempDir(), "zone")
	body := second + "\t3600\tIN\tSOA\tns1." + second + " hostmaster." + second + " 1 7200 1800 604800 7200\n" +
		second + "\t3600\tIN\tNS\tns1." + second + "\n" + "ns1." + second + "\t3600\tIN\tA\t192.0.2.53\n"
	if err := os.WriteFile(secondFile, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if z, ok := Zones.Get(second); ok {
			z.stopPublisher()
		}
		Zones.Remove(second)
	})

	conf := &Config{}
	conf.Internal.KeyDB = kdb
	conf.Internal.RefreshZoneCh = make(chan ZoneRefresher)
	conf.Internal.BumpZoneCh = make(chan BumperData, 1)
	// The reload re-parses the policies from this, and "base" is edited in it.
	edited := DnssecPolicyConf{Algorithm: "ECDSAP256SHA256"}
	edited.KSK.Lifetime, edited.ZSK.Lifetime, edited.CSK.Lifetime = "forever", "forever", "none"
	edited.SigValidity = DnssecPolicySigValidityConf{Default: "30d", Dnskey: "30d", Ds: "30d"}
	conf.Dnssec.Policies = map[string]DnssecPolicyConf{"base": edited}
	conf.Zones = []ZoneConf{
		{Name: h.zone, Type: "primary", Store: "map", Zonefile: h.file, DnssecPolicy: "base"},
		{Name: second, Type: "primary", Store: "map", Zonefile: secondFile, DnssecPolicy: "base"},
	}
	// The policy "base" as the live snapshot has it just before the first send,
	// taken on the reload's goroutine; the channel send orders it before the
	// test's read.
	var atFirstSend uint8
	var probed bool
	zoneRefresherSendProbe = func(zr ZoneRefresher) {
		if probed {
			return
		}
		probed = true
		atFirstSend = ConfLive().DnssecPolicies["base"].KSKAlgorithm
	}
	reloaded := make(chan error, 1)
	go func() {
		_, err := conf.ReloadZoneConfig(context.Background())
		reloaded <- err
	}()
	// Whatever happens, the reload is let go of, so that it does not hang the
	// run on a failure above.
	finish := func() {
		for {
			select {
			case <-conf.Internal.RefreshZoneCh:
			case err := <-reloaded:
				if err != nil {
					t.Errorf("ReloadZoneConfig: %v", err)
				}
				return
			case <-time.After(10 * time.Second):
				t.Error("the reload did not finish")
				return
			}
		}
	}
	defer finish()

	var zr ZoneRefresher
	select {
	case zr = <-conf.Internal.RefreshZoneCh:
	case <-time.After(10 * time.Second):
		t.Fatal("the reload queued no refresher")
	}
	if zr.Name != h.zone {
		t.Fatalf("the first refresher is for %q, want %q; the test has lost its point", zr.Name, h.zone)
	}

	// The refresher is in the test's hands, the reload not through yet.
	if atFirstSend != dns.ECDSAP256SHA256 {
		t.Errorf("the reload handed the engine a refresher before it had published its snapshot: policy \"base\" had KSK algorithm %d when the first was sent, the reload's is %d",
			atFirstSend, dns.ECDSAP256SHA256)
	}

	// The engine takes it, and the zone starts signing at once: under the
	// definition the config has now.
	h.answered(zr)
	if err := zd.StartSigning(context.Background(), 0); err != nil {
		t.Fatalf("StartSigning: %v", err)
	}
	sigs := servedRRset(t, zd, h.zone, dns.TypeSOA).RRSIGs
	if len(sigs) == 0 {
		t.Error("the SOA is unsigned after the start")
	}
	for _, rr := range sigs {
		if sig, ok := rr.(*dns.RRSIG); ok && sig.Algorithm != dns.ECDSAP256SHA256 {
			t.Errorf("the SOA is signed with algorithm %d, want the reload's definition's %d", sig.Algorithm, dns.ECDSAP256SHA256)
		}
	}
}

// A policy warning recorded for a zone that a reload has since removed does not
// put the zone back. The engine holds the zone it was handed; the reload removes
// it from the registry, and a write to the removed zone's error state went
// through setErrorLocked and clearErrorLocked, which end by registering the zone
// they were called on.
func TestAReloadsRecordOfAZoneThatWasRemovedDoesNotRegisterItAgain(t *testing.T) {
	kdb := reloadPolicySetup(t)
	z := loadedWithPolicy(t, kdb, "base")
	if err := z.zd.BindPolicyWithoutSigning(); err != nil {
		t.Fatalf("BindPolicyWithoutSigning: %v", err)
	}
	zd := z.zd
	Zones.Remove(ovZone) // the reload removes it; the engine still holds zd

	for _, step := range []struct{ name, what string }{
		{"gone", "a policy that cannot be bound (a warning)"},
		{"base", "the bound policy again (the warning cleared)"},
		{"other", "another policy that exists"},
		{"", "no policy (the binding removed)"},
	} {
		if !zd.recordPolicyOfNonSigningZone(step.name, nil) {
			t.Fatalf("%s: the zone was not handled", step.what)
		}
		if _, registered := Zones.Get(ovZone); registered {
			t.Errorf("%s: the zone that was removed is registered again", step.what)
			Zones.Remove(ovZone)
		}
	}
}

// After a reload has published its snapshot, the engine receives the refresher of
// every zone the reload kept, whatever its caller's context does. The reload-zones
// API handler passes the request's context, so a client that goes away in the
// middle of a reload cancels it; the refreshers not yet sent were dropped with the
// context, and the zones behind them kept the settings of the previous config (a
// downstream ACL the reload had removed, say, stays in force, because a ticker's
// refresh reuses the zone and does not read the config).
func TestAReloadDeliversEveryRefresherAfterItPublishedWhateverItsCallersContextDoes(t *testing.T) {
	authApp(t)
	kdb := Conf.Internal.KeyDB
	withLivePolicies(t, map[string]DnssecPolicy{}) // restores the snapshot the reload publishes
	prevSync := delegationSyncConf.Load()
	t.Cleanup(func() { delegationSyncConf.Store(prevSync) })

	dir := t.TempDir()
	names := []string{"cancelfirst.config.example.", "cancelsecond.config.example."}
	var zones []ZoneConf
	for _, name := range names {
		file := filepath.Join(dir, name+"zone")
		body := name + "\t3600\tIN\tSOA\tns1." + name + " hostmaster." + name + " 1 7200 1800 604800 7200\n" +
			name + "\t3600\tIN\tNS\tns1." + name + "\n" + "ns1." + name + "\t3600\tIN\tA\t192.0.2.53\n"
		if err := os.WriteFile(file, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		zones = append(zones, ZoneConf{Name: name, Type: "primary", Store: "map", Zonefile: file})
	}
	t.Cleanup(func() {
		for _, name := range names {
			if z, ok := Zones.Get(name); ok {
				z.stopPublisher()
			}
			Zones.Remove(name)
		}
	})

	conf := &Config{}
	conf.Internal.KeyDB = kdb
	conf.Internal.RefreshZoneCh = make(chan ZoneRefresher) // a send completes when the test takes it
	conf.Internal.BumpZoneCh = make(chan BumperData, 1)
	conf.Zones = zones

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reloaded := make(chan error, 1)
	go func() {
		_, err := conf.ReloadZoneConfig(ctx)
		reloaded <- err
	}()
	// The reload is let go of whatever happens below, so that it does not hang
	// the run; unless it has ended already.
	ended := false
	defer func() {
		for !ended {
			select {
			case <-conf.Internal.RefreshZoneCh:
			case <-reloaded:
				return
			case <-time.After(10 * time.Second):
				return
			}
		}
	}()

	var first ZoneRefresher
	select {
	case first = <-conf.Internal.RefreshZoneCh:
	case <-time.After(10 * time.Second):
		t.Fatal("the reload queued no refresher")
	}
	if first.Name != names[0] {
		t.Fatalf("the first refresher is for %q, want %q; the test has lost its point", first.Name, names[0])
	}

	// The reload has published, and is blocked on the second refresher. The caller
	// goes away.
	cancel()

	select {
	case second := <-conf.Internal.RefreshZoneCh:
		if second.Name != names[1] {
			t.Errorf("the second refresher is for %q, want %q", second.Name, names[1])
		}
	case err := <-reloaded:
		ended = true
		t.Fatalf("the reload ended (%v) without sending the refresher of its second zone after its caller's context was cancelled", err)
	case <-time.After(10 * time.Second):
		t.Fatal("the second refresher was not sent")
	}
	select {
	case err := <-reloaded:
		ended = true
		if err != nil {
			t.Errorf("ReloadZoneConfig: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the reload did not finish")
	}
}

// A refresher that a reload queued for a zone, which a later reload then removed,
// does not make the zone again. ParseZones registers every zone it queues a
// refresher for, so the engine finds it; when it does not, the zone was removed
// in between, and the refresher is the config of a zone that is no longer in the
// config, with the policies of a reload that has been superseded. Creating the
// zone from it registered the removed zone again and ran its first load.
func TestARefresherForAZoneRemovedByALaterReloadCreatesNoZone(t *testing.T) {
	authApp(t)
	kdb := Conf.Internal.KeyDB
	h := newReloadHarness(t, kdb, "removedmeanwhile.config.example.")
	base := named(validFor(kskzsk(dns.ED25519, dns.ED25519), 30*86400), "base")
	withLivePolicies(t, map[string]DnssecPolicy{"base": base})

	// A reload's parse: the zone is registered and its refresher is queued.
	h.conf.Internal.DnssecPolicies = map[string]DnssecPolicy{"base": base}
	h.conf.Zones = []ZoneConf{{Name: h.zone, Type: "primary", Store: "map", Zonefile: h.file, DnssecPolicy: "base"}}
	if _, _, err := h.conf.ParseZones(context.Background(), false); err != nil {
		t.Fatalf("ParseZones: %v", err)
	}
	zr := <-h.parsed
	zd, ok := Zones.Get(h.zone)
	if !ok {
		t.Fatal("the parse did not register the zone; the test has lost its point")
	}

	// A later reload removes the zone before the engine gets to the refresher.
	zd.stopPublisher()
	Zones.Remove(h.zone)
	zd.generation.Add(1)

	// The engine takes the refresher; a marker behind it, for a name no refresher
	// builds a zone for, is answered when the engine is through with it.
	h.engineConf.Internal.RefreshZoneCh <- zr
	marker := ZoneRefresher{Name: "marker.config.example.", Wait: true, Response: make(chan RefresherResponse, 1)}
	h.engineConf.Internal.RefreshZoneCh <- marker
	select {
	case <-marker.Response:
	case <-time.After(10 * time.Second):
		t.Fatal("the engine did not get through the refresher")
	}

	if created, registered := Zones.Get(h.zone); registered {
		created.stopPublisher()
		t.Error("the zone a later reload removed is registered again by the refresher of an earlier one")
	}
}

// A reload that adds a zone's first policy is recorded for a zone whose content
// the engine refuses to reload, too. The refusal is for a Primary with changes only
// memory holds (the delta journal is not recording them); the policy record
// changes no content, and without it a zone left naming no policy cannot start
// signing until a reload is accepted or the daemon restarts.
func TestAReloadTheContentGuardRefusesStillRecordsThePolicyOfAZoneThatDoesNotSign(t *testing.T) {
	authApp(t)
	kdb := Conf.Internal.KeyDB
	h := newReloadHarness(t, kdb, "guarded.config.example.")
	base := named(kskzsk(dns.ED25519, dns.ED25519), "base")
	pols := map[string]DnssecPolicy{"base": base}
	withLivePolicies(t, pols)

	zd := h.reload(false, "", pols) // loaded, no policy
	if n, _, _ := policyState(zd); n != "" {
		t.Fatalf("the zone records %q; the test has lost its point", n)
	}
	// Changes only memory holds: dirty, with no keystore to journal them.
	zd.SetOption(OptDirty, true)
	zd.mu.Lock()
	zd.KeyDB = nil
	zd.mu.Unlock()

	zr := ZoneRefresher{
		Name: h.zone, ZoneType: Primary, ZoneStore: MapZone, Zonefile: h.file, ConfigUpdate: true,
		DnssecPolicy: "base", DnssecPolicies: pols,
		Wait: true, Response: make(chan RefresherResponse, 1),
	}
	h.engineConf.Internal.RefreshZoneCh <- zr
	var resp RefresherResponse
	select {
	case resp = <-zr.Response:
	case <-time.After(10 * time.Second):
		t.Fatal("the engine did not answer")
	}

	if !strings.Contains(resp.Msg, "changes that only memory holds") {
		t.Errorf("the reload was not refused for its content: %q; the test has lost its point", resp.Msg)
	}
	if n, _, _ := policyState(zd); n != "base" {
		t.Errorf("the zone records %q after a reload that named %q and was refused for its content", n, "base")
	}
}

// What a refresher that ParseZones queued may assume about the zone it meets
// (the ordering invariant is written out where the engine enforces it, at the
// head of RefreshEngine's dispatch), one test per row:
//
//	absent                     no zone is created: TestARefresherForAZoneRemovedByALaterReloadCreatesNoZone
//	present, same registration the refresher is applied: every reload test that goes through ParseZones, and the last step here
//	present, newer registration the refresher is dropped, and the newer registration's own refresher
//	                           applies the config that registered it: this test
//
// The newer registration is the case of three reloads while a refresher waits in
// the queue. Reload A adds a signing zone; B removes it; C adds the same name with
// other algorithms; A's refresher is still queued, because queueing does not wait
// for the engine, and the engine dequeues it when the name is registered again. It
// took the zone as it found it, merged A's config into C's zone and bound A's
// policy to it, which signed the zone under A's algorithms; C's own refresher was
// then classified against the applied record and refused as an incompatible
// algorithm change, with A's binding kept.
func TestASupersededRefresherDoesNotBindItsPolicyToAZoneRegisteredAgain(t *testing.T) {
	authApp(t)
	kdb := Conf.Internal.KeyDB
	h := newReloadHarness(t, kdb, "superseded.config.example.", "online-signing")
	const month = 30 * 86400
	polA := map[string]DnssecPolicy{"base": named(validFor(kskzsk(dns.ED25519, dns.ED25519), month), "base")}
	polC := map[string]DnssecPolicy{"base": named(validFor(kskzsk(dns.ECDSAP256SHA256, dns.ECDSAP256SHA256), month), "base")}
	polD := map[string]DnssecPolicy{"base": named(validFor(kskzsk(dns.ECDSAP256SHA256, dns.ECDSAP256SHA256), 2*month), "base")}
	withLivePolicies(t, map[string]DnssecPolicy{}) // the running config has none of them

	// A reload's parse: the zone is registered and its refresher is queued.
	parse := func(pols map[string]DnssecPolicy) (ZoneRefresher, *ZoneData) {
		t.Helper()
		h.conf.Internal.DnssecPolicies = pols
		h.conf.Zones = []ZoneConf{{Name: h.zone, Type: "primary", Store: "map", Zonefile: h.file, DnssecPolicy: "base", OptionsStrs: h.options}}
		if _, _, err := h.conf.ParseZones(context.Background(), false); err != nil {
			t.Fatalf("ParseZones: %v", err)
		}
		zr := <-h.parsed
		zd, ok := Zones.Get(h.zone)
		if !ok {
			t.Fatal("the parse did not register the zone")
		}
		return zr, zd
	}
	zrA, zdA := parse(polA)

	// Reload B removes the zone, as a reload does.
	zdA.stopPublisher()
	Zones.Remove(h.zone)
	zdA.generation.Add(1)

	// Reload C registers the name again, with other algorithms.
	zrC, zdC := parse(polC)
	if zdC == zdA {
		t.Fatal("the zone was not registered again; the test has lost its point")
	}

	// A's refresher reaches the engine first, then C's. The load of a zone that
	// is not loaded yet is not answered, so a refresh behind them is, and the engine
	// takes them in order.
	h.engineConf.Internal.RefreshZoneCh <- zrA
	h.engineConf.Internal.RefreshZoneCh <- zrC
	h.answered(ZoneRefresher{Name: h.zone, ZoneStore: MapZone})

	if cur, ok := Zones.Get(h.zone); !ok || cur != zdC {
		t.Fatal("the zone C registered is not the one registered")
	}
	if zdC.HasServiceImpactingError() {
		t.Errorf("the zone is in an error state: %s", zdC.ErrorMsg)
	}
	if n, p, _ := policyState(zdC); n != "base" || p == nil || p.KSKAlgorithm != dns.ECDSAP256SHA256 {
		t.Errorf("the zone C registered records %q bound to KSK algorithm %d; want %q bound to C's %d, not A's %d",
			n, kskAlgOf(p), "base", dns.ECDSAP256SHA256, dns.ED25519)
	}
	sigs := servedRRset(t, zdC, h.zone, dns.TypeSOA).RRSIGs
	if len(sigs) == 0 {
		t.Error("the SOA is unsigned")
	}
	for _, rr := range sigs {
		if sig, ok := rr.(*dns.RRSIG); ok && sig.Algorithm != dns.ECDSAP256SHA256 {
			t.Errorf("the SOA is signed with algorithm %d, want C's %d", sig.Algorithm, dns.ECDSAP256SHA256)
		}
	}

	// The same registration's later reload is applied: the row that must go on
	// working.
	zd := h.reload(true, "base", polD)
	if zd != zdC {
		t.Fatal("a reload of the same registration reached another zone")
	}
	if n, p, w := policyState(zd); n != "base" || p == nil || p.SigValidity.Default != 2*month || w {
		t.Errorf("a later reload of the same registration: the zone records %q bound with signature validity %d, warning %v; want %q bound with %d",
			n, validityOf(p), w, "base", 2*month)
	}
}

// Two zones are added by one reload and one of them is removed by the next while
// the engine is in the middle of the first load of the zone that goes, as the rig's
// L1 case has it (150 zones added, the second half removed by a reload that starts a
// moment later). The engine holds the zone it dequeued, and what it goes on to do
// to it writes the zone's error state (the policy apply's signature-validity check
// clears DnssecError, for one), which ended with Zones.Set and registered the removed
// zone again, signed and served, with nothing in the config that names it.
//
// The probe holds the engine inside that first load until the second reload has run,
// which is what the queue's backlog does in the rig. The reload goes through
// ReloadZoneConfig, as the rig's does.
func TestAZoneARealReloadRemovedWhileItsFirstLoadWasInFlightIsNotRegisteredAgain(t *testing.T) {
	authApp(t)
	kdb := Conf.Internal.KeyDB
	// Registered before the harness, so that it runs after the engine has stopped.
	t.Cleanup(func() { policySyncProbe = nil })
	h := newReloadHarness(t, kdb, "inflightkept.config.example.")
	withLivePolicies(t, map[string]DnssecPolicy{})
	prevSync := delegationSyncConf.Load()
	t.Cleanup(func() { delegationSyncConf.Store(prevSync) })

	const gone = "inflightgone.config.example."
	goneFile := filepath.Join(t.TempDir(), "zone")
	body := gone + "\t3600\tIN\tSOA\tns1." + gone + " hostmaster." + gone + " 1 7200 1800 604800 7200\n" +
		gone + "\t3600\tIN\tNS\tns1." + gone + "\n" + "ns1." + gone + "\t3600\tIN\tA\t192.0.2.53\n"
	if err := os.WriteFile(goneFile, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if z, ok := Zones.Get(gone); ok {
			z.stopPublisher()
		}
		Zones.Remove(gone)
	})

	conf := &Config{}
	conf.Internal.KeyDB = kdb
	conf.Internal.RefreshZoneCh = h.engineConf.Internal.RefreshZoneCh // the harness's engine
	conf.Internal.BumpZoneCh = make(chan BumperData, 1)
	pol := DnssecPolicyConf{Algorithm: "ED25519"}
	pol.KSK.Lifetime, pol.ZSK.Lifetime, pol.CSK.Lifetime = "forever", "forever", "none"
	pol.SigValidity = DnssecPolicySigValidityConf{Default: "30d", Dnskey: "30d", Ds: "30d"}
	conf.Dnssec.Policies = map[string]DnssecPolicyConf{"base": pol}
	kept := ZoneConf{Name: h.zone, Type: "primary", Store: "map", Zonefile: h.file, DnssecPolicy: "base", OptionsStrs: []string{"online-signing"}}
	leaving := ZoneConf{Name: gone, Type: "primary", Store: "map", Zonefile: goneFile, DnssecPolicy: "base", OptionsStrs: []string{"online-signing"}}

	// The engine is held inside the first load of the zone that goes, until released.
	// The release is deferred, once, before the first reload starts, so that a failure
	// below does not leave the engine held in the probe, where it cannot answer the
	// shutdown the cleanup asks of it.
	inFlight, release := make(chan struct{}), make(chan struct{})
	var once, releaseOnce sync.Once
	closeRelease := func() { releaseOnce.Do(func() { close(release) }) }
	defer closeRelease()
	policySyncProbe = func(z *ZoneData, stage policySyncStage) {
		if z.ZoneName != gone || stage != policySyncRead {
			return
		}
		once.Do(func() {
			close(inFlight)
			<-release
		})
	}

	conf.Zones = []ZoneConf{kept, leaving}
	if _, err := conf.ReloadZoneConfig(context.Background()); err != nil {
		t.Fatalf("the reload that adds the zones: %v", err)
	}
	select {
	case <-inFlight:
	case <-time.After(10 * time.Second):
		t.Fatal("the engine did not reach the first load of the second zone")
	}
	goneZd, ok := Zones.Get(gone)
	if !ok {
		t.Fatal("the zone is not registered while its first load is in flight; the test has lost its point")
	}

	// The next reload no longer has the zone: it removes it while the engine is in it.
	conf.Zones = []ZoneConf{kept}
	if _, err := conf.ReloadZoneConfig(context.Background()); err != nil {
		t.Fatalf("the reload that removes the zone: %v", err)
	}
	if _, still := Zones.Get(gone); still {
		t.Fatal("the reload did not remove the zone; the test has lost its point")
	}

	// The engine goes on with the first load of the zone it holds. A marker behind
	// it, for a name no refresher builds a zone for, is answered when the engine is
	// through with the zone and with the kept zone's refresher that the second reload
	// queued. (Not a refresh of the kept zone: the engine reads the zone's fields as
	// it dispatches one, while the refresh that the second reload's refresher started
	// is still writing them.)
	closeRelease()
	marker := ZoneRefresher{Name: "marker.config.example.", Wait: true, Response: make(chan RefresherResponse, 1)}
	h.engineConf.Internal.RefreshZoneCh <- marker
	select {
	case <-marker.Response:
	case <-time.After(10 * time.Second):
		t.Fatal("the engine did not get through the first load")
	}

	if z, registered := Zones.Get(gone); registered {
		z.stopPublisher()
		t.Errorf("the zone a reload removed while its first load was in flight is registered again")
	}
	if goneZd.generation.Load() == 0 {
		t.Error("the removal did not mark the zone it removed")
	}
	if _, ok := Zones.Get(h.zone); !ok {
		t.Error("the kept zone is not registered")
	}
}

// The writers of a zone's state, and what each does to a ZoneData that something
// still holds after it left Zones -- written out where the engine enforces the
// ordering invariant (RefreshEngine's dispatch), one test per row that is not the
// engine's own:
//
//	the engine's merge, sync and first load   they go on, on the zone it dequeued: it is detached, and nothing
//	                                          they write registers it (TestAZoneARealReloadRemoved...)
//	SetError, ClearError, SetStatus and the   write the zone's own state and nothing in Zones (this test)
//	*Locked forms
//	recordPolicyOfNonSigningZone              writes no registry entry at all (TestAReloadsRecordOfAZoneThat...)
//	the resigner                              walks the live registry: a removed zone is not renewed
//	the engine, for a refresher queued        creates no zone, or drops it (the two tests above)
//	before the removal
//
// The zone the writers hold is a stale pointer in three ways: it was removed and
// marked (the reload's removal bumps its generation), it was removed by a path that
// does not mark it (a catalog's, a rollback's), or another registration took its
// name. None of them may put it into Zones, or over the registration that replaced
// it. A zone that was never registered is not registered by a write either: the
// creation paths register it themselves.
func TestTheStateWritersOfAZoneARealReloadRemovedDoNotRegisterItAgain(t *testing.T) {
	authApp(t)
	writers := func(zd *ZoneData) []struct {
		what string
		do   func()
	} {
		return []struct {
			what string
			do   func()
		}{
			{"SetError", func() { zd.SetError(DnssecPolicyWarning, "a warning") }},
			{"ClearError", func() { zd.ClearError(DnssecPolicyWarning) }},
			{"SetError (a service-impacting category)", func() { zd.SetError(DnssecError, "an error") }},
			{"ClearError (every category)", func() { zd.ClearError(NoError) }},
			{"SetStatus", func() { zd.SetStatus(ZoneStatusReady) }},
			{"the signature-validity check", func() {
				zd.mu.Lock()
				zd.Options = map[ZoneOption]bool{OptOnlineSigning: true}
				zd.mu.Unlock()
				UpdateSigValidityFloor(zd, &DnssecPolicy{}, 0, 0, false, func(uint8) bool { return false }, false)
			}},
		}
	}
	newZone := func(name string) *ZoneData {
		return &ZoneData{ZoneName: name, Options: map[ZoneOption]bool{}, Logger: discardLogger()}
	}

	for _, c := range []struct {
		what string
		mark bool // the removal bumps the generation
	}{
		{"removed and marked, as a reload removes a zone", true},
		{"removed without a mark, as a path that does not bump the generation does", false},
	} {
		name := "writers-" + strings.Fields(c.what)[0] + map[bool]string{true: "m", false: "u"}[c.mark] + ".config.example."
		zd := newZone(name)
		registerZones(t, zd)
		Zones.Remove(name)
		if c.mark {
			zd.generation.Add(1)
		}
		for _, w := range writers(zd) {
			w.do()
			if _, registered := Zones.Get(name); registered {
				t.Errorf("%s, %s: the zone that was removed is registered again", c.what, w.what)
				Zones.Remove(name)
			}
		}
	}

	// Another registration took the name: the stale pointer does not replace it.
	const taken = "writers-replaced.config.example."
	old, current := newZone(taken), newZone(taken)
	registerZones(t, old)
	Zones.Set(taken, current) // the replacement registers; old's generation is not bumped yet
	t.Cleanup(func() { Zones.Remove(taken) })
	for _, w := range writers(old) {
		w.do()
		if cur, _ := Zones.Get(taken); cur != current {
			t.Errorf("%s: a stale zone replaced the registration that took its name", w.what)
			Zones.Set(taken, current)
		}
	}

	// A zone that was never registered is not registered by a write.
	const never = "writers-never.config.example."
	fresh := newZone(never)
	for _, w := range writers(fresh) {
		w.do()
		if _, registered := Zones.Get(never); registered {
			t.Errorf("%s: a zone that was never registered is registered by a write", w.what)
			Zones.Remove(never)
		}
	}

	// And the window the generation check left: writers running while a
	// replacement lands, ending with the replacement in place.
	const raced = "writers-raced.config.example."
	for i := 0; i < 300; i++ {
		stale, fresh := newZone(raced), newZone(raced)
		Zones.Set(raced, stale)
		stop, done := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(done)
			for {
				select {
				case <-stop:
					return
				default:
					stale.SetError(DnssecPolicyWarning, "a warning")
					stale.ClearError(DnssecPolicyWarning)
				}
			}
		}()
		time.Sleep(50 * time.Microsecond)
		Zones.Set(raced, fresh)
		stale.generation.Add(1)
		close(stop)
		<-done
		if cur, _ := Zones.Get(raced); cur != fresh {
			t.Fatalf("round %d: a writer holding the replaced zone put it back over the registration that replaced it", i)
		}
		Zones.Remove(raced)
	}
}

// The latest reload wins. Two reloads of one new signing zone, with other
// algorithms, while the first one's refresher is still queued: the engine used to
// apply them in order, the first gave the zone keys under its algorithm, and the
// second named another that no rollover engine carries, and was refused as the
// algorithm change it then was; the zone signed with the older reload's. A
// refresher that a newer successful parse of the same registration has overtaken is
// dropped now, so the zone's first bind is the newest config's.
//
// What stays: a reload that changes the algorithms of a zone that already has keys
// is refused (TestAReloadThatChangesTheAlgorithmsOfASigningZonesPolicyUnderItsNameIsRefused),
// and a parse that fails part way overtakes nothing (the last test below).
func TestTwoQuickReloadsOfOneNewZoneTheLatestWins(t *testing.T) {
	authApp(t)
	kdb := Conf.Internal.KeyDB
	h := newReloadHarness(t, kdb, "twoquick.config.example.", "online-signing")
	const month = 30 * 86400
	polA := map[string]DnssecPolicy{"base": named(validFor(kskzsk(dns.ED25519, dns.ED25519), month), "base")}
	polB := map[string]DnssecPolicy{"base": named(validFor(kskzsk(dns.ECDSAP256SHA256, dns.ECDSAP256SHA256), month), "base")}
	withLivePolicies(t, map[string]DnssecPolicy{})

	parse := func(pols map[string]DnssecPolicy) ZoneRefresher {
		t.Helper()
		h.conf.Internal.DnssecPolicies = pols
		h.conf.Zones = []ZoneConf{{Name: h.zone, Type: "primary", Store: "map", Zonefile: h.file, DnssecPolicy: "base", OptionsStrs: h.options}}
		if _, _, err := h.conf.ParseZones(context.Background(), false); err != nil {
			t.Fatalf("ParseZones: %v", err)
		}
		return <-h.parsed
	}
	zrA := parse(polA) // the first reload: queued, not yet applied
	zrB := parse(polB) // the second, of the same registration, with another algorithm
	if zrA.Registered != zrB.Registered {
		t.Fatal("the two reloads did not reach the same registration; the test has lost its point")
	}

	h.engineConf.Internal.RefreshZoneCh <- zrA
	h.engineConf.Internal.RefreshZoneCh <- zrB
	h.answered(ZoneRefresher{Name: h.zone, ZoneStore: MapZone})

	zd, ok := Zones.Get(h.zone)
	if !ok {
		t.Fatal("the zone is not registered")
	}
	if zd.HasServiceImpactingError() {
		t.Errorf("the zone is in an error state: %s", zd.ErrorMsg)
	}
	if n, p, _ := policyState(zd); n != "base" || p == nil || p.KSKAlgorithm != dns.ECDSAP256SHA256 {
		t.Errorf("the zone records %q bound to KSK algorithm %d; want %q bound to the latest reload's %d",
			n, kskAlgOf(p), "base", dns.ECDSAP256SHA256)
	}
	sigs := servedRRset(t, zd, h.zone, dns.TypeSOA).RRSIGs
	if len(sigs) == 0 {
		t.Error("the SOA is unsigned")
	}
	for _, rr := range sigs {
		if sig, ok := rr.(*dns.RRSIG); ok && sig.Algorithm != dns.ECDSAP256SHA256 {
			t.Errorf("the SOA is signed with algorithm %d, want the latest reload's %d", sig.Algorithm, dns.ECDSAP256SHA256)
		}
	}
}

// The same with real reloads: the engine is held inside the first load of one zone
// while a reload adds a second, and a second reload changes the second's algorithms
// before the engine gets to it.
func TestTwoRealReloadsOfOneNewZoneTheLatestWins(t *testing.T) {
	authApp(t)
	kdb := Conf.Internal.KeyDB
	t.Cleanup(func() { policySyncProbe = nil })
	h := newReloadHarness(t, kdb, "tworealblock.config.example.")
	withLivePolicies(t, map[string]DnssecPolicy{})
	prevSync := delegationSyncConf.Load()
	t.Cleanup(func() { delegationSyncConf.Store(prevSync) })

	const wanted = "tworealwanted.config.example."
	wantedFile := filepath.Join(t.TempDir(), "zone")
	body := wanted + "\t3600\tIN\tSOA\tns1." + wanted + " hostmaster." + wanted + " 1 7200 1800 604800 7200\n" +
		wanted + "\t3600\tIN\tNS\tns1." + wanted + "\n" + "ns1." + wanted + "\t3600\tIN\tA\t192.0.2.53\n"
	if err := os.WriteFile(wantedFile, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if z, ok := Zones.Get(wanted); ok {
			z.stopPublisher()
		}
		Zones.Remove(wanted)
	})

	conf := &Config{}
	conf.Internal.KeyDB = kdb
	conf.Internal.RefreshZoneCh = h.engineConf.Internal.RefreshZoneCh // the harness's engine
	conf.Internal.BumpZoneCh = make(chan BumperData, 1)
	policy := func(alg string) map[string]DnssecPolicyConf {
		pol := DnssecPolicyConf{Algorithm: alg}
		pol.KSK.Lifetime, pol.ZSK.Lifetime, pol.CSK.Lifetime = "forever", "forever", "none"
		pol.SigValidity = DnssecPolicySigValidityConf{Default: "30d", Dnskey: "30d", Ds: "30d"}
		return map[string]DnssecPolicyConf{"base": pol}
	}
	zones := func() []ZoneConf {
		return []ZoneConf{
			{Name: h.zone, Type: "primary", Store: "map", Zonefile: h.file, DnssecPolicy: "base", OptionsStrs: []string{"online-signing"}},
			{Name: wanted, Type: "primary", Store: "map", Zonefile: wantedFile, DnssecPolicy: "base", OptionsStrs: []string{"online-signing"}},
		}
	}

	// The engine is held inside the first load of the first zone, with the second's
	// refresher queued behind it.
	inFlight, release := make(chan struct{}), make(chan struct{})
	var once, releaseOnce sync.Once
	closeRelease := func() { releaseOnce.Do(func() { close(release) }) }
	defer closeRelease()
	policySyncProbe = func(z *ZoneData, stage policySyncStage) {
		if z.ZoneName != h.zone || stage != policySyncRead {
			return
		}
		once.Do(func() {
			close(inFlight)
			<-release
		})
	}

	conf.Dnssec.Policies, conf.Zones = policy("ED25519"), zones()
	if _, err := conf.ReloadZoneConfig(context.Background()); err != nil {
		t.Fatalf("the first reload: %v", err)
	}
	select {
	case <-inFlight:
	case <-time.After(10 * time.Second):
		t.Fatal("the engine did not reach the first load of the first zone")
	}
	conf.Dnssec.Policies = policy("ECDSAP256SHA256")
	if _, err := conf.ReloadZoneConfig(context.Background()); err != nil {
		t.Fatalf("the second reload: %v", err)
	}
	closeRelease()
	marker := ZoneRefresher{Name: "marker.config.example.", Wait: true, Response: make(chan RefresherResponse, 1)}
	h.engineConf.Internal.RefreshZoneCh <- marker
	select {
	case <-marker.Response:
	case <-time.After(15 * time.Second):
		t.Fatal("the engine did not get through the refreshers")
	}

	zd, ok := Zones.Get(wanted)
	if !ok {
		t.Fatal("the second zone is not registered")
	}
	if zd.HasServiceImpactingError() {
		t.Errorf("the zone is in an error state: %s", zd.ErrorMsg)
	}
	if n, p, _ := policyState(zd); n != "base" || p == nil || p.KSKAlgorithm != dns.ECDSAP256SHA256 {
		t.Errorf("the zone records %q bound to KSK algorithm %d; want %q bound to the latest reload's %d",
			n, kskAlgOf(p), "base", dns.ECDSAP256SHA256)
	}
	for _, rr := range servedRRset(t, zd, wanted, dns.TypeSOA).RRSIGs {
		if sig, ok := rr.(*dns.RRSIG); ok && sig.Algorithm != dns.ECDSAP256SHA256 {
			t.Errorf("the SOA is signed with algorithm %d, want the latest reload's %d", sig.Algorithm, dns.ECDSAP256SHA256)
		}
	}
}

// A parse that fails part way overtakes nothing: the refresher an earlier reload
// queued for a zone is still applied, since the failed parse queued none of its own.
func TestAParseThatFailsDoesNotOvertakeAnEarlierRefresher(t *testing.T) {
	authApp(t)
	kdb := Conf.Internal.KeyDB
	h := newReloadHarness(t, kdb, "failedparse.config.example.", "online-signing")
	base := map[string]DnssecPolicy{"base": named(validFor(kskzsk(dns.ED25519, dns.ED25519), 30*86400), "base")}
	withLivePolicies(t, map[string]DnssecPolicy{})
	const bad = "failedparsebad.config.example."
	t.Cleanup(func() {
		if z, ok := Zones.Get(bad); ok {
			z.stopPublisher()
		}
		Zones.Remove(bad)
	})

	h.conf.Internal.DnssecPolicies = base
	h.conf.Zones = []ZoneConf{{Name: h.zone, Type: "primary", Store: "map", Zonefile: h.file, DnssecPolicy: "base", OptionsStrs: h.options}}
	if _, _, err := h.conf.ParseZones(context.Background(), false); err != nil {
		t.Fatalf("ParseZones: %v", err)
	}
	zr := <-h.parsed

	// A reload whose second zone does not validate.
	h.conf.Zones = []ZoneConf{
		{Name: h.zone, Type: "primary", Store: "map", Zonefile: h.file, DnssecPolicy: "base", OptionsStrs: h.options},
		{Name: bad, Type: "primary", Store: "map", Zonefile: h.file, DnssecPolicy: "base", TransferSrc: []string{"not-an-address"}},
	}
	if _, _, err := h.conf.ParseZones(context.Background(), true); err == nil {
		t.Fatal("ParseZones accepted a zone that does not validate; the test has lost its point")
	}

	h.engineConf.Internal.RefreshZoneCh <- zr
	h.answered(ZoneRefresher{Name: h.zone, ZoneStore: MapZone})
	zd, _ := Zones.Get(h.zone)
	if n, p, _ := policyState(zd); n != "base" || p == nil {
		t.Errorf("the earlier reload's refresher was dropped by a parse that failed: the zone records %q, bound %v", n, p != nil)
	}
}
