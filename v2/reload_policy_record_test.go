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
