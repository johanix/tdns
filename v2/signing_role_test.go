/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// A signing role learned while the daemon runs (johanix/tdns-mp#160, #146).
// Every load and refresh here goes through a running RefreshEngine, on the app
// type that relays some zones and signs others (origination_rule_derived_app_test.go).

// upstreamKeytag is the key of the signer upstream of the zone, in the signatures
// the zone's copy arrives with. Their algorithm is the one the zone's own policy
// names, which is what makes a relayed copy look signed already.
const upstreamKeytag = 4711

const upstreamSigRDATA = "example. AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="

func upstreamSig(owner, covered string) string {
	labels := "1"
	if owner != ovZone {
		labels = "2"
	}
	return owner + " 3600 IN RRSIG " + covered + " 15 " + labels + " 3600 20351231000000 20250101000000 4711 " + upstreamSigRDATA
}

// signedUpstream serves the zone at serial as a signer does, its signatures on it.
func signedUpstream(t *testing.T, serial uint32) *relayUpstream {
	t.Helper()
	up := startRelayUpstream(t, serial)
	up.extra = []string{
		upstreamSig(ovZone, "SOA"),
		upstreamSig(ovZone, "NS"),
		upstreamSig("www.example.", "A"),
		upstreamSig("www.example.", "AAAA"),
		upstreamSig("ns.example.", "A"),
	}
	up.publish(t, serial)
	return up
}

// roleSetup is the app, its keystore, a policy named "base" and a NOTIFY queue.
func roleSetup(t *testing.T) (*KeyDB, chan NotifyRequest) {
	t.Helper()
	kdb := asDerivedApp(t, derivedSignerApp)
	registerTestOriginationRuleApp(t, derivedSignerApp)
	withLivePolicies(t, map[string]DnssecPolicy{"base": kskzsk(dns.ED25519, dns.ED25519)})
	return kdb, withNotifyQ(t, 16)
}

func startRoleZone(t *testing.T, kdb *KeyDB, up *relayUpstream, opts map[ZoneOption]bool, prepare func(*ZoneData)) *relayedZone {
	t.Helper()
	return startRelayedZoneWith(t, kdb, up, &relayedZone{
		opts:   opts,
		policy: "base",
		notify: []PeerConf{{Addr: aDownstream}},
	}, prepare)
}

// withheldAtFirstLoad has the zone withheld as a derived app does: from the
// first load's pre-refresh callback, before the first publish.
func withheldAtFirstLoad(t *testing.T) func(*ZoneData) {
	t.Helper()
	var once atomic.Bool
	return func(zd *ZoneData) {
		zd.OnZonePreRefresh = append(zd.OnZonePreRefresh, func(zd, _ *ZoneData) {
			if once.CompareAndSwap(false, true) {
				if err := zd.Withhold(); err != nil {
					t.Errorf("Withhold at the first load: %v", err)
				}
			}
		})
	}
}

// genActiveKeys makes an active KSK and ZSK of the zone, as an owner's machine
// has them when the zone is to start signing.
func genActiveKeys(t *testing.T, kdb *KeyDB) map[uint16]bool {
	t.Helper()
	if _, _, err := kdb.GenerateKeypair(ovZone, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "KSK", nil); err != nil {
		t.Fatalf("KSK: %v", err)
	}
	genZSKFor(t, kdb)
	return zoneActiveKeytags(t, kdb)
}

func genZSKFor(t *testing.T, kdb *KeyDB) {
	t.Helper()
	if _, _, err := kdb.GenerateKeypair(ovZone, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "ZSK", nil); err != nil {
		t.Fatalf("ZSK: %v", err)
	}
}

func zoneActiveKeytags(t *testing.T, kdb *KeyDB) map[uint16]bool {
	t.Helper()
	dak, err := kdb.GetDnssecKeys(ovZone, DnskeyStateActive)
	if err != nil {
		t.Fatalf("GetDnssecKeys: %v", err)
	}
	tags := map[uint16]bool{}
	for _, k := range append(append([]*PrivateKeyCache{}, dak.KSKs...), dak.ZSKs...) {
		tags[k.KeyId] = true
	}
	return tags
}

func keytagsOf(sigs []dns.RR) map[uint16]bool {
	tags := map[uint16]bool{}
	for _, rr := range sigs {
		if sig, ok := rr.(*dns.RRSIG); ok {
			tags[sig.KeyTag] = true
		}
	}
	return tags
}

// servedRRset is the RRset as the zone's published snapshot holds it.
func servedRRset(t *testing.T, zd *ZoneData, name string, rrtype uint16) core.RRset {
	t.Helper()
	snap := zd.publishedSnapshot()
	if snap == nil {
		t.Fatal("no published snapshot")
	}
	owner, ok := snap.Data[name]
	if !ok {
		return core.RRset{}
	}
	return owner.RRtypes.GetOnlyRRSet(rrtype)
}

// wantRelayedCopy: the zone serves its upstream's copy, at the upstream's serial,
// with nothing of its own on it.
func wantRelayedCopy(t *testing.T, z *relayedZone, serial uint32, when string) {
	t.Helper()
	z.wantServed(t, serial, when)
	for _, q := range []struct {
		name   string
		rrtype uint16
	}{{ovZone, dns.TypeSOA}, {ovZone, dns.TypeNS}, {"www.example.", dns.TypeA}} {
		tags := keytagsOf(servedRRset(t, z.zd, q.name, q.rrtype).RRSIGs)
		if len(tags) != 1 || !tags[upstreamKeytag] {
			t.Errorf("%s: %s %s is signed by %v, want the upstream's %d alone", when, q.name, dns.TypeToString[q.rrtype], tags, upstreamKeytag)
		}
	}
	if keys := servedRRset(t, z.zd, ovZone, dns.TypeDNSKEY); len(keys.RRs) != 0 {
		t.Errorf("%s: the zone publishes %d DNSKEYs of its own in a relayed copy", when, len(keys.RRs))
	}
}

// wantOnlyOwnSignatures: every RRset in the served zone is signed, by the given
// keys and by no other. A key of neither side is a signature nothing validates.
func wantOnlyOwnSignatures(t *testing.T, zd *ZoneData, own map[uint16]bool, when string) {
	t.Helper()
	snap := zd.publishedSnapshot()
	if snap == nil {
		t.Fatalf("%s: no published snapshot", when)
	}
	for name, owner := range snap.Data {
		for _, rrt := range owner.RRtypes.Keys() {
			rrset := owner.RRtypes.GetOnlyRRSet(rrt)
			tags := keytagsOf(rrset.RRSIGs)
			if len(tags) == 0 {
				t.Errorf("%s: %s %s is not signed", when, name, dns.TypeToString[rrt])
			}
			for tag := range tags {
				if !own[tag] {
					t.Errorf("%s: %s %s carries a signature by %d, not one of the zone's own keys %v", when, name, dns.TypeToString[rrt], tag, own)
				}
			}
		}
	}
}

func wantNotReady(t *testing.T, zd *ZoneData, when string) {
	t.Helper()
	if zd.Ready || zd.GetStatus() == ZoneStatusReady {
		t.Fatalf("%s: the zone is Ready (status %s)", when, ZoneStatusToString[zd.GetStatus()])
	}
}

func wantReady(t *testing.T, zd *ZoneData, when string) {
	t.Helper()
	if !zd.Ready || zd.GetStatus() != ZoneStatusReady {
		t.Fatalf("%s: the zone is not Ready (status %s)", when, ZoneStatusToString[zd.GetStatus()])
	}
}

// A zone's first load with nothing known about its role offers nothing to anyone.
// With a DS at the parent an unsigned copy going out would be bogus, so this is
// the whole of what keeps it from going out: refused to a query and to a
// transfer, no NOTIFY, no key, no policy. Its refreshes go on underneath, and
// the release serves the current copy, with its one NOTIFY, and runs what the
// withholding held back, once.
func TestAFirstLoadWithNoRoleKnownIsOfferedToNobodyUntilItsRelease(t *testing.T) {
	kdb, notifies := roleSetup(t)
	up := startRelayUpstream(t, 40) // unsigned: the copy that would be bogus
	var firstLoads, postRefreshes atomic.Int32
	withheld := withheldAtFirstLoad(t)
	z := startRoleZone(t, kdb, up, nil, func(zd *ZoneData) {
		withheld(zd)
		zd.OnFirstLoad = append(zd.OnFirstLoad, func(*ZoneData) { firstLoads.Add(1) })
		zd.OnZonePostRefresh = append(zd.OnZonePostRefresh, func(*ZoneData) { postRefreshes.Add(1) })
	})

	check := func(when string) {
		t.Helper()
		wantNotReady(t, z.zd, when)
		if !z.zd.Withheld() {
			t.Errorf("%s: Withheld() is false", when)
		}
		if _, err := z.zd.GetOwner(ovZone); !errors.Is(err, ErrZoneNotReady) {
			t.Errorf("%s: GetOwner: %v, want ErrZoneNotReady", when, err)
		}
		if got := len(notifies); got != 0 {
			t.Errorf("%s: %d NOTIFYs", when, got)
		}
		if got := firstLoads.Load() + postRefreshes.Load(); got != 0 {
			t.Errorf("%s: %d callbacks ran on a zone that is not Ready", when, got)
		}
		if hasPendingOnFirstLoad(z.zd) {
			t.Errorf("%s: the ticker would retry the first load in place of the zone's refreshes", when)
		}
		if z.zd.DnssecPolicy != nil {
			t.Errorf("%s: a policy is bound", when)
		}
		if tags := zoneActiveKeytags(t, kdb); len(tags) != 0 {
			t.Errorf("%s: keys were made: %v", when, tags)
		}
	}
	check("after the first load")

	r := new(dns.Msg)
	r.SetAxfr(ovZone)
	rw := &fakeRW{remote: udpAddr("127.0.0.1")}
	if _, err := z.zd.ZoneTransferOut(context.Background(), rw, r, nil); err == nil && rw.written != nil && rw.written.Rcode == dns.RcodeSuccess {
		t.Error("a withheld zone was transferred out")
	}

	up.publish(t, 41)
	z.notified(t)
	z.wantServed(t, 41, "after a refresh of the withheld zone")
	check("after a refresh")

	z.zd.ReleaseWithheld()
	wantReady(t, z.zd, "after the release")
	if z.zd.Withheld() {
		t.Error("Withheld() after the release")
	}
	if got := len(notifies); got != 1 {
		t.Errorf("%d NOTIFYs for the release, want 1", got)
	}
	if got := firstLoads.Load(); got != 1 {
		t.Errorf("OnFirstLoad ran %d times, want once", got)
	}
	if got := postRefreshes.Load(); got != 1 {
		t.Errorf("the post-refresh callbacks ran %d times, want the debt paid once", got)
	}
	if owner, err := z.zd.GetOwner(ovZone); err != nil || owner == nil {
		t.Errorf("GetOwner after the release: %v", err)
	}

	z.zd.ReleaseWithheld() // nothing more
	if got := len(notifies); got != 1 {
		t.Errorf("a second release sent a NOTIFY: %d", got)
	}
	up.publish(t, 42)
	z.notified(t)
	if got := postRefreshes.Load(); got != 2 {
		t.Errorf("a refresh after the release: the post-refresh callbacks ran %d times in all, want 2", got)
	}
}

// The ticker's retry and the first load's own completion leave a withheld zone's
// callbacks alone, or a load would spend them on a zone that is not Ready.
func TestDrainingFirstLoadCallbacksLeavesAWithheldZonesAlone(t *testing.T) {
	zd := &ZoneData{ZoneName: "drained.example."}
	ran := 0
	zd.OnFirstLoad = []func(*ZoneData){func(*ZoneData) { ran++ }}
	if err := zd.Withhold(); err != nil {
		t.Fatalf("Withhold: %v", err)
	}
	drainAndRunOnFirstLoad(zd)
	if ran != 0 || len(zd.OnFirstLoad) != 1 {
		t.Fatalf("drained while withheld: ran %d, %d left", ran, len(zd.OnFirstLoad))
	}
}

// Withhold is for a zone not yet served: it does not take one off the air.
func TestWithholdRefusesAZoneAlreadyServed(t *testing.T) {
	kdb, _ := roleSetup(t)
	z := startRoleZone(t, kdb, startRelayUpstream(t, 40), nil, nil)
	wantReady(t, z.zd, "after the first load")
	if err := z.zd.Withhold(); err == nil {
		t.Fatal("a zone already served was withheld")
	}
	if z.zd.Withheld() {
		t.Fatal("Withheld() after the refusal")
	}
	wantReady(t, z.zd, "after the refusal")
}

// The mode #160 asks for: the policy is bound, so an owner can run the zone's
// keys, and the zone goes on relaying its upstream's copy unchanged. It has keys
// in the keystore and serves none of them, signs nothing, and takes the
// upstream's serial at every refresh. A resign an owner asks for after a key
// change finds nothing to do, and a config reload leaves the binding alone.
func TestAZoneBoundWithoutSigningRelaysItsCopyUnchanged(t *testing.T) {
	kdb, _ := roleSetup(t)
	up := signedUpstream(t, 40)
	z := startRoleZone(t, kdb, up, nil, nil)
	wantRelayedCopy(t, z, 40, "before the bind")
	if z.zd.DnssecPolicy != nil {
		t.Fatal("a zone that does not sign had a policy bound at its first load; the test has lost its point")
	}

	if err := z.zd.BindPolicyWithoutSigning(); err != nil {
		t.Fatalf("BindPolicyWithoutSigning: %v", err)
	}
	if z.zd.DnssecPolicy == nil || z.zd.DnssecPolicyName != "base" {
		t.Fatalf("binding: %q %v", z.zd.DnssecPolicyName, z.zd.DnssecPolicy)
	}
	if z.zd.signsItsOwnContent() {
		t.Fatal("the bind switched signing on")
	}
	if _, _, ok, err := GetZoneAppliedPolicy(kdb, ovZone); err != nil || ok {
		t.Fatalf("a last-applied record for a zone never signed under it: ok=%v err=%v", ok, err)
	}
	if tags := zoneActiveKeytags(t, kdb); len(tags) != 0 {
		t.Fatalf("the bind made keys: %v", tags)
	}
	genActiveKeys(t, kdb)
	wantRelayedCopy(t, z, 40, "with keys in the keystore")

	z.zd.markResignPending()
	z.zd.replaceSignaturesNow(context.Background())
	wantRelayedCopy(t, z, 40, "after a resign was asked for")

	up.publish(t, 41)
	z.notified(t)
	wantRelayedCopy(t, z, 41, "after a refresh")

	up.publish(t, 42)
	z.reloaded(t)
	wantRelayedCopy(t, z, 42, "after a config reload")
	if z.zd.DnssecPolicy == nil {
		t.Fatal("a config reload took the binding away")
	}
	if z.zd.signsItsOwnContent() {
		t.Fatal("a config reload switched signing on")
	}
}

// A bind that cannot be made says so and binds nothing, and a zone that signs
// has its policy from the policy paths.
func TestBindPolicyWithoutSigningRefuses(t *testing.T) {
	kdb := newTestKeyDB(t)
	broken := kskzsk(dns.ED25519, dns.ED25519)
	broken.Error = "no good"
	withLivePolicies(t, map[string]DnssecPolicy{"base": kskzsk(dns.ED25519, dns.ED25519), "broken": broken})
	for _, tc := range []struct {
		what, policy string
		kdb          *KeyDB
		opts         map[ZoneOption]bool
		refusal      string
	}{
		{"no keystore", "base", nil, nil, "no keystore"},
		{"names none", "", kdb, nil, "names no DNSSEC policy"},
		{"does not exist", "gone", kdb, nil, "does not exist"},
		{"broken", "broken", kdb, nil, "is broken"},
		{"signing", "base", kdb, map[ZoneOption]bool{OptInlineSigning: true}, "signs"},
	} {
		t.Run(tc.what, func(t *testing.T) {
			zd := &ZoneData{ZoneName: "refused.example.", KeyDB: tc.kdb, DnssecPolicyName: tc.policy, Options: tc.opts}
			err := zd.BindPolicyWithoutSigning()
			if err == nil || !strings.Contains(err.Error(), tc.refusal) {
				t.Fatalf("err = %v, want it to say %q", err, tc.refusal)
			}
			if zd.DnssecPolicy != nil {
				t.Fatal("a refused bind bound a policy")
			}
		})
	}
}

// The end of that mode. The relayed copy carries the upstream's signatures, by an
// algorithm the zone's policy also names, and its active keys match: every "is
// it signed" test in tdns says yes, so a first-load style bind leaves it as it
// is and the zone serves someone else's signatures while it believes it signs.
// StartSigning replaces them, DNSKEY RRset and all, in one version, at a serial
// above the one it served.
func TestStartSigningReplacesTheSignaturesOfARelayedCopy(t *testing.T) {
	kdb, notifies := roleSetup(t)
	up := signedUpstream(t, 40)
	z := startRoleZone(t, kdb, up, nil, nil)
	if err := z.zd.BindPolicyWithoutSigning(); err != nil {
		t.Fatalf("BindPolicyWithoutSigning: %v", err)
	}
	own := genActiveKeys(t, kdb)
	wantRelayedCopy(t, z, 40, "before the start")
	if !zoneServesIntentSOASig(z.zd, z.zd.DnssecPolicy) {
		t.Fatal("the relayed copy does not look signed; the test has lost its point")
	}
	before := len(notifies)

	if err := z.zd.StartSigning(context.Background(), 0); err != nil {
		t.Fatalf("StartSigning: %v", err)
	}

	wantReady(t, z.zd, "after the start")
	if !z.zd.signsItsOwnContent() {
		t.Fatal("the zone does not sign")
	}
	wantOnlyOwnSignatures(t, z.zd, own, "after the start")
	if got := z.served(t); got != 41 {
		t.Errorf("serial %d, want one above the 40 it served", got)
	}
	if keys := servedRRset(t, z.zd, ovZone, dns.TypeDNSKEY); len(keys.RRs) != 2 || len(keys.RRSIGs) == 0 {
		t.Errorf("the DNSKEY RRset: %d keys, %d signatures; want the keystore's 2, signed", len(keys.RRs), len(keys.RRSIGs))
	}
	if name, source, ok, err := GetZoneAppliedPolicy(kdb, ovZone); err != nil || !ok || name != "base" || source != string(PolicyApplySourceConfig) {
		t.Errorf("last-applied record: %q %q %v %v", name, source, ok, err)
	}
	if got := len(notifies) - before; got != 1 {
		t.Errorf("%d NOTIFYs for the signed version, want 1", got)
	}
	if got := zoneActiveKeytags(t, kdb); len(got) != len(own) {
		t.Errorf("the start made keys: %v, had %v", got, own)
	}

	// From here on the zone has a serial of its own and signs each refresh.
	up.publish(t, 42)
	z.notified(t)
	if got := z.served(t); !serialNewer(got, 41) {
		t.Errorf("after a refresh: serial %d did not move on from 41", got)
	}
	tags := keytagsOf(servedRRset(t, z.zd, ovZone, dns.TypeSOA).RRSIGs)
	for tag := range own {
		if !tags[tag] && activeKeyIsZSK(t, kdb, tag) {
			t.Errorf("after a refresh: the SOA is signed by %v, not by the zone's ZSK %d", tags, tag)
		}
	}
}

func activeKeyIsZSK(t *testing.T, kdb *KeyDB, tag uint16) bool {
	t.Helper()
	dak, err := kdb.GetDnssecKeys(ovZone, DnskeyStateActive)
	if err != nil {
		t.Fatalf("GetDnssecKeys: %v", err)
	}
	for _, k := range dak.ZSKs {
		if k.KeyId == tag && k.DnskeyRR.Flags == 256 {
			return true
		}
	}
	return false
}

// #146, as observed: a zone that was not a signer at its first load is named one
// while its daemon runs, at a refresh. It signs at once, with keys of its own and
// its policy bound, and no restart. A zone nobody owns gets its first keys here,
// as at a first load.
func TestAZoneNamedASignerAtARefreshSignsWithoutARestart(t *testing.T) {
	kdb, _ := roleSetup(t)
	up := startRelayUpstream(t, 40)
	var named atomic.Bool
	z := startRoleZone(t, kdb, up, nil, func(zd *ZoneData) {
		zd.OnZonePostRefresh = append(zd.OnZonePostRefresh, func(zd *ZoneData) {
			if named.Load() && !zd.signsItsOwnContent() {
				if err := zd.StartSigning(context.Background(), 0); err != nil {
					t.Errorf("StartSigning at the refresh: %v", err)
				}
			}
		})
	})
	if z.zd.DnssecPolicy != nil || z.zd.signsItsOwnContent() {
		t.Fatal("the zone signed from its first load; the test has lost its point")
	}

	named.Store(true)
	up.publish(t, 41)
	z.notified(t)

	wantReady(t, z.zd, "after the refresh")
	if z.zd.DnssecPolicy == nil || z.zd.DnssecPolicyName != "base" {
		t.Fatalf("binding after the refresh: %q %v", z.zd.DnssecPolicyName, z.zd.DnssecPolicy)
	}
	own := zoneActiveKeytags(t, kdb)
	if len(own) != 2 {
		t.Fatalf("active keys: %v, want a KSK and a ZSK made for the zone", own)
	}
	wantOnlyOwnSignatures(t, z.zd, own, "after the refresh")
	if got := z.served(t); !serialNewer(got, 41) {
		t.Errorf("serial %d, want above the 41 it took at the refresh", got)
	}

	// and it stays signing through a config reload, which lays the
	// configuration's options over the zone's
	z.reloaded(t)
	if !z.zd.signsItsOwnContent() {
		t.Fatal("a config reload took signing away")
	}
	if len(keytagsOf(servedRRset(t, z.zd, ovZone, dns.TypeSOA).RRSIGs)) == 0 {
		t.Fatal("the SOA is unsigned after a config reload")
	}
}

// The zone's servers may have been fed from elsewhere, at a serial this zone
// never saw. They take nothing at or below it, so the signed copy lands above it
// and stays there.
func TestStartSigningLandsAboveTheSerialItsServersServed(t *testing.T) {
	for _, tc := range []struct {
		what string
		min  uint32
		want uint32
	}{
		{"none", 0, 41},
		{"below what the zone served", 10, 41},
		{"what the zone served", 40, 41},
		{"above it", 5000, 5001},
	} {
		t.Run(tc.what, func(t *testing.T) {
			kdb, _ := roleSetup(t)
			up := signedUpstream(t, 40)
			z := startRoleZone(t, kdb, up, nil, nil)
			if err := z.zd.StartSigning(context.Background(), tc.min); err != nil {
				t.Fatalf("StartSigning: %v", err)
			}
			if got := z.served(t); got != tc.want {
				t.Fatalf("serial %d, want %d", got, tc.want)
			}
			up.publish(t, 41)
			z.notified(t)
			if got := z.served(t); !serialNewer(got, tc.want) {
				t.Fatalf("after a refresh: serial %d, want above %d", got, tc.want)
			}
		})
	}
}

// An owned zone's keys are its owner's to make. With no active key of every role
// the start is refused and nothing happens to the zone; once the owner has made
// them it starts, with those keys and no others.
func TestAnOwnedZoneStartsSigningOnlyWithItsOwnersKeys(t *testing.T) {
	kdb, _ := roleSetup(t)
	installOwner(t, &testOwner{owns: map[string]bool{ovZone: true}})
	up := signedUpstream(t, 40)
	z := startRoleZone(t, kdb, up, map[ZoneOption]bool{OptMultiProvider: true}, nil)
	if !zoneOwned(z.zd) {
		t.Fatal("the zone is not owned; the test has lost its point")
	}
	if err := z.zd.BindPolicyWithoutSigning(); err != nil {
		t.Fatalf("an owned zone with no keys: BindPolicyWithoutSigning: %v", err)
	}

	err := z.zd.StartSigning(context.Background(), 0)
	if !errors.Is(err, ErrKeyGenerationDeferred) {
		t.Fatalf("StartSigning with no keys: %v, want ErrKeyGenerationDeferred", err)
	}
	if z.zd.signsItsOwnContent() {
		t.Fatal("the refused start left signing on")
	}
	// Refused before it switched anything. With signing on and no key, a refresh
	// arriving in that moment would have its publish refused as a fault.
	z.zd.mu.Lock()
	_, switched := z.zd.runtimeOptions[OptInlineSigning]
	z.zd.mu.Unlock()
	if switched {
		t.Fatal("the refused start switched inline-signing on and back")
	}
	if z.zd.DnssecPolicy == nil {
		t.Fatal("the refused start took the binding away")
	}
	if tags := zoneActiveKeytags(t, kdb); len(tags) != 0 {
		t.Fatalf("tdns made keys for an owned zone: %v", tags)
	}
	wantReady(t, z.zd, "after the refusal")
	wantRelayedCopy(t, z, 40, "after the refusal")
	up.publish(t, 41)
	z.notified(t)
	wantRelayedCopy(t, z, 41, "a refresh after the refusal")

	own := genActiveKeys(t, kdb)
	if err := z.zd.StartSigning(context.Background(), 0); err != nil {
		t.Fatalf("StartSigning with the owner's keys: %v", err)
	}
	wantOnlyOwnSignatures(t, z.zd, own, "with the owner's keys")
	if got := zoneActiveKeytags(t, kdb); len(got) != len(own) {
		t.Fatalf("the start made keys beside the owner's: %v, had %v", got, own)
	}
}

// A start that cannot sign leaves the zone as it found it: relaying, unbound, at
// its serial, with no error, and with the next refresh served as ever. Here the
// keystore's active KSK is of another algorithm than the policy's, which the
// signing path refuses.
func TestAStartThatCannotSignLeavesTheZoneAsItWas(t *testing.T) {
	kdb, _ := roleSetup(t)
	up := signedUpstream(t, 40)
	z := startRoleZone(t, kdb, up, nil, nil)
	if _, _, err := kdb.GenerateKeypair(ovZone, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.RSASHA256, "KSK", nil); err != nil {
		t.Fatalf("KSK: %v", err)
	}

	err := z.zd.StartSigning(context.Background(), 5000)
	if err == nil {
		t.Fatal("StartSigning signed with a KSK of the wrong algorithm")
	}
	if z.zd.signsItsOwnContent() {
		t.Fatal("signing stayed on")
	}
	if z.zd.DnssecPolicy != nil {
		t.Fatal("the binding stayed")
	}
	if z.zd.HasError(DnssecError) {
		t.Fatalf("a DnssecError stayed: %s", z.zd.ErrorMsg)
	}
	if _, _, ok, gerr := GetZoneAppliedPolicy(kdb, ovZone); gerr != nil || ok {
		t.Fatalf("a last-applied record: ok=%v err=%v", ok, gerr)
	}
	wantReady(t, z.zd, "after the failure")
	wantRelayedCopy(t, z, 40, "after the failure")

	up.publish(t, 41)
	z.notified(t)
	wantRelayedCopy(t, z, 41, "a refresh after the failure")
	z.reloaded(t)
	if z.zd.signsItsOwnContent() {
		t.Fatal("a config reload switched signing back on")
	}
}

// The policy's own floor check fails the start by setting DnssecError, which
// SignZone and ResignZone refuse on. Left behind, that error would stop the zone
// from ever signing under a good policy.
func TestAStartRefusedByThePolicysFloorLeavesNoErrorBehind(t *testing.T) {
	kdb, _ := roleSetup(t)
	withLivePolicies(t, map[string]DnssecPolicy{"base": floorViolatingPolicy()})
	z := startRoleZone(t, kdb, signedUpstream(t, 40), nil, nil)

	if err := z.zd.StartSigning(context.Background(), 0); err == nil {
		t.Fatal("fixture: the floor-violating policy was accepted, so there is nothing to leave behind")
	}
	if z.zd.HasError(DnssecError) {
		t.Fatalf("the refused policy's DnssecError stayed: %s", z.zd.ErrorMsg)
	}
	wantRelayedCopy(t, z, 40, "after the refusal")
}

// A pass stopped part way leaves nothing staged: what it staged would go out with
// the next publish, on a zone that does not sign.
func TestAStartStoppedPartWayLeavesNothingStaged(t *testing.T) {
	kdb, _ := roleSetup(t)
	up := signedUpstream(t, 40)
	z := startRoleZone(t, kdb, up, nil, nil)
	genActiveKeys(t, kdb)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := z.zd.StartSigning(ctx, 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("StartSigning on a cancelled context: %v", err)
	}
	z.zd.mu.Lock()
	staged := z.zd.workingSet != nil
	z.zd.mu.Unlock()
	if staged {
		t.Fatal("a working set stayed staged")
	}
	wantRelayedCopy(t, z, 40, "after the stop")
	up.publish(t, 41)
	z.notified(t)
	wantRelayedCopy(t, z, 41, "a refresh after the stop")
}

// A withheld zone that is told it signs goes Ready on the signed copy, not on the
// one it was holding: no version with an unsigned SOA is ever on offer, and the
// one NOTIFY is for the signed serial. One that cannot start stays withheld.
func TestAWithheldZoneThatStartsSigningGoesReadyOnTheSignedCopy(t *testing.T) {
	t.Run("signed", func(t *testing.T) {
		kdb, notifies := roleSetup(t)
		var firstLoads atomic.Int32
		withheld := withheldAtFirstLoad(t)
		z := startRoleZone(t, kdb, startRelayUpstream(t, 40), nil, func(zd *ZoneData) {
			withheld(zd)
			zd.OnFirstLoad = append(zd.OnFirstLoad, func(*ZoneData) { firstLoads.Add(1) })
		})
		wantNotReady(t, z.zd, "before the start")

		if err := z.zd.StartSigning(context.Background(), 0); err != nil {
			t.Fatalf("StartSigning: %v", err)
		}
		wantReady(t, z.zd, "after the start")
		if z.zd.Withheld() {
			t.Fatal("still withheld")
		}
		wantOnlyOwnSignatures(t, z.zd, zoneActiveKeytags(t, kdb), "after the start")
		if got := len(notifies); got != 1 {
			t.Fatalf("%d NOTIFYs, want one: nothing unsigned is announced", got)
		}
		if got := firstLoads.Load(); got != 1 {
			t.Fatalf("OnFirstLoad ran %d times, want once", got)
		}
	})
	t.Run("refused", func(t *testing.T) {
		kdb, notifies := roleSetup(t)
		installOwner(t, &testOwner{owns: map[string]bool{ovZone: true}})
		z := startRoleZone(t, kdb, startRelayUpstream(t, 40), map[ZoneOption]bool{OptMultiProvider: true}, withheldAtFirstLoad(t))

		if err := z.zd.StartSigning(context.Background(), 0); !errors.Is(err, ErrKeyGenerationDeferred) {
			t.Fatalf("StartSigning: %v", err)
		}
		wantNotReady(t, z.zd, "after the refusal")
		if !z.zd.Withheld() {
			t.Fatal("the refused start ended the withholding")
		}
		if got := len(notifies); got != 0 {
			t.Fatalf("%d NOTIFYs", got)
		}
	})
}

// The publish gate holds a busy zone's work back for its cadence. StartSigning
// does not return until the signed copy is what the zone serves: its caller goes
// on to tell the operator so.
func TestStartSigningPublishesBeforeItReturnsOnABusyZone(t *testing.T) {
	kdb, _ := roleSetup(t)
	z := startRoleZone(t, kdb, signedUpstream(t, 40), nil, nil)
	own := genActiveKeys(t, kdb)
	z.zd.mu.Lock()
	z.zd.publishCadence = time.Hour
	z.zd.lastPublish = time.Now()
	z.zd.mu.Unlock()

	if err := z.zd.StartSigning(context.Background(), 0); err != nil {
		t.Fatalf("StartSigning: %v", err)
	}
	wantOnlyOwnSignatures(t, z.zd, own, "when it returned")
	if got := z.served(t); got != 41 {
		t.Fatalf("serial %d, want 41", got)
	}
}

// Signing already, with the policy bound: nothing to do, no new serial.
func TestStartSigningASecondTimeChangesNothing(t *testing.T) {
	kdb, notifies := roleSetup(t)
	z := startRoleZone(t, kdb, signedUpstream(t, 40), nil, nil)
	if err := z.zd.StartSigning(context.Background(), 0); err != nil {
		t.Fatalf("StartSigning: %v", err)
	}
	serial, sent := z.served(t), len(notifies)
	if err := z.zd.StartSigning(context.Background(), 5000); err != nil {
		t.Fatalf("StartSigning again: %v", err)
	}
	if got := z.served(t); got != serial {
		t.Fatalf("serial %d, was %d", got, serial)
	}
	if got := len(notifies); got != sent {
		t.Fatalf("%d NOTIFYs, was %d", got, sent)
	}
}

// Only a first load puts a zone on the renewal list, and this one's first load
// did not sign: its signatures would run out with nothing to renew them.
func TestStartSigningPutsTheZoneOnTheRenewalList(t *testing.T) {
	kdb, _ := roleSetup(t)
	prev := Conf.Internal.ResignQ
	q := make(chan ResignRequest, 4)
	Conf.Internal.ResignQ = q
	t.Cleanup(func() { Conf.Internal.ResignQ = prev })
	z := startRoleZone(t, kdb, signedUpstream(t, 40), nil, nil)

	if err := z.zd.StartSigning(context.Background(), 0); err != nil {
		t.Fatalf("StartSigning: %v", err)
	}
	for len(q) > 0 {
		if req := <-q; req.Zd == z.zd && req.Reason == ResignPeriodic {
			return
		}
	}
	t.Fatal("the zone was not registered for periodic re-signing")
}
