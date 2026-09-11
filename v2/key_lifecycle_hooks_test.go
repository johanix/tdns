package tdns

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// The key lifecycle hooks (B-MP T-S). What a multi-provider application
// registers, and what tdns does with it at the six sites: standby keys stage
// into the hooks' state and count as pipeline; no key is minted while a key
// of that role exists; a held published key is not promoted; a retired key
// parks in the hooks' retired state; every committed change is reported. And
// the two served-only states, mpdist and foreign, are in the DNSKEY RRset and
// never sign. Nil hooks are pinned by every existing signing and worker test.

func withKeyHooks(t *testing.T, h KeyLifecycleHooks) {
	t.Helper()
	RegisterKeyLifecycleHooks(h)
	t.Cleanup(func() { RegisterKeyLifecycleHooks(KeyLifecycleHooks{}) })
}

// hookRecorder is the multi-provider shape: staged keys go to "mpdist",
// retired ones to "mpremove", a published key is promotable only once its
// owner says so, no key is minted while one of that role exists in any
// state, and every change is recorded. Zones without the multi-provider
// option get the defaults, as they would in production.
type hookRecorder struct {
	mu         sync.Mutex
	changes    []string
	promotable map[uint16]bool
}

func newHookRecorder() *hookRecorder {
	return &hookRecorder{promotable: map[uint16]bool{}}
}

func (r *hookRecorder) allow(keyid uint16, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.promotable[keyid] = ok
}

func (r *hookRecorder) recorded() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.changes...)
}

func (r *hookRecorder) hooks(kdb *KeyDB) KeyLifecycleHooks {
	mp := func(zd *ZoneData) bool { return zd.Options[OptMultiProvider] }
	return KeyLifecycleHooks{
		StagedState: func(zd *ZoneData) string {
			if mp(zd) {
				return "mpdist"
			}
			return ""
		},
		RetiredState: func(zd *ZoneData) string {
			if mp(zd) {
				return "mpremove"
			}
			return ""
		},
		MayPromote: func(zd *ZoneData, keyid uint16) bool {
			if !mp(zd) {
				return true
			}
			r.mu.Lock()
			defer r.mu.Unlock()
			return r.promotable[keyid]
		},
		MayGenerate: func(zd *ZoneData, role string) bool {
			if !mp(zd) {
				return true
			}
			return countKeysOfRole(kdb, zd.ZoneName, role) == 0
		},
		OnStateChange: func(zone string, keyid uint16, from, to string) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.changes = append(r.changes, fmt.Sprintf("%d %s->%s", keyid, from, to))
		},
	}
}

func countKeysOfRole(kdb *KeyDB, zone, role string) int {
	flags := 257
	if role == "ZSK" {
		flags = 256
	}
	var n int
	if err := kdb.DB.QueryRow(`SELECT COUNT(*) FROM DnssecKeyStore WHERE zonename=? AND flags=?`, zone, flags).Scan(&n); err != nil {
		return 0
	}
	return n
}

func countKeysByCreator(t *testing.T, kdb *KeyDB, zone, creator string) int {
	t.Helper()
	var n int
	if err := kdb.DB.QueryRow(`SELECT COUNT(*) FROM DnssecKeyStore WHERE zonename=? AND creator=?`, zone, creator).Scan(&n); err != nil {
		t.Fatalf("count by creator: %v", err)
	}
	return n
}

func hookKeyState(t *testing.T, kdb *KeyDB, zone string, keyid uint16) string {
	t.Helper()
	var state string
	if err := kdb.DB.QueryRow(`SELECT state FROM DnssecKeyStore WHERE zonename=? AND keyid=?`, zone, keyid).Scan(&state); err != nil {
		t.Fatalf("state of key %d: %v", keyid, err)
	}
	return state
}

// mpSigningZone is a signing zone that carries the multi-provider option,
// with a bound policy and no keys.
func mpSigningZone(t *testing.T) (*ZoneData, *KeyDB) {
	t.Helper()
	zd := loadIxfrTestZone(t, basicZone)
	kdb := newTestKeyDB(t)
	if zd.Options == nil {
		zd.Options = map[ZoneOption]bool{}
	}
	zd.Options[OptOnlineSigning] = true
	zd.Options[OptMultiProvider] = true
	zd.KeyDB = kdb
	zd.DnssecPolicy = &DnssecPolicy{
		Mode:         DnssecPolicyModeKSKZSK,
		KSKAlgorithm: dns.ED25519,
		ZSKAlgorithm: dns.ED25519,
		SigValidity:  PolicySigValidity{Default: 14 * 86400, DNSKEY: 14 * 86400, DS: 14 * 86400},
	}
	return zd, kdb
}

func genKey(t *testing.T, kdb *KeyDB, zone, state, role string) uint16 {
	t.Helper()
	pkc, _, err := kdb.GenerateKeypair(zone, "test", state, dns.TypeDNSKEY, dns.ED25519, role, nil)
	if err != nil {
		t.Fatalf("generate %s %s: %v", state, role, err)
	}
	return pkc.KeyId
}

func servedDnskeyTags(t *testing.T, zd *ZoneData) map[uint16]bool {
	t.Helper()
	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil || apex == nil {
		t.Fatalf("GetOwner(apex): owner=%v err=%v", apex, err)
	}
	tags := map[uint16]bool{}
	for _, rr := range apex.RRtypes.GetOnlyRRSet(dns.TypeDNSKEY).RRs {
		tags[rr.(*dns.DNSKEY).KeyTag()] = true
	}
	return tags
}

func TestHooksStageStandbyKeysInTheStagedState(t *testing.T) {
	zd, kdb := mpSigningZone(t)
	rec := newHookRecorder()
	withKeyHooks(t, rec.hooks(kdb))
	genKey(t, kdb, zd.ZoneName, DnskeyStateActive, "KSK")
	genKey(t, kdb, zd.ZoneName, DnskeyStateActive, "ZSK")

	// The worker's walk no longer skips a multi-provider zone, and what it
	// mints lands in the hooks' staged state, not in "published".
	maintainStandbyKeys(context.Background(), noResignQ(), kdb, 1, 0)

	staged, err := GetDnssecKeysByState(kdb, zd.ZoneName, "mpdist")
	if err != nil {
		t.Fatalf("GetDnssecKeysByState: %v", err)
	}
	if len(staged) != 1 || staged[0].Flags != 256 {
		t.Fatalf("staged keys after maintenance: %+v, want one mpdist ZSK", staged)
	}
	if published, _ := GetDnssecKeysByState(kdb, zd.ZoneName, DnskeyStatePublished); len(published) != 0 {
		t.Fatalf("%d keys in published; the staged state is where they go", len(published))
	}

	// The staged key is pipeline: a second pass mints nothing beside it.
	maintainStandbyKeysForType(context.Background(), noResignQ(), kdb, zd.ZoneName, dns.ED25519, "ZSK", 256, 1, false)
	if staged, _ = GetDnssecKeysByState(kdb, zd.ZoneName, "mpdist"); len(staged) != 1 {
		t.Fatalf("%d staged keys after a second pass, want 1: the staged state did not count as pipeline", len(staged))
	}

	// The change was reported: created -> mpdist.
	if !containsChange(rec.recorded(), "created->mpdist") {
		t.Fatalf("no created->mpdist change reported; got %v", rec.recorded())
	}

	// A zone without the option, under the same hooks, gets the default.
	plain := testZone(t, "plain.example.", "plain.example.\t3600\tIN\tSOA\tns.plain.example. hostmaster.plain.example. 1 7200 1800 604800 7200\nplain.example.\t3600\tIN\tNS\tns.plain.example.\n")
	registerZones(t, plain)
	plain.Options = map[ZoneOption]bool{OptOnlineSigning: true}
	plain.KeyDB = kdb
	plain.DnssecPolicy = zd.DnssecPolicy
	genKey(t, kdb, plain.ZoneName, DnskeyStateActive, "KSK")
	genKey(t, kdb, plain.ZoneName, DnskeyStateActive, "ZSK")
	maintainStandbyKeysForType(context.Background(), noResignQ(), kdb, plain.ZoneName, dns.ED25519, "ZSK", 256, 1, false)
	if published, _ := GetDnssecKeysByState(kdb, plain.ZoneName, DnskeyStatePublished); len(published) != 1 {
		t.Fatalf("a plain zone staged %d published keys under the hooks, want 1", len(published))
	}
}

func containsChange(changes []string, suffix string) bool {
	for _, c := range changes {
		if strings.HasSuffix(c, suffix) {
			return true
		}
	}
	return false
}

// Review A1: a zone whose keys are all staged must not have tdns mint an
// active pair beside them on the first signing publish. The mint is deferred,
// the publish goes out unsigned and the zone stays not Ready -- the same "not
// yet" as an unbound policy -- until a key is released, promoted, and signs.
func TestHooksMayGenerateFalseDefersTheMint(t *testing.T) {
	zd, kdb := mpSigningZone(t)
	rec := newHookRecorder()
	withKeyHooks(t, rec.hooks(kdb))
	ksk := genKey(t, kdb, zd.ZoneName, "mpdist", "KSK")
	zsk := genKey(t, kdb, zd.ZoneName, "mpdist", "ZSK")

	_, err := zd.EnsureActiveDnssecKeys(kdb, false)
	if !errors.Is(err, ErrKeyGenerationDeferred) {
		t.Fatalf("EnsureActiveDnssecKeys with only staged keys: err=%v, want ErrKeyGenerationDeferred", err)
	}
	if n := countKeysByCreator(t, kdb, zd.ZoneName, "ensure-active-keys"); n != 0 {
		t.Fatalf("%d keys minted by the generation fallback beside the staged ones (defect 1.4, moved into tdns)", n)
	}
	if active, _ := GetDnssecKeysByState(kdb, zd.ZoneName, DnskeyStateActive); len(active) != 0 {
		t.Fatalf("%d active keys; nothing should be active yet", len(active))
	}

	// The publish path on a zone that has never served signed content:
	// unsigned, not Ready, and NOT a fault.
	zd.mu.Lock()
	zd.Ready = false
	zd.mu.Unlock()
	stageAndPublish(t, zd, stageAddA(t, zd, "one.example.test.", "192.0.2.11"))
	if !zd.HasPublishedData() {
		t.Fatal("the publish was refused; a deferred mint on a not-yet-servable zone is not a fault")
	}
	if zd.Ready {
		t.Fatal("the zone became Ready on an unsigned snapshot")
	}
	if zd.HasError(DnssecError) {
		t.Fatalf("DnssecError set for a deferred mint: %s", zd.ErrorMsg)
	}
	if soa := zd.publishedSnapshot().Apex.RRtypes.GetOnlyRRSet(dns.TypeSOA); len(soa.RRSIGs) != 0 {
		t.Fatal("the SOA was signed with no active key")
	}
	if n := countKeysByCreator(t, kdb, zd.ZoneName, "ensure-active-keys"); n != 0 {
		t.Fatalf("the publish path minted %d keys", n)
	}

	// The owner releases the keys: mpdist -> published, then promotable.
	for _, id := range []uint16{ksk, zsk} {
		if err := UpdateDnssecKeyState(kdb, zd.ZoneName, id, DnskeyStatePublished); err != nil {
			t.Fatalf("release key %d: %v", id, err)
		}
	}
	// Published but not yet promotable: still deferred, still published.
	if _, err := zd.EnsureActiveDnssecKeys(kdb, false); !errors.Is(err, ErrKeyGenerationDeferred) {
		t.Fatalf("EnsureActiveDnssecKeys with unpromotable published keys: err=%v", err)
	}
	if got := hookKeyState(t, kdb, zd.ZoneName, ksk); got != DnskeyStatePublished {
		t.Fatalf("a held KSK was moved to %s", got)
	}
	rec.allow(ksk, true)
	rec.allow(zsk, true)
	dak, err := zd.EnsureActiveDnssecKeys(kdb, false)
	if err != nil {
		t.Fatalf("EnsureActiveDnssecKeys after release: %v", err)
	}
	if len(dak.KSKs) != 1 || dak.KSKs[0].KeyId != ksk || len(dak.ZSKs) != 1 || dak.ZSKs[0].KeyId != zsk {
		t.Fatalf("active set after promotion: KSKs=%v ZSKs=%v, want %d and %d", dak.KSKs, dak.ZSKs, ksk, zsk)
	}
	if n := countKeysByCreator(t, kdb, zd.ZoneName, "ensure-active-keys"); n != 0 {
		t.Fatalf("%d keys minted although the staged ones were promotable", n)
	}

	// And now it signs, and becomes Ready, with those keys only.
	if _, err := zd.SignZone(context.Background(), kdb, false); err != nil {
		t.Fatalf("SignZone: %v", err)
	}
	if !zd.Ready {
		t.Fatal("the zone is not Ready after signing with the released keys")
	}
	for _, tag := range zd.mustRRSIGKeytags(t, zd.ZoneName, dns.TypeSOA) {
		if tag != ksk && tag != zsk {
			t.Fatalf("SOA signed by key %d, which is neither released key", tag)
		}
	}
	changes := rec.recorded()
	for _, want := range []string{fmt.Sprintf("%d mpdist->published", ksk), fmt.Sprintf("%d published->active", ksk), fmt.Sprintf("%d published->active", zsk)} {
		if !containsChange(changes, want) {
			t.Errorf("change %q not reported; got %v", want, changes)
		}
	}

	// On a READY signing zone the same deferral is a fault: refuse the
	// publish and keep the signed version, rather than publish unsigned.
	for _, id := range []uint16{ksk, zsk} {
		if err := UpdateDnssecKeyState(kdb, zd.ZoneName, id, "mpdist"); err != nil {
			t.Fatalf("withdraw key %d: %v", id, err)
		}
	}
	rec.allow(ksk, false)
	rec.allow(zsk, false)
	serial := zd.CurrentSerial
	stageAndPublish(t, zd, stageAddA(t, zd, "two.example.test.", "192.0.2.12"))
	if zd.CurrentSerial != serial {
		t.Fatalf("a Ready zone with no releasable key published serial %d over its signed %d", zd.CurrentSerial, serial)
	}
	if !zd.HasError(DnssecError) {
		t.Fatal("the refused publish did not set DnssecError")
	}
	if soa := zd.publishedSnapshot().Apex.RRtypes.GetOnlyRRSet(dns.TypeSOA); len(soa.RRSIGs) == 0 {
		t.Fatal("the served version lost its signature")
	}
}

// mpdist and foreign rows are in the served DNSKEY RRset, from a sign and
// from a refresh, and neither ever signs anything.
func TestForeignAndStagedKeysAreServedAndNeverSign(t *testing.T) {
	zd := loadIxfrTestZone(t, basicZone)
	kdb := makeZoneSigning(t, zd)
	active, err := kdb.GetDnssecKeys(zd.ZoneName, DnskeyStateActive)
	if err != nil || len(active.KSKs) != 1 || len(active.ZSKs) != 1 {
		t.Fatalf("active keys: %v %v", active, err)
	}
	activeTags := map[uint16]bool{active.KSKs[0].KeyId: true, active.ZSKs[0].KeyId: true}

	// A foreign key: another signer's public DNSKEY, no private half.
	foreign, err := GenerateKeyMaterial(zd.ZoneName, dns.TypeDNSKEY, dns.ED25519, "ZSK")
	if err != nil {
		t.Fatalf("GenerateKeyMaterial: %v", err)
	}
	foreignTag := foreign.DnskeyRR.KeyTag()
	if _, err := kdb.DB.Exec(`INSERT INTO DnssecKeyStore (zonename, state, keyid, algorithm, flags, creator, privatekey, keyrr) VALUES (?, 'foreign', ?, ?, 256, 'test', '', ?)`,
		zd.ZoneName, foreignTag, dns.AlgorithmToString[dns.ED25519], foreign.DnskeyRR.String()); err != nil {
		t.Fatalf("insert foreign row: %v", err)
	}
	stagedTag := genKey(t, kdb, zd.ZoneName, "mpdist", "ZSK")

	if _, err := zd.SignZone(context.Background(), kdb, false); err != nil {
		t.Fatalf("SignZone: %v", err)
	}
	check := func(when string) {
		t.Helper()
		served := servedDnskeyTags(t, zd)
		for tag, why := range map[uint16]string{foreignTag: "foreign", stagedTag: "mpdist", active.KSKs[0].KeyId: "active KSK", active.ZSKs[0].KeyId: "active ZSK"} {
			if !served[tag] {
				t.Errorf("%s: the %s key %d is not in the served DNSKEY RRset %v", when, why, tag, served)
			}
		}
		for _, rrtype := range []uint16{dns.TypeSOA, dns.TypeDNSKEY} {
			for _, tag := range zd.mustRRSIGKeytags(t, zd.ZoneName, rrtype) {
				if !activeTags[tag] {
					t.Errorf("%s: %s signed by key %d, which is not an active key", when, dns.TypeToString[rrtype], tag)
				}
			}
		}
		for _, tag := range zd.mustRRSIGKeytags(t, signedName, dns.TypeA) {
			if !activeTags[tag] {
				t.Errorf("%s: %s A signed by key %d, which is not an active key", when, signedName, tag)
			}
		}
	}
	check("after SignZone")

	// A refresh rebuilds the RRset from the keystore: the same predicate, so
	// the same set.
	dynamic := zd.CollectDynamicRRs(&Config{})
	newZd := draftZone(t, zd.ZoneName, basicZone)
	zd.mu.Lock()
	err = zd.applyRefreshReplacementLocked(newZd, dynamic, false, true)
	zd.mu.Unlock()
	if err != nil {
		t.Fatalf("applyRefreshReplacementLocked: %v", err)
	}
	check("after a refresh")
}

func TestHooksRetiredKeyParksInTheRetiredState(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		mp         bool
	}{
		{"multi-provider zone under the hooks", "mpremove", true},
		{"plain zone under the hooks", DnskeyStateRemoved, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			zd, kdb, oldTag := rolledZone(t)
			if tc.mp {
				zd.Options[OptMultiProvider] = true
			}
			rec := newHookRecorder()
			withKeyHooks(t, rec.hooks(kdb))
			longAgo := time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339)
			if _, err := kdb.DB.Exec(`UPDATE DnssecKeyStore SET retired_at=? WHERE zonename=? AND keyid=?`, longAgo, zd.ZoneName, oldTag); err != nil {
				t.Fatalf("age the retirement: %v", err)
			}

			transitionRetiredToRemoved(context.Background(), noResignQ(), kdb, time.Now(), time.Hour)

			if got := hookKeyState(t, kdb, zd.ZoneName, oldTag); got != tc.want {
				t.Fatalf("retired key is in state %q, want %q", got, tc.want)
			}
			if !containsChange(rec.recorded(), fmt.Sprintf("%d retired->%s", oldTag, tc.want)) {
				t.Fatalf("the transition was not reported; got %v", rec.recorded())
			}
			// Out of the served RRset once the re-sign the worker queues for
			// a key-state change has rebuilt it (SignZone stands in for the
			// resigner here), and in neither state does it sign.
			if _, err := zd.SignZone(context.Background(), kdb, false); err != nil {
				t.Fatalf("SignZone: %v", err)
			}
			if servedDnskeyTags(t, zd)[oldTag] {
				t.Fatalf("a %s key is still in the served DNSKEY RRset", tc.want)
			}
			for _, tag := range zd.mustRRSIGKeytags(t, signedName, dns.TypeA) {
				if tag == oldTag {
					t.Fatalf("a %s key still signs", tc.want)
				}
			}
		})
	}
}

func TestHooksReportEveryCommittedChange(t *testing.T) {
	zd, kdb := mpSigningZone(t)
	rec := newHookRecorder()
	withKeyHooks(t, rec.hooks(kdb))

	ksk := genKey(t, kdb, zd.ZoneName, DnskeyStateActive, "KSK")
	if err := kdb.PromoteDnssecKey(zd.ZoneName, ksk, DnskeyStateActive, DnskeyStateRetired); err != nil {
		t.Fatalf("PromoteDnssecKey: %v", err)
	}
	if err := UpdateDnssecKeyState(kdb, zd.ZoneName, ksk, DnskeyStateRemoved); err != nil {
		t.Fatalf("UpdateDnssecKeyState: %v", err)
	}
	want := []string{
		fmt.Sprintf("%d ->active", ksk),
		fmt.Sprintf("%d active->retired", ksk),
		fmt.Sprintf("%d retired->removed", ksk),
	}
	got := rec.recorded()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("reported changes %v, want %v", got, want)
	}
}
