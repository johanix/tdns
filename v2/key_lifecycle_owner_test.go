package tdns

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// S2: zone ownership (design §3.5, test plan §4.3). A registered owner that
// owns a multi-provider zone stops every tdns lifecycle path on it and turns
// every lifecycle verb into a refusal naming the owner's command.

type testOwner struct {
	owns   map[string]bool
	intent map[string]DSIntent
	asked  []string
}

func (o *testOwner) Name() string { return "test-owner" }
func (o *testOwner) Owns(zd *ZoneData) bool {
	o.asked = append(o.asked, zd.ZoneName)
	return o.owns[zd.ZoneName]
}
func (o *testOwner) Command(verb string) string { return "tdns-mpcli signer key " + verb }
func (o *testOwner) DSIntent(zd *ZoneData, digest uint8) (DSIntent, error) {
	in, ok := o.intent[zd.ZoneName]
	if !ok {
		return DSIntent{}, nil
	}
	return in, nil
}

// installOwner registers o for the test and clears it afterwards.
func installOwner(t *testing.T, o KeyLifecycleOwner) {
	t.Helper()
	RegisterKeyLifecycleOwner(o)
	t.Cleanup(func() { RegisterKeyLifecycleOwner(nil) })
}

// ownerZone is a multi-provider signing zone bound to a multi-DS policy,
// with an active KSK and ZSK, signed.
func ownerZone(t *testing.T, kdb *KeyDB, name string) *ZoneData {
	t.Helper()
	pol := ktMultiDSPolicy(dns.ED25519, dns.ED25519)
	pol.Rollover.ParentAgent = "127.0.0.1:1"
	pol.ZSK = KeyLifetime{Lifetime: 30 * 86400}
	zd := testZone(t, name, fmt.Sprintf("%s 3600 IN SOA ns.%s hostmaster.%s 1 7200 1800 604800 7200\n%s 3600 IN NS ns.%s\nns.%s 3600 IN A 192.0.2.1\n", name, name, name, name, name, name))
	registerZones(t, zd)
	zd.KeyDB = kdb
	zd.Options = map[ZoneOption]bool{OptInlineSigning: true, OptMultiProvider: true}
	zd.DnssecPolicy = pol
	zd.DnssecPolicyName = pol.Name
	zd.InstallInitialSnapshot()
	ktGenKSK(t, kdb, name, DnskeyStateActive, dns.ED25519)
	ktGenZSK(t, kdb, name, DnskeyStateActive, dns.ED25519)
	if _, err := zd.SignZone(context.Background(), kdb, true); err != nil {
		t.Fatalf("SignZone: %v", err)
	}
	return zd
}

// rolloverStamp sets one timestamp of the key's RolloverKeyState row.
func rolloverStamp(t *testing.T, kdb *KeyDB, zone string, keyid uint16, col string, at time.Time) {
	t.Helper()
	if _, err := kdb.DB.Exec(`UPDATE RolloverKeyState SET `+col+`=? WHERE zone=? AND keyid=?`, at.UTC().Format(time.RFC3339), zone, int(keyid)); err != nil {
		t.Fatal(err)
	}
}

func backdate(t *testing.T, kdb *KeyDB, zone string, keyid uint16, col string, at time.Time) {
	t.Helper()
	if _, err := kdb.DB.Exec(`UPDATE DnssecKeyStore SET `+col+`=? WHERE zonename=? AND keyid=?`, at.UTC().Format(time.RFC3339), zone, int(keyid)); err != nil {
		t.Fatal(err)
	}
}

func keyStateOf(t *testing.T, kdb *KeyDB, zone string, keyid uint16) string {
	t.Helper()
	return ktKeyState(t, kdb, zone, keyid)
}

// lifecyclePaths are the tdns paths §3.5 lists, each set up so that it WOULD
// write on the zone if it ran: the fixture is the thing the path acts on.
// run returns after the path, and check names what the path did when it was
// not skipped (for T2.2).
type lifecyclePath struct {
	name  string
	setup func(t *testing.T, kdb *KeyDB, zd *ZoneData) (check func(t *testing.T) bool)
	run   func(t *testing.T, kdb *KeyDB, zd *ZoneData)
}

func lifecyclePaths() []lifecyclePath {
	long := time.Now().Add(-48 * time.Hour)
	return []lifecyclePath{
		{"worker published->standby", func(t *testing.T, kdb *KeyDB, zd *ZoneData) func(*testing.T) bool {
			k := ktGenZSK(t, kdb, zd.ZoneName, DnskeyStatePublished, dns.ED25519)
			backdate(t, kdb, zd.ZoneName, k, "published_at", long)
			return func(t *testing.T) bool { return keyStateOf(t, kdb, zd.ZoneName, k) == DnskeyStateStandby }
		}, func(t *testing.T, kdb *KeyDB, zd *ZoneData) {
			transitionPublishedToStandby(&Conf, kdb, time.Now(), time.Minute)
		}},
		{"worker retired->removed", func(t *testing.T, kdb *KeyDB, zd *ZoneData) func(*testing.T) bool {
			k := ktGenZSK(t, kdb, zd.ZoneName, DnskeyStateRetired, dns.ED25519)
			backdate(t, kdb, zd.ZoneName, k, "retired_at", long)
			return func(t *testing.T) bool { return keyStateOf(t, kdb, zd.ZoneName, k) == DnskeyStateRemoved }
		}, func(t *testing.T, kdb *KeyDB, zd *ZoneData) {
			transitionRetiredToRemoved(context.Background(), &Conf, kdb, time.Now(), time.Minute)
		}},
		{"worker standby maintenance", func(t *testing.T, kdb *KeyDB, zd *ZoneData) func(*testing.T) bool {
			return func(t *testing.T) bool {
				ks, _ := GetDnssecKeysByState(kdb, zd.ZoneName, DnskeyStatePublished)
				return len(ks) > 0
			}
		}, func(t *testing.T, kdb *KeyDB, zd *ZoneData) {
			maintainStandbyKeys(context.Background(), &Conf, kdb, 1, 0)
		}},
		{"rollover walk ds-published->published", func(t *testing.T, kdb *KeyDB, zd *ZoneData) func(*testing.T) bool {
			// the active KSK's lifetime is long past: the successor's DNSKEY is due
			a := activeKeytags(t, kdb, zd.ZoneName, true)[0]
			if err := RegisterBootstrapActiveKSK(kdb, zd.ZoneName, a, RolloverMethodMultiDS, dns.ED25519); err != nil {
				t.Fatal(err)
			}
			rolloverStamp(t, kdb, zd.ZoneName, a, "active_at", time.Now().Add(-60*24*time.Hour))
			k, _, err := GenerateKskRolloverCreated(kdb, zd.ZoneName, "test", dns.ED25519, RolloverMethodMultiDS)
			if err != nil {
				t.Fatal(err)
			}
			if err := UpdateDnssecKeyState(kdb, zd.ZoneName, k, DnskeyStateDsPublished); err != nil {
				t.Fatal(err)
			}
			rolloverStamp(t, kdb, zd.ZoneName, k, "ds_observed_at", long)
			zd.ParentDSTTLObserved = 3600
			return func(t *testing.T) bool { return keyStateOf(t, kdb, zd.ZoneName, k) != DnskeyStateDsPublished }
		}, func(t *testing.T, kdb *KeyDB, zd *ZoneData) {
			TransitionRolloverKskDsPublishedToPublished(context.Background(), &Conf, kdb, time.Now(), time.Minute)
		}},
		{"rollover walk published->standby", func(t *testing.T, kdb *KeyDB, zd *ZoneData) func(*testing.T) bool {
			k, _, err := GenerateKskRolloverCreated(kdb, zd.ZoneName, "test", dns.ED25519, RolloverMethodMultiDS)
			if err != nil {
				t.Fatal(err)
			}
			if err := UpdateDnssecKeyState(kdb, zd.ZoneName, k, DnskeyStatePublished); err != nil {
				t.Fatal(err)
			}
			rolloverStamp(t, kdb, zd.ZoneName, k, "published_at", long)
			rolloverStamp(t, kdb, zd.ZoneName, k, "ds_observed_at", long)
			zd.ParentDSTTLObserved = 3600
			return func(t *testing.T) bool { return keyStateOf(t, kdb, zd.ZoneName, k) == DnskeyStateStandby }
		}, func(t *testing.T, kdb *KeyDB, zd *ZoneData) {
			TransitionRolloverKskPublishedToStandby(context.Background(), &Conf, kdb, time.Now(), time.Minute)
		}},
		{"rollover tick", func(t *testing.T, kdb *KeyDB, zd *ZoneData) func(*testing.T) bool {
			return func(t *testing.T) bool { return len(keystoreWrites(t, kdb)) > 0 }
		}, func(t *testing.T, kdb *KeyDB, zd *ZoneData) {
			// the walks over every zone, and the tick entered directly for
			// this zone, as a caller with its own deps would
			ktInstallFakeParent(t)
			rolloverAutomatedForAllZones(context.Background(), &Conf, kdb, time.Minute, time.Now())
			promoteStandbyKskBootstrapAll(&Conf, kdb)
			rolloverZsksForAllZones(context.Background(), &Conf, kdb, time.Minute, time.Now())
			deps := ktDeps(zd, kdb, time.Now())
			deps.Imr = &Imr{}
			if err := RolloverAutomatedTick(context.Background(), deps); err != nil {
				t.Fatalf("tick: %v", err)
			}
		}},
		{"ensure: promotion", func(t *testing.T, kdb *KeyDB, zd *ZoneData) func(*testing.T) bool {
			// no active KSK, a published one: EnsureActiveDnssecKeys promotes it
			for _, k := range activeKeytags(t, kdb, zd.ZoneName, true) {
				if err := UpdateDnssecKeyState(kdb, zd.ZoneName, k, DnskeyStateRetired); err != nil {
					t.Fatal(err)
				}
			}
			k := ktGenKSK(t, kdb, zd.ZoneName, DnskeyStatePublished, dns.ED25519)
			return func(t *testing.T) bool { return keyStateOf(t, kdb, zd.ZoneName, k) == DnskeyStateActive }
		}, func(t *testing.T, kdb *KeyDB, zd *ZoneData) {
			zd.EnsureActiveDnssecKeys(kdb, false)
		}},
		{"ensure: minting", func(t *testing.T, kdb *KeyDB, zd *ZoneData) func(*testing.T) bool {
			for _, k := range activeKeytags(t, kdb, zd.ZoneName, false) {
				if err := UpdateDnssecKeyState(kdb, zd.ZoneName, k, DnskeyStateRetired); err != nil {
					t.Fatal(err)
				}
			}
			return func(t *testing.T) bool { return len(activeKeytags(t, kdb, zd.ZoneName, false)) > 0 }
		}, func(t *testing.T, kdb *KeyDB, zd *ZoneData) {
			zd.EnsureActiveDnssecKeys(kdb, false)
		}},
		{"ensure: algorithm reconcile", func(t *testing.T, kdb *KeyDB, zd *ZoneData) func(*testing.T) bool {
			// a published KSK of an algorithm the policy does not want: the
			// reconcile retires it
			k := ktGenKSK(t, kdb, zd.ZoneName, DnskeyStatePublished, dns.ECDSAP256SHA256)
			return func(t *testing.T) bool { return keyStateOf(t, kdb, zd.ZoneName, k) != DnskeyStatePublished }
		}, func(t *testing.T, kdb *KeyDB, zd *ZoneData) {
			zd.EnsureActiveDnssecKeys(kdb, false)
		}},
		{"first-load validation", func(t *testing.T, kdb *KeyDB, zd *ZoneData) func(*testing.T) bool {
			zd.DnssecPolicy.Clamping.Enabled = true
			zd.DnssecPolicy.Clamping.Margin = time.Minute // E5: below min(served DNSKEY TTL, sigvalidity.dnskey)
			return func(t *testing.T) bool {
				return zd.HasError(RolloverPolicyViolation) || zd.HasError(RolloverPolicyWarning)
			}
		}, func(t *testing.T, kdb *KeyDB, zd *ZoneData) {
			EvaluateRolloverPolicyInvariants(zd, zd.DnssecPolicy)
		}},
	}
}

func activeKeytags(t *testing.T, kdb *KeyDB, zone string, sep bool) []uint16 {
	t.Helper()
	ks, err := GetDnssecKeysByState(kdb, zone, DnskeyStateActive)
	if err != nil {
		t.Fatal(err)
	}
	var out []uint16
	for _, k := range ks {
		if (k.Flags&dns.SEP != 0) == sep {
			out = append(out, k.KeyTag)
		}
	}
	return out
}

// T2.1: every lifecycle path skips an owned zone and writes nothing; every
// lifecycle verb is refused, naming the owner's command.
func TestOwnedZoneIsLeftAlone(t *testing.T) {
	for _, p := range lifecyclePaths() {
		t.Run(p.name, func(t *testing.T) {
			kdb := newTestKeyDB(t)
			zd := ownerZone(t, kdb, "owned.example.")
			owner := &testOwner{owns: map[string]bool{zd.ZoneName: true}}
			installOwner(t, owner)
			check := p.setup(t, kdb, zd)
			resetKeystoreWrites(t, kdb)
			zd.ClearError(RolloverPolicyViolation)
			zd.ClearError(RolloverPolicyWarning)
			p.run(t, kdb, zd)
			if w := keystoreWrites(t, kdb); len(w) != 0 {
				t.Errorf("the path wrote to the keystore of an owned zone: %v", w)
			}
			if check(t) {
				t.Errorf("the path acted on the owned zone")
			}
			if len(owner.asked) == 0 {
				t.Errorf("the path never asked the owner")
			}
		})
	}
}

// The verbs §3.5 refuses, each through the function its API handler calls.
type lifecycleVerb struct {
	name string
	verb string // what the refusal must name the owner's command for
	call func(t *testing.T, kdb *KeyDB, zd *ZoneData) error
}

func lifecycleVerbs() []lifecycleVerb {
	ctx := context.Background()
	mgmt := func(sub string) func(*testing.T, *KeyDB, *ZoneData) error {
		return func(t *testing.T, kdb *KeyDB, zd *ZoneData) error {
			_, err := kdb.DnssecKeyMgmt(ctx, nil, KeystorePost{Command: "dnssec-mgmt", SubCommand: sub, Zone: zd.ZoneName, Keyname: zd.ZoneName, KeyType: "KSK", State: DnskeyStateStandby, Keyid: activeKeytagsOr0(t, kdb, zd.ZoneName)})
			return err
		}
	}
	return []lifecycleVerb{
		{"keystore rollover", "rollover", func(t *testing.T, kdb *KeyDB, zd *ZoneData) error {
			_, _, err := kdb.RolloverKey(zd.ZoneName, "KSK", nil)
			return err
		}},
		{"keystore API rollover", "rollover", mgmt("rollover")},
		{"keystore API clear", "clear", mgmt("clear")},
		{"keystore API policy-cleanup", "policy-cleanup", mgmt("policy-cleanup")},
		{"keystore API setstate without flags", "setstate", mgmt("setstate")},
		{"rollover asap (KSK)", "asap", func(t *testing.T, kdb *KeyDB, zd *ZoneData) error {
			return SetManualRolloverRequest(kdb, zd.ZoneName, time.Now(), time.Now())
		}},
		{"rollover asap (ZSK)", "asap", func(t *testing.T, kdb *KeyDB, zd *ZoneData) error {
			return SetZskManualRolloverRequest(kdb, zd.ZoneName, time.Now(), time.Now())
		}},
		{"rollover cancel: alg-roll abort", "cancel", func(t *testing.T, kdb *KeyDB, zd *ZoneData) error {
			_, err := AbortKskAlgRollover(ctx, &Conf, kdb, zd.ZoneName)
			return err
		}},
		{"rollover cancel (KSK manual request)", "cancel", func(t *testing.T, kdb *KeyDB, zd *ZoneData) error {
			return ClearManualRolloverRequest(kdb, zd.ZoneName)
		}},
		{"rollover cancel (ZSK manual request)", "cancel", func(t *testing.T, kdb *KeyDB, zd *ZoneData) error {
			return ClearZskManualRolloverRequest(kdb, zd.ZoneName)
		}},
		{"atomic rollover", "rollover", func(t *testing.T, kdb *KeyDB, zd *ZoneData) error {
			_, _, err := AtomicRollover(&Conf, kdb, zd.ZoneName)
			return err
		}},
		{"rollover reset", "reset", func(t *testing.T, kdb *KeyDB, zd *ZoneData) error {
			return ClearLastRolloverError(kdb, zd.ZoneName, 0)
		}},
		{"rollover unstick", "unstick", func(t *testing.T, kdb *KeyDB, zd *ZoneData) error {
			return UnstickRollover(kdb, zd.ZoneName)
		}},
		{"algorithm rollover spawn", "alg-rollover", func(t *testing.T, kdb *KeyDB, zd *ZoneData) error {
			_, err := SpawnKskAlgRollover(&Conf, kdb, zd.ZoneName, dns.ED25519, dns.ECDSAP256SHA256)
			return err
		}},
		{"zone policy-change", "policy-change", func(t *testing.T, kdb *KeyDB, zd *ZoneData) error {
			_, err := changeZonePolicy(ctx, zd, kdb, "other")
			return err
		}},
		{"zone policy-reset", "policy-reset", func(t *testing.T, kdb *KeyDB, zd *ZoneData) error {
			_, err := resetZonePolicy(ctx, zd, kdb, true)
			return err
		}},
	}
}

func activeKeytagsOr0(t *testing.T, kdb *KeyDB, zone string) uint16 {
	t.Helper()
	if ks := activeKeytags(t, kdb, zone, true); len(ks) > 0 {
		return ks[0]
	}
	return 0
}

func TestOwnedZoneRefusesLifecycleVerbs(t *testing.T) {
	for _, v := range lifecycleVerbs() {
		t.Run(v.name, func(t *testing.T) {
			kdb := newTestKeyDB(t)
			zd := ownerZone(t, kdb, "owned.example.")
			owner := &testOwner{owns: map[string]bool{zd.ZoneName: true}}
			installOwner(t, owner)
			resetKeystoreWrites(t, kdb)
			err := v.call(t, kdb, zd)
			if err == nil {
				t.Fatalf("%s on an owned zone was not refused", v.name)
			}
			if !errors.Is(err, ErrZoneOwned) {
				t.Errorf("%s: the refusal is not ErrZoneOwned: %v", v.name, err)
			}
			if want := owner.Command(v.verb); !strings.Contains(err.Error(), want) {
				t.Errorf("%s: the refusal does not name the owner's command %q: %v", v.name, want, err)
			}
			if w := keystoreWrites(t, kdb); len(w) != 0 {
				t.Errorf("%s: the refused verb wrote: %v", v.name, w)
			}
		})
	}
}

// T2.2: with no owner registered the same paths behave as today: they act.
func TestNotOwnedZoneKeepsTodaysLifecycle(t *testing.T) {
	for _, p := range lifecyclePaths() {
		t.Run(p.name, func(t *testing.T) {
			kdb := newTestKeyDB(t)
			zd := ownerZone(t, kdb, "plain.example.")
			zd.Options[OptMultiProvider] = false // a tdns zone
			check := p.setup(t, kdb, zd)
			resetKeystoreWrites(t, kdb)
			zd.ClearError(RolloverPolicyViolation)
			zd.ClearError(RolloverPolicyWarning)
			p.run(t, kdb, zd)
			if !check(t) {
				t.Errorf("the path did not act on a zone nobody owns (writes: %v)", keystoreWrites(t, kdb))
			}
		})
	}
}

// T2.3: a multi-provider zone the registered owner does not own keeps
// today's behaviour, hooks included: the owner's rollout is per zone.
func TestMultiProviderZoneNotOwnedKeepsHooks(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := ownerZone(t, kdb, "notyet.example.")
	owner := &testOwner{owns: map[string]bool{}} // registered, owns nothing
	installOwner(t, owner)
	held := map[uint16]bool{}
	RegisterKeyLifecycleHooks(KeyLifecycleHooks{
		MayPromote:  func(_ *ZoneData, keyid uint16) bool { return !held[keyid] },
		MayGenerate: func(_ *ZoneData, _ string) bool { return false },
	})
	t.Cleanup(func() { RegisterKeyLifecycleHooks(KeyLifecycleHooks{}) })

	for _, k := range activeKeytags(t, kdb, zd.ZoneName, true) {
		if err := UpdateDnssecKeyState(kdb, zd.ZoneName, k, DnskeyStateRetired); err != nil {
			t.Fatal(err)
		}
	}
	k := ktGenKSK(t, kdb, zd.ZoneName, DnskeyStatePublished, dns.ED25519)
	held[k] = true
	zd.EnsureActiveDnssecKeys(kdb, false)
	if st := keyStateOf(t, kdb, zd.ZoneName, k); st != DnskeyStatePublished {
		t.Errorf("the hook held the key back but it is %s: the owner's answer was not honoured as 'not owned'", st)
	}
	held[k] = false
	zd.EnsureActiveDnssecKeys(kdb, false)
	if st := keyStateOf(t, kdb, zd.ZoneName, k); st != DnskeyStateActive {
		t.Errorf("with the hook releasing the key it is %s, want active: today's behaviour", st)
	}
	// and a lifecycle verb is not refused
	if _, _, err := kdb.RolloverKey(zd.ZoneName, "ZSK", nil); err != nil && errors.Is(err, ErrZoneOwned) {
		t.Errorf("a verb on a zone the owner does not own was refused as owned: %v", err)
	}
}

// T2.4: every caller of the key-writing functions is on the list of
// ownership-checked paths; a new caller fails until it is checked and listed.
func TestKeyWritersAreOwnershipChecked(t *testing.T) {
	writers := map[string]bool{"UpdateDnssecKeyState": true, "UpdateDnssecKeyStateTx": true, "PromoteDnssecKey": true, "GenerateKeypair": true, "UpdateKeyRow": true, "UpdateKeyRowFrom": true}
	// function (or method, as Type.Method) -> why it may call a writer
	allowed := map[string]string{
		"AbortKskAlgRollover":                     "refuses an owned zone (cancel)",
		"AtomicRollover":                          "refuses an owned zone (rollover)",
		"GenerateAndStageKey":                     "refuses an owned zone (generate)",
		"GenerateKskRolloverCreated":              "reached from RolloverAutomatedTick, which skips an owned zone",
		"KeyDB.DnssecKeyMgmt":                     "every lifecycle verb refuses an owned zone; setstate names the columns",
		"KeyDB.forceZoneKeysToPolicyRoles":        "refuses an owned zone (policy-reset)",
		"PromoteStandbyKskIfNoActive":             "skips an owned zone",
		"RolloverAutomatedTick":                   "skips an owned zone",
		"SpawnKskAlgRollover":                     "refuses an owned zone (alg-rollover)",
		"ZoneData.EnsureActiveDnssecKeys":         "returns an owned zone's active set untouched",
		"ZoneData.reconcileActiveKeyAlgorithms":   "reached from EnsureActiveDnssecKeys only",
		"advanceCreatedKeysInRangeTx":             "reached from the tick's confirm only",
		"capStandbyZsksByCount":                   "reached from maintainStandbyKeys, which skips an owned zone",
		"freezeNonActiveSEPKeysTx":                "reached from SpawnKskAlgRollover only",
		"transitionDsPublishedForManualRollover":  "the ds-published walk skips an owned zone",
		"transitionDsPublishedToPublishedForZone": "the ds-published walk skips an owned zone",
		"transitionPublishedToStandby":            "leaves an owned zone's keys alone",
		"transitionPublishedToStandbyForZone":     "the published walk skips an owned zone",
		"transitionRetiredToRemoved":              "leaves an owned zone's keys alone",
		"withdrawKskAlgRoll":                      "reached from the tick only",
		// SIG(0) keys (KEY records) share GenerateKeypair; they are not part
		// of the DNSSEC key lifecycle an owner runs.
		"KeyDB.SendSig0KeyUpdate": "SIG(0) keys, outside the owner's lifecycle",
		"KeyDB.Sig0KeyMgmt":       "SIG(0) keys, outside the owner's lifecycle",
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	found := map[string][]string{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		for _, d := range af.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			name := fd.Name.Name
			if fd.Recv != nil && len(fd.Recv.List) > 0 {
				if st, ok := fd.Recv.List[0].Type.(*ast.StarExpr); ok {
					if id, ok := st.X.(*ast.Ident); ok {
						name = id.Name + "." + name
					}
				}
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				var callee string
				switch fn := call.Fun.(type) {
				case *ast.Ident:
					callee = fn.Name
				case *ast.SelectorExpr:
					callee = fn.Sel.Name
				}
				if writers[callee] && !writers[fd.Name.Name] {
					found[name] = append(found[name], callee)
				}
				return true
			})
		}
	}
	var unlisted []string
	for fn := range found {
		if _, ok := allowed[fn]; !ok {
			unlisted = append(unlisted, fn)
		}
	}
	sort.Strings(unlisted)
	if len(unlisted) > 0 {
		t.Errorf("callers of a key writer that are not on the ownership-checked list (check them, then list them here):\n  %s", strings.Join(unlisted, "\n  "))
	}
	for fn := range allowed {
		if _, ok := found[fn]; !ok {
			t.Errorf("%s is on the list but calls no key writer any more; remove it", fn)
		}
	}
}

// T2.5: for an owned zone the DS intent is the owner's; an unset answer is
// unknown, whatever the rows say.
func TestOwnedZoneDSIntentIsTheOwners(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := ownerZone(t, kdb, "owned.example.")
	// the owner has written ds on the active KSK (a multi-provider zone's
	// rows get none from tdns)
	if _, err := kdb.DB.Exec(`UPDATE DnssecKeyStore SET ds=1 WHERE zonename=? AND state=? AND (flags & 1) = 1`, zd.ZoneName, DnskeyStateActive); err != nil {
		t.Fatal(err)
	}
	known, rows := dsIntentKeytags(t, kdb, zd.ZoneName)
	if !known || len(rows) == 0 {
		t.Fatal("fixture: the rows give no DS intent")
	}
	owner := &testOwner{owns: map[string]bool{zd.ZoneName: true}, intent: map[string]DSIntent{}}
	installOwner(t, owner)
	in, err := DSIntentForZone(kdb, zd.ZoneName, dns.SHA256)
	if err != nil || in.Known {
		t.Errorf("owner without an answer: known=%v err=%v, want unknown (the rows say %v)", in.Known, err, rows)
	}
	ds := &dns.DS{Hdr: dns.RR_Header{Name: zd.ZoneName, Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 3600}, KeyTag: 4711, Algorithm: dns.ED25519, DigestType: dns.SHA256, Digest: strings.Repeat("ab", 32)}
	owner.intent[zd.ZoneName] = DSIntent{Set: []dns.RR{ds}, Known: true}
	in, err = DSIntentForZone(kdb, zd.ZoneName, dns.SHA256)
	if err != nil || !in.Known || len(in.Set) != 1 || in.Set[0].(*dns.DS).KeyTag != 4711 {
		t.Errorf("owner with an answer: known=%v set=%v err=%v, want the owner's one DS", in.Known, in.Set, err)
	}
}

// T2.6: on an owned zone, setstate without the columns is refused; with
// them it goes through the write function, with the given columns.
func TestOwnedZoneSetstateNeedsTheColumns(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := ownerZone(t, kdb, "owned.example.")
	installOwner(t, &testOwner{owns: map[string]bool{zd.ZoneName: true}})
	k := ktGenKSK(t, kdb, zd.ZoneName, DnskeyStatePublished, dns.ED25519)
	resetKeystoreWrites(t, kdb)
	_, err := kdb.DnssecKeyMgmt(context.Background(), nil, KeystorePost{Command: "dnssec-mgmt", SubCommand: "setstate", Keyname: zd.ZoneName, Zone: zd.ZoneName, Keyid: k, State: DnskeyStateStandby})
	if err == nil || !errors.Is(err, ErrZoneOwned) {
		t.Fatalf("setstate without the columns on an owned zone: err=%v, want ErrZoneOwned", err)
	}
	if w := keystoreWrites(t, kdb); len(w) != 0 {
		t.Errorf("the refused setstate wrote: %v", w)
	}
	yes, no := true, false
	_, err = kdb.DnssecKeyMgmt(context.Background(), nil, KeystorePost{Command: "dnssec-mgmt", SubCommand: "setstate", Keyname: zd.ZoneName, Zone: zd.ZoneName, Keyid: k, State: "mpdist", Pub: &yes, Sign: &no, DS: &no})
	if err != nil {
		t.Fatalf("setstate with the columns: %v", err)
	}
	pub, sign, ds := readKeyRowFlags(t, kdb, zd.ZoneName, k)
	if keyStateOf(t, kdb, zd.ZoneName, k) != "mpdist" || pub == nil || *pub != 1 || sign == nil || *sign != 0 || ds == nil || *ds != 0 {
		t.Errorf("after setstate with the columns: state=%s pub=%s sign=%s ds=%s, want mpdist 1 0 0", keyStateOf(t, kdb, zd.ZoneName, k), flagString(pub), flagString(sign), flagString(ds))
	}
	if w := keystoreWrites(t, kdb); len(w) != 1 {
		t.Errorf("setstate with the columns made %d writes, want 1: %v", len(w), w)
	}
}

// policy-set on an owned zone (design Q1): a policy that changes an owner
// field, the KSK algorithm here, is refused; one that changes only a
// mechanism field, the signature validity, is not refused as owned.
func TestOwnedZonePolicySetKeepsTheOwnersFields(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := ownerZone(t, kdb, "owned.example.")
	installOwner(t, &testOwner{owns: map[string]bool{zd.ZoneName: true}})
	same := *zd.DnssecPolicy
	ttl := *zd.DnssecPolicy
	ttl.SigValidity.Default = zd.DnssecPolicy.SigValidity.Default + 3600
	alg := *zd.DnssecPolicy
	alg.KSKAlgorithm = dns.RSASHA256
	withLivePolicies(t, map[string]DnssecPolicy{"same": same, "ttl": ttl, "alg": alg})
	resetKeystoreWrites(t, kdb)
	if _, err := setZonePolicy(context.Background(), zd, kdb, "alg"); err == nil || !errors.Is(err, ErrZoneOwned) {
		t.Errorf("policy-set to a policy with another KSK algorithm on an owned zone: err=%v, want ErrZoneOwned", err)
	}
	if w := keystoreWrites(t, kdb); len(w) != 0 {
		t.Errorf("the refused policy-set wrote: %v", w)
	}
	for _, name := range []string{"same", "ttl"} {
		if _, err := setZonePolicy(context.Background(), zd, kdb, name); err != nil && errors.Is(err, ErrZoneOwned) {
			t.Errorf("policy-set to %q, which keeps the owner's fields, was refused as owned: %v", name, err)
		}
	}
}
