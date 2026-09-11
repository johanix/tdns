package tdns

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// KT-11 (F2): the pending-child-withdraw phase strips a retired KSK's RRSIGs
// from the served zone before marking it removed, and a strip failure leaves
// the key retired for retry. Drives RolloverAutomatedTick against a real
// on-disk KeyDB and a real signed zone.

const ktWithdrawZone = "withdraw.example."

const ktWithdrawZoneText = `withdraw.example.	3600	IN	SOA	ns.withdraw.example. hostmaster.withdraw.example. 1 7200 1800 604800 7200
withdraw.example.	3600	IN	NS	ns.withdraw.example.
ns.withdraw.example.	3600	IN	A	192.0.2.1
www.withdraw.example.	3600	IN	A	192.0.2.2
`

// ktMultiDSPolicy is a KSK-ZSK policy with the multi-DS engine configured
// and a short clamping margin, so a withdraw-phase test can run its clock
// with a backdated retired_at.
func ktMultiDSPolicy(ksk, zsk uint8) *DnssecPolicy {
	return &DnssecPolicy{
		Name:         "mds",
		Mode:         DnssecPolicyModeKSKZSK,
		KSKAlgorithm: ksk,
		ZSKAlgorithm: zsk,
		KSK:          KeyLifetime{Lifetime: 30 * 86400},
		SigValidity:  PolicySigValidity{Default: 14 * 86400, DNSKEY: 14 * 86400, DS: 14 * 86400},
		Rollover: RolloverPolicy{
			Method:         RolloverMethodMultiDS,
			NumDS:          2,
			DsPublishDelay: 5 * time.Minute,
		},
		Clamping: ClampingPolicy{Margin: time.Minute},
	}
}

// ktEngineZone builds a signable, registered zone bound to pol with a
// real KeyDB attached.
func ktEngineZone(t *testing.T, kdb *KeyDB, name, text string, pol *DnssecPolicy) *ZoneData {
	t.Helper()
	zd := testZone(t, name, text)
	registerZones(t, zd)
	zd.KeyDB = kdb
	zd.Options = map[ZoneOption]bool{OptInlineSigning: true}
	zd.DnssecPolicy = pol
	zd.DnssecPolicyName = pol.Name
	zd.InstallInitialSnapshot()
	return zd
}

func ktGenKSK(t *testing.T, kdb *KeyDB, zone, state string, alg uint8) uint16 {
	t.Helper()
	pkc, _, err := kdb.GenerateKeypair(zone, "test", state, dns.TypeDNSKEY, alg, "KSK", nil)
	if err != nil {
		t.Fatalf("generate KSK (%s, %s): %v", state, dns.AlgorithmToString[alg], err)
	}
	return pkc.KeyId
}

func ktGenZSK(t *testing.T, kdb *KeyDB, zone, state string, alg uint8) uint16 {
	t.Helper()
	pkc, _, err := kdb.GenerateKeypair(zone, "test", state, dns.TypeDNSKEY, alg, "ZSK", nil)
	if err != nil {
		t.Fatalf("generate ZSK (%s, %s): %v", state, dns.AlgorithmToString[alg], err)
	}
	return pkc.KeyId
}

func ktKeyState(t *testing.T, kdb *KeyDB, zone string, keyid uint16) string {
	t.Helper()
	var st string
	if err := kdb.DB.QueryRow(`SELECT state FROM DnssecKeyStore WHERE zonename=? AND keyid=?`, zone, int(keyid)).Scan(&st); err != nil {
		t.Fatalf("state of %d: %v", keyid, err)
	}
	return st
}

func ktHasKeytag(tags []uint16, want uint16) bool {
	for _, k := range tags {
		if k == want {
			return true
		}
	}
	return false
}

func ktSetInProgress(t *testing.T, kdb *KeyDB, zone string, v bool) {
	t.Helper()
	if err := EnsureRolloverZoneRow(kdb, zone); err != nil {
		t.Fatalf("EnsureRolloverZoneRow: %v", err)
	}
	tx, err := kdb.Begin("test")
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := setRolloverInProgressTx(tx, zone, v); err != nil {
		tx.Rollback()
		t.Fatalf("setRolloverInProgressTx: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

func ktBackdateRetiredAt(t *testing.T, kdb *KeyDB, zone string, keyid uint16, at time.Time) {
	t.Helper()
	if _, err := kdb.DB.Exec(`UPDATE DnssecKeyStore SET retired_at=? WHERE zonename=? AND keyid=?`,
		at.UTC().Format(time.RFC3339), zone, int(keyid)); err != nil {
		t.Fatalf("backdate retired_at on %d: %v", keyid, err)
	}
}

// ktWithdrawFixture: two KSKs (A retired with a long-elapsed retired_at, B
// active), both having signed the apex DNSKEY RRset, zone parked in
// pending-child-withdraw with rollover_in_progress set.
func ktWithdrawFixture(t *testing.T) (*ZoneData, *KeyDB, uint16, uint16) {
	t.Helper()
	kdb := newTestKeyDB(t)
	pol := ktMultiDSPolicy(dns.ED25519, dns.ED25519)
	zd := ktEngineZone(t, kdb, ktWithdrawZone, ktWithdrawZoneText, pol)

	a := ktGenKSK(t, kdb, ktWithdrawZone, DnskeyStateActive, dns.ED25519)
	ktGenZSK(t, kdb, ktWithdrawZone, DnskeyStateActive, dns.ED25519)
	if _, err := zd.SignZone(kdb, true); err != nil {
		t.Fatalf("SignZone (A): %v", err)
	}
	b := ktGenKSK(t, kdb, ktWithdrawZone, DnskeyStateActive, dns.ED25519)
	if _, err := zd.SignZone(kdb, true); err != nil {
		t.Fatalf("SignZone (A+B): %v", err)
	}
	tags := zd.mustRRSIGKeytags(t, ktWithdrawZone, dns.TypeDNSKEY)
	if !ktHasKeytag(tags, a) || !ktHasKeytag(tags, b) {
		t.Fatalf("fixture: apex DNSKEY RRSIG keytags = %v, want both %d and %d", tags, a, b)
	}

	if err := UpdateDnssecKeyState(kdb, ktWithdrawZone, a, DnskeyStateRetired); err != nil {
		t.Fatalf("retire A: %v", err)
	}
	ktBackdateRetiredAt(t, kdb, ktWithdrawZone, a, time.Now().Add(-2*time.Hour))
	ktSetInProgress(t, kdb, ktWithdrawZone, true)
	if err := SetRolloverPhase(kdb, ktWithdrawZone, rolloverPhasePendingChildWithdraw); err != nil {
		t.Fatalf("SetRolloverPhase: %v", err)
	}
	return zd, kdb, a, b
}

func ktDeps(zd *ZoneData, kdb *KeyDB, now time.Time) RolloverEngineDeps {
	return RolloverEngineDeps{
		Conf:             &Conf,
		KDB:              kdb,
		Zone:             zd,
		Policy:           zd.DnssecPolicy,
		Logger:           lgSigner,
		PropagationDelay: time.Minute,
		Now:              func() time.Time { return now },
	}
}

func TestKT11WithdrawStripsRemovedKeyRRSIGs(t *testing.T) {
	zd, kdb, a, b := ktWithdrawFixture(t)

	if err := RolloverAutomatedTick(context.Background(), ktDeps(zd, kdb, time.Now())); err != nil {
		t.Fatalf("tick: %v", err)
	}

	if st := ktKeyState(t, kdb, ktWithdrawZone, a); st != DnskeyStateRemoved {
		t.Fatalf("A state = %s, want removed", st)
	}
	tags := zd.mustRRSIGKeytags(t, ktWithdrawZone, dns.TypeDNSKEY)
	if ktHasKeytag(tags, a) {
		t.Fatalf("RRSIG by removed KSK %d still on the apex DNSKEY RRset: %v", a, tags)
	}
	if !ktHasKeytag(tags, b) {
		t.Fatalf("RRSIG by the active KSK %d missing after withdraw: %v", b, tags)
	}
	row, err := LoadRolloverZoneRow(kdb, ktWithdrawZone)
	if err != nil || row == nil {
		t.Fatalf("LoadRolloverZoneRow: row=%v err=%v", row, err)
	}
	if row.RolloverInProgress || row.RolloverPhase != rolloverPhaseIdle {
		t.Fatalf("after withdraw: in_progress=%v phase=%q, want false/idle", row.RolloverInProgress, row.RolloverPhase)
	}
}

func TestKT11WithdrawStripFailureLeavesKeyRetired(t *testing.T) {
	zd, kdb, a, _ := ktWithdrawFixture(t)

	// A cancelled context makes StripZoneRRSIGs fail before it touches
	// anything; the state write must not happen.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := RolloverAutomatedTick(ctx, ktDeps(zd, kdb, time.Now())); err != nil {
		t.Fatalf("tick: %v", err)
	}

	if st := ktKeyState(t, kdb, ktWithdrawZone, a); st != DnskeyStateRetired {
		t.Fatalf("A state = %s after a failed strip, want retired (retry next tick)", st)
	}
	if tags := zd.mustRRSIGKeytags(t, ktWithdrawZone, dns.TypeDNSKEY); !ktHasKeytag(tags, a) {
		t.Fatalf("RRSIG by %d was removed although the key is still retired: %v", a, tags)
	}
	row, _ := LoadRolloverZoneRow(kdb, ktWithdrawZone)
	if row == nil || !row.RolloverInProgress || row.RolloverPhase != rolloverPhasePendingChildWithdraw {
		t.Fatalf("a failed strip must leave the zone in pending-child-withdraw: %+v", row)
	}
}
