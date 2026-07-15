package tdns

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

// withLargeAlgorithm marks alg as a "large algorithm" in the global config for
// the duration of a test and restores the previous set on cleanup. The
// large-algorithm warning helpers read Conf.IsLargeAlgorithm (backed by
// Conf.Internal.LargeAlgorithms).
func withLargeAlgorithm(t *testing.T, alg uint8) {
	t.Helper()
	prev := Conf.Internal.LargeAlgorithms
	Conf.Internal.LargeAlgorithms = map[uint8]bool{alg: true}
	t.Cleanup(func() { Conf.Internal.LargeAlgorithms = prev })
}

// TestResignSOAUnderLockLargeAlgNoSelfDeadlock is the regression test for
// instance #3 of the re-entrant zd.mu self-deadlock class (instances #1/#2 fixed
// in 6e090a9 and 23710d1). The publish-path SOA re-sign holds zd.mu
// (publishWorkingSetLocked -> resignWorkingSetSOAIfSigned) and resolves the keys
// via EnsureActiveDnssecKeys(zdLocked=true). On a zone whose ZSK algorithm is a
// LARGE (PQ) algorithm, the fresh-key generate branch calls
// WarnLargeAlgZoneSigningRole, which read the error list and set a
// DnssecPolicyWarning via zd.ErrorList()/zd.SetError() — both re-acquire zd.mu.
// Go mutexes are not reentrant, so this self-deadlocks and wedges the daemon:
//
//	applyRefreshReplacementLocked -> publishWorkingSetLocked ->
//	resignWorkingSetSOAIfSigned -> EnsureActiveDnssecKeys(zdLocked=true) ->
//	WarnLargeAlgZoneSigningRole -> zd.ErrorList()/zd.SetError() -> zd.mu.Lock()
//
// 23710d1 routed only the DNSKEY publish (PublishDnskeyRRs) through a *Locked
// variant; the large-algorithm warning re-lock — which fires BEFORE the publish
// and only on a large algorithm, so 23710d1's ED25519 test never reached it —
// was missed. The fix threads zdLocked into the two Warn helpers so they use
// errorListLocked/setErrorLocked when the caller already holds zd.mu.
//
// The re-sign runs in a goroutine holding zd.mu; a re-introduced re-lock blocks
// it forever, so the timeout fails the test instead of hanging the whole run.
func TestResignSOAUnderLockLargeAlgNoSelfDeadlock(t *testing.T) {
	kdb := newTestKeyDB(t)

	// Mark ED25519 "large" so the ZSK generated below drives the large-algorithm
	// warning path under the lock — without needing a real (expensive) PQ key.
	withLargeAlgorithm(t, dns.ED25519)

	zone := `resign-large.example.	3600	IN	SOA	ns.resign-large.example. hostmaster.resign-large.example. 1 7200 1800 604800 7200
resign-large.example.	3600	IN	NS	ns.resign-large.example.
`
	zd := testZone(t, "resign-large.example.", zone)
	zd.KeyDB = kdb
	zd.Options = map[ZoneOption]bool{OptOnlineSigning: true}
	zd.DnssecPolicy = &DnssecPolicy{
		Mode:         DnssecPolicyModeKSKZSK,
		KSKAlgorithm: dns.ED25519,
		ZSKAlgorithm: dns.ED25519,
	}
	// No active keys are pre-generated: the first re-sign must GENERATE the ZSK,
	// which triggers WarnLargeAlgZoneSigningRole — the large-algorithm branch that
	// re-locked zd.mu via ErrorList()/SetError().

	done := make(chan struct{})
	go func() {
		zd.mu.Lock() // the publishWorkingSetLocked context: zd.mu held across the re-sign
		defer zd.mu.Unlock()
		zd.ensureWorkingSet()
		zd.resignWorkingSetSOAIfSigned()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("resignWorkingSetSOAIfSigned deadlocked while zd.mu was held (re-entrant zd.mu via EnsureActiveDnssecKeys -> WarnLargeAlgZoneSigningRole -> ErrorList/SetError)")
	}

	// The SOA must actually carry an RRSIG now — proves the re-sign ran to
	// completion (generated keys, published DNSKEYs, signed the SOA).
	zd.mu.Lock()
	apex := zd.workingSet[zd.ZoneName]
	zd.mu.Unlock()
	if apex == nil {
		t.Fatal("apex missing from working set after resign")
	}
	soa := apex.RRtypes.GetOnlyRRSet(dns.TypeSOA)
	if len(soa.RRSIGs) == 0 {
		t.Fatal("SOA was not signed under the lock (re-sign did not complete)")
	}

	// The large-algorithm DnssecPolicyWarning must have been recorded — this
	// proves the warning helper actually executed under the held lock (the exact
	// re-lock site), rather than the test passing because the branch was skipped.
	if !zd.HasError(DnssecPolicyWarning) {
		t.Fatal("expected a DnssecPolicyWarning from the large-algorithm ZSK warning path; the re-lock site was not exercised")
	}
}
