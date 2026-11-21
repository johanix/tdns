package tdns

import (
	"context"
	"io"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// A parent that answers NOERROR to an UPDATE signed with the zone's SIG(0) key
// trusts the key, whether or not it speaks KeyState (tdns-mp #404). The child
// records it as trusted, as a KeyState answer would.

// sig0ParentState is what the keystore holds of the parent's view of the key.
func sig0ParentState(t *testing.T, kdb *KeyDB, zone string, keyid uint16) uint8 {
	t.Helper()
	var state int
	if err := kdb.DB.QueryRow("SELECT parent_state FROM Sig0KeyStore WHERE zonename=? AND keyid=?",
		zone, keyid).Scan(&state); err != nil {
		t.Fatalf("parent_state of %s key %d: %v", zone, keyid, err)
	}
	return uint8(state)
}

// proofChild is a child with one active SIG(0) key, whose delegation sync goes
// to a parent that answers rcode. Its own KeyDB is nil, so a BADKEY
// re-bootstrap ends at once.
func proofChild(t *testing.T, rcode int) (*ZoneData, *KeyDB, uint16, *DsyncTarget) {
	t.Helper()
	const zone = "child.parent.example."
	kdb := newTestKeyDB(t)
	keyid := generateSig0Key(t, kdb, zone, Sig0StateActive)
	zd := &ZoneData{ZoneName: zone, Logger: log.New(io.Discard, "", 0)}
	zd.SetParent("parent.example.")
	target := &DsyncTarget{Name: "parent.example.", Addresses: []string{startRcodeResponder(t, rcode)}}
	return zd, kdb, keyid, target
}

func proofSync(t *testing.T) DelegationSyncStatus {
	t.Helper()
	ns, err := dns.NewRR("child.parent.example. 3600 IN NS ns1.child.parent.example.")
	if err != nil {
		t.Fatal(err)
	}
	return DelegationSyncStatus{NsAdds: []dns.RR{ns}}
}

func TestAnAcceptedUpdateRecordsTheKeyTrusted(t *testing.T) {
	zd, kdb, keyid, target := proofChild(t, dns.RcodeSuccess)
	if got := sig0ParentState(t, kdb, zd.ZoneName, keyid); got != 0 {
		t.Fatalf("a new key starts at parent_state %d, want 0", got)
	}
	_, rcode, _, err := zd.sendDelegationUpdate(context.Background(), kdb, proofSync(t), target,
		UpdateModeDelta, 1, time.Millisecond)
	if err != nil || rcode != dns.RcodeSuccess {
		t.Fatalf("sync: rcode %s, err %v", dns.RcodeToString[int(rcode)], err)
	}
	if got := sig0ParentState(t, kdb, zd.ZoneName, keyid); got != edns0.KeyStateTrusted {
		t.Errorf("parent_state %s after a NOERROR, want trusted", edns0.KeyStateToString(got))
	}
}

// A verdict the parent gave by KeyState earlier gives way to an UPDATE it has
// since accepted: that is the later proof.
func TestAnAcceptedUpdateOverridesAnEarlierVerdict(t *testing.T) {
	zd, kdb, keyid, target := proofChild(t, dns.RcodeSuccess)
	UpdateParentState(kdb, zd.ZoneName, keyid, edns0.KeyStateValidationFail)
	if _, _, _, err := zd.sendDelegationUpdate(context.Background(), kdb, proofSync(t), target,
		UpdateModeDelta, 1, time.Millisecond); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if got := sig0ParentState(t, kdb, zd.ZoneName, keyid); got != edns0.KeyStateTrusted {
		t.Errorf("parent_state %s after a NOERROR, want trusted", edns0.KeyStateToString(got))
	}
}

func TestARefusedUpdateRecordsNothing(t *testing.T) {
	t.Run("REFUSED", func(t *testing.T) {
		zd, kdb, keyid, target := proofChild(t, dns.RcodeRefused)
		_, _, ur, err := zd.sendDelegationUpdate(context.Background(), kdb, proofSync(t), target,
			UpdateModeDelta, 1, time.Millisecond)
		if err == nil || ur.Rcode != dns.RcodeRefused {
			t.Fatalf("sync: rcode %s, err %v; want the refusal", dns.RcodeToString[ur.Rcode], err)
		}
		if got := sig0ParentState(t, kdb, zd.ZoneName, keyid); got != 0 {
			t.Errorf("parent_state %s after REFUSED, want 0", edns0.KeyStateToString(got))
		}
	})
	t.Run("BADKEY", func(t *testing.T) {
		zd, kdb, keyid, target := proofChild(t, dns.RcodeBadKey)
		_, _, _, err := zd.sendDelegationUpdate(context.Background(), kdb, proofSync(t), target,
			UpdateModeDelta, 2, time.Millisecond)
		// The re-bootstrap ran: its own error (no keystore here) ends the sync.
		if err == nil || !strings.Contains(err.Error(), "re-bootstrap after BADKEY") {
			t.Errorf("sync ended with %v, want the BADKEY re-bootstrap's error", err)
		}
		if got := sig0ParentState(t, kdb, zd.ZoneName, keyid); got != 0 {
			t.Errorf("parent_state %s after BADKEY, want 0", edns0.KeyStateToString(got))
		}
	})
}

// With two active key rows tdns signs with one of them (GetSig0Keys), and
// only that key is recorded.
func TestOnlyTheKeyThatSignedIsRecorded(t *testing.T) {
	zd, kdb, first, target := proofChild(t, dns.RcodeSuccess)
	second := generateSig0Key(t, kdb, zd.ZoneName, Sig0StateActive)
	sak, err := kdb.GetSig0Keys(zd.ZoneName, Sig0StateActive)
	if err != nil || len(sak.Keys) != 1 {
		t.Fatalf("the signing key: err=%v keys=%+v", err, sak)
	}
	signer := sak.Keys[0].KeyRR.KeyTag()
	other := first
	if signer == first {
		other = second
	}
	if _, _, _, err := zd.sendDelegationUpdate(context.Background(), kdb, proofSync(t), target,
		UpdateModeDelta, 1, time.Millisecond); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if got := sig0ParentState(t, kdb, zd.ZoneName, signer); got != edns0.KeyStateTrusted {
		t.Errorf("signing key %d: parent_state %s, want trusted", signer, edns0.KeyStateToString(got))
	}
	if got := sig0ParentState(t, kdb, zd.ZoneName, other); got != 0 {
		t.Errorf("key %d, which did not sign: parent_state %s, want 0", other, edns0.KeyStateToString(got))
	}
}
