package tdns

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// #934: RolloverSig0KeyWithParent held one keystore transaction across both
// UPDATEs to the parent, began a second while the first was open (every
// action but add), panicked on the nil *Tx that Begin returned, and left the
// keystore locked until a restart. It also read the new key back outside
// that transaction, so it could not see it.

const rolloverZone = `child.example.	3600	IN	SOA	ns.child.example. hostmaster.child.example. 1 7200 1800 604800 7200
child.example.	3600	IN	NS	ns.child.example.
ns.child.example.	3600	IN	A	192.0.2.1
`

const otherRolloverZone = `other.example.	3600	IN	SOA	ns.other.example. hostmaster.other.example. 1 7200 1800 604800 7200
other.example.	3600	IN	NS	ns.other.example.
ns.other.example.	3600	IN	A	192.0.2.2
`

type rolloverAnswer struct {
	rcode int
	err   error
}

// rolloverParent plays the parent: it answers each UPDATE with the next scripted
// answer, keeps what it was sent, and checks that no keystore transaction is
// open while the child waits for it. during, if set, runs while an UPDATE
// waits for its answer.
type rolloverParent struct {
	t       *testing.T
	kdb     *KeyDB
	answers []rolloverAnswer
	sent    []*dns.Msg
	during  func(m *dns.Msg)
}

func (fp *rolloverParent) send(ctx context.Context, m *dns.Msg, zone string, addrs []string) (int, UpdateResult, error) {
	tx, err := fp.kdb.Begin("fake parent")
	if err != nil {
		fp.t.Errorf("keystore transaction held across UPDATE %d: %v", len(fp.sent)+1, err)
	} else {
		tx.Rollback()
	}
	if fp.during != nil {
		fp.during(m)
	}
	fp.sent = append(fp.sent, m.Copy())
	if len(fp.answers) == 0 {
		fp.t.Fatalf("unexpected UPDATE %d", len(fp.sent))
	}
	a := fp.answers[0]
	fp.answers = fp.answers[1:]
	return a.rcode, UpdateResult{}, a.err
}

// newRolloverZone builds a zone with one active SIG(0) key in a real keystore
// and a fake parent that gives the answers listed.
func newRolloverZone(t *testing.T, answers ...rolloverAnswer) (*ZoneData, *KeyDB, *rolloverParent) {
	t.Helper()
	zd := testZone(t, "child.example.", rolloverZone)
	zd.SetParent("example.")
	kdb := newTestKeyDB(t)
	kdb.UpdateQ = make(chan UpdateRequest, 8)
	zd.KeyDB = kdb
	generateSig0Key(t, kdb, zd.ZoneName, Sig0StateActive)

	fp := &rolloverParent{t: t, kdb: kdb, answers: answers}
	prevLookup, prevSend := rolloverLookupDSYNCTarget, rolloverSendUpdate
	rolloverLookupDSYNCTarget = func(ctx context.Context, zone string) (*DsyncTarget, error) {
		return &DsyncTarget{Name: "updates.example.", Addresses: []string{"192.0.2.53:53"}}, nil
	}
	rolloverSendUpdate = fp.send
	t.Cleanup(func() { rolloverLookupDSYNCTarget, rolloverSendUpdate = prevLookup, prevSend })
	return zd, kdb, fp
}

func generateSig0Key(t *testing.T, kdb *KeyDB, zone, state string) uint16 {
	t.Helper()
	resp, err := kdb.Sig0KeyMgmt(nil, KeystorePost{
		Command:    "sig0-mgmt",
		SubCommand: "generate",
		Zone:       zone,
		Algorithm:  dns.ED25519,
		State:      state,
		Creator:    "test",
	})
	if err != nil {
		t.Fatalf("generate %s SIG(0) key: %v", state, err)
	}
	return resp.GeneratedSig0Key.KeyRR.KeyTag()
}

// rolloverKeyStates returns keyid -> state for the zone's SIG(0) keys.
func rolloverKeyStates(t *testing.T, kdb *KeyDB, zone string) map[uint16]string {
	t.Helper()
	rows, err := kdb.Query("SELECT keyid, state FROM Sig0KeyStore WHERE zonename=?", zone)
	if err != nil {
		t.Fatalf("query Sig0KeyStore: %v", err)
	}
	defer rows.Close()
	states := map[uint16]string{}
	for rows.Next() {
		var keyid int
		var state string
		if err := rows.Scan(&keyid, &state); err != nil {
			t.Fatalf("scan Sig0KeyStore: %v", err)
		}
		states[uint16(keyid)] = state
	}
	return states
}

func activeSig0KeyTag(t *testing.T, kdb *KeyDB, zone string) uint16 {
	t.Helper()
	sak, err := kdb.GetSig0Keys(zone, Sig0StateActive)
	if err != nil || len(sak.Keys) == 0 {
		t.Fatalf("no active SIG(0) key for %s: %v", zone, err)
	}
	return sak.Keys[0].KeyRR.KeyTag()
}

// assertKeystoreFree fails unless a new keystore transaction can begin.
func assertKeystoreFree(t *testing.T, kdb *KeyDB) {
	t.Helper()
	tx, err := kdb.Begin("test")
	if err != nil {
		t.Fatalf("keystore left with a transaction open: %v", err)
	}
	tx.Rollback()
}

// updateKey returns the key tag and class of the one KEY in m's update
// section, and the key tag of the SIG(0) that signs m.
func updateKey(t *testing.T, m *dns.Msg) (keyid uint16, class uint16, signer uint16) {
	t.Helper()
	if len(m.Ns) != 1 {
		t.Fatalf("UPDATE carries %d records, want 1: %v", len(m.Ns), m.Ns)
	}
	k, ok := m.Ns[0].(*dns.KEY)
	if !ok {
		t.Fatalf("UPDATE record is %T, want *dns.KEY", m.Ns[0])
	}
	for _, rr := range m.Extra {
		if sig, ok := rr.(*dns.SIG); ok {
			return k.KeyTag(), k.Header().Class, sig.KeyTag
		}
	}
	t.Fatalf("UPDATE is not SIG(0) signed")
	return 0, 0, 0
}

// Every action but add goes on past the ADD. It must finish without a panic,
// leave no transaction open, and use the key the generate step made.
func TestRolloverSig0KeyNonAddActions(t *testing.T) {
	for _, action := range []string{"complete", "remove", "update-local"} {
		t.Run(action, func(t *testing.T) {
			ok := rolloverAnswer{rcode: dns.RcodeSuccess}
			zd, kdb, fp := newRolloverZone(t, ok, ok)
			oldid := activeSig0KeyTag(t, kdb, zd.ZoneName)

			_, gotOld, gotNew, _, err := zd.RolloverSig0KeyWithParent(context.Background(), dns.ED25519, action)
			if err != nil {
				t.Fatalf("RolloverSig0KeyWithParent: %v", err)
			}
			assertKeystoreFree(t, kdb)
			if gotOld != oldid {
				t.Errorf("old keyid = %d, want %d", gotOld, oldid)
			}
			if len(fp.sent) != 2 {
				t.Fatalf("UPDATEs sent = %d, want 2", len(fp.sent))
			}
			if id, class, signer := updateKey(t, fp.sent[0]); id != gotNew || class != dns.ClassINET || signer != oldid {
				t.Errorf("ADD: key %d class %d signed by %d, want key %d class IN signed by %d", id, class, signer, gotNew, oldid)
			}
			if id, class, signer := updateKey(t, fp.sent[1]); id != oldid || class != dns.ClassNONE || signer != gotNew {
				t.Errorf("REMOVE: key %d class %d signed by %d, want key %d class NONE signed by %d", id, class, signer, oldid, gotNew)
			}

			states := rolloverKeyStates(t, kdb, zd.ZoneName)
			if states[gotNew] != Sig0StateActive || states[oldid] != Sig0StateRetired {
				t.Errorf("states after the roll = %v, want %d active and %d retired", states, gotNew, oldid)
			}
			if id := activeSig0KeyTag(t, kdb, zd.ZoneName); id != gotNew {
				t.Errorf("GetSig0Keys returns active key %d, want %d", id, gotNew)
			}

			var published bool
			for _, k := range keyRRsFor(kdb.UpdateQ, zd.ZoneName) {
				published = published || k.KeyTag() == gotNew
			}
			if !published {
				t.Errorf("new key %d was not published", gotNew)
			}
		})
	}
}

// An older created key in the keystore must not be taken for the new one.
func TestRolloverSig0KeyUsesTheGeneratedKey(t *testing.T) {
	ok := rolloverAnswer{rcode: dns.RcodeSuccess}
	zd, kdb, fp := newRolloverZone(t, ok, ok)
	stale := generateSig0Key(t, kdb, zd.ZoneName, Sig0StateCreated)

	_, _, gotNew, _, err := zd.RolloverSig0KeyWithParent(context.Background(), dns.ED25519, "complete")
	if err != nil {
		t.Fatalf("RolloverSig0KeyWithParent: %v", err)
	}
	if gotNew == stale {
		t.Fatalf("rollover used the older created key %d", stale)
	}
	if id, _, _ := updateKey(t, fp.sent[0]); id != gotNew {
		t.Errorf("ADD carries key %d, want the generated key %d", id, gotNew)
	}
	states := rolloverKeyStates(t, kdb, zd.ZoneName)
	if states[gotNew] != Sig0StateActive || states[stale] != Sig0StateCreated {
		t.Errorf("states after the roll = %v, want %d active and %d still created", states, gotNew, stale)
	}
}

// add stops after the parent accepted the new key: the new key stays created
// and the old one stays active.
func TestRolloverSig0KeyAdd(t *testing.T) {
	zd, kdb, fp := newRolloverZone(t, rolloverAnswer{rcode: dns.RcodeSuccess})
	oldid := activeSig0KeyTag(t, kdb, zd.ZoneName)

	_, _, gotNew, _, err := zd.RolloverSig0KeyWithParent(context.Background(), dns.ED25519, "add")
	if err != nil {
		t.Fatalf("RolloverSig0KeyWithParent: %v", err)
	}
	assertKeystoreFree(t, kdb)
	if len(fp.sent) != 1 {
		t.Fatalf("UPDATEs sent = %d, want 1", len(fp.sent))
	}
	states := rolloverKeyStates(t, kdb, zd.ZoneName)
	if states[gotNew] != Sig0StateCreated || states[oldid] != Sig0StateActive {
		t.Errorf("states after add = %v, want %d created and %d active", states, gotNew, oldid)
	}
}

// When the parent does not accept the roll the old key stays active here. A
// new key the parent refused is removed; one it may hold is kept. A REMOVE
// with no answer may have left the parent trusting only the new key, so that
// error names the setstate commands that finish the roll.
func TestRolloverSig0KeyParentFailures(t *testing.T) {
	ok := rolloverAnswer{rcode: dns.RcodeSuccess}
	refused := rolloverAnswer{rcode: dns.RcodeRefused}
	unanswered := rolloverAnswer{err: errors.New("no answer")}
	cases := []struct {
		name     string
		answers  []rolloverAnswer
		newState string // "" = the new key is gone
		recovery bool   // the parent may trust only the new key: the error names setstate
	}{
		{"ADD refused", []rolloverAnswer{refused}, "", false},
		{"ADD unanswered", []rolloverAnswer{unanswered}, Sig0StateCreated, false},
		{"REMOVE refused", []rolloverAnswer{ok, refused}, Sig0StateCreated, false},
		{"REMOVE unanswered", []rolloverAnswer{ok, unanswered}, Sig0StateCreated, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			zd, kdb, fp := newRolloverZone(t, tc.answers...)
			oldid := activeSig0KeyTag(t, kdb, zd.ZoneName)

			_, _, _, _, err := zd.RolloverSig0KeyWithParent(context.Background(), dns.ED25519, "complete")
			if err == nil {
				t.Fatal("RolloverSig0KeyWithParent succeeded, want an error")
			}
			assertKeystoreFree(t, kdb)
			if len(fp.sent) != len(tc.answers) {
				t.Fatalf("UPDATEs sent = %d, want %d", len(fp.sent), len(tc.answers))
			}
			newid, _, _ := updateKey(t, fp.sent[0])

			states := rolloverKeyStates(t, kdb, zd.ZoneName)
			if states[oldid] != Sig0StateActive {
				t.Errorf("old key %d is %q, want active", oldid, states[oldid])
			}
			if got, present := states[newid]; tc.newState == "" && present {
				t.Errorf("refused new key %d left in the keystore as %q", newid, got)
			} else if tc.newState != "" && got != tc.newState {
				t.Errorf("new key %d is %q, want %q", newid, got, tc.newState)
			}
			if id := activeSig0KeyTag(t, kdb, zd.ZoneName); id != oldid {
				t.Errorf("GetSig0Keys returns active key %d, want %d", id, oldid)
			}
			if tc.recovery {
				assertNamesRecovery(t, err, zd.ZoneName, newid, oldid)
			} else if strings.Contains(err.Error(), "keystore sig0 setstate") {
				t.Errorf("error names a setstate recovery the parent's answer does not call for: %v", err)
			}
			assertRolloverReleased(t, kdb, zd.ZoneName)
		})
	}
}

// assertNamesRecovery fails unless err names the setstate commands that make
// newid active and retire oldid.
func assertNamesRecovery(t *testing.T, err error, zone string, newid, oldid uint16) {
	t.Helper()
	for _, want := range []string{
		fmt.Sprintf("keystore sig0 setstate -z %s --keyid %d --state active", zone, newid),
		fmt.Sprintf("keystore sig0 setstate -z %s --keyid %d --state retired", zone, oldid),
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not name %q: %v", want, err)
		}
	}
}

// assertRolloverReleased fails unless a new rollover of zone may start.
func assertRolloverReleased(t *testing.T, kdb *KeyDB, zone string) {
	t.Helper()
	release, err := kdb.beginSig0Rollover(zone)
	if err != nil {
		t.Fatalf("rollover of %s not released: %v", zone, err)
	}
	release()
}

// Two rollovers of one zone must not run at once: each would get its new key
// accepted by the parent and make it active. A rollover of another zone is not
// held up.
func TestRolloverSig0KeyOneAtATimePerZone(t *testing.T) {
	ok := rolloverAnswer{rcode: dns.RcodeSuccess}
	zd, kdb, fp := newRolloverZone(t, ok, ok, ok)
	other := testZone(t, "other.example.", otherRolloverZone)
	other.SetParent("example.")
	other.KeyDB = kdb
	generateSig0Key(t, kdb, other.ZoneName, Sig0StateActive)

	var refused []error
	var otherErr error
	ranOther := false
	fp.during = func(m *dns.Msg) {
		if m.Ns[0].Header().Name != zd.ZoneName {
			return
		}
		_, _, _, _, err := zd.RolloverSig0KeyWithParent(context.Background(), dns.ED25519, "complete")
		refused = append(refused, err)
		if release, err := kdb.beginSig0Rollover("CHILD.Example"); err == nil {
			release()
			t.Error("the rollover guard is not keyed on the canonical zone name")
		}
		if !ranOther {
			ranOther = true
			_, _, _, _, otherErr = other.RolloverSig0KeyWithParent(context.Background(), dns.ED25519, "add")
		}
	}

	if _, _, _, _, err := zd.RolloverSig0KeyWithParent(context.Background(), dns.ED25519, "complete"); err != nil {
		t.Fatalf("RolloverSig0KeyWithParent: %v", err)
	}
	if len(refused) != 2 {
		t.Fatalf("second rollovers tried = %d, want one during each UPDATE", len(refused))
	}
	for i, err := range refused {
		if err == nil || !strings.Contains(err.Error(), "a SIG(0) rollover for child.example. is already running") {
			t.Errorf("second rollover during UPDATE %d: err = %v, want it refused", i+1, err)
		}
	}
	if otherErr != nil {
		t.Errorf("rollover of another zone was held up: %v", otherErr)
	}
	if states := rolloverKeyStates(t, kdb, zd.ZoneName); len(states) != 2 {
		t.Errorf("keys after one rollover = %v, want the old and the new key only", states)
	}
	assertRolloverReleased(t, kdb, zd.ZoneName)
}

// setstate on a key that is not there is an error, not only a message, so a
// caller changing several states in one transaction can roll back.
func TestSig0SetstateMissingKeyIsAnError(t *testing.T) {
	kdb := newTestKeyDB(t)
	zone := "child.example."
	id := generateSig0Key(t, kdb, zone, Sig0StateCreated)
	setstate := func(keyid uint16) error {
		_, err := kdb.Sig0KeyMgmt(nil, KeystorePost{Command: "sig0-mgmt", SubCommand: "setstate",
			Keyname: zone, Keyid: keyid, State: Sig0StateActive})
		return err
	}
	if err := setstate(id + 1); err == nil {
		t.Error("setstate on a missing key returned no error")
	}
	if err := setstate(id); err != nil {
		t.Fatalf("setstate on key %d: %v", id, err)
	}
	if states := rolloverKeyStates(t, kdb, zone); states[id] != Sig0StateActive {
		t.Errorf("key %d is %q, want active", id, states[id])
	}
}

// Both UPDATEs accepted, then the local state change fails. It rolls back
// whole, so the old key is not left retired with nothing active, and since
// the parent trusts only the new key the error names the setstate commands
// that finish the roll.
func TestRolloverSig0KeyActivationFailure(t *testing.T) {
	ok := rolloverAnswer{rcode: dns.RcodeSuccess}
	zd, kdb, fp := newRolloverZone(t, ok, ok)
	oldid := activeSig0KeyTag(t, kdb, zd.ZoneName)
	fp.during = func(m *dns.Msg) {
		if len(fp.sent) != 1 {
			return
		}
		// During the REMOVE: the new key's row goes away.
		newid, _, _ := updateKey(t, fp.sent[0])
		if _, err := kdb.DB.Exec("DELETE FROM Sig0KeyStore WHERE zonename=? AND keyid=?", zd.ZoneName, newid); err != nil {
			t.Fatalf("delete new key: %v", err)
		}
	}

	_, _, gotNew, _, err := zd.RolloverSig0KeyWithParent(context.Background(), dns.ED25519, "complete")
	if err == nil {
		t.Fatal("RolloverSig0KeyWithParent succeeded with the new key gone")
	}
	assertNamesRecovery(t, err, zd.ZoneName, gotNew, oldid)
	assertKeystoreFree(t, kdb)
	if states := rolloverKeyStates(t, kdb, zd.ZoneName); states[oldid] != Sig0StateActive {
		t.Errorf("old key %d is %q after the failed state change, want active", oldid, states[oldid])
	}
	assertRolloverReleased(t, kdb, zd.ZoneName)
}
