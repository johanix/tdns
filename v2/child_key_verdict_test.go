package tdns

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// #677, fix 2: every KEY lookup gets its own verdict. A KEY that is not there
// yet is worth another attempt; one that is there and wrong is not; one
// DNSSEC-validated KEY is enough.

const (
	vdOtherProviderNS = "ns.other.net."
	vdApex            = cuChild
)

var vdOtherProviderName = signalOwnerName(signalPrefixSig0Key, cuChild, vdOtherProviderNS)

// keyAnswer is one stubbed KEY lookup: the key it holds (empty for none) and
// the DNSSEC state it validated to. err makes the lookup itself fail.
type keyAnswer struct {
	key   string
	state cache.ValidationState
	err   error
}

func (a keyAnswer) response(t *testing.T, name string) (*ImrResponse, error) {
	t.Helper()
	if a.err != nil {
		return nil, a.err
	}
	if a.key == "" {
		return &ImrResponse{Msg: "NXDOMAIN (negative response type 3)"}, nil
	}
	rr := mustRR(t, a.key)
	rr.Header().Name = name
	return &ImrResponse{
		RRset:           &core.RRset{Name: name, RRtype: dns.TypeKEY, RRs: []dns.RR{rr}},
		Validated:       a.state == cache.ValidationStateSecure,
		ValidationState: a.state,
	}, nil
}

// stubKeyAnswers answers each name from answers, and every other name with no
// KEY.
func stubKeyAnswers(t *testing.T, answers map[string]keyAnswer) {
	t.Helper()
	orig := childKeyQuery
	t.Cleanup(func() { childKeyQuery = orig })
	childKeyQuery = func(ctx context.Context, imr *Imr, name string) (*ImrResponse, error) {
		return answers[name].response(t, name)
	}
}

// twoProviderParent delegates child.example. to two providers and nothing
// inside the child, with no DS.
func twoProviderParent(t *testing.T) *ZoneData {
	t.Helper()
	return newMapZone(cuParent, Primary, map[string][]dns.RR{
		cuParent: {
			mustRR(t, "example. 3600 IN SOA ns.example. h.example. 1 3600 600 604800 300"),
			mustRR(t, "example. 3600 IN NS ns.example."),
		},
		cuChild: {
			mustRR(t, "child.example. 3600 IN NS ns.provider.net."),
			mustRR(t, "child.example. 3600 IN NS "+vdOtherProviderNS),
		},
	})
}

func strictBothMechanisms() DelegationPolicy {
	return DelegationPolicy{Name: "strict", Mechanisms: []string{"at-apex", "at-ns"}, RequireDnssec: true}
}

const vdOtherKey = "child.example. 3600 IN KEY 256 3 15 AAAAlEmXPWWDCFZmJqFhOJjHtBSKuLnCJHBTLzNJnUE="

func TestJudgeChildKeyAnswer(t *testing.T) {
	strict := DelegationPolicy{Name: "strict", RequireDnssec: true}
	lax := DelegationPolicy{Name: "lax", RequireDnssec: false}
	const name = "_sig0key.child.example._signal.ns.provider.net."

	for _, tc := range []struct {
		name    string
		answer  keyAnswer
		pol     DelegationPolicy
		verdict childKeyVerdict
		dnssec  bool
	}{
		{"the lookup failed", keyAnswer{err: errors.New("timeout")}, strict, childKeyNotFound, false},
		{"no KEY there", keyAnswer{}, strict, childKeyNotFound, false},
		{"the offered key, validated", keyAnswer{key: atNsTestKey, state: cache.ValidationStateSecure}, strict, childKeyAccepted, true},
		{"a different key, validated", keyAnswer{key: vdOtherKey, state: cache.ValidationStateSecure}, strict, childKeyRejected, false},
		{"the offered key, bogus", keyAnswer{key: atNsTestKey, state: cache.ValidationStateBogus}, strict, childKeyRejected, false},
		{"the offered key, bogus, DNSSEC not required", keyAnswer{key: atNsTestKey, state: cache.ValidationStateBogus}, lax, childKeyRejected, false},
		{"the offered key, unsigned zone", keyAnswer{key: atNsTestKey, state: cache.ValidationStateInsecure}, strict, childKeyRejected, false},
		{"the offered key, unsigned zone, DNSSEC not required", keyAnswer{key: atNsTestKey, state: cache.ValidationStateInsecure}, lax, childKeyAccepted, false},
		{"a different key, unsigned zone, DNSSEC not required", keyAnswer{key: vdOtherKey, state: cache.ValidationStateInsecure}, lax, childKeyRejected, false},
		{"the offered key, validation indeterminate", keyAnswer{key: atNsTestKey, state: cache.ValidationStateIndeterminate}, strict, childKeyNotFound, false},
		{"the offered key, validation not attempted", keyAnswer{key: atNsTestKey}, strict, childKeyNotFound, false},
		{"the offered key, validation indeterminate, DNSSEC not required", keyAnswer{key: atNsTestKey, state: cache.ValidationStateIndeterminate}, lax, childKeyAccepted, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := tc.answer.response(t, name)
			got := judgeChildKeyAnswer(name, resp, err, atNsTestKey, tc.pol)
			if got.verdict != tc.verdict || got.dnssec != tc.dnssec {
				t.Errorf("verdict %s dnssec=%v (%s), want %s dnssec=%v", got.verdict, got.dnssec, got.why, tc.verdict, tc.dnssec)
			}
			if !strings.Contains(got.why, name) {
				t.Errorf("the reason %q does not name the lookup", got.why)
			}
		})
	}
}

// One DNSSEC-validated KEY is enough, whatever the other provider serves. The
// old rule required every name that answered to validate, so a second
// provider serving the same key from an unsigned zone refused the bootstrap.
func TestOneValidatedKeyIsEnough(t *testing.T) {
	registerZones(t, twoProviderParent(t))
	stubKeyAnswers(t, map[string]keyAnswer{
		atNsProviderName:    {key: atNsTestKey, state: cache.ValidationStateSecure},
		vdOtherProviderName: {key: atNsTestKey, state: cache.ValidationStateInsecure},
	})

	accepted, dnssec, reason := VerifyChildKey(context.Background(), cuChild, cuParent, atNsTestKey, nil, strictBothMechanisms())
	if !accepted || !dnssec || reason != nil {
		t.Errorf("accepted=%v dnssec=%v reason=%v, want accepted and validated: one provider"+
			" serves the offered key DNSSEC-validated", accepted, dnssec, reason)
	}
}

// The #677 bootstrap before the provider publishes. The unsigned child's apex
// KEY is rejected under require-dnssec, and would be on every attempt; the
// signal name holds nothing yet, which another attempt may change. The
// verdict must not be final.
func TestAKeyNotYetAtTheSignalNameIsWorthAnotherAttempt(t *testing.T) {
	registerZones(t, cuParentZone(t))
	stubKeyAnswers(t, map[string]keyAnswer{
		vdApex: {key: atNsTestKey, state: cache.ValidationStateInsecure},
	})

	accepted, _, reason := VerifyChildKey(context.Background(), cuChild, cuParent, atNsTestKey, nil, strictBothMechanisms())
	if accepted {
		t.Fatal("accepted a key that validates nowhere")
	}
	if errors.Is(reason, errChildKeyFinal) {
		t.Errorf("reason %q is final; the signal name holds no KEY yet, and the next attempt may find it", reason)
	}
	for _, want := range []string{"at-apex:", "unsigned zone", "at-ns:", "no KEY at " + atNsProviderName} {
		if reason == nil || !strings.Contains(reason.Error(), want) {
			t.Errorf("reason %v lacks %q", reason, want)
		}
	}
}

// A delegation that names nothing to ask yet is not a verdict either: the
// next attempt reads it again.
func TestNoNameserverToAskIsWorthAnotherAttempt(t *testing.T) {
	registerZones(t, oneNSParent(t))
	stubKeyAnswers(t, map[string]keyAnswer{
		vdApex: {key: atNsTestKey, state: cache.ValidationStateInsecure},
	})

	_, _, reason := VerifyChildKey(context.Background(), cuChild, cuParent, atNsTestKey, nil, strictBothMechanisms())
	if reason == nil || errors.Is(reason, errChildKeyFinal) {
		t.Errorf("reason %v; want a failure that is not final", reason)
	}
}

// Every lookup rejected is final: nothing another attempt could see changes a
// bogus KEY or an unsigned zone.
func TestEveryLookupRejectedIsFinal(t *testing.T) {
	registerZones(t, cuParentZone(t))
	stubKeyAnswers(t, map[string]keyAnswer{
		vdApex:           {key: atNsTestKey, state: cache.ValidationStateInsecure},
		atNsProviderName: {key: atNsTestKey, state: cache.ValidationStateBogus},
	})

	_, _, reason := VerifyChildKey(context.Background(), cuChild, cuParent, atNsTestKey, nil, strictBothMechanisms())
	if !errors.Is(reason, errChildKeyFinal) {
		t.Errorf("reason %v is not final; every lookup found a KEY it had to reject", reason)
	}
	if reason == nil || !strings.Contains(reason.Error(), "DNSSEC-bogus") {
		t.Errorf("reason %v does not say the signal name's KEY is bogus", reason)
	}
}

// A final verdict ends the attempts at once and is recorded with the reason.
func TestRunChildKeyVerificationStopsAtAFinalVerdict(t *testing.T) {
	kdb := newTestKeyDB(t)
	keyid, _ := addVfChildKey(t, kdb, false)
	pol := DelegationPolicy{Name: "t", Mechanisms: []string{"at-ns"}, RequireDnssec: true,
		RetryMaxAttempts: 3, RetryInterval: time.Millisecond}

	calls := 0
	ok := kdb.runChildKeyVerification(context.Background(), vfChild, keyid, pol,
		func(context.Context) (bool, bool, error) {
			calls++
			return false, false, &childKeyFinalError{msg: "at-ns: the KEY at x is DNSSEC-bogus"}
		})
	if ok || calls != 1 {
		t.Fatalf("ok=%v calls=%d, want false and 1: a final verdict must not wait out the retries", ok, calls)
	}
	sk := lookupChildKey(t, kdb, keyid)
	if !sk.ValidationFailed || !strings.Contains(sk.ValidationError, "1 attempt via") ||
		!strings.Contains(sk.ValidationError, "DNSSEC-bogus") {
		t.Errorf("recorded failed=%v %q, want the failure with its reason", sk.ValidationFailed, sk.ValidationError)
	}
	if ks, _ := kdb.GetKeyStatus(vfChild, keyid); ks.KeyState != edns0.KeyStateValidationFail {
		t.Errorf("KeyState %d, want %d", ks.KeyState, edns0.KeyStateValidationFail)
	}
}

// Attempts are spaced by the interval, not backed off.
func TestRunChildKeyVerificationSpacesAttemptsEvenly(t *testing.T) {
	kdb := newTestKeyDB(t)
	keyid, _ := addVfChildKey(t, kdb, false)
	const interval = 200 * time.Millisecond
	pol := DelegationPolicy{Name: "t", Mechanisms: []string{"at-ns"}, RequireDnssec: true,
		RetryMaxAttempts: 3, RetryInterval: interval}

	var at []time.Time
	kdb.runChildKeyVerification(context.Background(), vfChild, keyid, pol,
		func(context.Context) (bool, bool, error) {
			at = append(at, time.Now())
			return false, false, errors.New("no KEY yet")
		})
	if len(at) != 3 {
		t.Fatalf("%d attempts, want 3", len(at))
	}
	if gap := at[2].Sub(at[1]); gap >= interval*7/4 {
		t.Errorf("the second wait took %v with an interval of %v; attempts are backed off, not spaced", gap, interval)
	}
}

func clearChildKeyCooldown(t *testing.T, child string, keyid uint16) {
	t.Helper()
	id := childKeyVerificationID(child, keyid)
	childKeyVerificationsEnded.Delete(id)
	t.Cleanup(func() { childKeyVerificationsEnded.Delete(id) })
}

func TestChildKeyCoolingDown(t *testing.T) {
	const child, keyid = "cooling.example.", 4242
	clearChildKeyCooldown(t, child, keyid)
	now := time.Now()

	if childKeyCoolingDown(child, keyid, now) {
		t.Error("a key never verified is cooling down")
	}
	noteChildKeyVerificationEnded(child, keyid, func() time.Time { return now.Add(-time.Minute) })
	if !childKeyCoolingDown(child, keyid, now) {
		t.Error("a key verified a minute ago is not cooling down")
	}
	noteChildKeyVerificationEnded(child, keyid, func() time.Time { return now.Add(-childKeyReBootstrapCooldown) })
	if childKeyCoolingDown(child, keyid, now) {
		t.Error("a key whose cooldown has passed is still cooling down")
	}
	if _, ok := childKeyVerificationsEnded.Load(childKeyVerificationID(child, keyid)); ok {
		t.Error("an expired cooldown entry was kept")
	}
}

// The cooldown, through the real update path. A re-bootstrap straight after a
// failed verification is refused the way a failed key is (KEY-VALIDATION-
// FAILED) and starts nothing; once the cooldown has passed it starts over.
func TestAReBootstrapWithinTheCooldownIsRefused(t *testing.T) {
	zd, key := rebootstrapParent(t, true)
	stubSig0Verify(t)

	reBootstrap := func() (*UpdateStatus, error) {
		r := ceremonyUpdateFrom(t, zd.ZoneName, key)
		us := &UpdateStatus{Type: "TRUSTSTORE-UPDATE"}
		if err := zd.ValidateUpdate(context.Background(), r, us); err != nil {
			t.Fatalf("ValidateUpdate: %v", err)
		}
		return us, zd.TrustUpdate(r, us)
	}

	noteChildKeyVerificationEnded(key.Hdr.Name, key.KeyTag(), time.Now)
	us, err := reBootstrap()
	if err == nil {
		t.Fatal("a re-bootstrap within the cooldown started a verification over")
	}
	if us.RejectionEDE != edns0.EDESig0KeyValidationFailed {
		t.Errorf("EDE %d, want %d", us.RejectionEDE, edns0.EDESig0KeyValidationFailed)
	}

	noteChildKeyVerificationEnded(key.Hdr.Name, key.KeyTag(),
		func() time.Time { return time.Now().Add(-childKeyReBootstrapCooldown - time.Second) })
	if _, err := reBootstrap(); err != nil {
		t.Errorf("a re-bootstrap after the cooldown was refused: %v", err)
	}
}

// The verifier stamps the end of its run, so the cooldown is measured from
// the verification the child is reacting to.
func TestAVerificationStartsTheCooldown(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := cuParentZone(t)
	zd.KeyDB = kdb
	registerZones(t, zd)
	pol := compiledDefaultDelegationPolicy()
	pol.RetryMaxAttempts = 1
	zd.DelegationPolicy = &pol
	key := discoveredTestKey(t)
	clearChildKeyCooldown(t, key.Name, key.Keyid)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := kdb.TriggerChildKeyVerification(ctx, key.Name, zd.ZoneName, key.Keyid, key.Key.String())
	if done == nil {
		t.Fatal("no verification started")
	}
	<-done
	if !childKeyCoolingDown(key.Name, key.Keyid, time.Now()) {
		t.Error("the key is not cooling down after its verification ended")
	}
}

// ImrQueryFresh does not serve the cached answer. A cached NXDOMAIN for the
// signal name is exactly what hid a freshly published KEY from every retry.
func TestImrQueryFreshSkipsTheCachedAnswer(t *testing.T) {
	const qname = "_sig0key.child.example._signal.ns.provider.net."
	imr := newTestImr(t)
	imr.Cache.Set(qname, dns.TypeKEY, &cache.CachedRRset{
		Name:       qname,
		RRtype:     dns.TypeKEY,
		Rcode:      uint8(dns.RcodeNameError),
		Context:    cache.ContextNXDOMAIN,
		State:      cache.ValidationStateSecure,
		Expiration: time.Now().Add(time.Hour),
		Transport:  core.TransportDo53,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// The plain query serves the cached NXDOMAIN.
	if resp, err := imr.ImrQuery(ctx, qname, dns.TypeKEY, dns.ClassINET, nil); err != nil || resp.Error {
		t.Fatalf("fixture: the cached NXDOMAIN was not served (err=%v resp=%+v)", err, resp)
	}
	// The fresh one goes to the network. This cache knows no servers, so it
	// can only fail; serving the cached entry would be a success.
	resp, err := imr.ImrQueryFresh(ctx, qname, dns.TypeKEY, dns.ClassINET)
	if err == nil && (resp == nil || !resp.Error) {
		t.Errorf("ImrQueryFresh served the cached NXDOMAIN (resp=%+v)", resp)
	}
}
