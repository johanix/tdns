package tdns

import (
	"testing"

	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// D-8: the three bootstrap-state EDEs of ddns-02 §"Communication in Case of
// Errors", all on REFUSED for an UPDATE signed by a known-but-untrusted key,
// with the same precedence as the KeyState codes 10/8/9.
func TestKnownUntrustedKeyEDE(t *testing.T) {
	failed := &Sig0Key{ValidationFailed: true}
	plain := &Sig0Key{}
	cases := []struct {
		name   string
		key    *Sig0Key
		manual bool
		want   uint16
	}{
		{"in progress", plain, false, edns0.EDESig0KeyKnownButNotTrusted},
		{"validation failed", failed, false, edns0.EDESig0KeyValidationFailed},
		{"manual policy", plain, true, edns0.EDESig0ManualBootstrapRequired},
		{"manual policy outranks a failure", failed, true, edns0.EDESig0ManualBootstrapRequired},
		{"nil key", nil, false, edns0.EDESig0KeyKnownButNotTrusted},
	}
	for _, c := range cases {
		if got := knownUntrustedKeyEDE(c.key, c.manual); got != c.want {
			t.Errorf("%s: EDE %d, want %d", c.name, got, c.want)
		}
	}
}

func TestTrustUpdateBootstrapStateEDEs(t *testing.T) {
	mk := func(key *Sig0Key) *UpdateStatus {
		return &UpdateStatus{
			Validated:       true,
			ValidationRcode: dns.RcodeSuccess,
			Signers: []Sig0UpdateSigner{{
				Name: "child.example.", KeyId: 111, Validated: true, Sig0Key: key,
			}},
		}
	}
	check := func(t *testing.T, zd *ZoneData, us *UpdateStatus, want uint16) {
		t.Helper()
		if err := zd.TrustUpdate(nil, us); err == nil {
			t.Fatal("expected refusal for a known-but-untrusted key")
		}
		if us.ValidationRcode != dns.RcodeRefused {
			t.Errorf("rcode = %d, want REFUSED", us.ValidationRcode)
		}
		if us.RejectionEDE != want {
			t.Errorf("EDE = %d (%s), want %d (%s)", us.RejectionEDE, edns0.EDECodeToString[us.RejectionEDE], want, edns0.EDECodeToString[want])
		}
		if us.ValidatedByTrustedKey {
			t.Error("ValidatedByTrustedKey must be false")
		}
	}

	t.Run("validation failed -> KEY-VALIDATION-FAILED", func(t *testing.T) {
		check(t, &ZoneData{}, mk(&Sig0Key{Name: "child.example.", Keyid: 111, ValidationFailed: true}), edns0.EDESig0KeyValidationFailed)
	})
	t.Run("manual policy -> MANUAL-BOOTSTRAP-REQUIRED, even after a failure", func(t *testing.T) {
		zd := &ZoneData{DelegationPolicy: &DelegationPolicy{Name: "manual", Manual: true}}
		check(t, zd, mk(&Sig0Key{Name: "child.example.", Keyid: 111, ValidationFailed: true}), edns0.EDESig0ManualBootstrapRequired)
	})
	t.Run("in progress -> KEY-KNOWN-NOT-TRUSTED", func(t *testing.T) {
		check(t, &ZoneData{}, mk(&Sig0Key{Name: "child.example.", Keyid: 111}), edns0.EDESig0KeyKnownButNotTrusted)
	})
	t.Run("the EDE follows the signer whose signature verified", func(t *testing.T) {
		us := &UpdateStatus{
			Validated:       true,
			ValidationRcode: dns.RcodeSuccess,
			Signers: []Sig0UpdateSigner{
				{Name: "child.example.", KeyId: 1, Validated: false, Sig0Key: &Sig0Key{ValidationFailed: true}},
				{Name: "child.example.", KeyId: 2, Validated: true, Sig0Key: &Sig0Key{}},
			},
		}
		check(t, &ZoneData{}, us, edns0.EDESig0KeyKnownButNotTrusted)
	})
}
