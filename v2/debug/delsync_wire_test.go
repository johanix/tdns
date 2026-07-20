package debug

import (
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

// TestVerifySig0 covers the response-signature check the mutual-authentication
// cases turn on. It is deliberately exercised over a real exchange rather than
// on a locally-packed message, because the whole point of capturing the wire
// buffer is that a re-packed message is not guaranteed to reproduce the bytes
// the signature covered.
func TestVerifySig0(t *testing.T) {
	receiver := newTestSigner(t, "update-receiver.parent.example.")
	attacker := newTestSigner(t, "attacker.example.")

	script, err := ParseDoubleScript([]byte(`
rules:
  - match: {qname: "good.example."}
    respond: {keystate: 4, sign: correct}
  - match: {qname: "forged.example."}
    respond: {keystate: 4, sign: wrong-key}
  - match: {qname: "bare.example."}
    respond: {rcode: NOERROR, sign: none}
`))
	if err != nil {
		t.Fatalf("ParseDoubleScript: %v", err)
	}
	d := startTestDouble(t, DoubleConfig{Script: script, Signer: receiver, WrongSigner: attacker})

	for _, tc := range []struct {
		name           string
		qname          string
		wantSigned     bool
		wantVerified   bool
		wantSignerName string
	}{
		{"correctly signed", "good.example.", true, true, "update-receiver.parent.example."},
		{"signed by the wrong key", "forged.example.", true, false, "attacker.example."},
		{"unsigned", "bare.example.", false, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := new(dns.Msg)
			q.SetQuestion(tc.qname, dns.TypeKEY)
			q.SetEdns0(4096, false)

			resp, wire, err := exchangeCapturingWire(d.Addr(), q, "tcp", 3*time.Second)
			if err != nil {
				t.Fatalf("exchange: %v", err)
			}

			signed, verified, signer, _ := verifySig0(resp, wire, receiver.publicKEY())
			if signed != tc.wantSigned {
				t.Errorf("signed = %v, want %v", signed, tc.wantSigned)
			}
			if verified != tc.wantVerified {
				t.Errorf("verified = %v, want %v", verified, tc.wantVerified)
			}
			if tc.wantSignerName != "" && signer != tc.wantSignerName {
				t.Errorf("signer = %q, want %q", signer, tc.wantSignerName)
			}
		})
	}
}

// TestVerifySig0NilKey: with no expected key, a signature can be observed but
// never confirmed. This is the G5 "receiver KEY not obtainable" shape — the
// caller must be able to tell "signed but unverifiable" from "unsigned", since
// the draft's carve-out treats them differently.
func TestVerifySig0NilKey(t *testing.T) {
	receiver := newTestSigner(t, "update-receiver.parent.example.")
	script, err := ParseDoubleScript([]byte(`
rules:
  - match: {}
    respond: {keystate: 4, sign: correct}
`))
	if err != nil {
		t.Fatalf("ParseDoubleScript: %v", err)
	}
	d := startTestDouble(t, DoubleConfig{Script: script, Signer: receiver})

	q := new(dns.Msg)
	q.SetQuestion("whatever.example.", dns.TypeKEY)
	q.SetEdns0(4096, false)
	resp, wire, err := exchangeCapturingWire(d.Addr(), q, "tcp", 3*time.Second)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	signed, verified, _, _ := verifySig0(resp, wire, nil)
	if !signed {
		t.Error("signed = false, want true — the response carries a SIG even though we cannot check it")
	}
	if verified {
		t.Error("verified = true with no key to verify against")
	}
}

// TestExchangeCapturingWireRoundTrip pins the transport helper itself: the raw
// buffer must be exactly what the parsed message came from, over both
// transports. If these ever diverge, every signature verdict built on top
// becomes unreliable.
func TestExchangeCapturingWireRoundTrip(t *testing.T) {
	d := startTestDouble(t, DoubleConfig{})

	for _, transport := range []string{"udp", "tcp"} {
		t.Run(transport, func(t *testing.T) {
			q := new(dns.Msg)
			q.SetQuestion("example.", dns.TypeSOA)
			q.SetEdns0(4096, false)

			resp, wire, err := exchangeCapturingWire(d.Addr(), q, transport, 3*time.Second)
			if err != nil {
				t.Fatalf("exchange: %v", err)
			}
			if len(wire) == 0 {
				t.Fatal("no wire bytes captured")
			}
			// The buffer must independently parse to the same message id.
			reparsed := new(dns.Msg)
			if err := reparsed.Unpack(wire); err != nil {
				t.Fatalf("captured buffer does not parse: %v", err)
			}
			if reparsed.Id != resp.Id {
				t.Errorf("captured buffer parses to id %d, response has id %d", reparsed.Id, resp.Id)
			}
			if resp.Id != q.Id {
				t.Errorf("response id %d does not match request id %d", resp.Id, q.Id)
			}
		})
	}
}

// TestSignMsgMultiKeyVerification documents how tdns's SignMsg behaves with
// several active keys, because verifySig0's "accept if ANY signature verifies"
// rule depends on it. SignMsg appends one SIG per key, each signing the message
// as it stands at that point -- so an earlier SIG is covered by a later one and
// the message the earlier signature was computed over is no longer the message
// on the wire.
//
// Whatever the outcome, a receiver mid-rollover must not read as a forgery, so
// this asserts the property that actually matters: at least one signature
// verifies under one of the signing keys.
func TestSignMsgMultiKeyVerification(t *testing.T) {
	a := newTestSigner(t, "receiver.example.")
	b := newTestSigner(t, "receiver.example.")

	// One signer holding two active keys, which is what a rollover looks like.
	both := &Sig0Signer{
		Zone:    a.Zone,
		KeyName: a.KeyName,
		sak: &tdns.Sig0ActiveKeys{Keys: []*tdns.PrivateKeyCache{
			a.sak.Keys[0], b.sak.Keys[0],
		}},
	}

	d := startTestDouble(t, DoubleConfig{
		Script: DoubleScript{Rules: []DoubleRule{{
			Respond: DoubleRespond{KeyState: u8ptr(4), Sign: "correct"},
		}}},
		Signer: both,
	})

	q := new(dns.Msg)
	q.SetQuestion("rollover.example.", dns.TypeKEY)
	q.SetEdns0(4096, false)
	resp, wire, err := exchangeCapturingWire(d.Addr(), q, "tcp", 3*time.Second)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	sigs := 0
	for _, rr := range resp.Extra {
		if _, ok := rr.(*dns.SIG); ok {
			sigs++
		}
	}
	if sigs != 2 {
		t.Fatalf("response carries %d SIG RRs, want 2 (one per active key)", sigs)
	}

	_, verifiedA, _, _ := verifySig0(resp, wire, a.publicKEY())
	_, verifiedB, _, _ := verifySig0(resp, wire, b.publicKEY())
	t.Logf("multi-key SignMsg: first key verifies=%v, second key verifies=%v", verifiedA, verifiedB)

	if !verifiedA && !verifiedB {
		t.Error("neither active key verified the response — a rollover receiver would be read as a forgery")
	}
}

func u8ptr(v uint8) *uint8 { return &v }
