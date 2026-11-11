package debug

import (
	"context"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// The double is an ORACLE: scenarios will assert real tdns behaviour by reading
// its journal, so a bug in the double reads as a bug in tdns. These tests pin
// the behaviours the matrix depends on — rule ordering and exhaustion (D2 vs
// D3), drop (D1), ceremony classification (D3/E1), transport recording (C1),
// and the three signing modes (A3/G3/G4).

func startTestDouble(t *testing.T, cfg DoubleConfig) *Double {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	d, err := StartDouble(ctx, cfg)
	if err != nil {
		t.Fatalf("StartDouble: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

// updateMsg builds a plain (non-ceremony) delegation UPDATE.
func updateMsg(t *testing.T, zone string) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetUpdate(dns.Fqdn(zone))
	rr, err := dns.NewRR("child." + dns.Fqdn(zone) + " 3600 IN NS ns1.example.")
	if err != nil {
		t.Fatalf("NewRR: %v", err)
	}
	m.Insert([]dns.RR{rr})
	m.SetEdns0(1232, false)
	return m
}

// ceremonyMsg builds the bootstrap ceremony: DEL <child> ANY KEY + ADD <child> KEY,
// exactly as BootstrapSig0KeyWithParent does (RemoveRRset then Insert).
func ceremonyMsg(t *testing.T, zone, child string) *dns.Msg {
	t.Helper()
	signer := newTestSigner(t, child)
	keyRR := signer.publicKEY()

	m := new(dns.Msg)
	m.SetUpdate(dns.Fqdn(zone))
	m.RemoveRRset([]dns.RR{keyRR}) // DEL <child> ANY KEY
	m.Insert([]dns.RR{keyRR})      // ADD <child> KEY
	m.SetEdns0(1232, false)
	return m
}

func exchange(t *testing.T, addr string, m *dns.Msg, net string) (*dns.Msg, error) {
	t.Helper()
	c := &dns.Client{Net: net, Timeout: 3 * time.Second}
	r, _, err := c.Exchange(m, addr)
	return r, err
}

// TestDoubleRuleOrderAndExhaustion is the D2-vs-D3 distinction: `times: 1`
// must fire once and then fall through to the next matching rule.
func TestDoubleRuleOrderAndExhaustion(t *testing.T) {
	script, err := ParseDoubleScript([]byte(`
rules:
  - match: {opcode: UPDATE}
    respond: {rcode: BADKEY}
    times: 1
  - match: {opcode: UPDATE}
    respond: {rcode: NOERROR}
`))
	if err != nil {
		t.Fatalf("ParseDoubleScript: %v", err)
	}
	d := startTestDouble(t, DoubleConfig{Script: script})

	want := []int{dns.RcodeBadKey, dns.RcodeSuccess, dns.RcodeSuccess}
	for i, wantRcode := range want {
		r, err := exchange(t, d.Addr(), updateMsg(t, "parent.example."), "tcp")
		if err != nil {
			t.Fatalf("exchange %d: %v", i, err)
		}
		if r.Rcode != wantRcode {
			t.Errorf("exchange %d: rcode = %s, want %s",
				i, dns.RcodeToString[r.Rcode], dns.RcodeToString[wantRcode])
		}
	}

	j := d.Journal()
	if len(j) != 3 {
		t.Fatalf("journal has %d entries, want 3", len(j))
	}
	if j[0].RuleIndex != 0 || j[1].RuleIndex != 1 || j[2].RuleIndex != 1 {
		t.Errorf("rule indices = %d,%d,%d, want 0,1,1", j[0].RuleIndex, j[1].RuleIndex, j[2].RuleIndex)
	}
}

// TestDoubleDropIsSilent is the D1 primitive: a dropped request must produce no
// answer at all (so the child's timeout fires), yet still be journaled — the
// attempt count and spacing are the whole assertion.
func TestDoubleDropIsSilent(t *testing.T) {
	script, err := ParseDoubleScript([]byte(`
rules:
  - match: {opcode: UPDATE}
    respond: {drop: true}
`))
	if err != nil {
		t.Fatalf("ParseDoubleScript: %v", err)
	}
	d := startTestDouble(t, DoubleConfig{Script: script})

	c := &dns.Client{Net: "udp", Timeout: 300 * time.Millisecond}
	if _, _, err := c.Exchange(updateMsg(t, "parent.example."), d.Addr()); err == nil {
		t.Fatal("exchange succeeded against a dropping double; expected a timeout")
	}

	j := d.Journal()
	if len(j) != 1 {
		t.Fatalf("journal has %d entries, want 1 — a dropped request must still be recorded", len(j))
	}
	if !j[0].Dropped {
		t.Error("journal entry not marked Dropped")
	}
	if j[0].RespondedRcode != "" {
		t.Errorf("dropped entry recorded a response rcode %q", j[0].RespondedRcode)
	}
}

// TestDoubleCeremonyClassification is the D3/E1 assertion surface: the journal
// must distinguish a bootstrap DEL+ADD ceremony from an ordinary UPDATE, and
// from a bare ADD (an ordinary key upload, which is NOT a re-bootstrap).
func TestDoubleCeremonyClassification(t *testing.T) {
	d := startTestDouble(t, DoubleConfig{})

	// 1. Plain delegation UPDATE.
	if _, err := exchange(t, d.Addr(), updateMsg(t, "parent.example."), "tcp"); err != nil {
		t.Fatalf("plain update: %v", err)
	}
	// 2. Full ceremony (DEL ANY KEY + ADD KEY).
	if _, err := exchange(t, d.Addr(), ceremonyMsg(t, "parent.example.", "child.parent.example."), "tcp"); err != nil {
		t.Fatalf("ceremony update: %v", err)
	}
	// 3. Bare ADD KEY, no DEL — a key upload, not a ceremony.
	bare := new(dns.Msg)
	bare.SetUpdate("parent.example.")
	bare.Insert([]dns.RR{newTestSigner(t, "child.parent.example.").publicKEY()})
	bare.SetEdns0(1232, false)
	if _, err := exchange(t, d.Addr(), bare, "tcp"); err != nil {
		t.Fatalf("bare add: %v", err)
	}

	j := d.Journal()
	if len(j) != 3 {
		t.Fatalf("journal has %d entries, want 3", len(j))
	}
	for i, want := range []bool{false, true, false} {
		if j[i].Ceremony != want {
			t.Errorf("entry %d: Ceremony = %v, want %v (update section: %v)",
				i, j[i].Ceremony, want, j[i].UpdateSection)
		}
	}
	// E1 also needs the wire form itself, not just the boolean.
	if len(j[1].UpdateSection) != 2 {
		t.Errorf("ceremony update section has %d RRs, want 2 (DEL + ADD): %v",
			len(j[1].UpdateSection), j[1].UpdateSection)
	}
}

// TestDoubleRecordsTransport backs the C1 assertion (delegation UPDATEs go over
// TCP). The double must serve and distinguish both, or C1 would "pass" simply
// because UDP was impossible.
func TestDoubleRecordsTransport(t *testing.T) {
	d := startTestDouble(t, DoubleConfig{})

	if _, err := exchange(t, d.Addr(), updateMsg(t, "parent.example."), "udp"); err != nil {
		t.Fatalf("udp exchange: %v", err)
	}
	if _, err := exchange(t, d.Addr(), updateMsg(t, "parent.example."), "tcp"); err != nil {
		t.Fatalf("tcp exchange: %v", err)
	}

	j := d.Journal()
	if len(j) != 2 {
		t.Fatalf("journal has %d entries, want 2", len(j))
	}
	if j[0].Transport != "udp" || j[1].Transport != "tcp" {
		t.Errorf("transports = %q,%q, want udp,tcp", j[0].Transport, j[1].Transport)
	}
}

// TestDoubleKeyStateSigningModes pins the three signing modes the mutual-auth
// cases need: a correctly-signed KeyState response (what a conforming receiver
// sends, A3), one signed by the wrong key (G3 forgery), and an unsigned one
// (G4). Verification is done against the real wire bytes via dns.SIG.Verify,
// the same check the child will perform.
func TestDoubleKeyStateSigningModes(t *testing.T) {
	receiver := newTestSigner(t, "update-receiver.parent.example.")
	attacker := newTestSigner(t, "attacker.example.")

	script, err := ParseDoubleScript([]byte(`
rules:
  - match: {opcode: QUERY, keystate: true, qname: "correct.example."}
    respond: {keystate: 4, sign: correct}
  - match: {opcode: QUERY, keystate: true, qname: "forged.example."}
    respond: {keystate: 4, sign: wrong-key}
  - match: {opcode: QUERY, keystate: true, qname: "unsigned.example."}
    respond: {keystate: 4, sign: none}
`))
	if err != nil {
		t.Fatalf("ParseDoubleScript: %v", err)
	}
	d := startTestDouble(t, DoubleConfig{Script: script, Signer: receiver, WrongSigner: attacker})

	for _, tc := range []struct {
		qname        string
		wantSigned   bool
		wantVerifies bool
	}{
		{"correct.example.", true, true},
		{"forged.example.", true, false},  // signed, but not by the receiver's key
		{"unsigned.example.", false, false},
	} {
		t.Run(tc.qname, func(t *testing.T) {
			q := new(dns.Msg)
			q.SetQuestion(tc.qname, dns.TypeKEY)
			edns0.AttachKeyStateToResponse(q, &edns0.KeyStateOption{
				KeyID: 4711, KeyState: edns0.KeyStateInquiryKey,
			})

			// Exchange over TCP and keep the raw bytes: SIG.Verify needs the
			// exact wire buffer the signature was computed over.
			r, wire, err := exchangeCapturingWire(d.Addr(), q, "tcp", 3*time.Second)
			if err != nil {
				t.Fatalf("exchange: %v", err)
			}

			opt := r.IsEdns0()
			if opt == nil {
				t.Fatal("response carries no OPT RR")
			}
			ks, found := edns0.ExtractKeyStateOption(opt)
			if !found {
				t.Fatal("response carries no KeyState option")
			}
			if ks.KeyState != edns0.KeyStateTrusted {
				t.Errorf("KEY-STATE = %d, want %d", ks.KeyState, edns0.KeyStateTrusted)
			}
			if ks.KeyID != 4711 {
				t.Errorf("KEY-ID = %d, want the inquired 4711 echoed back", ks.KeyID)
			}

			var sig *dns.SIG
			for _, rr := range r.Extra {
				if s, ok := rr.(*dns.SIG); ok {
					sig = s
					break
				}
			}
			if gotSigned := sig != nil; gotSigned != tc.wantSigned {
				t.Fatalf("signed = %v, want %v", gotSigned, tc.wantSigned)
			}
			if !tc.wantSigned {
				return
			}

			err = sig.Verify(receiver.publicKEY(), wire)
			if verifies := err == nil; verifies != tc.wantVerifies {
				t.Errorf("verification against the receiver's key = %v, want %v (err %v)",
					verifies, tc.wantVerifies, err)
			}
		})
	}
}

// TestDoubleExtendedRcodeSurvives guards a packing hazard rather than a policy:
// rcodes above 15 need an OPT RR to carry the upper bits, and miekg/dns refuses
// to pack a message without one. If the double got this wrong, a scripted
// BADKEY would silently never arrive and D2/D3 would fail for the wrong reason.
func TestDoubleExtendedRcodeSurvives(t *testing.T) {
	script, err := ParseDoubleScript([]byte(`
rules:
  - match: {opcode: UPDATE}
    respond: {rcode: BADKEY}
`))
	if err != nil {
		t.Fatalf("ParseDoubleScript: %v", err)
	}
	d := startTestDouble(t, DoubleConfig{Script: script})

	r, err := exchange(t, d.Addr(), updateMsg(t, "parent.example."), "tcp")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if r.Rcode != dns.RcodeBadKey {
		t.Errorf("rcode = %s (%d), want BADKEY (%d)",
			dns.RcodeToString[r.Rcode], r.Rcode, dns.RcodeBadKey)
	}
	if r.IsEdns0() == nil {
		t.Error("extended-rcode response carries no OPT RR; the upper rcode bits have nowhere to live")
	}
}

// TestDoubleJournalsRequestSigner confirms the double reads the SIG(0) signer
// and keytag off the wire. Scenarios use this to tell a self-signed bootstrap
// from a trusted-key delegation UPDATE without the double doing any validation.
func TestDoubleJournalsRequestSigner(t *testing.T) {
	child := newTestSigner(t, "child.parent.example.")
	d := startTestDouble(t, DoubleConfig{})

	m := updateMsg(t, "parent.example.")
	signed, err := tdns.SignMsg(*m, child.KeyName, child.sak)
	if err != nil {
		t.Fatalf("SignMsg: %v", err)
	}
	if _, err := exchange(t, d.Addr(), signed, "tcp"); err != nil {
		t.Fatalf("exchange: %v", err)
	}

	j := d.Journal()
	if len(j) != 1 {
		t.Fatalf("journal has %d entries, want 1", len(j))
	}
	if !j[0].Signed {
		t.Error("signed request not marked Signed")
	}
	if j[0].Signer != "child.parent.example." {
		t.Errorf("Signer = %q, want child.parent.example.", j[0].Signer)
	}
	if j[0].KeyID != child.publicKEY().KeyTag() {
		t.Errorf("KeyID = %d, want %d", j[0].KeyID, child.publicKEY().KeyTag())
	}
}

// TestDoubleUnmatchedRequestDefaults: a request matching no rule is answered
// NOERROR and still journaled with RuleIndex -1, so an unexpected request is
// visible rather than silently absorbed.
func TestDoubleUnmatchedRequestDefaults(t *testing.T) {
	script, err := ParseDoubleScript([]byte(`
rules:
  - match: {opcode: QUERY}
    respond: {rcode: REFUSED}
`))
	if err != nil {
		t.Fatalf("ParseDoubleScript: %v", err)
	}
	d := startTestDouble(t, DoubleConfig{Script: script})

	r, err := exchange(t, d.Addr(), updateMsg(t, "parent.example."), "tcp")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if r.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %s, want NOERROR for an unmatched request", dns.RcodeToString[r.Rcode])
	}
	j := d.Journal()
	if len(j) != 1 || j[0].RuleIndex != -1 {
		t.Errorf("want one journal entry with RuleIndex -1, got %+v", j)
	}
}

// TestParseDoubleScriptRejectsGarbage: a typo in a script must fail loudly at
// parse time. A silently-ignored `rcode: BADKY` would make a scenario pass by
// answering NOERROR, which is the worst possible failure mode for a test tool.
func TestParseDoubleScriptRejectsGarbage(t *testing.T) {
	for _, tc := range []struct{ name, yaml string }{
		{"bad rcode", "rules:\n  - match: {opcode: UPDATE}\n    respond: {rcode: BADKY}\n"},
		{"bad sign mode", "rules:\n  - match: {opcode: UPDATE}\n    respond: {sign: sortof}\n"},
		{"bad opcode", "rules:\n  - match: {opcode: NOTIFY}\n    respond: {rcode: NOERROR}\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseDoubleScript([]byte(tc.yaml)); err == nil {
				t.Error("ParseDoubleScript accepted an invalid script")
			}
		})
	}
}
