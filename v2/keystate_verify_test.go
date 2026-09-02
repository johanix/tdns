package tdns

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// D-7 (draft-ietf-dnsop-delegation-mgmt-via-ddns-02 §"Mutual Authentication"):
// the child verifies the UPDATE Receiver's SIG(0) on KeyState responses. These
// tests use REAL ED25519 keys and the real miekg verifier -- a KeyState reply
// carries exactly one SIG(0), so unlike the multi-signer UPDATE tests there is
// no need for the sig0Verify seam except where a specific verifier error has
// to be provoked.

const (
	d7Receiver = "updates.parent.example."
	d7Child    = "child.parent.example."
	d7KeyID    = uint16(4242)
)

// genSig0Key generates an active SIG(0) key for name in kdb and returns the
// active-key set (for signing) and its KEY RR (what the owner would publish).
func genSig0Key(t *testing.T, kdb *KeyDB, name string) (*Sig0ActiveKeys, *dns.KEY) {
	t.Helper()
	if err := kdb.ensureSig0KeyForTest(name); err != nil {
		t.Fatalf("generate SIG(0) key for %s: %v", name, err)
	}
	sak, err := kdb.GetSig0Keys(name, Sig0StateActive)
	if err != nil || sak == nil || len(sak.Keys) == 0 {
		t.Fatalf("GetSig0Keys(%s): %v (keys=%v)", name, err, sak)
	}
	key := sak.Keys[0].KeyRR
	key.Hdr.Name = name
	return sak, &key
}

// keyStateReply builds the parent's reply to inquiry carrying ks. When sak is
// non-nil the reply is SIG(0)-signed as signer, the way keyStateResponseWriter
// signs it. The reply is returned unpacked from its own wire form, which is
// what the child has in hand.
func keyStateReply(t *testing.T, inquiry *dns.Msg, ks *edns0.KeyStateOption, signer string, sak *Sig0ActiveKeys) (*dns.Msg, []byte) {
	t.Helper()
	m := new(dns.Msg)
	m.SetReply(inquiry)
	edns0.AttachKeyStateToResponse(m, ks)
	if sak != nil {
		signed, err := SignMsg(*m, signer, sak)
		if err != nil {
			t.Fatalf("SignMsg: %v", err)
		}
		m = signed
	}
	wire, err := m.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	r := new(dns.Msg)
	if err := r.Unpack(wire); err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	return r, wire
}

// tamperKeyState rewrites the KEY-STATE byte of the KeyState option inside a
// packed message -- the on-path attack this whole item exists to stop -- and
// returns the tampered message unpacked plus its wire form.
func tamperKeyState(t *testing.T, wire []byte, newState uint8) (*dns.Msg, []byte) {
	t.Helper()
	code := edns0.EDNS0_KEYSTATE_OPTION_CODE
	// Option header: CODE(2) LEN(2); the option data is KEY-ID(2) KEY-STATE(1)
	// KEY-DATA(1) EXTRA-TEXT. Our test option has no EXTRA-TEXT, so LEN == 4.
	needle := []byte{byte(code >> 8), byte(code), 0, 4}
	i := bytes.Index(wire, needle)
	if i < 0 {
		t.Fatal("KeyState option not found in wire message")
	}
	out := append([]byte(nil), wire...)
	out[i+4+2] = newState
	r := new(dns.Msg)
	if err := r.Unpack(out); err != nil {
		t.Fatalf("Unpack tampered: %v", err)
	}
	return r, out
}

func fetchKeys(keys []dns.RR, validated bool, err error) receiverKeyFetcher {
	return func(context.Context, string) ([]dns.RR, bool, error) { return keys, validated, err }
}

func noTrust(string, uint16) (*dns.KEY, bool) { return nil, false }

func TestVerifyKeyStateResponse(t *testing.T) {
	parentKdb := newTestKeyDB(t)
	sak, receiverKey := genSig0Key(t, parentKdb, d7Receiver)
	otherKdb := newTestKeyDB(t)
	otherSak, _ := genSig0Key(t, otherKdb, "evil.example.")

	inquiry := newKeyStateInquiryMsg(d7Child, d7KeyID)
	ks := &edns0.KeyStateOption{KeyID: d7KeyID, KeyState: edns0.KeyStateTrusted}

	signed, signedWire := keyStateReply(t, inquiry, ks, d7Receiver, sak)
	unsigned, unsignedWire := keyStateReply(t, inquiry, ks, "", nil)
	// SIG names another zone as signer.
	wrongSigner, wrongSignerWire := keyStateReply(t, inquiry, ks, "evil.example.", otherSak)
	// SIG names the receiver as signer but was made with a key the receiver
	// does not publish (the key tag will not be found).
	unknownKey, unknownKeyWire := keyStateReply(t, inquiry, ks, d7Receiver, otherSak)
	// Genuinely signed, then the key state rewritten in flight.
	tampered, tamperedWire := tamperKeyState(t, signedWire, edns0.KeyStateUnknown)
	if got, _ := edns0.ExtractKeyStateOption(tampered.IsEdns0()); got.KeyState != edns0.KeyStateUnknown {
		t.Fatalf("tamper did not take: state %d", got.KeyState)
	}

	published := []dns.RR{receiverKey}

	cases := []struct {
		name          string
		r             *dns.Msg
		wire          []byte
		dsyncOK       bool
		fetch         receiverKeyFetcher
		allowInsecure bool
		wantAuth      bool
		wantErr       string // substring; "" means no error
	}{
		{
			name: "authenticated: DNSSEC-validated receiver KEY and DSYNC",
			r:    signed, wire: signedWire, dsyncOK: true,
			fetch:    fetchKeys(published, true, nil),
			wantAuth: true,
		},
		{
			name: "unvalidated receiver KEY rejected by default",
			r:    signed, wire: signedWire, dsyncOK: true,
			fetch:   fetchKeys(published, false, nil),
			wantErr: "not authenticated",
		},
		{
			name: "unvalidated receiver KEY accepted under allow-insecure, unauthenticated",
			r:    signed, wire: signedWire, dsyncOK: true,
			fetch:         fetchKeys(published, false, nil),
			allowInsecure: true,
			wantAuth:      false,
		},
		{
			// The DSYNC target IS the receiver identity; a validated KEY at a
			// forged target must not authenticate.
			name: "validated KEY but unvalidated DSYNC rejected by default",
			r:    signed, wire: signedWire, dsyncOK: false,
			fetch:   fetchKeys(published, true, nil),
			wantErr: "DSYNC DNSSEC-validated: false",
		},
		{
			name: "unsigned response rejected by default",
			r:    unsigned, wire: unsignedWire, dsyncOK: true,
			fetch:   fetchKeys(published, true, nil),
			wantErr: "not SIG(0)-signed",
		},
		{
			name: "unsigned response accepted under allow-insecure, unauthenticated",
			r:    unsigned, wire: unsignedWire, dsyncOK: true,
			fetch:         fetchKeys(published, true, nil),
			allowInsecure: true,
			wantAuth:      false,
		},
		{
			name: "wrong signer name rejected even under allow-insecure",
			r:    wrongSigner, wire: wrongSignerWire, dsyncOK: true,
			fetch:         fetchKeys(published, true, nil),
			allowInsecure: true,
			wantErr:       "signed by",
		},
		{
			name: "unknown signing keyid rejected by default",
			r:    unknownKey, wire: unknownKeyWire, dsyncOK: true,
			fetch:   fetchKeys(published, true, nil),
			wantErr: "no KEY with keyid",
		},
		{
			name: "unknown signing keyid accepted under allow-insecure, unauthenticated",
			r:    unknownKey, wire: unknownKeyWire, dsyncOK: true,
			fetch:         fetchKeys(published, true, nil),
			allowInsecure: true,
			wantAuth:      false,
		},
		{
			name: "tampered response rejected even under allow-insecure",
			r:    tampered, wire: tamperedWire, dsyncOK: true,
			fetch:         fetchKeys(published, true, nil),
			allowInsecure: true,
			wantErr:       "does not verify",
		},
		{
			name: "receiver KEY lookup failure rejected by default",
			r:    signed, wire: signedWire, dsyncOK: true,
			fetch:   fetchKeys(nil, false, errors.New("SERVFAIL")),
			wantErr: "no KEY with keyid",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			auth, err := verifyKeyStateResponse(context.Background(), c.wire, c.r, d7Receiver, c.dsyncOK,
				noTrust, c.fetch, c.allowInsecure)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, c.wantErr)
				}
				if auth {
					t.Fatal("authenticated=true alongside an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if auth != c.wantAuth {
				t.Fatalf("authenticated = %v, want %v", auth, c.wantAuth)
			}
		})
	}
}

// A receiver KEY the operator has put in the truststore and marked trusted is
// the manual bootstrap of ddns-02 §"Acquiring and Validating the UPDATE
// Receiver's Key": it authenticates on its own, with no DNSSEC anywhere and no
// DNS lookup at all. Until it is marked trusted it counts for nothing.
func TestVerifyKeyStateResponseManualTrust(t *testing.T) {
	parentKdb := newTestKeyDB(t)
	sak, receiverKey := genSig0Key(t, parentKdb, d7Receiver)
	childKdb := newTestKeyDB(t)

	inquiry := newKeyStateInquiryMsg(d7Child, d7KeyID)
	ks := &edns0.KeyStateOption{KeyID: d7KeyID, KeyState: edns0.KeyStateTrusted}
	signed, wire := keyStateReply(t, inquiry, ks, d7Receiver, sak)

	lookupFails := fetchKeys(nil, false, errors.New("unsigned parent zone, nothing published"))
	trust := childKdb.receiverKeyTrust()
	ctx := context.Background()

	// Nothing in the truststore: cannot authenticate.
	if _, err := verifyKeyStateResponse(ctx, wire, signed, d7Receiver, false, trust, lookupFails, false); err == nil {
		t.Fatal("expected rejection with an empty truststore")
	}

	// Added from a key file: stored untrusted, still counts for nothing.
	if _, err := childKdb.Sig0TrustMgmt(nil, TruststorePost{
		Command: "child-sig0-mgmt", SubCommand: "add", Src: "file",
		Keyname: d7Receiver, Keyid: int(receiverKey.KeyTag()), KeyRR: receiverKey.String(),
	}); err != nil {
		t.Fatalf("truststore add: %v", err)
	}
	if _, err := verifyKeyStateResponse(ctx, wire, signed, d7Receiver, false, trust, lookupFails, false); err == nil {
		t.Fatal("expected rejection while the receiver key is untrusted")
	}

	// The operator's trust decision.
	if _, err := childKdb.Sig0TrustMgmt(nil, TruststorePost{
		Command: "child-sig0-mgmt", SubCommand: "trust",
		Keyname: d7Receiver, Keyid: int(receiverKey.KeyTag()),
	}); err != nil {
		t.Fatalf("truststore trust: %v", err)
	}
	auth, err := verifyKeyStateResponse(ctx, wire, signed, d7Receiver, false, trust, lookupFails, false)
	if err != nil {
		t.Fatalf("manually trusted receiver key: %v", err)
	}
	if !auth {
		t.Fatal("authenticated = false with a trusted receiver key")
	}

	// A trusted key does not make a forged signature acceptable.
	tampered, tamperedWire := tamperKeyState(t, wire, edns0.KeyStateUnknown)
	if _, err := verifyKeyStateResponse(ctx, tamperedWire, tampered, d7Receiver, false, trust, lookupFails, true); err == nil ||
		!strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("tampered response against trusted key: err = %v", err)
	}
}

// A verifier failure is terminal whatever the policy, and a validity-window
// failure is reported as such so the operator can tell clock skew from a
// forgery.
func TestVerifyKeyStateResponseVerifierErrors(t *testing.T) {
	parentKdb := newTestKeyDB(t)
	sak, receiverKey := genSig0Key(t, parentKdb, d7Receiver)
	inquiry := newKeyStateInquiryMsg(d7Child, d7KeyID)
	signed, wire := keyStateReply(t, inquiry, &edns0.KeyStateOption{KeyID: d7KeyID, KeyState: edns0.KeyStateTrusted}, d7Receiver, sak)
	published := fetchKeys([]dns.RR{receiverKey}, true, nil)

	orig := sig0Verify
	t.Cleanup(func() { sig0Verify = orig })

	sig0Verify = func(*dns.SIG, *dns.KEY, []byte) error { return dns.ErrSig }
	if _, err := verifyKeyStateResponse(context.Background(), wire, signed, d7Receiver, true, noTrust, published, true); err == nil ||
		!strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("ErrSig under allow-insecure: err = %v, want rejection", err)
	}

	sig0Verify = func(*dns.SIG, *dns.KEY, []byte) error { return dns.ErrTime }
	if _, err := verifyKeyStateResponse(context.Background(), wire, signed, d7Receiver, true, noTrust, published, true); err == nil ||
		!strings.Contains(err.Error(), "validity window") {
		t.Fatalf("ErrTime: err = %v, want a validity-window message", err)
	}
}

// The production fetcher: a DNSSEC-secure KEY RRset in the IMR cache comes
// back validated. (Only the cache-hit path is exercised; a miss would go to
// the network.)
func TestImrReceiverKeyFetcherSecureCacheHit(t *testing.T) {
	imr := newTestImr(t)
	rr, err := dns.NewRR(d7Receiver + " 300 IN KEY 512 3 15 " + validChildKeyRRBase64())
	if err != nil {
		t.Fatal(err)
	}
	imr.Cache.Set(d7Receiver, dns.TypeKEY, &cache.CachedRRset{
		Name: d7Receiver, RRtype: dns.TypeKEY,
		RRset:   &core.RRset{Name: d7Receiver, RRtype: dns.TypeKEY, RRs: []dns.RR{rr}},
		Context: cache.ContextAnswer,
		State:   cache.ValidationStateSecure,
	})

	keys, validated, err := imrReceiverKeyFetcher(imr)(context.Background(), d7Receiver)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(keys) != 1 || !validated {
		t.Fatalf("keys=%d validated=%v, want 1 key, validated", len(keys), validated)
	}
	if _, _, err := imrReceiverKeyFetcher(nil)(context.Background(), d7Receiver); err == nil {
		t.Fatal("nil IMR must be an error, not an empty answer")
	}
}

// validChildKeyRRBase64 is 32 zero bytes, which is a syntactically valid
// ED25519 public key.
func validChildKeyRRBase64() string {
	return "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
}

// TestQueryKeyStateRoundTripTCP drives the child's inquiry against a real
// in-process responder that signs with the real parent-side writer
// (keyStateResponseWriter). This is what proves the wire-bytes handling: the
// SIG(0) the server computed over its own packed reply verifies against the
// bytes the child read off the TCP socket. It also proves the inquiry uses
// TCP -- the responder listens on nothing else.
func TestQueryKeyStateRoundTripTCP(t *testing.T) {
	parentKdb := newTestKeyDB(t)
	sak, receiverKey := genSig0Key(t, parentKdb, d7Receiver)
	childKdb := newTestKeyDB(t)
	_, childKey := genSig0Key(t, childKdb, d7Child)
	keyid := childKey.KeyTag()

	var unsignedMode atomic.Bool
	var served atomic.Int32
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	defer ln.Close()
	srv := &dns.Server{
		Listener: ln,
		Net:      "tcp",
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			served.Add(1)
			m := new(dns.Msg)
			m.SetReply(r)
			ks := &edns0.KeyStateOption{KeyID: keyid, KeyState: edns0.KeyStateTrusted, ExtraText: "Key state: Trusted"}
			if unsignedMode.Load() {
				edns0.AttachKeyStateToResponse(m, ks)
				_ = w.WriteMsg(m)
				return
			}
			ksw := &keyStateResponseWriter{ResponseWriter: w, keyStateResponse: ks, sig0Signer: d7Receiver, sig0Keys: sak}
			_ = ksw.WriteMsg(m)
		}),
	}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	defer func() {
		done := make(chan struct{})
		go func() { _ = srv.Shutdown(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("srv.Shutdown() timed out")
		}
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("responder did not start")
	}

	ctx := context.Background()
	trust := childKdb.receiverKeyTrust()
	published := fetchKeys([]dns.RR{receiverKey}, true, nil)
	target := func(validated bool) *DsyncTarget {
		return &DsyncTarget{Name: d7Receiver, Addresses: []string{ln.Addr().String()}, Validated: validated}
	}

	ks, auth, err := queryKeyState(ctx, childKdb, d7Child, keyid, target(true), trust, published, false)
	if err != nil {
		t.Fatalf("signed round trip: %v", err)
	}
	if !auth || ks.KeyState != edns0.KeyStateTrusted || ks.KeyID != keyid || ks.ExtraText != "Key state: Trusted" {
		t.Fatalf("got auth=%v ks=%+v", auth, ks)
	}
	if served.Load() == 0 {
		t.Fatal("the TCP responder was never reached")
	}

	if _, _, err := queryKeyState(ctx, childKdb, d7Child, keyid, target(false), trust, published, false); err == nil ||
		!strings.Contains(err.Error(), "DSYNC DNSSEC-validated: false") {
		t.Fatalf("unvalidated DSYNC: err = %v", err)
	}

	unsignedMode.Store(true)
	if _, _, err := queryKeyState(ctx, childKdb, d7Child, keyid, target(true), trust, published, false); err == nil ||
		!strings.Contains(err.Error(), "not SIG(0)-signed") {
		t.Fatalf("unsigned reply, strict: err = %v", err)
	}
	ks, auth, err = queryKeyState(ctx, childKdb, d7Child, keyid, target(true), trust, published, true)
	if err != nil {
		t.Fatalf("unsigned reply, allow-insecure: %v", err)
	}
	if auth || ks.KeyState != edns0.KeyStateTrusted {
		t.Fatalf("unsigned reply, allow-insecure: auth=%v ks=%+v, want unauthenticated Trusted", auth, ks)
	}

	// No responder: a transport error, not a verification error.
	dead := &DsyncTarget{Name: d7Receiver, Addresses: []string{"127.0.0.1:1"}, Validated: true}
	if _, _, err := queryKeyState(ctx, childKdb, d7Child, keyid, dead, trust, published, false); err == nil ||
		!strings.Contains(err.Error(), "exchange failed") {
		t.Fatalf("dead target: err = %v", err)
	}
}
