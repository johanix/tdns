package tdns

import (
	"context"
	"log"
	"net"
	"os"
	"testing"
	"time"

	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// captureWriter is a dns.ResponseWriter that records the message the responder
// wrote instead of putting it on a wire.
type captureWriter struct {
	got *dns.Msg
}

func (c *captureWriter) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
}
func (c *captureWriter) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4711}
}
func (c *captureWriter) WriteMsg(m *dns.Msg) error {
	c.got = m
	return nil
}
func (c *captureWriter) Write(b []byte) (int, error) { return len(b), nil }
func (c *captureWriter) Close() error                { return nil }
func (c *captureWriter) TsigStatus() error           { return nil }
func (c *captureWriter) TsigTimersOnly(bool)         {}
func (c *captureWriter) Hijack()                     {}

// TestUpdateResponderRelaysValidationRcodeAndEDE asserts that the responder
// puts ValidateUpdate's chosen rcode and EDE on the wire rather than
// overwriting them.
//
// An UPDATE with no signature and no OPT RR makes ValidateUpdate set
// FORMERR + EDESig0FormatError. The responder used to discard both and
// hardcode SERVFAIL + EDESig0KeyNotKnown, which was wrong twice over: the
// rcode misreported a malformed message as a server failure, the EDE claimed a
// key problem for a message that carried no key at all, and EDESig0FormatError
// became unreachable on the wire from this path.
func TestUpdateResponderRelaysValidationRcodeAndEDE(t *testing.T) {
	const zone = "parent.example."

	// The zone must hold a PUBLISHED snapshot, not just exist in the Zones map.
	// UpdateResponder refuses with SERVFAIL + EDEZoneNotFound before it ever
	// reaches ValidateUpdate when !zd.HasPublishedData() -- the same predicate
	// the query path uses. A bare &ZoneData{} passes the Zones.Get but not that
	// gate, so it would exercise the refusal instead of the relay this test is
	// about.
	zd := testSnapshotZone(t, zone, `parent.example.	3600	IN	SOA	ns.parent.example. hostmaster.parent.example. 1 7200 1800 604800 7200
parent.example.	3600	IN	NS	ns.parent.example.
ns.parent.example.	3600	IN	A	192.0.2.53
`)
	zd.Options = map[ZoneOption]bool{OptAllowUpdates: true}

	// An UPDATE with no SIG(0) and, deliberately, no EDNS0 OPT: that is the
	// len(r.Extra) == 0 branch in ValidateUpdate.
	m := new(dns.Msg)
	m.SetUpdate(zone)
	rr, err := dns.NewRR("www.parent.example. 3600 IN A 192.0.2.1")
	if err != nil {
		t.Fatalf("NewRR: %v", err)
	}
	m.Insert([]dns.RR{rr})
	if len(m.Extra) != 0 {
		t.Fatalf("test message must carry no additional records, got %d", len(m.Extra))
	}

	cw := &captureWriter{}
	dur := &DnsUpdateRequest{
		ResponseWriter: cw,
		Msg:            m,
		Qname:          zone,
		Status:         &UpdateStatus{},
	}

	// An unsigned update is expected to return an error; we assert on the wire
	// response, not on the error.
	_ = UpdateResponder(context.Background(), dur, nil)

	if cw.got == nil {
		t.Fatal("responder wrote no response")
	}

	if got, want := cw.got.Rcode, dns.RcodeFormatError; got != want {
		t.Errorf("rcode = %d (%s), want %d (%s) — the responder must relay the rcode ValidateUpdate chose, not substitute SERVFAIL",
			got, dns.RcodeToString[got], want, dns.RcodeToString[want])
	}

	found, code, _ := edns0.ExtractEDEFromMsg(cw.got)
	if !found {
		t.Fatal("response carries no EDE option")
	}
	if code != edns0.EDESig0FormatError {
		t.Errorf("EDE = %d, want %d (EDESig0FormatError) — a message with no signature at all is a format error, not an unknown key",
			code, edns0.EDESig0FormatError)
	}

	// The status the responder acted on must agree with what went on the wire.
	if dur.Status.ValidationRcode != dns.RcodeFormatError {
		t.Errorf("Status.ValidationRcode = %d, want %d", dur.Status.ValidationRcode, dns.RcodeFormatError)
	}
	if dur.Status.Validated {
		t.Error("Status.Validated is true for an unsigned update")
	}
}

// TestUpdateResponderReleasesOnShutdownRatherThanBlocking.
//
// The handoff to the zone updater was a bare channel send. The updater exits on
// the SAME root context, so at shutdown this was a send to a queue nobody would
// ever read again -- and the DNS update engine stayed open on it indefinitely.
//
// The update has to VALIDATE for the responder to reach the send at all, which
// is why this carries a trusted key and a stubbed verifier: an unsigned message
// is refused long before the queue, and a test built on one passes whether the
// send is cancellable or not.
func TestUpdateResponderReleasesOnShutdownRatherThanBlocking(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := cuParentZone(t)
	registerZones(t, zd)
	zd.KeyDB = kdb
	zd.Logger = log.New(os.Stderr, "", 0)
	zd.Options = map[ZoneOption]bool{OptAllowUpdates: true, OptAllowChildUpdates: true}
	// ApproveUpdate rejects anything the policy does not name, and a rejected
	// update is answered immediately -- never reaching the queue.
	zd.UpdatePolicy = UpdatePolicy{
		Zone: UpdatePolicyDetail{Type: "selfsub", RRtypes: map[uint16]bool{dns.TypeA: true}, TTL: 3600},
	}

	// A key the parent already trusts, so ValidateUpdate + TrustUpdate accept
	// the message and the responder gets as far as the queue.
	key := mustRR(t, "example. 3600 IN KEY 256 3 15 kR7NlEmXPWWDCFZmJqFhOJjHtBSKuLnCJHBTLzNJnUE=").(*dns.KEY)
	if _, err := kdb.Sig0TrustMgmt(nil, TruststorePost{
		Command: "sig0", SubCommand: "add", Keyname: "example.",
		Keyid: int(key.KeyTag()), Src: "file", KeyRR: key.String(),
	}); err != nil {
		t.Fatalf("add key: %v", err)
	}
	if _, err := kdb.Sig0TrustMgmt(nil, TruststorePost{
		Command: "child-sig0-mgmt", SubCommand: "trust", Keyname: "example.",
		Keyid: int(key.KeyTag()),
	}); err != nil {
		t.Fatalf("trust key: %v", err)
	}
	stubSig0Verify(t)

	full := make(chan UpdateRequest) // unbuffered, no reader: the stopped updater
	ctx, cancel := context.WithCancel(context.Background())

	m := signedUpdateFrom(t, zd.ZoneName, "example.", key.KeyTag())
	// A name in the parent that is NOT a delegation, so this is a ZONE-UPDATE
	// rather than a CHILD-UPDATE (which the coherence checks refuse with no
	// scanner configured, long before the queue).
	m.Ns = []dns.RR{mustRR(t, "www.example. 3600 IN A 192.0.2.1")}
	dur := &DnsUpdateRequest{
		ResponseWriter: &captureWriter{},
		Msg:            m,
		Qname:          zd.ZoneName,
		Status:         &UpdateStatus{},
	}

	returned := make(chan error, 1)
	go func() { returned <- UpdateResponder(ctx, dur, full) }()

	// It must actually be parked on the send, or this proves nothing.
	select {
	case err := <-returned:
		t.Fatalf("the responder returned before reaching the update queue (%v); the fixture"+
			" is being refused somewhere earlier and the send is never exercised", err)
	case <-time.After(300 * time.Millisecond):
	}

	cancel()

	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("UpdateResponder did not return after its context was cancelled; the DNS" +
			" update engine cannot shut down while it is parked on this send")
	}
}
