package tdns

import (
	"log"
	"net"
	"os"
	"testing"

	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// captureWriter is a dns.ResponseWriter that records the message the responder
// wrote instead of putting it on a wire.
type captureWriter struct {
	got *dns.Msg
}

func (c *captureWriter) LocalAddr() net.Addr  { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53} }
func (c *captureWriter) RemoteAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4711} }
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

	Zones.Set(zone, &ZoneData{
		ZoneName: zone,
		Options:  map[ZoneOption]bool{OptAllowUpdates: true},
		Logger:   log.New(os.Stderr, "", 0),
	})
	t.Cleanup(func() { Zones.Remove(zone) })

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
	_ = UpdateResponder(dur, nil)

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
