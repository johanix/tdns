package tdns

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestTsigBadtimeResponseIsSigned sends a TSIG-signed query whose Time Signed is
// an hour off to a real server set up the way Do53 is: the keystore provider on
// the dns.Server and TsigSigningHandler around the handler.
//
// RFC 8945 §5.2.3: a BADTIME response MUST be signed with the request's key.
// §5.3.2: the digest covers the request MAC (it validated), then the response,
// then the TSIG variables, and Time Signed is the client's.
//
// miekg's client cannot check this for us: its stripTsig returns ErrAuth for
// any NOTAUTH response before looking at the MAC. So the test recomputes the
// response MAC with the exported TsigGenerateWithProvider, over the received
// response and the request MAC, and compares it with the MAC on the wire.
func TestTsigBadtimeResponseIsSigned(t *testing.T) {
	conf := tsigTestConf(t)
	provider := conf.tsigProvider()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var answered atomic.Bool
	started := make(chan struct{})
	srv := &dns.Server{
		PacketConn:   pc,
		TsigProvider: provider,
		Handler: dns.HandlerFunc(TsigSigningHandler(func(w dns.ResponseWriter, r *dns.Msg) {
			answered.Store(true)
			m := new(dns.Msg)
			m.SetReply(r)
			_ = w.WriteMsg(m)
		})),
		NotifyStartedFunc: func() { close(started) },
	}
	go func() { _ = srv.ActivateAndServe() }()
	defer func() { _ = srv.Shutdown() }()
	<-started

	const fudge = 120 // not tsigFudge, so an echoed Fudge is visible
	skewed := uint64(time.Now().Add(-time.Hour).Unix())
	req := new(dns.Msg)
	req.SetQuestion("example.", dns.TypeSOA)
	req.SetTsig("tkey.", dns.HmacSHA256, fudge, int64(skewed))
	wire, reqMAC, err := dns.TsigGenerateWithProvider(req, provider, "", false)
	if err != nil {
		t.Fatalf("sign request: %v", err)
	}

	conn, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(wire); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(buf[:n]); err != nil {
		t.Fatalf("unpack response: %v", err)
	}

	if answered.Load() {
		t.Error("the handler answered a request whose TSIG failed the time check")
	}
	if resp.Rcode != dns.RcodeNotAuth {
		t.Errorf("rcode = %s, want NOTAUTH", dns.RcodeToString[resp.Rcode])
	}
	ts := resp.IsTsig()
	if ts == nil {
		t.Fatal("no TSIG on the BADTIME response")
	}
	if ts.Error != dns.RcodeBadTime {
		t.Errorf("TSIG error = %d, want BADTIME (%d)", ts.Error, dns.RcodeBadTime)
	}
	if ts.TimeSigned != skewed {
		t.Errorf("Time Signed = %d, want the client's %d (RFC 8945 §5.3.2)", ts.TimeSigned, skewed)
	}
	if ts.Fudge != fudge {
		t.Errorf("Fudge = %d, want the client's %d (RFC 8945 §5.2.3)", ts.Fudge, fudge)
	}
	if ts.OtherLen != 6 {
		t.Errorf("Other Len = %d, want 6 (the server's time)", ts.OtherLen)
	}
	if ts.MACSize == 0 || ts.MAC == "" {
		t.Fatal("BADTIME response has an empty MAC; RFC 8945 §5.2.3 requires it signed")
	}

	// What a verifier computes: the response without its MAC, signed with the
	// key over the request MAC + response + TSIG variables.
	expect := func(requestMAC string) string {
		m := resp.Copy()
		et := *ts
		et.MAC, et.MACSize = "", 0
		m.Extra[len(m.Extra)-1] = &et
		_, mac, err := dns.TsigGenerateWithProvider(m, provider, requestMAC, false)
		if err != nil {
			t.Fatalf("recompute MAC: %v", err)
		}
		return mac
	}
	if got, want := ts.MAC, expect(reqMAC); got != want {
		t.Errorf("response MAC does not verify with the request's key and MAC:\n got  %s\n want %s", got, want)
	}
	if ts.MAC == expect("") {
		t.Error("response MAC verifies WITHOUT the request MAC; RFC 8945 §5.3.2 puts it in the digest")
	}
}
