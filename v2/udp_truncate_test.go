/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type stubNetAddr struct {
	network string
}

func (a stubNetAddr) Network() string { return a.network }
func (a stubNetAddr) String() string  { return "stub:" + a.network }

type recordingRW struct {
	dns.ResponseWriter
	network string
	written *dns.Msg
}

func (w *recordingRW) RemoteAddr() net.Addr { return stubNetAddr{network: w.network} }
func (w *recordingRW) WriteMsg(m *dns.Msg) error {
	w.written = m
	return nil
}

func oversizedResponseFor(t *testing.T, minLen int) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeDNSKEY)
	m.SetEdns0(512, true)
	txt := make([]byte, minLen)
	for i := range txt {
		txt[i] = 'x'
	}
	m.Answer = append(m.Answer, &dns.TXT{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
		Txt: []string{string(txt)},
	})
	if m.Len() <= minLen {
		t.Fatalf("fixture not oversized for %d: len=%d", minLen, m.Len())
	}
	return m
}

func oversizedResponse(t *testing.T) *dns.Msg {
	return oversizedResponseFor(t, 512)
}

func TestTruncatingResponseWriter_UDPTruncates(t *testing.T) {
	inner := &recordingRW{network: "udp"}
	w := &truncatingResponseWriter{ResponseWriter: inner, udp: true, bufsize: 512}
	resp := oversizedResponse(t)

	if err := w.WriteMsg(resp); err != nil {
		t.Fatalf("WriteMsg: %v", err)
	}
	if inner.written == nil {
		t.Fatal("inner WriteMsg not called")
	}
	if !inner.written.Truncated {
		t.Error("expected TC bit set on truncated UDP response")
	}
	if inner.written.Len() > 512 {
		t.Errorf("truncated response len=%d, want <=512", inner.written.Len())
	}
	if len(inner.written.Question) != 1 {
		t.Errorf("question section lost: %+v", inner.written.Question)
	}
	if inner.written.IsEdns0() == nil {
		t.Error("expected OPT preserved in truncated response")
	}
}

func TestTruncatingResponseWriter_TCPPassthrough(t *testing.T) {
	inner := &recordingRW{network: "tcp"}
	w := &truncatingResponseWriter{ResponseWriter: inner, udp: false, bufsize: 512}
	resp := oversizedResponse(t)
	before := resp.Len()

	if err := w.WriteMsg(resp); err != nil {
		t.Fatalf("WriteMsg: %v", err)
	}
	if inner.written.Truncated {
		t.Error("TCP response must not be truncated")
	}
	if inner.written.Len() != before {
		t.Errorf("TCP response size changed: got %d want %d", inner.written.Len(), before)
	}
}

func TestTruncatingResponseWriter_UDPSmallUntouched(t *testing.T) {
	inner := &recordingRW{network: "udp"}
	w := &truncatingResponseWriter{ResponseWriter: inner, udp: true, bufsize: 512}
	resp := new(dns.Msg)
	resp.SetQuestion("example.com.", dns.TypeA)
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.IP{192, 0, 2, 1},
	})

	if err := w.WriteMsg(resp); err != nil {
		t.Fatalf("WriteMsg: %v", err)
	}
	if inner.written.Truncated {
		t.Error("small UDP response must not set TC")
	}
}

func TestUdpTruncate_UsesRequestBufsize(t *testing.T) {
	inner := &recordingRW{network: "udp"}
	var gotBufsize uint16
	serve := udpTruncate(func(w dns.ResponseWriter, r *dns.Msg) {
		tw := w.(*truncatingResponseWriter)
		gotBufsize = tw.bufsize
		resp := oversizedResponseFor(t, 1232)
		_ = w.WriteMsg(resp)
	})

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeDNSKEY)
	req.SetEdns0(1232, true)
	serve(inner, req)

	if gotBufsize != 1232 {
		t.Errorf("bufsize=%d, want 1232", gotBufsize)
	}
	if inner.written == nil || !inner.written.Truncated {
		t.Fatal("expected truncated response for oversized answer")
	}
}

func TestTsigSigningHandler_TruncatesBeforeMAC(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeDNSKEY)
	req.SetEdns0(512, true)
	req.SetTsig("mykey.", dns.HmacSHA256, 300, time.Now().Unix())

	inner := &fakeTsigRW{tsigStatus: nil, network: "udp"}
	serve := TsigSigningHandler(udpTruncate(func(w dns.ResponseWriter, r *dns.Msg) {
		_ = w.WriteMsg(oversizedResponse(t))
	}))
	serve(inner, req)

	if inner.written == nil {
		t.Fatal("no response written")
	}
	if !inner.written.Truncated {
		t.Error("expected TC on TSIG response chain")
	}
	if inner.written.Len() > 512 {
		t.Errorf("TSIG response len=%d, want <=512", inner.written.Len())
	}
	if inner.written.IsTsig() == nil {
		t.Error("expected response TSIG added after truncation")
	}
}
