package tdns

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// fakeRW is a minimal dns.ResponseWriter for exercising the inbound TSIG/ACL
// helpers without a live server: RemoteAddr and TsigStatus are settable, the rest
// are no-ops, and WriteMsg records the last response.
type fakeRW struct {
	remote     net.Addr
	tsigStatus error
	written    *dns.Msg
}

func (f *fakeRW) LocalAddr() net.Addr       { return f.remote }
func (f *fakeRW) RemoteAddr() net.Addr      { return f.remote }
func (f *fakeRW) WriteMsg(m *dns.Msg) error { f.written = m; return nil }
func (f *fakeRW) Write(b []byte) (int, error) {
	return len(b), nil
}
func (f *fakeRW) Close() error        { return nil }
func (f *fakeRW) TsigStatus() error   { return f.tsigStatus }
func (f *fakeRW) TsigTimersOnly(bool) {}
func (f *fakeRW) Hijack()             {}

func udpAddr(ip string) net.Addr { return &net.UDPAddr{IP: net.ParseIP(ip), Port: 5353} }

func signedMsg(keyName string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion("example.test.", dns.TypeSOA)
	m.SetTsig(dns.CanonicalName(keyName), dns.HmacSHA256, 300, time.Now().Unix())
	return m
}

func TestCheckInboundTSIG(t *testing.T) {
	unsigned := new(dns.Msg)
	unsigned.SetQuestion("example.test.", dns.TypeSOA)

	// NOKEY / empty: always accepted, signed or not.
	if err := checkInboundTSIG(&fakeRW{}, unsigned, NOKEY); err != nil {
		t.Errorf("NOKEY unsigned: unexpected error %v", err)
	}
	if err := checkInboundTSIG(&fakeRW{}, signedMsg("k"), ""); err != nil {
		t.Errorf("empty required key: unexpected error %v", err)
	}

	// Named key required but request unsigned -> error.
	if err := checkInboundTSIG(&fakeRW{}, unsigned, "k"); err == nil {
		t.Error("named key + unsigned request should error")
	}

	// Named key, request signed but the server reported a bad MAC -> error.
	if err := checkInboundTSIG(&fakeRW{tsigStatus: errors.New("bad mac")}, signedMsg("k"), "k"); err == nil {
		t.Error("named key + failed TsigStatus should error")
	}

	// Named key, signed and verified, names match -> ok.
	if err := checkInboundTSIG(&fakeRW{}, signedMsg("k"), "k"); err != nil {
		t.Errorf("named key + valid TSIG: unexpected error %v", err)
	}

	// Named key, signed and verified, but with a DIFFERENT key than the ACL
	// requires -> error (a valid MAC under the wrong key must not pass).
	if err := checkInboundTSIG(&fakeRW{}, signedMsg("other"), "k"); err == nil {
		t.Error("valid TSIG under the wrong key name should error")
	}
}

// A key provisioned for one algorithm must reject an inbound TSIG that names a
// different algorithm, even if the secret matches (RFC 8945 keys are algo-bound).
func TestProviderRejectsAlgorithmMismatch(t *testing.T) {
	conf := &Config{}
	conf.Internal.TsigKeyStore = NewTsigKeyStore()
	conf.Internal.TsigKeyStore.Add(TsigDetails{Name: "k", Algorithm: "hmac-sha256", Secret: "MTIzNDU2Nzg5MDEyMzQ1Ng=="})
	p := tsigKeyProvider{conf.Internal.TsigKeyStore}

	mismatch := &dns.TSIG{Hdr: dns.RR_Header{Name: "k."}, Algorithm: dns.HmacSHA1}
	if _, err := p.hmac(mismatch); err != dns.ErrKeyAlg {
		t.Errorf("algorithm mismatch: got err=%v, want ErrKeyAlg", err)
	}
	match := &dns.TSIG{Hdr: dns.RR_Header{Name: "k."}, Algorithm: dns.HmacSHA256}
	if _, err := p.hmac(match); err != nil {
		t.Errorf("matching algorithm: unexpected err=%v", err)
	}
}

func TestAllowNotifyDecision(t *testing.T) {
	// Empty allow-notify: accept (unsigned) from a resolved primary IP only.
	zd := &ZoneData{Upstreams: []PeerConf{{Addr: "192.0.2.1:53"}, {Addr: "192.0.2.2:53"}}}
	if ok, key := zd.allowNotifyDecision(netip.MustParseAddr("192.0.2.1")); !ok || key != NOKEY {
		t.Errorf("empty ACL, primary src: got (%v,%q), want (true,NOKEY)", ok, key)
	}
	if ok, _ := zd.allowNotifyDecision(netip.MustParseAddr("203.0.113.9")); ok {
		t.Error("empty ACL, non-primary src should be denied")
	}

	// Non-empty allow-notify: matchACL governs (and the primary list is ignored).
	zd2 := &ZoneData{
		Upstreams:   []PeerConf{{Addr: "192.0.2.1:53"}},
		AllowNotify: []AclEntry{{Prefix: "198.51.100.0/24", Key: "nkey"}},
	}
	if ok, key := zd2.allowNotifyDecision(netip.MustParseAddr("198.51.100.7")); !ok || key != "nkey" {
		t.Errorf("ACL match: got (%v,%q), want (true,nkey)", ok, key)
	}
	if ok, _ := zd2.allowNotifyDecision(netip.MustParseAddr("192.0.2.1")); ok {
		t.Error("with a non-empty ACL, a primary not in the ACL must be denied")
	}
}

func TestDownstreamsDecision(t *testing.T) {
	// Empty downstreams: deny (hard cutover from open AXFR).
	zd := &ZoneData{}
	if ok, _ := zd.downstreamsDecision(netip.MustParseAddr("192.0.2.1")); ok {
		t.Error("empty downstreams must deny")
	}

	zd2 := &ZoneData{Downstreams: []AclEntry{{Prefix: "0.0.0.0/0", Key: "xkey"}}}
	if ok, key := zd2.downstreamsDecision(netip.MustParseAddr("192.0.2.1")); !ok || key != "xkey" {
		t.Errorf("0.0.0.0/0 xkey: got (%v,%q), want (true,xkey)", ok, key)
	}
}

func TestSignResponseLikeRequest(t *testing.T) {
	// Unsigned request -> response stays unsigned.
	resp := new(dns.Msg)
	resp.SetQuestion("example.test.", dns.TypeSOA)
	signResponseLikeRequest(&fakeRW{}, new(dns.Msg), resp)
	if resp.IsTsig() != nil {
		t.Error("unsigned request must not produce a signed response")
	}

	// Signed + verified request -> response carries a TSIG with the same key.
	resp2 := new(dns.Msg)
	resp2.SetQuestion("example.test.", dns.TypeSOA)
	signResponseLikeRequest(&fakeRW{}, signedMsg("k"), resp2)
	ts := resp2.IsTsig()
	if ts == nil {
		t.Fatal("signed+verified request should yield a signed response")
	}
	if ts.Hdr.Name != "k." {
		t.Errorf("response TSIG key = %q, want k.", ts.Hdr.Name)
	}

	// Signed request that FAILED verification -> response stays unsigned.
	resp3 := new(dns.Msg)
	resp3.SetQuestion("example.test.", dns.TypeSOA)
	signResponseLikeRequest(&fakeRW{tsigStatus: errors.New("bad mac")}, signedMsg("k"), resp3)
	if resp3.IsTsig() != nil {
		t.Error("a request that failed TSIG verification must not get a signed response")
	}
}
