package tdns

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

type fakeTsigRW struct {
	tsigStatus error
	written    *dns.Msg
	network    string
}

func (f *fakeTsigRW) LocalAddr() net.Addr { return nil }
func (f *fakeTsigRW) RemoteAddr() net.Addr {
	if f.network == "" {
		return stubNetAddr{network: "tcp"}
	}
	return stubNetAddr{network: f.network}
}
func (f *fakeTsigRW) WriteMsg(m *dns.Msg) error { f.written = m; return nil }
func (f *fakeTsigRW) Write([]byte) (int, error) { return 0, nil }
func (f *fakeTsigRW) Close() error              { return nil }
func (f *fakeTsigRW) TsigStatus() error         { return f.tsigStatus }
func (f *fakeTsigRW) TsigTimersOnly(bool)       {}
func (f *fakeTsigRW) Hijack()                   {}

func TestTsigSignResponseWriter(t *testing.T) {
	reqTsig := &dns.TSIG{
		Hdr:       dns.RR_Header{Name: "mykey.", Rrtype: dns.TypeTSIG, Class: dns.ClassANY},
		Algorithm: dns.HmacSHA256,
	}
	mk := func() *dns.Msg { m := new(dns.Msg); m.SetQuestion("x.", dns.TypeSOA); return m }

	cases := []struct {
		name    string
		reqTsig *dns.TSIG
		status  error
		want    bool // response should be signed
	}{
		{"validated request -> signed", reqTsig, nil, true},
		{"failed request -> unsigned", reqTsig, dns.ErrSig, false},
		{"no request TSIG -> unsigned", nil, nil, false},
	}
	for _, c := range cases {
		frw := &fakeTsigRW{tsigStatus: c.status}
		w := &tsigSignResponseWriter{ResponseWriter: frw, reqTsig: c.reqTsig}
		if err := w.WriteMsg(mk()); err != nil {
			t.Fatalf("%s: WriteMsg: %v", c.name, err)
		}
		if got := frw.written.IsTsig() != nil; got != c.want {
			t.Errorf("%s: signed=%v, want %v", c.name, got, c.want)
		}
	}
}
