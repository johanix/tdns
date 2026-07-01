package tdns

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

type fakeWriteRW struct{ written []byte }

func (f *fakeWriteRW) LocalAddr() net.Addr         { return nil }
func (f *fakeWriteRW) RemoteAddr() net.Addr        { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5353} }
func (f *fakeWriteRW) WriteMsg(*dns.Msg) error     { return nil }
func (f *fakeWriteRW) Write(b []byte) (int, error) { f.written = append([]byte(nil), b...); return len(b), nil }
func (f *fakeWriteRW) Close() error                { return nil }
func (f *fakeWriteRW) TsigStatus() error           { return nil }
func (f *fakeWriteRW) TsigTimersOnly(bool)         {}
func (f *fakeWriteRW) Hijack()                     {}

func TestWriteTsigErrorResponse(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.", dns.TypeSOA)
	req.SetTsig("mykey.", dns.HmacSHA256, 300, 1)
	reqTsig := req.IsTsig()

	cases := []struct {
		err      error
		wantCode uint16
	}{
		{dns.ErrSig, dns.RcodeBadSig},
		{dns.ErrSecret, dns.RcodeBadKey},
		{dns.ErrKeyAlg, dns.RcodeBadKey},
		{dns.ErrTime, dns.RcodeBadTime},
	}
	for _, c := range cases {
		frw := &fakeWriteRW{}
		writeTsigErrorResponse(frw, req, reqTsig, c.err)
		resp := new(dns.Msg)
		if err := resp.Unpack(frw.written); err != nil {
			t.Fatalf("%v: unpack: %v", c.err, err)
		}
		if resp.Rcode != dns.RcodeNotAuth {
			t.Errorf("%v: rcode=%d, want NOTAUTH(9)", c.err, resp.Rcode)
		}
		ts := resp.IsTsig()
		if ts == nil {
			t.Errorf("%v: no TSIG on response", c.err)
			continue
		}
		if ts.Error != c.wantCode {
			t.Errorf("%v: TSIG error=%d, want %d", c.err, ts.Error, c.wantCode)
		}
		if ts.MAC != "" || ts.MACSize != 0 {
			t.Errorf("%v: error TSIG must have empty MAC, got %q/%d", c.err, ts.MAC, ts.MACSize)
		}
		if ts.Hdr.Name != "mykey." || ts.Algorithm != dns.HmacSHA256 {
			t.Errorf("%v: TSIG key/algo not echoed: %s/%s", c.err, ts.Hdr.Name, ts.Algorithm)
		}
		found := false
		if opt := resp.IsEdns0(); opt != nil {
			for _, o := range opt.Option {
				if _, ok := o.(*dns.EDNS0_EDE); ok {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("%v: no EDE on response", c.err)
		}
	}
}
