package tdns

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func tsigTestConf(t *testing.T) *Config {
	t.Helper()
	conf := &Config{}
	// "MTIzNDU2Nzg5MDEyMzQ1Ng==" is valid std-base64 (decodes to 16 bytes).
	conf.Keys.Tsig = []TsigDetails{{Name: "tkey", Algorithm: "hmac-sha256", Secret: "MTIzNDU2Nzg5MDEyMzQ1Ng=="}}
	if err := conf.LoadTsigKeys(); err != nil {
		t.Fatalf("LoadTsigKeys: %v", err)
	}
	return conf
}

func TestSignForPeer_NOKEY(t *testing.T) {
	conf := tsigTestConf(t)
	m := new(dns.Msg)
	m.SetQuestion("example.", dns.TypeSOA)
	p, err := SignForPeer(m, NOKEY, conf)
	if err != nil || p != nil {
		t.Fatalf("NOKEY should be a no-op: p=%v err=%v", p, err)
	}
	if m.IsTsig() != nil {
		t.Error("NOKEY must not add a TSIG RR")
	}
}

func TestSignForPeer_SetsTsig(t *testing.T) {
	conf := tsigTestConf(t)
	m := new(dns.Msg)
	m.SetQuestion("example.", dns.TypeSOA)
	p, err := SignForPeer(m, "tkey", conf)
	if err != nil || p == nil {
		t.Fatalf("keyed sign: p=%v err=%v", p, err)
	}
	ts := m.IsTsig()
	if ts == nil {
		t.Fatal("no TSIG RR set")
	}
	if ts.Hdr.Name != "tkey." {
		t.Errorf("TSIG key name = %q, want tkey.", ts.Hdr.Name)
	}
	if ts.Algorithm != dns.HmacSHA256 {
		t.Errorf("TSIG algorithm = %q, want %q", ts.Algorithm, dns.HmacSHA256)
	}
}

func TestSignForPeer_UnknownKey(t *testing.T) {
	conf := tsigTestConf(t)
	m := new(dns.Msg)
	m.SetQuestion("example.", dns.TypeSOA)
	if _, err := SignForPeer(m, "nope", conf); err == nil {
		t.Error("unknown key should error")
	}
}

// Sign a message with the provider and verify it back, via the vendored library's
// own generate/verify — proving the provider matches the wire format (and so
// interoperates with BIND/NSD), and that a wrong secret fails.
func TestTsigProvider_RoundTrip(t *testing.T) {
	conf := tsigTestConf(t)
	provider := conf.tsigProvider()

	m := new(dns.Msg)
	m.SetQuestion("example.", dns.TypeSOA)
	m.SetTsig(dns.CanonicalName("tkey"), dns.HmacSHA256, tsigFudge, time.Now().Unix())
	signed, _, err := dns.TsigGenerateWithProvider(m, provider, "", false)
	if err != nil {
		t.Fatalf("TsigGenerate: %v", err)
	}
	if err := dns.TsigVerifyWithProvider(signed, provider, "", false); err != nil {
		t.Fatalf("TsigVerify (good secret): %v", err)
	}

	other := &Config{}
	other.Keys.Tsig = []TsigDetails{{Name: "tkey", Algorithm: "hmac-sha256", Secret: "YWJjZGVmZ2hpamtsbW5vcA=="}}
	if err := other.LoadTsigKeys(); err != nil {
		t.Fatalf("LoadTsigKeys(other): %v", err)
	}
	if err := dns.TsigVerifyWithProvider(signed, other.tsigProvider(), "", false); err == nil {
		t.Error("verification with a wrong secret should fail")
	}
}

func TestNotifyKeyFor(t *testing.T) {
	zd := &ZoneData{Notify: []PeerConf{
		{Addr: "192.0.2.1:53", Key: "k1"},
		{Addr: "192.0.2.2:5353", Key: "k2"},
		{Addr: "192.0.2.3:53", Key: NOKEY},
	}}
	cases := map[string]string{
		"192.0.2.1:53":   "k1",
		"192.0.2.1:9999": "k1", // IP-only match (configured vs actual port differ)
		"192.0.2.2:5353": "k2",
		"192.0.2.3:53":   NOKEY,
		"203.0.113.9:53":  NOKEY, // no matching notify peer
	}
	for target, want := range cases {
		if got := zd.notifyKeyFor(target); got != want {
			t.Errorf("notifyKeyFor(%q) = %q, want %q", target, got, want)
		}
	}
}

func TestPeerIP(t *testing.T) {
	cases := map[string]string{
		"192.0.2.1:53":     "192.0.2.1",
		"192.0.2.1":        "192.0.2.1",
		"[2001:db8::1]:53": "2001:db8::1",
		"2001:db8::1":      "2001:db8::1",
	}
	for in, want := range cases {
		got, ok := peerIP(in)
		if !ok || got.String() != want {
			t.Errorf("peerIP(%q) = %v ok=%v, want %v", in, got, ok, want)
		}
	}
	if _, ok := peerIP("garbage"); ok {
		t.Error("garbage should not parse to an IP")
	}
}
