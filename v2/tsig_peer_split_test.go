package tdns

import (
	"testing"

	"github.com/miekg/dns"
)

// SignForPeer was split into TsigMaterialForPeer (reads config) and
// StampTsigForPeer (stamps a message), so ProbeUpstreamSerials can snapshot
// config for every upstream up front while still stamping each message
// immediately before its own exchange. These tests pin the behaviour of the
// pieces and assert SignForPeer still composes them exactly as before.

func TestTsigMaterialForPeer(t *testing.T) {
	conf := tsigTestConf(t)

	// A configured key yields a provider plus its algorithm, and must NOT
	// stamp anything -- that is the whole point of the split.
	provider, algo, err := TsigMaterialForPeer("tkey", conf)
	if err != nil {
		t.Fatalf("TsigMaterialForPeer: %v", err)
	}
	if provider == nil {
		t.Fatal("expected a provider for a configured key")
	}
	if algo != "hmac-sha256" {
		t.Errorf("algorithm: got %q want %q", algo, "hmac-sha256")
	}

	// NOKEY and empty are the plain-exchange cases: no provider, no error.
	for _, name := range []string{"", NOKEY} {
		p, a, err := TsigMaterialForPeer(name, conf)
		if err != nil || p != nil || a != "" {
			t.Errorf("TsigMaterialForPeer(%q): got (%v, %q, %v), want (nil, \"\", nil)", name, p, a, err)
		}
	}

	// An unknown key is an error, not a silent plain exchange.
	if _, _, err := TsigMaterialForPeer("nosuchkey", conf); err == nil {
		t.Error("expected an error for a key that is not in the store")
	}
}

func TestStampTsigForPeerSetsFreshTSIG(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("example.", dns.TypeSOA)
	StampTsigForPeer(m, "tkey", "hmac-sha256")

	tsig := m.IsTsig()
	if tsig == nil {
		t.Fatal("no TSIG RR was set")
	}
	if tsig.Hdr.Name != dns.CanonicalName("tkey") {
		t.Errorf("key name: got %q want %q", tsig.Hdr.Name, dns.CanonicalName("tkey"))
	}
	if tsig.Algorithm != dns.CanonicalName("hmac-sha256") {
		t.Errorf("algorithm: got %q want %q", tsig.Algorithm, dns.CanonicalName("hmac-sha256"))
	}
	if tsig.TimeSigned == 0 {
		t.Error("TimeSigned should be stamped with the current time")
	}
}

// SignForPeer must behave exactly as it did before the split: stamp the message
// and return the provider for a configured key, and do neither for NOKEY.
func TestSignForPeerStillStampsAndReturnsProvider(t *testing.T) {
	conf := tsigTestConf(t)

	m := new(dns.Msg)
	m.SetQuestion("example.", dns.TypeSOA)
	provider, err := SignForPeer(m, "tkey", conf)
	if err != nil {
		t.Fatalf("SignForPeer: %v", err)
	}
	if provider == nil {
		t.Fatal("expected a provider")
	}
	if m.IsTsig() == nil {
		t.Error("SignForPeer must stamp the message")
	}

	plain := new(dns.Msg)
	plain.SetQuestion("example.", dns.TypeSOA)
	p, err := SignForPeer(plain, NOKEY, conf)
	if err != nil || p != nil {
		t.Errorf("SignForPeer(NOKEY): got (%v, %v), want (nil, nil)", p, err)
	}
	if plain.IsTsig() != nil {
		t.Error("SignForPeer(NOKEY) must not stamp the message")
	}
}
