package tdns

import "testing"

func TestTsigKeyStore_GetHasAdd(t *testing.T) {
	s := NewTsigKeyStore()
	s.Add(TsigDetails{Name: "k1", Algorithm: "hmac-sha256", Secret: "AAAA"})
	if d, ok := s.Get("k1"); !ok || d.Secret != "AAAA" || d.Algorithm != "hmac-sha256" {
		t.Fatalf("Get k1: got %+v ok=%v", d, ok)
	}
	if !s.Has("k1") {
		t.Error("Has(k1) = false")
	}
	for _, n := range []string{"", NOKEY, "unknown"} {
		if _, ok := s.Get(n); ok {
			t.Errorf("Get(%q) unexpectedly ok", n)
		}
		if s.Has(n) {
			t.Errorf("Has(%q) unexpectedly true", n)
		}
	}
}

func TestTsigKeyStore_NilSafe(t *testing.T) {
	var s *TsigKeyStore
	if _, ok := s.Get("k1"); ok {
		t.Error("nil store Get returned ok")
	}
	if s.Has("k1") {
		t.Error("nil store Has returned true")
	}
	s.Add(TsigDetails{Name: "k1"}) // must not panic
}

func TestLoadTsigKeys_ReservedAndIncompleteSkipped(t *testing.T) {
	conf := &Config{}
	conf.Keys.Tsig = []TsigDetails{
		{Name: "good", Algorithm: "hmac-sha256", Secret: b64Secret16},
		{Name: "NOKEY", Algorithm: "hmac-sha256", Secret: b64Secret16}, // reserved -> error, skipped
		{Name: "incomplete", Algorithm: "", Secret: b64Secret16},       // no algorithm -> error, skipped
		{Name: "good2", Algorithm: "hmac-sha512", Secret: b64Secret16},
	}
	if err := conf.LoadTsigKeys(); err == nil {
		t.Fatal("expected an error for the reserved/incomplete entries")
	}
	store := conf.Internal.TsigKeyStore
	if !store.Has("good") || !store.Has("good2") {
		t.Error("valid keys were not loaded")
	}
	if store.Has("NOKEY") || store.Has("incomplete") {
		t.Error("reserved/incomplete keys should be skipped")
	}
}

func TestLoadTsigKeys_CleanLoad(t *testing.T) {
	conf := &Config{}
	conf.Keys.Tsig = []TsigDetails{{Name: "k", Algorithm: "hmac-sha256", Secret: b64Secret16}}
	if err := conf.LoadTsigKeys(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !conf.Internal.TsigKeyStore.Has("k") {
		t.Error("key k not loaded")
	}
}

func TestTsigKeyDefined(t *testing.T) {
	conf := &Config{}
	conf.Keys.Tsig = []TsigDetails{{Name: "k", Algorithm: "hmac-sha256", Secret: b64Secret16}}
	_ = conf.LoadTsigKeys()
	if !conf.tsigKeyDefined(NOKEY) {
		t.Error("NOKEY should be accepted (no TSIG)")
	}
	if !conf.tsigKeyDefined("k") {
		t.Error("defined key k should be accepted")
	}
	if conf.tsigKeyDefined("nope") {
		t.Error("unknown key was accepted")
	}
}
