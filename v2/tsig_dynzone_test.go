package tdns

import "testing"

const b64Secret16 = "MTIzNDU2Nzg5MDEyMzQ1Ng==" // valid std-base64, 16 bytes

func TestKnownTsigAlgo(t *testing.T) {
	for _, a := range []string{"hmac-sha256", "hmac-sha256.", "HMAC-SHA512", "hmac-sha1", "hmac-sha224", "hmac-sha384"} {
		if !knownTsigAlgo(a) {
			t.Errorf("knownTsigAlgo(%q) = false, want true", a)
		}
	}
	for _, a := range []string{"", "md5", "gss-tsig", "sha256"} {
		if knownTsigAlgo(a) {
			t.Errorf("knownTsigAlgo(%q) = true, want false", a)
		}
	}
}

func TestValidateTsigKeySpec(t *testing.T) {
	if err := validateTsigKeySpec("k", "hmac-sha256", b64Secret16); err != nil {
		t.Errorf("valid spec rejected: %v", err)
	}
	bad := []struct{ name, algo, secret string }{
		{"", "hmac-sha256", b64Secret16},      // no name
		{"k", "hmac-sha256", ""},              // no secret
		{"NOKEY", "hmac-sha256", b64Secret16}, // reserved (any case)
		{"blocked", "hmac-sha256", b64Secret16},
		{"k", "md5", b64Secret16},        // unsupported algo
		{"k", "hmac-sha256", "not b64!"}, // bad base64
	}
	for _, c := range bad {
		if err := validateTsigKeySpec(c.name, c.algo, c.secret); err == nil {
			t.Errorf("validateTsigKeySpec(%q,%q,%q) = nil, want error", c.name, c.algo, c.secret)
		}
	}
}

func TestStageInlineTsigKey(t *testing.T) {
	conf := &Config{}
	conf.Internal.TsigKeyStore = NewTsigKeyStore()
	in := DynamicZoneInput{
		Name:       "example.test.",
		Primaries:  []PeerConf{{Addr: "192.0.2.1:53", Key: NOKEY}, {Addr: "192.0.2.2:53", Key: "explicit"}},
		TsigName:   "ikey",
		TsigSecret: b64Secret16, // no algo -> default hmac-sha256
	}
	staged, err := conf.stageInlineTsigKey(&in)
	if err != nil {
		t.Fatalf("stageInlineTsigKey: %v", err)
	}
	if staged == nil || staged.Algorithm != "hmac-sha256" {
		t.Fatalf("staged key missing or wrong default algo: %+v", staged)
	}
	// Staging must NOT touch the live store.
	if conf.Internal.TsigKeyStore.Has("ikey") {
		t.Error("staging must not commit the key to the live store")
	}
	// Keyless primary points at the inline key; the explicit one is untouched.
	if in.Primaries[0].Key != "ikey" {
		t.Errorf("keyless primary Key = %q, want ikey", in.Primaries[0].Key)
	}
	if in.Primaries[1].Key != "explicit" {
		t.Errorf("explicit primary Key = %q, want explicit (must be untouched)", in.Primaries[1].Key)
	}

	// Commit installs it; the returned rollback removes a newly-added key.
	rollback, err := conf.commitStagedTsigKey(staged)
	if err != nil {
		t.Fatalf("commitStagedTsigKey: %v", err)
	}
	if d, ok := conf.Internal.TsigKeyStore.Get("ikey"); !ok || d.Algorithm != "hmac-sha256" {
		t.Fatalf("commit did not install the key: %+v ok=%v", d, ok)
	}
	rollback()
	if conf.Internal.TsigKeyStore.Has("ikey") {
		t.Error("rollback should remove a newly-added key")
	}

	// A differing secret for an existing name is rejected (create-if-absent).
	conf.Internal.TsigKeyStore.Add(TsigDetails{Name: "pre", Algorithm: "hmac-sha256", Secret: b64Secret16})
	if _, err := conf.stageInlineTsigKey(&DynamicZoneInput{
		TsigName: "pre", TsigSecret: "YWJjZGVmZ2hpamtsbW5vcA==",
	}); err == nil {
		t.Fatal("expected error staging inline key with conflicting secret")
	}
	if _, err := conf.commitStagedTsigKey(&TsigDetails{
		Name: "pre", Algorithm: "hmac-sha256", Secret: "YWJjZGVmZ2hpamtsbW5vcA==",
	}); err == nil {
		t.Fatal("expected error committing conflicting inline key")
	}
	if d, _ := conf.Internal.TsigKeyStore.Get("pre"); d.Secret != b64Secret16 {
		t.Errorf("conflicting commit must not change stored secret, got %q", d.Secret)
	}

	// No inline name -> (nil, nil) no-op.
	in2 := DynamicZoneInput{Primaries: []PeerConf{{Addr: "x", Key: NOKEY}}}
	staged2, err := conf.stageInlineTsigKey(&in2)
	if err != nil || staged2 != nil || in2.Primaries[0].Key != NOKEY {
		t.Errorf("no inline name should be a no-op: staged=%v err=%v key=%q", staged2, err, in2.Primaries[0].Key)
	}

	// Inline name with an invalid secret -> error, nothing staged, nothing stored.
	in3 := DynamicZoneInput{TsigName: "bad", TsigSecret: "%%%"}
	if staged3, err := conf.stageInlineTsigKey(&in3); err == nil || staged3 != nil {
		t.Errorf("invalid inline secret should error with no staged key: staged=%v err=%v", staged3, err)
	}
	if conf.Internal.TsigKeyStore.Has("bad") {
		t.Error("a rejected inline key must not be stored")
	}
}

func TestGetDynamicTsigKeysFromZones(t *testing.T) {
	conf := &Config{}
	conf.Internal.TsigKeyStore = NewTsigKeyStore()
	conf.Internal.TsigKeyStore.Add(TsigDetails{Name: "k1", Algorithm: "hmac-sha256", Secret: b64Secret16})
	conf.Internal.TsigKeyStore.Add(TsigDetails{Name: "k2", Algorithm: "hmac-sha256", Secret: b64Secret16})
	zones := []ZoneConf{
		{Name: "a.", Primaries: []PeerConf{{Addr: "1", Key: "k1"}, {Addr: "2", Key: NOKEY}}},
		{Name: "b.", Primaries: []PeerConf{{Addr: "3", Key: "k2"}, {Addr: "4", Key: "k1"}}}, // k1 again
		{Name: "c.", Primaries: []PeerConf{{Addr: "5", Key: "missing"}}},                    // not in store
	}
	keys := conf.getDynamicTsigKeysFromZones(zones)
	if len(keys) != 2 {
		t.Fatalf("got %d keys, want 2 (k1,k2 deduped; NOKEY and missing skipped)", len(keys))
	}
	if keys[0].Name != "k1" || keys[1].Name != "k2" { // sorted by name
		t.Errorf("keys = [%s %s], want sorted [k1 k2]", keys[0].Name, keys[1].Name)
	}
}

func TestLoadDynamicTsigKeys_ConfigWins(t *testing.T) {
	conf := &Config{}
	conf.Internal.TsigKeyStore = NewTsigKeyStore()
	// Pre-existing config key "shared" (loaded first) with secret A.
	conf.Internal.TsigKeyStore.Add(TsigDetails{Name: "shared", Algorithm: "hmac-sha256", Secret: b64Secret16})

	conf.loadDynamicTsigKeys([]TsigDetails{
		{Name: "shared", Algorithm: "hmac-sha256", Secret: "YWJjZGVmZ2hpamtsbW5vcA=="}, // must NOT override
		{Name: "dyn", Algorithm: "hmac-sha256", Secret: "YWJjZGVmZ2hpamtsbW5vcA=="},    // new -> loaded
		{Name: "broken", Algorithm: "md5", Secret: "x"},                                // invalid -> skipped
	})

	if d, _ := conf.Internal.TsigKeyStore.Get("shared"); d.Secret != b64Secret16 {
		t.Error("config key must win; the dynamic override must be skipped")
	}
	if !conf.Internal.TsigKeyStore.Has("dyn") {
		t.Error("a new dynamic key should be loaded")
	}
	if conf.Internal.TsigKeyStore.Has("broken") {
		t.Error("an invalid dynamic key should be skipped")
	}
}
