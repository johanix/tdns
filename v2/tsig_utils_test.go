package tdns

import "testing"

func TestParseTsigKeys_StrictValidation(t *testing.T) {
	Globals.TsigKeys = nil
	n, secrets := ParseTsigKeys(&KeyConf{Tsig: []TsigDetails{
		{Name: "good.", Algorithm: "hmac-sha256", Secret: b64Secret16},
		{Name: "NOKEY", Algorithm: "hmac-sha256", Secret: b64Secret16},
		{Name: "bad", Algorithm: "md5", Secret: b64Secret16},
		{Name: "incomplete", Algorithm: "hmac-sha256", Secret: ""},
	}})
	if n != 1 || len(secrets) != 1 {
		t.Fatalf("got n=%d secrets=%d, want 1 valid key", n, len(secrets))
	}
	if _, ok := secrets["good."]; !ok {
		t.Fatalf("secrets: %+v", secrets)
	}
	if Globals.TsigKeys == nil || Globals.TsigKeys["good."] == nil {
		t.Fatal("Globals.TsigKeys missing good.")
	}
}
