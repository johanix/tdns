package core

import (
	"encoding/json"
	"testing"
)

// The key inventory entry carries the row's columns beside the state; a
// sender that predates them sends none, and the receiver sees ds nil.
func TestKeyInventoryEntryCarriesTheColumns(t *testing.T) {
	yes := true
	e := KeyInventoryEntry{KeyTag: 4711, Algorithm: 15, Flags: 257, State: "standby", KeyRR: "z. 3600 IN DNSKEY 257 3 15 dGVzdA==", Pub: true, DS: &yes}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var back KeyInventoryEntry
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if !back.Pub || back.Sign || back.DS == nil || !*back.DS {
		t.Errorf("round trip lost the columns: %+v from %s", back, b)
	}
	old := []byte(`{"key_tag":4711,"algorithm":15,"flags":257,"state":"standby","keyrr":"z. 3600 IN DNSKEY 257 3 15 dGVzdA=="}`)
	var fromOld KeyInventoryEntry
	if err := json.Unmarshal(old, &fromOld); err != nil {
		t.Fatal(err)
	}
	if fromOld.DS != nil || fromOld.Pub || fromOld.Sign {
		t.Errorf("an old sender's entry decoded with columns: %+v", fromOld)
	}
	var post AgentKeystatePost
	if err := json.Unmarshal([]byte(`{"Zone":"z.","Signal":"inventory","Owned":true}`), &post); err != nil || !post.Owned {
		t.Errorf("Owned not decoded: %+v err=%v", post, err)
	}
	if b, _ := json.Marshal(AgentKeystatePost{Zone: "z."}); string(b) == "" || contains(string(b), "Owned") {
		t.Errorf("Owned encoded when false: %s", b)
	}
}

// tdns-mp #58 and design Q9: a DNSKEY operation carries, per key, what the
// sending provider says about it; old and new decode each other, and the
// payload is pinned (test plan T5.1, T5.2).
func TestDnskeyOperationCarriesTheKeyStates(t *testing.T) {
	yes, no := true, false
	op := RROperation{Operation: "replace", RRtype: "DNSKEY",
		Records: []string{"z. 3600 IN DNSKEY 257 3 15 a2V5MQ==", "z. 3600 IN DNSKEY 256 3 15 a2V5Mg=="},
		KeyStates: []KeyState{
			{KeyTag: 4711, State: "standby", DS: &yes},
			{KeyTag: 4712, State: "active", DS: &no},
			{KeyTag: 4713, State: "mpdist"},
		}}
	b, err := json.Marshal(op)
	if err != nil {
		t.Fatal(err)
	}
	const golden = `{"operation":"replace","rrtype":"DNSKEY","records":["z. 3600 IN DNSKEY 257 3 15 a2V5MQ==","z. 3600 IN DNSKEY 256 3 15 a2V5Mg=="],"key_states":[{"key_tag":4711,"state":"standby","ds":true},{"key_tag":4712,"state":"active","ds":false},{"key_tag":4713,"state":"mpdist"}]}`
	if string(b) != golden {
		t.Errorf("the DNSKEY operation's payload changed:\n got %s\nwant %s", b, golden)
	}
	var back RROperation
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if len(back.KeyStates) != 3 || back.KeyStates[0].DS == nil || !*back.KeyStates[0].DS ||
		back.KeyStates[1].DS == nil || *back.KeyStates[1].DS || back.KeyStates[2].DS != nil {
		t.Errorf("round trip lost a key state or turned an unset ds into a value: %+v", back.KeyStates)
	}

	// an old sender: no key states, and the receiver sees none (the rows
	// it makes stay undecided)
	var fromOld RROperation
	if err := json.Unmarshal([]byte(`{"operation":"replace","rrtype":"DNSKEY","records":["z. 3600 IN DNSKEY 257 3 15 a2V5MQ=="]}`), &fromOld); err != nil {
		t.Fatal(err)
	}
	if fromOld.KeyStates != nil || len(fromOld.Records) != 1 {
		t.Errorf("an old sender's operation decoded as %+v", fromOld)
	}
	// an old receiver: the struct it knows, which ignores the new field
	var oldReceiver struct {
		Operation string   `json:"operation"`
		RRtype    string   `json:"rrtype"`
		Records   []string `json:"records,omitempty"`
	}
	if err := json.Unmarshal(b, &oldReceiver); err != nil || len(oldReceiver.Records) != 2 || oldReceiver.RRtype != "DNSKEY" {
		t.Errorf("an old receiver does not decode the new payload: %+v err=%v", oldReceiver, err)
	}
	// an operation without key states encodes as it always did
	plain, _ := json.Marshal(RROperation{Operation: "add", RRtype: "NS", Records: []string{"z. 3600 IN NS ns1.z."}})
	if contains(string(plain), "key_states") {
		t.Errorf("key_states encoded when empty: %s", plain)
	}
}

// What an agent hands its signer about the other providers' keys: the
// provider's label beside each key state, under Signal "foreign".
func TestKeystatePostCarriesTheForeignKeys(t *testing.T) {
	yes := true
	post := AgentKeystatePost{Zone: "z.", Signal: "foreign", ForeignKeys: []ForeignKeyState{
		{Provider: "p2", KeyState: KeyState{KeyTag: 4711, State: "active", DS: &yes}},
		{Provider: "p3", KeyState: KeyState{KeyTag: 4714, State: "published"}},
	}}
	b, err := json.Marshal(post)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(string(b), `"ForeignKeys":[{"provider":"p2","key_tag":4711,"state":"active","ds":true},{"provider":"p3","key_tag":4714,"state":"published"}]`) {
		t.Errorf("the foreign keys' payload changed: %s", b)
	}
	var back AgentKeystatePost
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if len(back.ForeignKeys) != 2 || back.ForeignKeys[0].Provider != "p2" || back.ForeignKeys[0].DS == nil || back.ForeignKeys[1].DS != nil {
		t.Errorf("round trip: %+v", back.ForeignKeys)
	}
	if b, _ := json.Marshal(AgentKeystatePost{Zone: "z.", Signal: "inventory"}); contains(string(b), "ForeignKeys") {
		t.Errorf("ForeignKeys encoded when empty: %s", b)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
