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

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
