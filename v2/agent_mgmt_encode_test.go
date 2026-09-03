package tdns

import (
	"encoding/json"
	"testing"
)

// AgentMgmtPost is both an in-process message and the mgmt API request body.
// Its Response channel must never reach the encoder: encoding/json rejects a
// chan field outright, nil or not, so an untagged one broke every POST of this
// struct -- the entire "parentsync" subtree -- before it left the CLI.
func TestAgentMgmtPostIsJSONEncodable(t *testing.T) {
	if _, err := json.Marshal(&AgentMgmtPost{Command: "status", Zone: "example."}); err != nil {
		t.Fatalf("AgentMgmtPost does not marshal: %v", err)
	}
	// And with the channel actually populated, since in-process senders may.
	p := &AgentMgmtPost{Command: "status", Response: make(chan *AgentMgmtResponse, 1)}
	if _, err := json.Marshal(p); err != nil {
		t.Fatalf("AgentMgmtPost with a live Response channel does not marshal: %v", err)
	}
}
