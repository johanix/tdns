package tdns

import (
	"testing"

	"github.com/johanix/tdns/v2/edns0"
)

// TestProcessKeyStateMalformed asserts K-2: per keystate-03, the only valid
// sender code in a KeyState request is 2 (INTENT_INQUIRE_KEY). Every other
// value — the unassigned codes, the receiver-only codes, and anything above
// the registry — MUST be answered with KEY_REQUEST_MALFORMED(0), echoing the
// KEY-ID and with KEY-DATA=0. All the values below are answered without
// touching the truststore, so a zero-value KeyDB suffices.
func TestProcessKeyStateMalformed(t *testing.T) {
	kdb := &KeyDB{}
	for _, state := range []uint8{0, 1, 3, 4, 5, 10, 11, 99, 200} {
		resp, err := kdb.ProcessKeyState(&edns0.KeyStateOption{KeyID: 4242, KeyState: state}, "child.example.")
		if err != nil {
			t.Fatalf("state=%d: ProcessKeyState: %v", state, err)
		}
		if resp == nil {
			t.Fatalf("state=%d: nil response", state)
		}
		if resp.KeyState != uint8(edns0.KeyStateRequestMalformed) {
			t.Errorf("state=%d: KeyState = %d, want 0 (KEY_REQUEST_MALFORMED)", state, resp.KeyState)
		}
		if resp.KeyID != 4242 {
			t.Errorf("state=%d: KeyID = %d, want 4242 (echoed)", state, resp.KeyID)
		}
		if resp.KeyData != 0 {
			t.Errorf("state=%d: KeyData = %d, want 0", state, resp.KeyData)
		}
	}
}
