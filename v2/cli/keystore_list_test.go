package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/johanix/tdns/v2"
)

// T1a.6: the key listing with the pub, sign and ds columns, pinned by a
// golden. Regenerate with TDNS_UPDATE_GOLDEN=1 when the format changes on
// purpose.
func TestDnssecKeyListGolden(t *testing.T) {
	yes, no := true, false
	keys := map[string]tdns.DnssecKey{
		"example.::1111":       {Name: "example.", State: "active", Keyid: 1111, Flags: 257, Algorithm: "ED25519", Keystr: "example. 3600 IN DNSKEY 257 3 15 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Pub: true, Sign: true, DS: &yes},
		"example.::2222":       {Name: "example.", State: "active", Keyid: 2222, Flags: 256, Algorithm: "ED25519", Keystr: "example. 3600 IN DNSKEY 256 3 15 BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=", Pub: true, Sign: true},
		"example.::3333":       {Name: "example.", State: "standby", Keyid: 3333, Flags: 257, Algorithm: "ED25519", Keystr: "example. 3600 IN DNSKEY 257 3 15 CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=", Pub: true, DS: &no},
		"example.::4444":       {Name: "example.", State: "foreign", Keyid: 4444, Flags: 257, Algorithm: "ECDSAP256SHA256", Keystr: "example. 3600 IN DNSKEY 257 3 13 DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=", Pub: true},
		"child.example.::5555": {Name: "child.example.", State: "removed", Keyid: 5555, Flags: 256, Algorithm: "ED25519", Keystr: "child.example. 3600 IN DNSKEY 256 3 15 EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE="},
	}
	got := formatDnssecKeyList(keys, true)
	golden := filepath.Join("testdata", "keystore_dnssec_list.golden")
	if os.Getenv("TDNS_UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(golden, []byte(got), 0644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("%v (TDNS_UPDATE_GOLDEN=1 writes it)", err)
	}
	if got != string(want) {
		t.Errorf("listing differs from the golden:\n--- got ---\n%s--- want ---\n%s", got, want)
	}
	if empty := formatDnssecKeyList(nil, true); empty != "No DNSSEC key pairs found\n" {
		t.Errorf("empty listing: %q", empty)
	}
}
