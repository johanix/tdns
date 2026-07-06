package tdns

import (
	"testing"

	"github.com/mitchellh/mapstructure"
)

// TestLegacyAclParsing pins D2: a legacy bare-string allow-notify:/downstreams:
// list decodes into AclEntry{Legacy} (no whole-config decode failure), and
// ValidateACL rejects it so only that zone is quarantined -- while a proper
// {prefix, key} ACL still validates.
func TestLegacyAclParsing(t *testing.T) {
	var acls []AclEntry
	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:     &acls,
		DecodeHook: stringToAclEntryHook(),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Legacy bare-string list must decode without error (the D2 fix).
	if err := dec.Decode([]interface{}{"192.0.2.1", "10.0.0.0/8"}); err != nil {
		t.Fatalf("bare-string ACL list should decode, got: %v", err)
	}
	if len(acls) != 2 || acls[0].Legacy != "192.0.2.1" || acls[1].Legacy != "10.0.0.0/8" {
		t.Fatalf("decoded acls = %+v, want two Legacy markers", acls)
	}
	// ValidateACL must reject the legacy entries (-> per-zone quarantine).
	if err := ValidateACL(acls, func(string) bool { return true }); err == nil {
		t.Error("ValidateACL must reject a legacy bare-string ACL")
	}
	// A proper {prefix, key} ACL still validates.
	if err := ValidateACL([]AclEntry{{Prefix: "0.0.0.0/0", Key: NOKEY}}, func(string) bool { return true }); err != nil {
		t.Errorf("valid {prefix,key} ACL rejected: %v", err)
	}
}
