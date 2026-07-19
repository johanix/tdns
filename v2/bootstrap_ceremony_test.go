package tdns

import (
	"strconv"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// TestBootstrapCeremony pins the recognition of the self-signed key-bootstrap
// ceremony: exactly one ADD (class INET) KEY, optionally with a single
// "DEL <same-name> ANY KEY". Anything else is not a ceremony.
func TestBootstrapCeremony(t *testing.T) {
	addKeyRR, err := dns.NewRR(validChildKeyRR(t))
	if err != nil {
		t.Fatalf("build ADD KEY: %v", err)
	}
	addKey := addKeyRR.(*dns.KEY)
	delAnyKey := &dns.ANY{Hdr: dns.RR_Header{Name: "child.example.", Rrtype: dns.TypeKEY, Class: dns.ClassANY}}
	delOther := &dns.ANY{Hdr: dns.RR_Header{Name: "other.example.", Rrtype: dns.TypeKEY, Class: dns.ClassANY}}
	ns, err := dns.NewRR("child.example. 3600 IN NS ns1.example.")
	if err != nil {
		t.Fatalf("build NS: %v", err)
	}

	t.Run("single ADD KEY, no DEL", func(t *testing.T) {
		k, hasDel, ok := bootstrapCeremony([]dns.RR{addKey})
		if !ok || hasDel || k == nil {
			t.Fatalf("ok=%v hasDel=%v k=%v, want ok=true hasDel=false", ok, hasDel, k)
		}
	})
	t.Run("DEL ANY KEY + ADD KEY", func(t *testing.T) {
		k, hasDel, ok := bootstrapCeremony([]dns.RR{delAnyKey, addKey})
		if !ok || !hasDel || k == nil {
			t.Fatalf("ok=%v hasDel=%v, want ok=true hasDel=true", ok, hasDel)
		}
	})
	t.Run("DEL only (no ADD) is not a ceremony", func(t *testing.T) {
		if _, _, ok := bootstrapCeremony([]dns.RR{delAnyKey}); ok {
			t.Error("a bare DEL-ANY-KEY must not be recognized as a ceremony")
		}
	})
	t.Run("two ADD KEYs is not a ceremony", func(t *testing.T) {
		if _, _, ok := bootstrapCeremony([]dns.RR{addKey, addKey}); ok {
			t.Error("two ADD KEYs must not be a ceremony")
		}
	})
	t.Run("DEL name != ADD name is not a ceremony", func(t *testing.T) {
		if _, _, ok := bootstrapCeremony([]dns.RR{delOther, addKey}); ok {
			t.Error("mismatched DEL/ADD owner must not be a ceremony")
		}
	})
	t.Run("extra unrelated RR is not a ceremony", func(t *testing.T) {
		if _, _, ok := bootstrapCeremony([]dns.RR{addKey, ns}); ok {
			t.Error("an extra unrelated RR must not be a ceremony")
		}
	})
}

func addChildKey(t *testing.T, kdb *KeyDB, name string, keyid int, keyRR string, validated, trusted bool) {
	t.Helper()
	if _, err := kdb.Sig0TrustMgmt(nil, TruststorePost{
		Command: "child-sig0-mgmt", SubCommand: "add", Src: "child-update",
		Keyname: name, Keyid: keyid, KeyRR: keyRR, Validated: validated, Trusted: trusted,
	}); err != nil {
		t.Fatalf("add child key %d: %v", keyid, err)
	}
}

func listChildKeyids(t *testing.T, kdb *KeyDB, name string) map[int]bool {
	t.Helper()
	tr, err := kdb.Sig0TrustMgmt(nil, TruststorePost{Command: "child-sig0-mgmt", SubCommand: "list"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	out := map[int]bool{}
	prefix := name + "::"
	for mk := range tr.ChildSig0keys {
		if strings.HasPrefix(mk, prefix) {
			if id, err := strconv.Atoi(strings.TrimPrefix(mk, prefix)); err == nil {
				out[id] = true
			}
		}
	}
	return out
}

// TestApplyPendingKeyReplacement verifies the deferred DEL-ANY-KEY completion:
// once the new key is trusted and its replacement was registered, the child's
// OTHER keys are removed and the new key is kept.
func TestApplyPendingKeyReplacement(t *testing.T) {
	kdb := newTestKeyDB(t)
	child := "child.example."
	keyRR := validChildKeyRR(t)
	addChildKey(t, kdb, child, 111, keyRR, true, true) // old key
	addChildKey(t, kdb, child, 222, keyRR, true, true) // new key, just promoted to trusted

	registerPendingKeyReplacement(child, 222)
	kdb.applyPendingKeyReplacement(child, 222)

	keys := listChildKeyids(t, kdb, child)
	if keys[111] {
		t.Error("old key 111 should have been removed by the deferred DEL-ANY-KEY")
	}
	if !keys[222] {
		t.Error("newly-trusted key 222 must be retained")
	}
}

// TestApplyPendingKeyReplacementNoPending is the safety no-op: a key promoted to
// trusted WITHOUT a registered bootstrap replacement must never evict any key.
// This is the invariant that stops a self-signed DEL-ANY-KEY (which never
// registers-and-trusts through independent validation) from becoming an
// eviction primitive.
func TestApplyPendingKeyReplacementNoPending(t *testing.T) {
	kdb := newTestKeyDB(t)
	child := "child.example."
	keyRR := validChildKeyRR(t)
	addChildKey(t, kdb, child, 111, keyRR, true, true)
	addChildKey(t, kdb, child, 222, keyRR, true, true)

	kdb.applyPendingKeyReplacement(child, 222) // nothing registered

	keys := listChildKeyids(t, kdb, child)
	if !keys[111] || !keys[222] {
		t.Errorf("no key may be removed when no replacement is pending; have 111=%v 222=%v", keys[111], keys[222])
	}
}
