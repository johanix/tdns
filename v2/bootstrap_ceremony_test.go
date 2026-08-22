package tdns

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

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
	kdb.applyPendingKeyReplacement(context.Background(), child, 222)

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

	kdb.applyPendingKeyReplacement(context.Background(), child, 222) // nothing registered

	keys := listChildKeyids(t, kdb, child)
	if !keys[111] || !keys[222] {
		t.Errorf("no key may be removed when no replacement is pending; have 111=%v 222=%v", keys[111], keys[222])
	}
}

// A DEL-ANY-KEY record carries RDLENGTH=0 (RFC 2136 §2.5.2). Classifying on
// Class+Type alone would accept a record with RDATA as a wholesale "delete
// every KEY at this name".
func TestBootstrapCeremonyRejectsDelAnyKeyWithRdata(t *testing.T) {
	addKey, err := dns.NewRR("child.example. 3600 IN KEY 512 3 15 dGVzdA==")
	if err != nil {
		t.Fatal(err)
	}
	del := &dns.ANY{Hdr: dns.RR_Header{
		Name: "child.example.", Rrtype: dns.TypeKEY, Class: dns.ClassANY, Rdlength: 0,
	}}

	if _, hasDel, ok := bootstrapCeremony([]dns.RR{del, addKey}); !ok || !hasDel {
		t.Fatal("a well-formed ceremony (RDLENGTH=0) was rejected")
	}

	del.Hdr.Rdlength = 4 // not a delete-RRset record any more
	if _, _, ok := bootstrapCeremony([]dns.RR{del, addKey}); ok {
		t.Error("a class-ANY KEY record carrying RDATA was accepted as a DEL-ANY-KEY")
	}
}

// The cleanup must retry on its own. A key is promoted to trusted exactly once,
// so "keep the marker and let the next promotion retry" never retries at all --
// the superseded keys stay authorized for the life of the process.
func TestPendingKeyReplacementRetriesRatherThanWaitingForAnotherPromotion(t *testing.T) {
	const child = "retry.example."
	registerPendingKeyReplacement(child, 111)
	t.Cleanup(func() { pendingKeyReplacements.Delete(pendingKeyReplacementKey(child, 111)) })

	// A cancelled context makes the bounded retry give up immediately instead
	// of sleeping through its schedule; what matters is that it RETRIED rather
	// than returning after a single attempt.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	kdb := newTestKeyDB(t)
	start := time.Now()
	kdb.applyPendingKeyReplacement(ctx, child, 111)
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("took %v — the cancelled context did not stop the retry schedule", elapsed)
	}

	// The marker is retained on failure: it is the only record that these keys
	// were meant to be removed and still are not.
	if _, still := pendingKeyReplacements.Load(pendingKeyReplacementKey(child, 111)); !still {
		t.Error("the pending marker was dropped after a failed cleanup, so nothing records" +
			" that superseded keys remain authorized")
	}
}
