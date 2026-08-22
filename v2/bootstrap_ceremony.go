package tdns

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// bootstrapCeremony inspects a DNS UPDATE's Update section for the self-signed
// SIG(0) key-bootstrap ceremony of draft-ietf-dnsop-delegation-mgmt-via-ddns-02
// §"Bootstrapping the Child's Key" / §"Re-bootstrapping In Case of Errors":
//
//	DEL child.parent. {ttl} ANY KEY   (optional — remove any previous keys)
//	ADD child.parent. {ttl} IN  KEY   (the new key, which self-signs the UPDATE)
//
// It accepts exactly one ADD (class INET) KEY, optionally accompanied by a
// single "DEL <name> ANY KEY" (class ANY, type KEY) for the SAME owner name.
// Any other content makes it not a ceremony (ok=false), so the strict
// single-RR key-upload rules still apply elsewhere.
//
// Note: a wire "DEL <name> ANY KEY" is a class-ANY, rdlength-0 record that
// miekg/dns (and the tdns fork) represents as *dns.ANY with the KEY type in its
// header, so this classifies on the header's Class+Rrtype, not the Go type.
func bootstrapCeremony(ns []dns.RR) (addKey *dns.KEY, hasDelAnyKey bool, ok bool) {
	var delName string
	for _, rr := range ns {
		h := rr.Header()
		switch {
		case h.Class == dns.ClassINET && h.Rrtype == dns.TypeKEY:
			k, isKey := rr.(*dns.KEY)
			if !isKey || addKey != nil {
				return nil, false, false // malformed, or more than one ADD KEY
			}
			addKey = k
		case h.Class == dns.ClassANY && h.Rrtype == dns.TypeKEY:
			if hasDelAnyKey {
				return nil, false, false // more than one DEL ANY KEY
			}
			hasDelAnyKey = true
			delName = h.Name
		default:
			return nil, false, false // anything else disqualifies the ceremony
		}
	}
	if addKey == nil {
		return nil, false, false // must add exactly one KEY
	}
	if hasDelAnyKey && !strings.EqualFold(delName, addKey.Header().Name) {
		return nil, false, false // the DEL must target the same owner as the ADD
	}
	return addKey, hasDelAnyKey, true
}

// pendingKeyReplacements records self-signed bootstrap ceremonies that carried a
// "DEL <child> ANY KEY" alongside the new key. The DEL is DEFERRED: it MUST NOT
// evict an already-trusted key until the newly added key has itself been
// validated and promoted to trusted (draft §"Re-bootstrapping In Case of
// Errors" — the guard against a bogus self-signed UPDATE evicting the real key).
// Once the new (childZone,keyid) key becomes trusted, the deferred DEL is
// completed by removing the child's OTHER keys.
//
// It is in-memory by design (see the 3a design note): the entry only ever gates
// a *cleanup* that happens strictly AFTER independent validation, so losing it
// on a mid-cycle restart leaves an old key un-cleaned but never evicts a key
// early — the safety invariant holds regardless. Keyed by "childZone::keyid".
var pendingKeyReplacements sync.Map

func pendingKeyReplacementKey(childZone string, keyid uint16) string {
	return fmt.Sprintf("%s::%d", childZone, keyid)
}

// registerPendingKeyReplacement marks that once (childZone,keyid) is promoted to
// trusted, the child's other SIG(0) keys should be removed (the deferred half of
// a bootstrap DEL-ANY-KEY ceremony).
func registerPendingKeyReplacement(childZone string, keyid uint16) {
	pendingKeyReplacements.Store(pendingKeyReplacementKey(childZone, keyid), struct{}{})
}

// applyPendingKeyReplacement completes a deferred bootstrap DEL-ANY-KEY: if the
// newly-trusted (childZone,keyid) was registered as a replacement, it removes
// the child's OTHER SIG(0) keys from the truststore. It is a no-op if no
// replacement was pending. Called only AFTER the key has been promoted to
// trusted, so it can never evict a key that is still the sole trusted one.
// The marker is cleared only once every superseded key is actually gone. An
// earlier version removed it up front, which turned any failure below --
// listing the child's keys, or deleting one of them -- into a permanent one:
// nothing could retry, and the key the ceremony was supposed to supersede
// stayed authorized to sign UPDATEs for that child indefinitely. Retrying a
// completed cleanup is harmless; abandoning an incomplete one is not.
func (kdb *KeyDB) applyPendingKeyReplacement(childZone string, keyid uint16) {
	mapKeyPending := pendingKeyReplacementKey(childZone, keyid)
	if _, ok := pendingKeyReplacements.Load(mapKeyPending); !ok {
		return
	}

	tr, err := kdb.Sig0TrustMgmt(nil, TruststorePost{
		Command:    "child-sig0-mgmt",
		SubCommand: "list",
	})
	if err != nil {
		// Marker retained: the next promotion of this key retries.
		lgSigner.Error("applyPendingKeyReplacement: failed to list child keys;"+
			" the superseded key(s) are still authorized and the cleanup will be retried",
			"zone", childZone, "err", err)
		return
	}

	prefix := childZone + "::"
	failed := 0
	for mapKey := range tr.ChildSig0keys {
		if !strings.HasPrefix(mapKey, prefix) {
			continue
		}
		// ParseUint bounded to 16 bits: a key id is a uint16, and Atoi+narrowing
		// would silently wrap a malformed or oversized suffix into a valid-looking
		// id -- which here selects which key gets DELETED.
		otherKeyid64, err := strconv.ParseUint(strings.TrimPrefix(mapKey, prefix), 10, 16)
		if err != nil {
			continue
		}
		otherKeyid := uint16(otherKeyid64)
		if otherKeyid == keyid {
			continue // keep the newly-trusted key
		}
		if _, err := kdb.Sig0TrustMgmt(nil, TruststorePost{
			Command:    "child-sig0-mgmt",
			SubCommand: "delete",
			Keyname:    childZone,
			Keyid:      int(otherKeyid),
		}); err != nil {
			failed++
			lgSigner.Error("applyPendingKeyReplacement: failed to remove superseded key",
				"zone", childZone, "keyid", otherKeyid, "err", err)
		} else {
			lgSigner.Info("applyPendingKeyReplacement: removed superseded key (deferred DEL-ANY-KEY completed)",
				"zone", childZone, "removedKeyid", otherKeyid, "keptKeyid", keyid)
		}
	}

	if failed > 0 {
		lgSigner.Error("applyPendingKeyReplacement: cleanup incomplete; keeping the pending"+
			" marker so it is retried rather than leaving superseded keys authorized",
			"zone", childZone, "keptKeyid", keyid, "failed", failed)
		return
	}
	pendingKeyReplacements.Delete(mapKeyPending)
}
