/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * A child's SIG(0) KEY belongs in the parent's truststore. It must never
 * become content of the parent zone.
 */
package tdns

import (
	"context"
	"testing"

	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

const childKeyParentZone = `parent.example.	3600	IN	SOA	ns.parent.example. hostmaster.parent.example. 1 7200 1800 604800 7200
parent.example.	3600	IN	NS	ns.parent.example.
ns.parent.example.	3600	IN	A	192.0.2.53
child.parent.example.	3600	IN	NS	ns1.child.parent.example.
ns1.child.parent.example.	3600	IN	A	192.0.2.1
`

const childKeyRR = "child.parent.example. 3600 IN KEY 256 3 15 kR7NlEmXPWWDCFZmJqFhOJjHtBSKuLnCJHBTLzNJnUE="

// childKeyParent is a parent that takes child updates and whose child policy
// permits KEY -- which it MUST, or no child could ever bootstrap a SIG(0) key.
// That same allowlist used to be what let the KEY through into the zone.
func childKeyParent(t *testing.T) *ZoneData {
	t.Helper()
	zd := testSnapshotZone(t, "parent.example.", childKeyParentZone)
	zd.Options = map[ZoneOption]bool{OptAllowChildUpdates: true}
	zd.UpdatePolicy = UpdatePolicy{
		Child: UpdatePolicyDetail{
			Type:    "selfsub",
			RRtypes: map[uint16]bool{dns.TypeNS: true, dns.TypeA: true, dns.TypeAAAA: true, dns.TypeDS: true, dns.TypeKEY: true},
			TTL:     120,
		},
	}
	return zd
}

// classify runs an update section through UpdateResponder and reports the type
// it was given. The message is unsigned, so validation fails immediately after
// classification -- which is the point: it isolates the classifier without
// needing a SIG(0) keypair.
func classify(t *testing.T, zd *ZoneData, rrs ...dns.RR) (*DnsUpdateRequest, *dns.Msg) {
	t.Helper()
	m := new(dns.Msg)
	m.SetUpdate(zd.ZoneName)
	m.Ns = append(m.Ns, rrs...)

	cw := &captureWriter{}
	dur := &DnsUpdateRequest{ResponseWriter: cw, Msg: m, Qname: zd.ZoneName, Status: &UpdateStatus{}}
	_ = UpdateResponder(context.Background(), dur, nil)
	if cw.got == nil {
		t.Fatal("responder wrote no response")
	}
	return dur, cw.got
}

// THE REGRESSION. The child's bootstrap sender (ops_key.go) builds
// "DEL <child> ANY KEY" + "ADD <child> KEY" with the RFC 2136 QNAME, i.e. the
// parent zone -- two records, so the responder's single-record shortcut never
// applied and classifyDelegationUpdate placed it as a CHILD-UPDATE.
//
// On the FIRST send that was masked: ValidateUpdate, failing to find the
// signing key in the truststore, recognised the self-signed upload and
// rewrote us.Type to TRUSTSTORE-UPDATE. On every send after that the key WAS
// in the truststore, ValidateUpdate returned down its first branch without
// touching us.Type, and the ceremony stayed a CHILD-UPDATE -- so the child's
// KEY was written into the parent zone at the delegation point, with
// updatepolicy.child.ttl for a TTL.
//
// Classification must not depend on where the signing key was found.
func TestBootstrapCeremonyIsATruststoreUpdate(t *testing.T) {
	zd := childKeyParent(t)
	key := mustRR(t, childKeyRR)

	del := dns.Copy(key)
	del.Header().Class = dns.ClassANY
	del.Header().Ttl = 0

	dur, _ := classify(t, zd, del, key)

	if dur.Status.Type != "TRUSTSTORE-UPDATE" {
		t.Fatalf("bootstrap ceremony classified as %q, want TRUSTSTORE-UPDATE; "+
			"a CHILD-UPDATE publishes the child's KEY into the parent zone", dur.Status.Type)
	}
}

// The bare single-KEY upload kept working throughout, via the responder's
// "exactly one record and it is a KEY" shortcut. It has to keep working now
// that the shortcut is gone.
func TestSingleKeyUploadIsATruststoreUpdate(t *testing.T) {
	zd := childKeyParent(t)
	dur, _ := classify(t, zd, mustRR(t, childKeyRR))

	if dur.Status.Type != "TRUSTSTORE-UPDATE" {
		t.Fatalf("single KEY upload classified as %q, want TRUSTSTORE-UPDATE", dur.Status.Type)
	}
}

// Withdrawing a key is the same question -- which store does this record
// belong in -- and the answer does not depend on the class.
func TestKeyRemovalIsATruststoreUpdate(t *testing.T) {
	zd := childKeyParent(t)
	del := dns.Copy(mustRR(t, childKeyRR))
	del.Header().Class = dns.ClassNONE

	dur, _ := classify(t, zd, del)

	if dur.Status.Type != "TRUSTSTORE-UPDATE" {
		t.Fatalf("KEY removal classified as %q, want TRUSTSTORE-UPDATE", dur.Status.Type)
	}
}

// The diversion is confined to KEYs at a child's name. A KEY at the parent's
// own apex is the parent's data and stays judged by updatepolicy.zone.
func TestKeyAtZoneApexIsNotATruststoreUpdate(t *testing.T) {
	zd := childKeyParent(t)
	apexKey := mustRR(t, "parent.example. 3600 IN KEY 256 3 15 kR7NlEmXPWWDCFZmJqFhOJjHtBSKuLnCJHBTLzNJnUE=")

	if child, ok := zd.classifyTruststoreUpdate([]dns.RR{apexKey}); ok {
		t.Fatalf("a KEY at the zone apex was classified as key material for child %q", child)
	}
}

// Delegation data is unaffected: the ordinary child update still classifies as
// one, or the fix would have traded one bug for a worse one.
func TestDelegationUpdateStillClassifiesAsChildUpdate(t *testing.T) {
	zd := childKeyParent(t)
	dur, _ := classify(t, zd,
		mustRR(t, "child.parent.example. 3600 IN DS 1 15 2 0000"),
		mustRR(t, "ns1.child.parent.example. 3600 IN AAAA 2001:db8::1"))

	if dur.Status.Type != "CHILD-UPDATE" {
		t.Fatalf("delegation update classified as %q, want CHILD-UPDATE", dur.Status.Type)
	}
}

// Key material for two children in one message is not a truststore update:
// the applier authorises per child, so the message is refused rather than
// split -- the same rule classifyDelegationUpdate applies to delegations.
func TestKeysForTwoChildrenIsNotATruststoreUpdate(t *testing.T) {
	zd := testSnapshotZone(t, "parent.example.", childKeyParentZone+
		"other.parent.example.	3600	IN	NS	ns1.other.parent.example.\n")

	if child, ok := zd.classifyTruststoreUpdate([]dns.RR{
		mustRR(t, childKeyRR),
		mustRR(t, "other.parent.example. 3600 IN KEY 256 3 15 kR7NlEmXPWWDCFZmJqFhOJjHtBSKuLnCJHBTLzNJnUE="),
	}); ok {
		t.Fatalf("keys for two children were classified as key material for %q alone", child)
	}
}

// A message mixing key material with delegation data is refused whole: the two
// halves go to different stores, and one rcode cannot report that half of it
// landed. Previously the delegation half was applied and the KEY published
// alongside it.
func TestChildUpdateMixingKeyAndDelegationIsRefused(t *testing.T) {
	zd := childKeyParent(t)

	r := new(dns.Msg)
	r.SetUpdate(zd.ZoneName)
	r.Ns = []dns.RR{
		mustRR(t, "child.parent.example. 3600 IN DS 1 15 2 0000"),
		mustRR(t, childKeyRR),
	}

	// Straight to the approver with validation already satisfied: this is the
	// state a re-send from an established child arrives in, and the state in
	// which the leak happened.
	us := &UpdateStatus{
		Type:                  "CHILD-UPDATE",
		Validated:             true,
		ValidatedByTrustedKey: true,
		SignerName:            "child.parent.example.",
		ValidationRcode:       dns.RcodeSuccess,
	}

	approved, updateZone, err := zd.ApproveChildUpdate(zd.ZoneName, us, r)
	if err != nil {
		t.Fatalf("ApproveChildUpdate returned an error: %v", err)
	}
	if approved {
		t.Fatal("a child update mixing a KEY with delegation data was approved")
	}
	if updateZone {
		t.Fatal("a refused child update asked for the zone to be written")
	}
	if us.RejectionEDE != edns0.EDEZoneUpdateRRtypeNotAllowed {
		t.Errorf("RejectionEDE = %d, want %d (RRtype not allowed) so the child learns which record was unacceptable",
			us.RejectionEDE, edns0.EDEZoneUpdateRRtypeNotAllowed)
	}
}

// The structural backstop, independent of any classification: no delegation
// backend is ever handed key material to write.
func TestFirstKeyRRFindsKeyMaterial(t *testing.T) {
	ns := mustRR(t, "child.parent.example. 3600 IN NS ns1.child.parent.example.")
	key := mustRR(t, childKeyRR)

	if firstKeyRR([]dns.RR{ns}) != nil {
		t.Error("firstKeyRR reported key material in a pure delegation update")
	}
	got := firstKeyRR([]dns.RR{ns, key})
	if got == nil {
		t.Fatal("firstKeyRR missed the KEY in a mixed update")
	}
	if got.Header().Name != "child.parent.example." {
		t.Errorf("firstKeyRR returned %q, want the KEY owner", got.Header().Name)
	}
}

// THE OTHER BUG, guarded from the other side. A self-signed KEY upload from a
// child the parent does not yet trust must be ACCEPTED -- refusing it is how
// the parent used to make SIG(0) bootstrap impossible. Routing key material to
// ApproveTrustUpdate must not narrow that door.
//
// It widens it, in fact: ApproveChildUpdate still refuses an untrusted upload
// of more than one record ("only a single KEY record allowed from untrusted
// key"), which is the two-record bootstrap ceremony the child actually sends.
// ApproveTrustUpdate has no such restriction, so the ceremony is approved on
// its own merits rather than depending on ValidateUpdate having failed to find
// the key first.
func TestUntrustedBootstrapCeremonyIsApproved(t *testing.T) {
	zd := childKeyParent(t)
	zd.DelegationPolicy = &DelegationPolicy{Name: "test", AllowUnvalidatedUpload: true}

	key := mustRR(t, childKeyRR)
	del := dns.Copy(key)
	del.Header().Class = dns.ClassANY
	del.Header().Ttl = 0

	r := new(dns.Msg)
	r.SetUpdate(zd.ZoneName)
	r.Ns = []dns.RR{del, key}

	// Nothing is trusted yet, and the signature is self-signed: the state a
	// first-ever bootstrap arrives in.
	us := &UpdateStatus{
		Type:            "TRUSTSTORE-UPDATE",
		SignerName:      "child.parent.example.",
		ValidationRcode: dns.RcodeSuccess,
	}

	approved, updateZone, err := zd.ApproveTrustUpdate(zd.ZoneName, us, r)
	if err != nil {
		t.Fatalf("ApproveTrustUpdate returned an error: %v", err)
	}
	if !approved {
		t.Fatal("a self-signed bootstrap ceremony was refused; the child cannot bootstrap a SIG(0) key at all")
	}
	if updateZone {
		t.Fatal("an approved key upload asked for the parent zone to be written")
	}
}

// And with the allowance switched off it is refused rather than published --
// the acceptance gate and the publication gate are separate, and closing the
// first must not open the second.
func TestUntrustedBootstrapCeremonyWithoutAllowanceIsRefused(t *testing.T) {
	zd := childKeyParent(t)
	zd.DelegationPolicy = &DelegationPolicy{Name: "test", AllowUnvalidatedUpload: false}

	key := mustRR(t, childKeyRR)
	del := dns.Copy(key)
	del.Header().Class = dns.ClassANY
	del.Header().Ttl = 0

	r := new(dns.Msg)
	r.SetUpdate(zd.ZoneName)
	r.Ns = []dns.RR{del, key}

	us := &UpdateStatus{Type: "TRUSTSTORE-UPDATE", SignerName: "child.parent.example.", ValidationRcode: dns.RcodeSuccess}

	approved, updateZone, err := zd.ApproveTrustUpdate(zd.ZoneName, us, r)
	if err != nil {
		t.Fatalf("ApproveTrustUpdate returned an error: %v", err)
	}
	if approved {
		t.Fatal("an untrusted key upload was approved with allow-unvalidated-upload off")
	}
	if updateZone {
		t.Fatal("a refused key upload asked for the parent zone to be written")
	}
}

// childKeyParentWithSibling is childKeyParent plus a second delegation, and a
// zone policy that would accept KEY as the parent's own data -- the shape a
// parent has when it publishes its own apex KEY. That policy knows nothing
// about zone cuts, which is what makes the ZONE-UPDATE route dangerous for
// child key material.
func childKeyParentWithSibling(t *testing.T) *ZoneData {
	t.Helper()
	zd := testSnapshotZone(t, "parent.example.", childKeyParentZone+
		"other.parent.example.	3600	IN	NS	ns1.other.parent.example.\n")
	zd.Options = map[ZoneOption]bool{OptAllowUpdates: true, OptAllowChildUpdates: true}
	zd.UpdatePolicy = UpdatePolicy{
		Zone:  UpdatePolicyDetail{Type: "selfsub", RRtypes: map[uint16]bool{dns.TypeKEY: true, dns.TypeDS: true, dns.TypeA: true}, TTL: 120},
		Child: UpdatePolicyDetail{Type: "selfsub", RRtypes: map[uint16]bool{dns.TypeNS: true, dns.TypeDS: true, dns.TypeKEY: true}, TTL: 120},
	}
	return zd
}

// Key material that names no single child is refused outright. It is neither a
// truststore update (the applier authorises per child) nor a delegation update
// (classifyDelegationUpdate refuses a message spanning two delegations), so
// without a rule of its own it fell through to ZONE-UPDATE -- past
// ApproveChildUpdate and past ZoneUpdater's CHILD-UPDATE guard, to be judged
// by updatepolicy.zone, which has no notion of a zone cut.
func TestKeysForTwoChildrenAreRefused(t *testing.T) {
	zd := childKeyParentWithSibling(t)

	dur, got := classify(t, zd,
		mustRR(t, childKeyRR),
		mustRR(t, "other.parent.example. 3600 IN KEY 256 3 15 kR7NlEmXPWWDCFZmJqFhOJjHtBSKuLnCJHBTLzNJnUE="))

	if dur.Status.Type == "ZONE-UPDATE" {
		t.Fatal("KEY material for two children was routed to ZONE-UPDATE, where updatepolicy.zone could publish it into the parent zone")
	}
	if got.Rcode != dns.RcodeRefused {
		t.Errorf("rcode = %s, want REFUSED", dns.RcodeToString[got.Rcode])
	}
}

// The same rule catches one child's key beside another child's delegation
// records, which spans two children in the other direction.
func TestChildKeyBesideAnotherChildsDelegationIsRefused(t *testing.T) {
	zd := childKeyParentWithSibling(t)

	dur, got := classify(t, zd,
		mustRR(t, "child.parent.example. 3600 IN DS 1 15 2 0000"),
		mustRR(t, "other.parent.example. 3600 IN KEY 256 3 15 kR7NlEmXPWWDCFZmJqFhOJjHtBSKuLnCJHBTLzNJnUE="))

	if dur.Status.Type == "ZONE-UPDATE" {
		t.Fatal("child key material alongside another child's DS was routed to ZONE-UPDATE")
	}
	if got.Rcode != dns.RcodeRefused {
		t.Errorf("rcode = %s, want REFUSED", dns.RcodeToString[got.Rcode])
	}
}

// The refusal is confined to KEYs at a zone cut. The parent's own apex KEY --
// the reason updatepolicy.zone lists KEY in the first place -- is untouched
// and still reaches the ordinary auth-data path.
func TestApexKeyStillReachesTheZoneUpdatePath(t *testing.T) {
	zd := childKeyParentWithSibling(t)

	dur, _ := classify(t, zd,
		mustRR(t, "parent.example. 3600 IN KEY 256 3 15 kR7NlEmXPWWDCFZmJqFhOJjHtBSKuLnCJHBTLzNJnUE="))

	if dur.Status.Type != "ZONE-UPDATE" {
		t.Fatalf("the parent's own apex KEY classified as %q, want ZONE-UPDATE", dur.Status.Type)
	}
}
