/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// An inline-signing zone answers IXFR from zd.IxfrChain, and every link in it
// is computed at publish time by diffing the snapshot being replaced against
// the one about to be stored (updateIxfrChainLocked). A link is therefore only
// a record of what changed if the outgoing snapshot still holds exactly what it
// held when it was published. A signing pass that rewrites a published RRset in
// place breaks that twice over: the served zone changes under an unchanged
// serial, and the next link is diffed against content no earlier link ever
// added, so it deletes records a downstream never had and misses the ones it
// should replace. Refs #797.
//
// The zone-level tests trigger a forced pass with a policy whose only change is
// the signature validity. That reaches the same forced SignZone pass as an
// algorithm change, and a different validity guarantees that every signature
// the pass writes differs from the one it replaces. ED25519 is deterministic,
// so with the same validity a re-signature made in the same second can come out
// byte-identical and hide the defect.
//
// The SignRRset tests below them pin the storage contract directly: signing
// never writes into storage it did not allocate.

// resignTestZone is a signed inline-signing zone with a real signature validity
// (so a fresh signature is not due for renewal), an RRset of two records, both
// address families, and a delegation with glue.
func resignTestZone(t *testing.T, kdb *KeyDB) *ZoneData {
	t.Helper()
	const zone = `resign.example.	3600	IN	SOA	ns.resign.example. hostmaster.resign.example. 1 7200 1800 604800 7200
resign.example.	3600	IN	NS	ns.resign.example.
resign.example.	3600	IN	MX	10 alpha.resign.example.
ns.resign.example.	3600	IN	A	192.0.2.53
ns.resign.example.	3600	IN	AAAA	2001:db8::53
alpha.resign.example.	3600	IN	A	192.0.2.1
alpha.resign.example.	3600	IN	A	192.0.2.2
alpha.resign.example.	3600	IN	AAAA	2001:db8::1
bravo.resign.example.	3600	IN	TXT	"bravo"
child.resign.example.	3600	IN	NS	ns1.child.resign.example.
ns1.child.resign.example.	3600	IN	A	192.0.2.54
`
	zd := testZone(t, "resign.example.", zone)
	registerZones(t, zd)
	zd.KeyDB = kdb
	zd.Options = map[ZoneOption]bool{OptInlineSigning: true}
	zd.DnssecPolicy = &DnssecPolicy{
		Mode:         DnssecPolicyModeKSKZSK,
		KSKAlgorithm: dns.ED25519,
		ZSKAlgorithm: dns.ED25519,
		SigValidity:  PolicySigValidity{Default: 14 * 24 * 3600, DNSKEY: 14 * 24 * 3600, DS: 14 * 24 * 3600},
	}
	zd.InstallInitialSnapshot()
	if _, err := zd.SignZone(context.Background(), kdb, true); err != nil {
		t.Fatalf("initial SignZone: %v", err)
	}
	return zd
}

// servedRRs is the text of every RR a full transfer of snap carries, apart from
// the apex SOA itself: an IXFR carries that in the SOAs bracketing each
// difference sequence, never inside one. The apex SOA's RRSIGs are ordinary
// content and are included.
func servedRRs(snap *zoneSnapshot, zone string) map[string]bool {
	out := map[string]bool{}
	for name, od := range snap.Data {
		if od == nil {
			continue
		}
		apex := core.EqualNames(name, zone)
		for _, rrt := range od.RRtypes.Keys() {
			rs := od.RRtypes.GetOnlyRRSet(rrt)
			if !(apex && rrt == dns.TypeSOA) {
				for _, rr := range rs.RRs {
					out[rr.String()] = true
				}
			}
			for _, rr := range rs.RRSIGs {
				out[rr.String()] = true
			}
		}
		for _, rr := range od.NSEC.RRs {
			out[rr.String()] = true
		}
		for _, rr := range od.NSEC.RRSIGs {
			out[rr.String()] = true
		}
	}
	return out
}

// replayIxfr applies the chain from serial `from` to the published snapshot onto
// base, as a strict IXFR client does: a deletion must name an RR the client
// holds, an addition one it does not (RFC 1995 §4; NSD refuses the transfer on
// either). It returns the resulting zone and every violation.
func replayIxfr(t *testing.T, zd *ZoneData, from uint32, base map[string]bool) (map[string]bool, []string) {
	t.Helper()
	snap := zd.publishedSnapshot()
	steps, ok := ixfrDeltaSteps(snap, from)
	if !ok {
		t.Fatalf("no IXFR history from serial %d to %d: the chain was reset, so there is nothing to replay", from, snap.Serial)
	}
	z := make(map[string]bool, len(base))
	for s := range base {
		z[s] = true
	}
	var bad []string
	for _, st := range steps {
		for _, rs := range st.Removed {
			for _, rr := range append(append([]dns.RR(nil), rs.RRs...), rs.RRSIGs...) {
				s := rr.String()
				if !z[s] {
					bad = append(bad, fmt.Sprintf("%d->%d deletes an RR the zone did not hold: %s", st.FromSerial, st.ToSerial, brief(s)))
				}
				delete(z, s)
			}
		}
		for _, rs := range st.Added {
			for _, rr := range append(append([]dns.RR(nil), rs.RRs...), rs.RRSIGs...) {
				s := rr.String()
				if z[s] {
					bad = append(bad, fmt.Sprintf("%d->%d adds an RR the zone already held: %s", st.FromSerial, st.ToSerial, brief(s)))
				}
				z[s] = true
			}
		}
	}
	return z, bad
}

// checkReplay replays the chain from `from` onto base and reports every way the
// result differs from what the zone serves now.
func checkReplay(t *testing.T, zd *ZoneData, from uint32, base map[string]bool) {
	t.Helper()
	served := zd.publishedSnapshot()
	got, bad := replayIxfr(t, zd, from, base)
	for _, b := range bad {
		t.Errorf("IXFR %d->%d: %s", from, served.Serial, b)
	}
	want := servedRRs(served, zd.ZoneName)
	chainOnly, servedOnly := onlyIn(got, want), onlyIn(want, got)
	if len(chainOnly) > 0 || len(servedOnly) > 0 {
		t.Errorf("replaying IXFR %d->%d onto the zone served at %d does not give the zone served at %d:"+
			" %d RRs only in the replay, %d only in the served zone",
			from, served.Serial, from, served.Serial, len(chainOnly), len(servedOnly))
		for _, s := range chainOnly {
			t.Logf("  replay only: %s", s)
		}
		for _, s := range servedOnly {
			t.Logf("  served only: %s", s)
		}
	}
}

// checkUnchanged reports every RR of snap that differs from before: the
// snapshot was rewritten after it was published.
func checkUnchanged(t *testing.T, snap *zoneSnapshot, zone string, before map[string]bool) {
	t.Helper()
	after := servedRRs(snap, zone)
	gone, appeared := onlyIn(before, after), onlyIn(after, before)
	if len(gone) > 0 || len(appeared) > 0 {
		t.Errorf("serial %d changed under a reader after it was published: %d RRs rewritten in place",
			snap.Serial, len(gone))
		for _, s := range gone {
			t.Logf("  was: %s", s)
		}
		for _, s := range appeared {
			t.Logf("  now: %s", s)
		}
	}
}

// onlyIn returns the members of a that are not in b, sorted and shortened.
func onlyIn(a, b map[string]bool) []string {
	var out []string
	for s := range a {
		if !b[s] {
			out = append(out, brief(s))
		}
	}
	sort.Strings(out)
	return out
}

// brief shortens an RR's text for a log line. The cut is past the signer name
// of an RRSIG, so the TTL, inception, expiration and key tag that tell two
// signatures apart are all kept.
func brief(s string) string {
	const limit = 140
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "..."
}

// withSigValidity returns a copy of pol whose signature validity is days long.
func withSigValidity(pol *DnssecPolicy, days uint32) DnssecPolicy {
	p := *pol
	v := days * 24 * 3600
	p.SigValidity = PolicySigValidity{Default: v, DNSKEY: v, DS: v}
	return p
}

// The root cause. A snapshot, once published, is what a downstream that
// transferred that serial holds; it must not change while it is being served.
// SignRRset used to remove a signature by shifting the RRSIGs slice in place and
// append the new one into the capacity that freed, so a forced SignZone pass
// over an RRset that still shared its RRSIGs backing array with the published
// snapshot wrote the new signature into the version being served.
func TestSignZoneDoesNotWriteThroughToThePublishedSnapshot(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := resignTestZone(t, kdb)

	published := zd.publishedSnapshot()
	before := servedRRs(published, zd.ZoneName)

	zd.mu.Lock()
	shorter := withSigValidity(zd.DnssecPolicy, 13)
	zd.DnssecPolicy = &shorter
	zd.mu.Unlock()

	if _, err := zd.SignZone(context.Background(), kdb, true); err != nil {
		t.Fatalf("SignZone(force): %v", err)
	}
	if zd.publishedSnapshot().Serial == published.Serial {
		t.Fatalf("fixture: the forced pass did not publish a new serial")
	}
	checkUnchanged(t, published, zd.ZoneName, before)
}

// The symptom, as #797 reported it from the wire. After a policy change the
// IXFR from the serial served before it must turn that serial's zone into the
// zone now served: no deletion of an RR the downstream never had, no addition
// of one it already has, and nothing left out of step.
func TestIxfrAfterAPolicyChangeReplaysToTheServedZone(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := resignTestZone(t, kdb)

	start := zd.publishedSnapshot()
	base := servedRRs(start, zd.ZoneName)

	zd.mu.Lock()
	pol := withSigValidity(zd.DnssecPolicy, 13)
	zd.mu.Unlock()
	if _, err := applyZonePolicyTransactional(context.Background(), zd, kdb, &pol,
		"shorter-validity", PolicyApplySourceCommand); err != nil {
		t.Fatalf("policy apply: %v", err)
	}
	if zd.publishedSnapshot().Serial == start.Serial {
		t.Fatalf("fixture: the policy apply did not publish a new serial")
	}
	checkReplay(t, zd, start.Serial, base)
}

// The contrast. A key-state change reaches the zone through ResignZone, which
// strips each RRset's signatures on a local copy (RRSIGs = nil) before
// re-signing, so its signature handling never touched the published snapshot.
// With no TTL change its links replay cleanly across a ZSK roll -- which is why
// the ZSK rolls around the policy changes in #797 transferred without complaint.
func TestIxfrAfterAKeyStateResignReplaysToTheServedZone(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := resignTestZone(t, kdb)

	start := zd.publishedSnapshot()
	base := servedRRs(start, zd.ZoneName)

	// Roll the ZSK: a new one active, the old one retired.
	dak, err := kdb.GetDnssecKeys(zd.ZoneName, DnskeyStateActive)
	if err != nil || len(dak.ZSKs) == 0 {
		t.Fatalf("fixture: no active ZSK: %v", err)
	}
	oldTag := dak.ZSKs[0].KeyId
	if _, _, err := kdb.GenerateKeypair(zd.ZoneName, "test", DnskeyStateActive,
		dns.TypeDNSKEY, dns.ED25519, "ZSK", nil); err != nil {
		t.Fatalf("generate replacement ZSK: %v", err)
	}
	if err := kdb.PromoteDnssecKey(zd.ZoneName, oldTag, DnskeyStateActive, DnskeyStateRetired); err != nil {
		t.Fatalf("retire the old ZSK: %v", err)
	}
	if _, err := zd.ResignZone(context.Background(), kdb); err != nil {
		t.Fatalf("ResignZone: %v", err)
	}
	if zd.publishedSnapshot().Serial == start.Serial {
		t.Fatalf("fixture: ResignZone did not publish a new serial")
	}
	checkReplay(t, zd, start.Serial, base)
}

// The same write-through, through the RRs instead of the signatures. The TTL
// clamp (applyClampToRRset) used to assign Header().Ttl on the RRs SignRRset
// was handed, and ResignZone hands it RRs that are the published snapshot's own
// -- it replaces the RRSIGs slice but not the RRs. So when the ceiling moved
// between two passes (ttls.max-served lowered, or a K-step during a KSK
// rollover) the published snapshot's TTLs changed in place, both sides of the
// diff showed the new TTL, and the link omitted the change.
func TestIxfrAfterALoweredTtlCeilingReplaysToTheServedZone(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := resignTestZone(t, kdb) // authored TTLs are 3600, no ceiling yet

	start := zd.publishedSnapshot()
	base := servedRRs(start, zd.ZoneName)

	zd.mu.Lock()
	pol := *zd.DnssecPolicy
	pol.TTLS.MaxServed = 300
	zd.DnssecPolicy = &pol
	zd.mu.Unlock()
	if _, err := zd.ResignZone(context.Background(), kdb); err != nil {
		t.Fatalf("ResignZone: %v", err)
	}
	if zd.publishedSnapshot().Serial == start.Serial {
		t.Fatalf("fixture: ResignZone did not publish a new serial")
	}
	checkUnchanged(t, start, zd.ZoneName, base)
	checkReplay(t, zd, start.Serial, base)
}

// Queries and transfers read the published snapshot without taking zd.mu, so a
// signing pass that writes into it is also a data race. Run with -race to see
// it; without -race the final assertion still catches the rewrite.
func TestSigningRacesNoReaderOfThePublishedSnapshot(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := resignTestZone(t, kdb)

	start := zd.publishedSnapshot()
	base := servedRRs(start, zd.ZoneName)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = servedRRs(zd.publishedSnapshot(), zd.ZoneName)
		}
	}()

	zd.mu.Lock()
	pol := withSigValidity(zd.DnssecPolicy, 13)
	pol.TTLS.MaxServed = 300
	zd.DnssecPolicy = &pol
	zd.mu.Unlock()
	_, err := zd.SignZone(context.Background(), kdb, true)

	close(stop)
	wg.Wait()
	if err != nil {
		t.Fatalf("SignZone(force): %v", err)
	}
	checkUnchanged(t, start, zd.ZoneName, base)
}

// --- SignRRset's storage contract ---

// signingFixture returns a signed zone, its active keys, and an RRset of two
// records copied out of the published snapshot, so the test owns it outright.
func signingFixture(t *testing.T) (*ZoneData, *DnssecKeys, core.RRset) {
	t.Helper()
	kdb := newTestKeyDB(t)
	zd := resignTestZone(t, kdb)
	dak, err := kdb.GetDnssecKeys(zd.ZoneName, DnskeyStateActive)
	if err != nil || len(dak.KSKs) == 0 || len(dak.ZSKs) == 0 {
		t.Fatalf("fixture: no active keys: %v", err)
	}
	od := getOwnerFrom(zd.publishedSnapshot(), "alpha.resign.example.")
	if od == nil {
		t.Fatal("fixture: no alpha owner")
	}
	rs := cloneRRset(od.RRtypes.GetOnlyRRSet(dns.TypeA))
	rs.RRtype = dns.TypeA
	if len(rs.RRs) != 2 || len(rs.RRSIGs) != 1 {
		t.Fatalf("fixture: alpha A has %d RRs and %d RRSIGs, want 2 and 1", len(rs.RRs), len(rs.RRSIGs))
	}
	return zd, dak, rs
}

// sigVariant returns a copy of sig as though it had been made by another key:
// a different key tag, or the same tag with a different algorithm. Its
// expiration is pushed out so it is never due for renewal.
func sigVariant(sig dns.RR, tag uint16, alg uint8) dns.RR {
	c := dns.Copy(sig).(*dns.RRSIG)
	c.KeyTag, c.Algorithm = tag, alg
	c.Expiration = uint32(time.Now().Add(30 * 24 * time.Hour).Unix())
	return c
}

// inputImage records what SignRRset was handed: every pointer in the RRs and
// RRSIGs backing arrays, up to their capacity, and the text of every object
// they point at.
type inputImage struct {
	rrs, sigs []dns.RR
	text      []string
}

func imageOf(rs core.RRset) inputImage {
	img := inputImage{
		rrs:  append([]dns.RR(nil), rs.RRs[:cap(rs.RRs)]...),
		sigs: append([]dns.RR(nil), rs.RRSIGs[:cap(rs.RRSIGs)]...),
	}
	for _, rr := range append(append([]dns.RR(nil), img.rrs...), img.sigs...) {
		if rr != nil {
			img.text = append(img.text, rr.String())
		} else {
			img.text = append(img.text, "<nil>")
		}
	}
	return img
}

// checkNotWrittenInto compares the storage rs pointed at on entry with what it
// holds now.
func checkNotWrittenInto(t *testing.T, entry core.RRset, img inputImage) {
	t.Helper()
	now := imageOf(entry)
	for i := range img.rrs {
		if now.rrs[i] != img.rrs[i] {
			t.Errorf("RRs backing array slot %d was overwritten", i)
		}
	}
	for i := range img.sigs {
		if now.sigs[i] != img.sigs[i] {
			t.Errorf("RRSIGs backing array slot %d was overwritten", i)
		}
	}
	for i := range img.text {
		if now.text[i] != img.text[i] {
			t.Errorf("a record SignRRset was handed was modified:\n was %s\n now %s",
				brief(img.text[i]), brief(now.text[i]))
		}
	}
}

func sameSlice(a, b []dns.RR) bool {
	return len(a) == len(b) && cap(a) == cap(b) && (len(a) == 0 || &a[0] == &b[0])
}

// SignRRset must never write into the slices or records it is handed: they are
// borrowed from the published snapshot. Each case exercises one way it used to.
func TestSignRRsetDoesNotWriteIntoItsInput(t *testing.T) {
	zd, dak, alpha := signingFixture(t)
	zsk := dak.ZSKs[0].DnskeyRR

	cases := []struct {
		name  string
		setup func(rs core.RRset) core.RRset
		force bool
		clamp *ClampParams
	}{{
		// The signing key has no signature here, so it signs and appends --
		// into the capacity the caller's slice has spare.
		name: "append into spare capacity",
		setup: func(rs core.RRset) core.RRset {
			sigs := make([]dns.RR, 1, 4)
			sigs[0] = sigVariant(rs.RRSIGs[0], zsk.KeyTag()+1, zsk.Algorithm)
			rs.RRSIGs = sigs
			return rs
		},
	}, {
		// A forced re-sign drops the old signature and adds a new one.
		name:  "forced re-sign",
		setup: func(rs core.RRset) core.RRset { return rs },
		force: true,
	}, {
		// The clamp lowers every TTL.
		name:  "clamp lowers the TTL",
		setup: func(rs core.RRset) core.RRset { return rs },
		force: true,
		clamp: &ClampParams{MaxServedTTL: 300},
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := tc.setup(cloneRRset(alpha))
			entry := in
			img := imageOf(entry)

			signed, err := zd.SignRRset(&in, zd.ZoneName, dak, tc.force, tc.clamp)
			if err != nil {
				t.Fatalf("SignRRset: %v", err)
			}
			if !signed {
				t.Fatal("fixture: nothing was signed")
			}
			checkNotWrittenInto(t, entry, img)
			if tc.clamp != nil {
				for _, rr := range in.RRs {
					if rr.Header().Ttl != 300 {
						t.Errorf("returned RR has TTL %d, want the clamped 300: %s", rr.Header().Ttl, rr)
					}
				}
			}
		})
	}

	// And a pass with nothing to do hands back the very slices it was given.
	t.Run("nothing to do", func(t *testing.T) {
		in := cloneRRset(alpha)
		entry := in
		signed, err := zd.SignRRset(&in, zd.ZoneName, dak, false, nil)
		if err != nil || signed {
			t.Fatalf("SignRRset on a freshly signed RRset: signed=%v err=%v, want false, nil", signed, err)
		}
		if !sameSlice(in.RRs, entry.RRs) || !sameSlice(in.RRSIGs, entry.RRSIGs) {
			t.Error("a pass that changed nothing did not return the slices it was given")
		}
	})
}

// failingSigner is a crypto.Signer whose Sign always fails.
type failingSigner struct{ pub crypto.PublicKey }

func (f failingSigner) Public() crypto.PublicKey { return f.pub }
func (f failingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("injected signing failure")
}

// A failed sign must leave the RRset exactly as it was: the caller's struct and
// everything it points at. The deferred rollback that used to do this restored
// the caller's slice header but not the backing array it had already shifted,
// so a failure on [sig-by-k, sig-by-other] left the served snapshot reading
// [sig-by-other, sig-by-other].
func TestSignRRsetFailureLeavesTheRRsetAsItWas(t *testing.T) {
	zd, dak, alpha := signingFixture(t)
	good := dak.ZSKs[0]
	bad := *good
	bad.CS = failingSigner{pub: good.CS.Public()}
	failing := &DnssecKeys{KSKs: dak.KSKs, ZSKs: []*PrivateKeyCache{&bad}}

	in := cloneRRset(alpha)
	in.RRSIGs = []dns.RR{in.RRSIGs[0], sigVariant(in.RRSIGs[0], good.DnskeyRR.KeyTag()+1, good.DnskeyRR.Algorithm)}
	entry := in
	img := imageOf(entry)

	signed, err := zd.SignRRset(&in, zd.ZoneName, failing, true, &ClampParams{MaxServedTTL: 300})
	if err == nil {
		t.Fatal("SignRRset with a failing signer reported success")
	}
	if signed {
		t.Error("a failed SignRRset reported that it signed")
	}
	checkNotWrittenInto(t, entry, img)
	if !sameSlice(in.RRs, entry.RRs) || !sameSlice(in.RRSIGs, entry.RRSIGs) || in.UnclampedTTL != entry.UnclampedTTL {
		t.Error("a failed SignRRset changed the caller's RRset")
	}
}

// Two signatures by the signing key used to panic a forced pass: the removal
// loop shrank the slice it was ranging over and sliced past its end. Now both
// are replaced by one new signature, and another key's signature is kept.
func TestSignRRsetReplacesSeveralSignaturesByOneKey(t *testing.T) {
	zd, dak, alpha := signingFixture(t)
	zsk := dak.ZSKs[0].DnskeyRR
	tag, alg := zsk.KeyTag(), zsk.Algorithm

	own := alpha.RRSIGs[0]
	own2 := dns.Copy(own)
	other := sigVariant(own, tag+1, alg)
	in := cloneRRset(alpha)
	in.RRSIGs = []dns.RR{own, other, own2}

	var signed bool
	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("SignRRset panicked: %v", r)
			}
		}()
		signed, err = zd.SignRRset(&in, zd.ZoneName, dak, true, nil)
	}()
	if err != nil || !signed {
		t.Fatalf("SignRRset: signed=%v err=%v", signed, err)
	}

	byKey, keptOther := 0, false
	for _, rr := range in.RRSIGs {
		sig := rr.(*dns.RRSIG)
		switch {
		case sig.KeyTag == tag && sig.Algorithm == alg:
			byKey++
			// By identity, not by text: ED25519 is deterministic, and a new
			// signature made in the same second with the same jitter is
			// byte-identical to the old one.
			if rr == own || rr == own2 {
				t.Error("an old signature by the signing key survived a forced pass")
			}
		case rr == other:
			keptOther = true
		}
	}
	if byKey != 1 {
		t.Errorf("%d signatures by the signing key, want exactly 1", byKey)
	}
	if !keptOther {
		t.Error("another key's signature was dropped")
	}
}

// A signature is made by a key, and a key is its tag AND its algorithm. Two keys
// of different algorithms can share a tag, which an algorithm roll makes likely
// enough to matter. Matching on the tag alone dropped the other key's signature
// on a forced pass and, worse, counted it as this key's on a normal pass, so
// the RRset was left without a signature by the key that should have signed.
func TestSignRRsetKeepsASignatureByAnotherAlgorithmWithTheSameTag(t *testing.T) {
	zd, dak, alpha := signingFixture(t)
	zsk := dak.ZSKs[0].DnskeyRR
	tag, alg := zsk.KeyTag(), zsk.Algorithm
	otherAlg := uint8(dns.ECDSAP256SHA256)
	if otherAlg == alg {
		otherAlg = dns.RSASHA256
	}

	for _, force := range []bool{false, true} {
		t.Run(fmt.Sprintf("force=%v", force), func(t *testing.T) {
			sameTag := sigVariant(alpha.RRSIGs[0], tag, otherAlg)
			in := cloneRRset(alpha)
			in.RRSIGs = []dns.RR{sameTag}

			if _, err := zd.SignRRset(&in, zd.ZoneName, dak, force, nil); err != nil {
				t.Fatalf("SignRRset: %v", err)
			}
			kept, byKey := false, 0
			for _, rr := range in.RRSIGs {
				sig := rr.(*dns.RRSIG)
				if rr == sameTag {
					kept = true
				}
				if sig.KeyTag == tag && sig.Algorithm == alg {
					byKey++
				}
			}
			if !kept {
				t.Error("the signature by the other-algorithm key with the same tag was dropped")
			}
			if byKey != 1 {
				t.Errorf("%d signatures by the signing key, want 1", byKey)
			}
		})
	}
}
