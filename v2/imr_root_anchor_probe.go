/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// Choosing the root anchor by the root's own keys.
//
// A resolver whose config names no anchor uses the compiled-in IANA root
// anchor (imr_default_anchor.go). Where the config may lead to another root --
// a root-hints file, a forward or a stub for "." -- the config alone cannot
// say whether it does: a stub for "." that names b.root-servers.net is the IANA
// root, one that names a lab's root is not. The root says it itself, by the
// keys it serves. So the resolver fetches the root's DNSKEY RRset and uses the
// compiled-in anchor when a key in it hashes to one of its DS records and signs
// the set. Against a private root no key matches, and the resolver keeps what
// it had before: no anchor, every answer Indeterminate, and a warning.
//
// The check is the one validation would make with the anchor loaded, made
// first and offline, so that the anchor is only loaded where it can match: the
// IANA anchor against a private root would make every signed answer Bogus.
// Nothing here trusts the answer: a root that lies about its keys fails the
// match and gets no anchor, which is where a private root is anyway.

// rootAnchorSource is where the compiled-in root anchor comes from. A variable
// so that a test can stand in a root of its own.
var rootAnchorSource = compiledInRootAnchors

// rootProbeRetry is how long to wait between attempts to fetch the root's
// DNSKEY RRset. The last wait repeats, for as long as the resolver runs: until
// the root answers there is nothing else to do, and queries are Indeterminate
// as they were when no anchor was chosen at all.
var rootProbeRetry = []time.Duration{5 * time.Second, 15 * time.Second, 30 * time.Second, time.Minute}

// noAnchorKeysError is fetchAnchorKeys' answer when the zone was reached and
// has no DNSKEY RRset: it is not signed. That is a fact about the zone, unlike
// an error from not reaching it, and the root probe treats it so: a private
// root that is not signed is not the IANA root, however often it is asked.
type noAnchorKeysError struct{ zone string }

func (e noAnchorKeysError) Error() string { return fmt.Sprintf("no %s DNSKEY RRset found", e.zone) }

// rootVerdict is what rootKeysMatchAnchor concludes about a root's keys.
type rootVerdict int

const (
	// rootDiffers: another root. No key in the set hashes to the anchor, or the
	// one that does has no signature over the set that verifies.
	rootDiffers rootVerdict = iota
	// rootMatches: the root the anchor is for.
	rootMatches
	// rootUnverifiable: a key hashes to the anchor, but the only signatures by it
	// are outside their validity period at this host's clock. That is not a
	// different root: a clock that is wrong, or a signature that is about to be
	// replaced, makes the same set verify later. It is asked again, as an
	// unreachable root is.
	rootUnverifiable
)

// rootKeysMatchAnchor says whether rrset, the DNSKEY RRset a root served,
// belongs to the root the DS records in dss anchor: a DNSKEY at the root
// hashes to one of them (RFC 4035 section 5.2) and an RRSIG by that key over
// the whole RRset verifies at now. On rootMatches it returns the key's tag;
// otherwise why says what was missing, and the verdict says whether to ask
// again (rootUnverifiable) or not (rootDiffers).
func rootKeysMatchAnchor(rrset *core.RRset, dss []*dns.DS, now time.Time) (keytag uint16, verdict rootVerdict, why string) {
	if rrset == nil || len(rrset.RRs) == 0 {
		return 0, rootDiffers, "it served no DNSKEY RRset"
	}
	var anchored []*dns.DNSKEY // the keys that hash to one of the DS records
	nkeys := 0
	for _, rr := range rrset.RRs {
		dk, isKey := rr.(*dns.DNSKEY)
		if !isKey || dns.Fqdn(dk.Hdr.Name) != "." {
			continue
		}
		nkeys++
		for _, ds := range dss {
			// The digest covers the key's algorithm field but not the DS's,
			// so a DS naming another algorithm would otherwise still match.
			if ds.KeyTag != dk.KeyTag() || ds.Algorithm != dk.Algorithm {
				continue
			}
			if computed := dk.ToDS(ds.DigestType); computed != nil && strings.EqualFold(computed.Digest, ds.Digest) {
				anchored = append(anchored, dk)
				break
			}
		}
	}
	if len(anchored) == 0 {
		return 0, rootDiffers, fmt.Sprintf("none of the %d DNSKEY records it served hashes to a compiled-in root DS", nkeys)
	}
	// A signature that is out of its validity period and one that does not
	// verify are kept apart: only the first can be the clock's doing.
	var outsideValidity, verifyFailed error
	for _, dk := range anchored {
		for _, rr := range rrset.RRSIGs {
			sig, isSig := rr.(*dns.RRSIG)
			if !isSig || sig.TypeCovered != dns.TypeDNSKEY || sig.KeyTag != dk.KeyTag() || sig.Algorithm != dk.Algorithm {
				continue
			}
			if !sig.ValidityPeriod(now) {
				outsideValidity = fmt.Errorf("the RRSIG is valid from %s to %s, and it is %s",
					time.Unix(int64(sig.Inception), 0).UTC().Format(time.RFC3339),
					time.Unix(int64(sig.Expiration), 0).UTC().Format(time.RFC3339),
					now.UTC().Format(time.RFC3339))
				continue
			}
			if err := sig.Verify(dk, rrset.RRs); err != nil {
				verifyFailed = err
				continue
			}
			return dk.KeyTag(), rootMatches, ""
		}
	}
	if outsideValidity != nil && verifyFailed == nil {
		return 0, rootUnverifiable, fmt.Sprintf("key %d matches a compiled-in root DS, but %v (is this host's clock right?)",
			anchored[0].KeyTag(), outsideValidity)
	}
	problem := verifyFailed
	if problem == nil {
		problem = errors.New("it served no RRSIG over the DNSKEY RRset by that key")
	}
	return 0, rootDiffers, fmt.Sprintf("key %d matches a compiled-in root DS, but the DNSKEY RRset does not verify with it: %v",
		anchored[0].KeyTag(), problem)
}

// rootAnchorByProbe fetches the root's DNSKEY RRset, the way resolution will
// ask for it, and returns the compiled-in root DS records when the root serves
// the keys they anchor. It returns nil when it does not (the root is another
// one: no anchor, and a warning) and when ctx ends first. why says how the
// config reaches the root (NonDefaultRoot).
//
// It waits for a root that does not answer, and tries again for as long as ctx
// lasts (rootProbeRetry): that the root cannot be reached now does not say
// which root it is. Nor does a signature that is out of date by this host's
// clock (rootUnverifiable); a clock that is stepped, or a signature that is
// replaced, makes the same root verify later.
func (imr *Imr) rootAnchorByProbe(ctx context.Context, why string) []*dns.DS {
	dss, _, err := rootAnchorSource()
	if err != nil {
		// A constant in this binary: it not parsing is a bug.
		lgImr.Error("the compiled-in root trust anchor cannot be read", "err", err)
		return nil
	}
	for attempt := 0; ; attempt++ {
		rrset, _, _, err := imr.fetchAnchorKeys(ctx, ".")
		var unsigned noAnchorKeysError
		// retry says why this attempt did not decide, and how to word the wait.
		var retry, retryMsg string
		if err == nil || errors.As(err, &unsigned) {
			// A root that answered, with keys or without, has said which root it
			// is, unless its signature is out of date by this host's clock.
			// (No keys: rrset is nil, and nothing matches.)
			keytag, verdict, mismatch := rootKeysMatchAnchor(rrset, dss, cache.Now())
			switch verdict {
			case rootMatches:
				lgImr.Info("the root serves the IANA root keys: using the compiled-in IANA root trust anchor",
					"zone", ".", "keytag", keytag, "root-reached-through", why)
				return dss
			case rootUnverifiable:
				retry = mismatch
				retryMsg = "the root's DNSKEY RRset cannot be verified yet against the compiled-in root trust anchor;" +
					" until it can, nothing validates"
			default:
				lgImr.Warn("no trust anchor configured, and the root does not serve the IANA root keys, so the compiled-in"+
					" root anchor is not used: nothing will validate (answers are Indeterminate)."+
					" Configure trust-anchor-ds or trust-anchor-file for the root in use",
					"root-reached-through", why, "mismatch", mismatch)
				return nil
			}
		} else {
			retry = err.Error()
			retryMsg = "the root's DNSKEY RRset cannot be fetched to check it against the compiled-in root trust anchor;" +
				" until it can, nothing validates"
		}
		if ctx.Err() != nil {
			return nil
		}
		wait := rootProbeRetry[min(attempt, len(rootProbeRetry)-1)]
		lgImr.Warn(retryMsg, "root-reached-through", why, "err", retry, "retry-in", wait)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}
