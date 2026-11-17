/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"errors"
	"net/http"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// #848: a parent that could not read the DS it publishes for a child treated
// the child as having none. That is the bootstrap case, which accepts an
// unvalidated DNSKEY answer, so a child that HAS a DS could have it replaced on
// an answer nothing authenticated -- the one change the coherence check exists
// to stop.

// countingFetcher answers with rrset and state, and counts the lookups.
func countingFetcher(state cache.ValidationState, rrset *core.RRset, calls *int) dnskeyFetcher {
	return func(string) (*core.RRset, cache.ValidationState, error) {
		*calls++
		return rrset, state, nil
	}
}

// The attack: the child has a DS, and the update swaps it for one matching a
// key the parent has never seen, on an unvalidated answer that publishes that
// key. With the DS read, this is refused; with no DS, it is a bootstrap.
func TestCoherenceRefusesWhenTheParentCannotReadItsOwnDS(t *testing.T) {
	const child = "child.parent.example."
	live := newSignerTestKey(t, child, 257)
	rogue := newSignerTestKey(t, child, 257)
	now := time.Now()
	forged := signedDnskeys(t, testKeys(rogue), testKeys(rogue), now.Add(-time.Hour), now.Add(time.Hour))
	swap := []dns.RR{
		delOneDS(dsForKey(t, live)),
		addDS(dsForKey(t, rogue)),
	}

	for _, tc := range []struct {
		name       string
		unreadable func(zd *ZoneData)
		cause      error
		status     int
	}{
		{
			// Retryable: the zone will be readable once it has loaded.
			name:       "zone not Ready",
			unreadable: func(zd *ZoneData) { zd.Ready = false },
			cause:      ErrZoneNotReady,
			status:     http.StatusServiceUnavailable,
		},
		{
			// Not retryable: this store never answers by owner name.
			name:       "store with no owner index",
			unreadable: func(zd *ZoneData) { zd.ZoneStore = XfrZone },
			cause:      errParentDSUnreadable,
			status:     http.StatusConflict,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			zd := childDSParent(t, dsForKey(t, live))
			tc.unreadable(zd)

			calls := 0
			err := zd.CheckDelegationCoherenceForUpdate(swap,
				countingFetcher(cache.ValidationStateInsecure, forged, &calls))
			if err == nil {
				t.Fatal("the DS was swapped on an unvalidated answer:" +
					" a parent that could not read its DS took it to have none")
			}
			if !errors.Is(err, ErrDelegationUnverifiable) {
				t.Errorf("not marked unverifiable: %v", err)
			}
			if !errors.Is(err, tc.cause) {
				t.Errorf("the refusal lost its cause: %v, want it to wrap %v", err, tc.cause)
			}
			if calls != 0 {
				t.Errorf("the child's DNSKEYs were looked up %d time(s) with nothing to judge them against", calls)
			}
			if got := delegationCoherenceEDE(err); got != edns0.EDEDelegationUnverifiable {
				t.Errorf("EDE %d (%s), want unverifiable", got, edns0.EDECodeToString[got])
			}
			if got := dsyncApiCoherenceStatus(err); got != tc.status {
				t.Errorf("status %d, want %d", got, tc.status)
			}
		})
	}
}

// The same swap through the UPDATE path, as the child receives it: the real
// approval, the resolver's Insecure answer as it hands it over, and the rcode
// and EDE the child is sent. A parent that is not Ready has checked nothing, so
// the update is not approved and the child is told to try again.
func TestApproveChildUpdateRefusesWhenTheParentCannotReadItsOwnDS(t *testing.T) {
	const child = "child.parent.example."
	live := newSignerTestKey(t, child, 257)
	rogue := newSignerTestKey(t, child, 257)
	now := time.Now()
	zd := childDSParent(t, dsForKey(t, live))
	zd.Ready = false
	resolverAnswers(t, child, signedDnskeys(t, testKeys(rogue), testKeys(rogue), now.Add(-time.Hour), now.Add(time.Hour)),
		cache.ValidationStateInsecure)

	r := new(dns.Msg)
	r.SetUpdate(zd.ZoneName)
	r.Ns = []dns.RR{delOneDS(dsForKey(t, live)), addDS(dsForKey(t, rogue))}
	us := &UpdateStatus{
		Type:                  "CHILD-UPDATE",
		Validated:             true,
		ValidatedByTrustedKey: true,
		SignerName:            child,
		ValidationRcode:       dns.RcodeSuccess,
	}
	approved, _, err := zd.ApproveChildUpdate(zd.ZoneName, us, r)
	if approved {
		t.Fatal("the DS swap was approved by a parent that could not read its DS")
	}
	if !errors.Is(err, ErrZoneNotReady) {
		t.Errorf("refused, but not for the unreadable DS: %v", err)
	}
	if us.ValidationRcode != dns.RcodeRefused || us.RejectionEDE != edns0.EDEDelegationUnverifiable {
		t.Errorf("rcode %s, EDE %d; want REFUSED with EDE %d",
			dns.RcodeToString[int(us.ValidationRcode)], us.RejectionEDE, edns0.EDEDelegationUnverifiable)
	}
}

// And "no DS" still means bootstrap when it is true: a child with no DS at its
// owner, and a child with no owner at all, may add its first DS on an
// unvalidated answer.
func TestCoherenceStillBootstrapsAChildWithNoDS(t *testing.T) {
	for _, child := range []string{
		"child.parent.example.", // delegated, no DS
		"new.parent.example.",   // not in the zone at all
	} {
		t.Run(child, func(t *testing.T) {
			zd := childDSParent(t)
			key := newSignerTestKey(t, child, 257)
			now := time.Now()
			keys := signedDnskeys(t, testKeys(key), testKeys(key), now.Add(-time.Hour), now.Add(time.Hour))

			calls := 0
			if err := zd.CheckDelegationCoherenceForUpdate([]dns.RR{addDS(dsForKey(t, key))},
				countingFetcher(cache.ValidationStateInsecure, keys, &calls)); err != nil {
				t.Fatalf("the first DS was refused: %v", err)
			}
			if calls != 1 {
				t.Errorf("DNSKEY lookups: %d, want 1", calls)
			}
		})
	}
}
