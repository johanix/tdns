/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"errors"
	"testing"

	"github.com/miekg/dns"
)

// A parent whose resolver has not started yet has not checked the delegation.
// Its refusal must be one a caller can tell apart from a verdict, and from a
// parent that has no resolver at all, where asking again changes nothing.
func TestCoherenceTellsANotYetRunningResolverFromNoResolver(t *testing.T) {
	_, ds := cohKey(t, "0F+2q0hUwq0k2iVfSmJDVWCMPRZ7hhQVR/4Gh0DBSD0=")
	update := []dns.RR{addDS(ds)}

	conf := &Config{}
	conf.Internal.ImrReady = NewImrReadiness() // not published: still priming

	err := CheckDelegationCoherence(cohChild, nil, update, coherenceDnskeyFetcher(conf))
	if !errors.Is(err, ErrNoImrEngine) {
		t.Fatalf("resolver not running yet: got %v, want an error wrapping ErrNoImrEngine", err)
	}
	if !errors.Is(err, ErrDelegationUnverifiable) {
		t.Errorf("resolver not running yet: %v no longer wraps ErrDelegationUnverifiable", err)
	}

	off := false
	conf.Imr.Active = &off
	if coherenceDnskeyFetcher(conf) != nil {
		t.Error("a server configured without a resolver got a fetcher")
	}
	err = CheckDelegationCoherence(cohChild, nil, update, coherenceDnskeyFetcher(conf))
	if err == nil || errors.Is(err, ErrNoImrEngine) {
		t.Errorf("no resolver by configuration: got %v, want a plain unverifiable refusal", err)
	}
}
