/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"errors"
	"net/http"
	"testing"

	"github.com/miekg/dns"
)

// The status follows what the coherence check actually concluded, and is taken
// from the check's own errors rather than from hand-built ones.
func TestDsyncApiCoherenceStatus(t *testing.T) {
	dk, ds := cohKey(t, "0F+2q0hUwq0k2iVfSmJDVWCMPRZ7hhQVR/4Gh0DBSD0=")
	_ = dk
	other, _ := cohKey(t, "l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=")
	update := []dns.RR{addDS(ds)}

	cases := []struct {
		name  string
		fetch dnskeyFetcher
		want  int
	}{
		{"the child's DNSKEY lookup failed (not at its nameservers yet)",
			func(string) ([]dns.RR, bool, error) { return nil, false, errors.New("i/o timeout") },
			http.StatusServiceUnavailable},
		{"this server's resolver has not started",
			func(string) ([]dns.RR, bool, error) { return nil, false, ErrNoImrEngine },
			http.StatusServiceUnavailable},
		{"no resolver at all", nil, http.StatusConflict},
		{"the resulting DS set matches no published key", fetcherFor(other), http.StatusConflict},
	}
	for _, c := range cases {
		err := CheckDelegationCoherence(cohChild, nil, update, c.fetch)
		if err == nil {
			t.Fatalf("%s: the check accepted the update", c.name)
		}
		if got := dsyncApiCoherenceStatus(err); got != c.want {
			t.Errorf("%s: status %d, want %d (err: %v)", c.name, got, c.want, err)
		}
	}
}
