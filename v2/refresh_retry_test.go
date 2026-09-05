package tdns

import (
	"testing"
)

// basicZone's SOA carries REFRESH 3600 and RETRY 600 -- distinct, so the two
// cannot be mistaken for one another.
func retryTestZone(t *testing.T, ztype ZoneType) *ZoneData {
	t.Helper()
	zd := loadTestTransferZone(t, basicZone)
	zd.ZoneType = ztype
	return zd
}

// A secondary retries on its SOA RETRY, which is a different number from its
// REFRESH and is what RFC 1034 says to use after a failure.
func TestFindSoaRetryReadsTheRetryField(t *testing.T) {
	zd := retryTestZone(t, Secondary)

	retry, err := FindSoaRetry(zd)
	if err != nil {
		t.Fatalf("FindSoaRetry: %v", err)
	}
	if retry != 600 {
		t.Fatalf("retry %d, want 600 (the SOA's RETRY, not its REFRESH of 3600)", retry)
	}
}

// A primary re-stats a file; it has no primary to retry against, and the SOA's
// RETRY field describes a secondary's behaviour toward one. FindSoaRefresh
// short-circuits primaries for exactly this reason and FindSoaRetry has to do
// the same -- copying it with one field swapped would hand a primary a 15-minute
// re-stat interval read from a field that says nothing about it.
func TestFindSoaRetryIgnoresTheSoaForAPrimary(t *testing.T) {
	zd := retryTestZone(t, Primary)

	retry, err := FindSoaRetry(zd)
	if err != nil {
		t.Fatalf("FindSoaRetry: %v", err)
	}
	if retry != 86400 {
		t.Fatalf("retry %d, want 86400: a primary's retry must not come from the SOA", retry)
	}
	refresh, _ := FindSoaRefresh(zd)
	if retry != refresh {
		t.Errorf("a primary's retry (%d) and refresh (%d) should agree; both are re-stat intervals",
			retry, refresh)
	}
}

// A counter with no retry value -- one built before the field existed, or for a
// zone with no readable SOA -- falls back to its refresh interval rather than to
// zero, which would retry in a tight loop.
func TestRefreshCounterRetryFallsBackToRefresh(t *testing.T) {
	if got := refreshCounterRetry(&RefreshCounter{SOARefresh: 3600}); got != 3600 {
		t.Fatalf("fallback %d, want 3600", got)
	}
	if got := refreshCounterRetry(&RefreshCounter{SOARefresh: 3600, SOARetry: 900}); got != 900 {
		t.Fatalf("retry %d, want 900", got)
	}
}
