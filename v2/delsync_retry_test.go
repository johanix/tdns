package tdns

import (
	"fmt"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestRetryWithBackoff(t *testing.T) {
	fast := time.Millisecond

	t.Run("done on first attempt", func(t *testing.T) {
		calls := 0
		err := retryWithBackoff(5, fast, func(attempt int) (bool, error) {
			calls++
			return true, nil
		})
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if calls != 1 {
			t.Errorf("calls = %d, want 1", calls)
		}
	})

	t.Run("retries then done", func(t *testing.T) {
		calls := 0
		err := retryWithBackoff(5, fast, func(attempt int) (bool, error) {
			calls++
			return calls == 3, nil
		})
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if calls != 3 {
			t.Errorf("calls = %d, want 3", calls)
		}
	})

	t.Run("exhausts and returns last error", func(t *testing.T) {
		calls := 0
		err := retryWithBackoff(4, fast, func(attempt int) (bool, error) {
			calls++
			return false, fmt.Errorf("still failing")
		})
		if calls != 4 {
			t.Errorf("calls = %d, want 4", calls)
		}
		if err == nil {
			t.Fatal("expected error after exhaustion")
		}
	})

	t.Run("exhausts with no error returns generic", func(t *testing.T) {
		err := retryWithBackoff(2, fast, func(attempt int) (bool, error) {
			return false, nil
		})
		if err == nil {
			t.Fatal("expected generic exhausted error")
		}
	})
}

// TestSendUpdateWithRetryBADKEYBound pins the re-bootstrap bound: a BADKEY that
// persists after one re-bootstrap is a hard error, and re-bootstrap is invoked
// at most once (no BADKEY -> re-bootstrap -> BADKEY loop).
func TestSendUpdateWithRetryBADKEYBound(t *testing.T) {
	fast := time.Millisecond

	t.Run("NOERROR first try, no re-bootstrap", func(t *testing.T) {
		reboots := 0
		rcode, _, err := sendUpdateWithRetry(5, fast,
			func() (int, UpdateResult, error) { return dns.RcodeSuccess, UpdateResult{}, nil },
			func() error { reboots++; return nil })
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if rcode != dns.RcodeSuccess {
			t.Errorf("rcode = %d, want NOERROR", rcode)
		}
		if reboots != 0 {
			t.Errorf("reBootstrap called %d times, want 0", reboots)
		}
	})

	t.Run("BADKEY then NOERROR: one re-bootstrap, success", func(t *testing.T) {
		sends, reboots := 0, 0
		rcode, _, err := sendUpdateWithRetry(5, fast,
			func() (int, UpdateResult, error) {
				sends++
				if sends == 1 {
					return dns.RcodeBadKey, UpdateResult{}, nil
				}
				return dns.RcodeSuccess, UpdateResult{}, nil
			},
			func() error { reboots++; return nil })
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if rcode != dns.RcodeSuccess {
			t.Errorf("rcode = %d, want NOERROR", rcode)
		}
		if reboots != 1 {
			t.Errorf("reBootstrap called %d times, want 1", reboots)
		}
	})

	t.Run("BADKEY forever: bounded to one re-bootstrap, hard error", func(t *testing.T) {
		reboots := 0
		_, _, err := sendUpdateWithRetry(5, fast,
			func() (int, UpdateResult, error) { return dns.RcodeBadKey, UpdateResult{}, nil },
			func() error { reboots++; return nil })
		if err == nil {
			t.Fatal("expected hard error when BADKEY persists after re-bootstrap")
		}
		if reboots != 1 {
			t.Errorf("reBootstrap called %d times, want exactly 1 (no loop)", reboots)
		}
	})

	t.Run("re-bootstrap failure is a hard error", func(t *testing.T) {
		reboots := 0
		_, _, err := sendUpdateWithRetry(5, fast,
			func() (int, UpdateResult, error) { return dns.RcodeBadKey, UpdateResult{}, nil },
			func() error { reboots++; return fmt.Errorf("bootstrap boom") })
		if err == nil {
			t.Fatal("expected hard error when re-bootstrap fails")
		}
		if reboots != 1 {
			t.Errorf("reBootstrap called %d times, want 1", reboots)
		}
	})

	t.Run("repeated REFUSED exhausts within the retry budget", func(t *testing.T) {
		sends := 0
		_, _, err := sendUpdateWithRetry(3, fast,
			func() (int, UpdateResult, error) { sends++; return dns.RcodeRefused, UpdateResult{}, nil },
			func() error { return nil })
		if err == nil {
			t.Fatal("expected error after repeated REFUSED")
		}
		if sends != 3 {
			t.Errorf("sends = %d, want 3 (bounded retry)", sends)
		}
	})
}
