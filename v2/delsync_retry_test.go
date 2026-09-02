package tdns

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestRetryWithBackoff(t *testing.T) {
	fast := time.Millisecond

	t.Run("done on first attempt", func(t *testing.T) {
		calls := 0
		err := retryWithBackoff(context.Background(), 5, fast, func(attempt int) (bool, error) {
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
		err := retryWithBackoff(context.Background(), 5, fast, func(attempt int) (bool, error) {
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
		err := retryWithBackoff(context.Background(), 4, fast, func(attempt int) (bool, error) {
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
		err := retryWithBackoff(context.Background(), 2, fast, func(attempt int) (bool, error) {
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
		rcode, _, err := sendUpdateWithRetry(context.Background(), 5, fast,
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
		rcode, _, err := sendUpdateWithRetry(context.Background(), 5, fast,
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
		_, _, err := sendUpdateWithRetry(context.Background(), 5, fast,
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
		_, _, err := sendUpdateWithRetry(context.Background(), 5, fast,
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
		_, _, err := sendUpdateWithRetry(context.Background(), 3, fast,
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

// The transport-error branch is the core contract of the retry engine: no
// response, or a send that failed outright, must be RETRIED rather than treated
// as terminal. Every other branch keys on an RCODE the parent actually sent;
// this one is the case where nothing came back at all.
func TestSendUpdateWithRetryRetriesTransportErrors(t *testing.T) {
	fast := time.Millisecond

	t.Run("transient failure then success", func(t *testing.T) {
		calls := 0
		rcode, _, err := sendUpdateWithRetry(context.Background(), 5, fast,
			func() (int, UpdateResult, error) {
				calls++
				if calls < 3 {
					return 0, UpdateResult{}, fmt.Errorf("no response from parent")
				}
				return dns.RcodeSuccess, UpdateResult{}, nil
			}, nil)
		if err != nil {
			t.Fatalf("err = %v, want nil once the send finally succeeds", err)
		}
		if calls != 3 {
			t.Errorf("send called %d times, want 3 (two failures then success)", calls)
		}
		if rcode != dns.RcodeSuccess {
			t.Errorf("rcode = %d, want NOERROR", rcode)
		}
	})

	t.Run("exhaustion reports the last rcode and the transport error", func(t *testing.T) {
		calls := 0
		rcode, _, err := sendUpdateWithRetry(context.Background(), 3, fast,
			func() (int, UpdateResult, error) {
				calls++
				return dns.RcodeServerFailure, UpdateResult{}, fmt.Errorf("connection refused")
			}, nil)
		if calls != 3 {
			t.Errorf("send called %d times, want 3 (every attempt used)", calls)
		}
		if err == nil {
			t.Fatal("exhausting every attempt returned nil error")
		}
		// The rcode from the final attempt is reported, not a zero value: the
		// caller decides what to do with it and cannot see it any other way.
		if rcode != dns.RcodeServerFailure {
			t.Errorf("rcode = %d, want the last attempt's SERVFAIL", rcode)
		}
	})
}

// A cancelled context must stop the retries promptly rather than sleeping
// through the whole backoff schedule.
func TestRetryWithBackoffHonoursCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0

	start := time.Now()
	err := retryWithBackoff(ctx, 5, 10*time.Second, func(attempt int) (bool, error) {
		calls++
		cancel() // cancelled while the engine is about to back off
		return false, fmt.Errorf("attempt %d failed", attempt)
	})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("cancellation returned a nil error")
	}
	if calls != 1 {
		t.Errorf("fn called %d times after cancellation, want 1", calls)
	}
	// Without cancellation this would sleep 10s before the second attempt.
	if elapsed > 2*time.Second {
		t.Errorf("took %v — the backoff slept through the cancellation", elapsed)
	}
}

// A re-bootstrap that fails only because the parent's SVCB bootstrap
// advertisement could not be looked up (carry-over 9) is deferred, not spent:
// the next attempt may re-bootstrap again, and the one-re-bootstrap bound
// applies once a re-bootstrap actually runs.
func TestSendUpdateWithRetryDefersReBootstrapOnAdvertisementLookupFailure(t *testing.T) {
	fast := time.Millisecond

	t.Run("transient lookup failure, then success", func(t *testing.T) {
		sends, reboots := 0, 0
		rcode, _, err := sendUpdateWithRetry(context.Background(), 5, fast,
			func() (int, UpdateResult, error) {
				sends++
				if sends <= 2 {
					return dns.RcodeBadKey, UpdateResult{}, nil
				}
				return dns.RcodeSuccess, UpdateResult{}, nil
			},
			func() error {
				reboots++
				if reboots == 1 {
					return fmt.Errorf("BootstrapSig0KeyWithParent: %w", errBootstrapAdvertisementLookup)
				}
				return nil
			})
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if rcode != dns.RcodeSuccess {
			t.Errorf("rcode = %d, want NOERROR", rcode)
		}
		if reboots != 2 || sends != 3 {
			t.Errorf("reboots=%d sends=%d, want 2 and 3", reboots, sends)
		}
	})

	t.Run("persistent lookup failure exhausts the budget", func(t *testing.T) {
		reboots := 0
		_, _, err := sendUpdateWithRetry(context.Background(), 3, fast,
			func() (int, UpdateResult, error) { return dns.RcodeBadKey, UpdateResult{}, nil },
			func() error { reboots++; return errBootstrapAdvertisementLookup })
		if err == nil {
			t.Fatal("expected an error after exhausting retries")
		}
		if reboots != 3 {
			t.Errorf("reboots = %d, want 3 (one deferred attempt per retry)", reboots)
		}
	})
}

// A re-bootstrap that reports the parent requires MANUAL bootstrap is
// terminal on the first attempt: retrying cannot help, and the error says
// what the operator has to do.
func TestSendUpdateWithRetryManualBootstrapIsTerminal(t *testing.T) {
	sends, reboots := 0, 0
	_, _, err := sendUpdateWithRetry(context.Background(), 5, time.Millisecond,
		func() (int, UpdateResult, error) { sends++; return dns.RcodeBadKey, UpdateResult{}, nil },
		func() error { reboots++; return fmt.Errorf("BootstrapSig0KeyWithParent: %w", errBootstrapManual) })
	if !errors.Is(err, errBootstrapManual) {
		t.Fatalf("err = %v, want errBootstrapManual", err)
	}
	if sends != 1 || reboots != 1 {
		t.Errorf("sends=%d reboots=%d, want 1 and 1", sends, reboots)
	}
}
