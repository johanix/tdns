package tdns

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// Delegation-sync retry schedule, per draft-ietf-dnsop-delegation-mgmt-via-ddns-02
// §"No response to a DNS UPDATE": wait at least 5s before treating a missing
// response as a timeout, double the interval each time, and give up after no
// more than 5 attempts.
const (
	delegationSyncMaxRetries   = 5
	delegationSyncInitialDelay = 5 * time.Second
)

// retryWithBackoff runs fn up to maxRetries times, sleeping initialDelay and
// doubling it between attempts (with the delegation-sync schedule: 5s, 10s, 20s,
// 40s). fn returns done=true to stop early (success or a terminal condition);
// its error is then returned verbatim. If every attempt returns done=false the
// last error is returned, or a generic "exhausted" error if there was none.
//
// The schedule is parameterized so callers share one implementation (the
// KeyState poller and the UPDATE sender) and tests can use tiny delays.
// The backoff waits on ctx as well as the clock. With the delegation-sync
// schedule a caller can otherwise sit in uncancellable sleeps for 5+10+20+40 =
// 75 seconds per send, which a shutdown cannot interrupt and a cancelled
// operation keeps paying for.
func retryWithBackoff(ctx context.Context, maxRetries int, initialDelay time.Duration, fn func(attempt int) (done bool, err error)) error {
	if ctx == nil {
		ctx = context.Background()
	}
	delay := initialDelay
	var lastErr error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("retryWithBackoff: cancelled before attempt %d: %w", attempt, err)
		}
		done, err := fn(attempt)
		if done {
			return err
		}
		lastErr = err
		if attempt < maxRetries {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				if lastErr != nil {
					return fmt.Errorf("retryWithBackoff: cancelled after attempt %d (last error: %v): %w",
						attempt, lastErr, ctx.Err())
				}
				return fmt.Errorf("retryWithBackoff: cancelled after attempt %d: %w", attempt, ctx.Err())
			case <-timer.C:
			}
			delay *= 2
		}
	}
	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("retryWithBackoff: exhausted %d attempts", maxRetries)
}

// sendUpdateWithRetry is the transport-independent core of SendUpdateWithRetry.
// send performs one UPDATE send; reBootstrap performs the bounded BADKEY
// recovery. Both are injected so the retry/backoff and re-bootstrap-bound logic
// can be unit-tested without real DNS.
//
// RCODE handling (draft-ietf-dnsop-delegation-mgmt-via-ddns-02):
//   - NOERROR  -> done.
//   - REFUSED  -> bounded retry (a single REFUSED is not a stop signal).
//   - SERVFAIL -> bounded retry (transient parent-side failure).
//   - BADKEY   -> re-bootstrap the child's key with the parent AT MOST ONCE,
//     then retry. A BADKEY that recurs after re-bootstrap is a hard error.
//   - other    -> hard error.
//
// The re-bootstrap is bounded to one attempt per call and reBootstrap must not
// itself route back through this function, so there is no BADKEY -> re-bootstrap
// -> BADKEY loop.
func sendUpdateWithRetry(ctx context.Context, maxRetries int, initialDelay time.Duration,
	send func() (int, UpdateResult, error), reBootstrap func() error) (int, UpdateResult, error) {

	reBootstrapped := false
	var lastRcode int
	var lastUR UpdateResult

	err := retryWithBackoff(ctx, maxRetries, initialDelay, func(attempt int) (bool, error) {
		rcode, ur, serr := send()
		lastRcode, lastUR = rcode, ur
		if serr != nil {
			// Transport error / no response — retry per the backoff.
			lgDns.Warn("sendUpdateWithRetry: send failed, will retry", "attempt", attempt, "err", serr)
			return false, serr
		}
		switch rcode {
		case dns.RcodeSuccess:
			return true, nil
		case dns.RcodeRefused:
			lgDns.Warn("sendUpdateWithRetry: parent REFUSED, bounded retry", "attempt", attempt)
			return false, fmt.Errorf("parent REFUSED the delegation UPDATE")
		case dns.RcodeServerFailure:
			// Transient by definition: the parent failed to process a request
			// it did not reject. The draft names BADKEY and REFUSED explicitly
			// and is silent here, but treating SERVFAIL as terminal gives up
			// after one attempt on exactly the failure a retry exists for --
			// and it is indistinguishable, to the child, from the no-response
			// case the draft does say to retry.
			lgDns.Warn("sendUpdateWithRetry: parent SERVFAIL, bounded retry", "attempt", attempt)
			return false, fmt.Errorf("parent returned SERVFAIL for the delegation UPDATE")
		case dns.RcodeBadKey:
			if reBootstrapped {
				return true, fmt.Errorf("delegation UPDATE still BADKEY after re-bootstrap")
			}
			if reBootstrap == nil {
				return true, fmt.Errorf("delegation UPDATE got BADKEY and no re-bootstrap action is available")
			}
			lgDns.Warn("sendUpdateWithRetry: BADKEY, re-bootstrapping SIG(0) key once")
			if berr := reBootstrap(); berr != nil {
				if errors.Is(berr, errBootstrapAdvertisementLookup) {
					// The re-bootstrap never got as far as choosing a method:
					// the parent's advertisement could not be looked up. Leave
					// the one re-bootstrap unspent and let the next attempt
					// try again, within the same bound.
					lgDns.Warn("sendUpdateWithRetry: re-bootstrap deferred, advertisement lookup failed", "attempt", attempt, "err", berr)
					return false, fmt.Errorf("re-bootstrap after BADKEY deferred: %w", berr)
				}
				return true, fmt.Errorf("re-bootstrap after BADKEY failed: %v", berr)
			}
			reBootstrapped = true
			return false, fmt.Errorf("re-bootstrapped after BADKEY, retrying UPDATE")
		default:
			return true, fmt.Errorf("parent returned rcode %s", dns.RcodeToString[rcode])
		}
	})
	return lastRcode, lastUR, err
}

// SendUpdateWithRetry sends a delegation-sync DNS UPDATE with the retry/backoff
// and RCODE handling of draft-ietf-dnsop-delegation-mgmt-via-ddns-02. It is for
// the delegation-DATA senders only; the shared SendUpdate keeps single-shot
// semantics for its other callers (KSK DS push, CLI, etc.).
func (zd *ZoneData) SendUpdateWithRetry(ctx context.Context, msg *dns.Msg, parent string, addrs []string) (int, UpdateResult, error) {
	return sendUpdateWithRetry(ctx, delegationSyncMaxRetries, delegationSyncInitialDelay,
		func() (int, UpdateResult, error) {
			return SendUpdate(ctx, msg, parent, addrs)
		},
		func() error {
			// Re-bootstrap re-uploads the child's existing active SIG(0) key
			// (algorithm 0 is only consulted when no active key exists, which is
			// not the case for a zone already sending signed delegation UPDATEs).
			// BootstrapSig0KeyWithParent never calls SendUpdateWithRetry, so this
			// cannot recurse.
			// The caller's context, not a fresh Background one: a re-bootstrap
			// is part of the operation being cancelled, not separate from it.
			_, _, berr := zd.BootstrapSig0KeyWithParent(ctx, 0)
			return berr
		})
}
