package tdns

import (
	"context"
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
func retryWithBackoff(maxRetries int, initialDelay time.Duration, fn func(attempt int) (done bool, err error)) error {
	delay := initialDelay
	var lastErr error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		done, err := fn(attempt)
		if done {
			return err
		}
		lastErr = err
		if attempt < maxRetries {
			time.Sleep(delay)
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
//   - BADKEY   -> re-bootstrap the child's key with the parent AT MOST ONCE,
//     then retry. A BADKEY that recurs after re-bootstrap is a hard error.
//   - other    -> hard error.
//
// The re-bootstrap is bounded to one attempt per call and reBootstrap must not
// itself route back through this function, so there is no BADKEY -> re-bootstrap
// -> BADKEY loop.
func sendUpdateWithRetry(maxRetries int, initialDelay time.Duration,
	send func() (int, UpdateResult, error), reBootstrap func() error) (int, UpdateResult, error) {

	reBootstrapped := false
	var lastRcode int
	var lastUR UpdateResult

	err := retryWithBackoff(maxRetries, initialDelay, func(attempt int) (bool, error) {
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
		case dns.RcodeBadKey:
			if reBootstrapped {
				return true, fmt.Errorf("delegation UPDATE still BADKEY after re-bootstrap")
			}
			if reBootstrap == nil {
				return true, fmt.Errorf("delegation UPDATE got BADKEY and no re-bootstrap action is available")
			}
			lgDns.Warn("sendUpdateWithRetry: BADKEY, re-bootstrapping SIG(0) key once")
			if berr := reBootstrap(); berr != nil {
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
func (zd *ZoneData) SendUpdateWithRetry(msg *dns.Msg, parent string, addrs []string) (int, UpdateResult, error) {
	return sendUpdateWithRetry(delegationSyncMaxRetries, delegationSyncInitialDelay,
		func() (int, UpdateResult, error) {
			return SendUpdate(msg, parent, addrs)
		},
		func() error {
			// Re-bootstrap re-uploads the child's existing active SIG(0) key
			// (algorithm 0 is only consulted when no active key exists, which is
			// not the case for a zone already sending signed delegation UPDATEs).
			// BootstrapSig0KeyWithParent never calls SendUpdateWithRetry, so this
			// cannot recurse.
			_, _, berr := zd.BootstrapSig0KeyWithParent(context.Background(), 0)
			return berr
		})
}
