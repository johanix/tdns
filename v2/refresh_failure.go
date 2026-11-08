/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

// A failed refresh logs ONE ERROR, at noteRefreshFailure. The lines that used
// to say the same thing beside it -- DoTransfer's and fetchFromUpstream's
// "failed on all upstreams" and Refresh's "FetchZone failed" -- are DEBUG, so
// that one line has to carry all they did, and it carries more: each upstream
// with its own error, where they named the addresses and the last error only.
//
// It is read by its fields, not its text. Every refresh failure now shares one
// file:line, so a matcher keyed on the message would let an ACL refusal pass as
// a stopped primary. stage and kind are what tell them apart.

// Where in a refresh it failed.
const (
	refreshStageProbe    = "probe"    // no upstream answered the SOA probe
	refreshStageTransfer = "transfer" // a probe answered; no upstream gave the zone
	refreshStageFile     = "file"     // a primary's zone file
	refreshStageOther    = "other"    // anything else: the apply, the gate, no upstreams
)

// The kinds refreshErrorKind does not derive from an error's type.
const (
	refreshKindConfig = "config" // the peer's TLS or TSIG config could not be resolved
	refreshKindMixed  = "mixed"  // the upstreams failed in different ways
)

// upstreamFailure is one upstream's part in a refresh that failed on all of
// them.
type upstreamFailure struct {
	addr string
	err  error
	kind string
}

func newUpstreamFailure(addr string, err error) upstreamFailure {
	return upstreamFailure{addr: addr, err: err, kind: refreshErrorKind(err)}
}

// upstreamsFailedError is a refresh that failed on every upstream it tried.
// Its text and its chain are exactly the error the refresh returned before,
// which is what RefreshError shows and what errors.Is walks; what it adds is
// each upstream's own error.
type upstreamsFailedError struct {
	stage    string
	failures []upstreamFailure
	err      error
}

func (e *upstreamsFailedError) Error() string { return e.err.Error() }
func (e *upstreamsFailedError) Unwrap() error { return e.err }

// refreshStageError carries the stage of a failure that is not an upstream's:
// a primary's zone file that could not be read. Same text and chain as err.
type refreshStageError struct {
	stage string
	err   error
}

func (e *refreshStageError) Error() string { return e.err.Error() }
func (e *refreshStageError) Unwrap() error { return e.err }

// peerConfigError is a peer whose TLS or TSIG configuration could not be
// resolved, at the probe or at the transfer. Same text and chain as err; the
// type is what makes its kind config.
type peerConfigError struct{ err error }

func (e *peerConfigError) Error() string { return e.err.Error() }
func (e *peerConfigError) Unwrap() error { return e.err }

// kind is the upstreams' common kind, or mixed.
func (e *upstreamsFailedError) kind() string {
	kind := ""
	for _, f := range e.failures {
		switch kind {
		case "":
			kind = f.kind
		case f.kind:
		default:
			return refreshKindMixed
		}
	}
	return kind
}

// upstreams is "addr=kind,addr=kind": no spaces, so a matcher can take it as
// one field.
func (e *upstreamsFailedError) upstreams() string {
	parts := make([]string, 0, len(e.failures))
	for _, f := range e.failures {
		parts = append(parts, f.addr+"="+f.kind)
	}
	return strings.Join(parts, ",")
}

// upstreamErrors is "addr: error | addr: error".
func (e *upstreamsFailedError) upstreamErrors() string {
	parts := make([]string, 0, len(e.failures))
	for _, f := range e.failures {
		parts = append(parts, f.addr+": "+f.err.Error())
	}
	return strings.Join(parts, " | ")
}

// refreshErrorKind names what kind of failure err is, from its type and never
// from its text: config, timeout, connrefused, unreachable, closed, reset,
// eof, tls, tsig, the rcode an upstream answered a transfer with in lower case
// (servfail, refused, notauth, ...), and other.
//
// No mapping of a closed connection to a timeout: exchangeCancellable closes
// the connection when a probe's deadline passes, so some timeouts read as
// closed. That mapping belongs to the rate-limit that needs a stable kind.
func refreshErrorKind(err error) string {
	var cfgErr *peerConfigError
	var rcErr *xfrRcodeError
	var netErr net.Error
	switch {
	case errors.As(err, &cfgErr):
		return refreshKindConfig
	case errors.As(err, &rcErr):
		if name := dns.RcodeToString[rcErr.rcode]; name != "" {
			return strings.ToLower(name)
		}
		return "rcode"
	case isTsigError(err):
		return "tsig"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connrefused"
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		return "unreachable"
	case errors.Is(err, net.ErrClosed):
		return "closed"
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE):
		return "reset"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "eof"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded),
		errors.As(err, &netErr) && netErr.Timeout():
		return "timeout"
	case isTLSError(err):
		return "tls"
	}
	return "other"
}

func isTsigError(err error) bool {
	for _, e := range []error{dns.ErrSig, dns.ErrTime, dns.ErrKeyAlg, dns.ErrSecret, dns.ErrAuth, dns.ErrNoSig} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

func isTLSError(err error) bool {
	var certErr *tls.CertificateVerificationError
	var recErr tls.RecordHeaderError
	var alertErr tls.AlertError
	var authErr x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var invalidErr x509.CertificateInvalidError
	return errors.As(err, &certErr) || errors.As(err, &recErr) || errors.As(err, &alertErr) ||
		errors.As(err, &authErr) || errors.As(err, &hostErr) || errors.As(err, &invalidErr)
}

// refreshFailureAttrs are the fields of the one ERROR a failed refresh logs.
// zone first, the fields a matcher keys on next, and the two free-text fields
// last, since the log format does not quote values. The stage comes with the
// error, never from the zone's type: a primary that read its file and then
// failed to apply it did not fail at the file.
func refreshFailureAttrs(zone string, err error, attempts int, since time.Time) []any {
	stage, kind := refreshStageOther, refreshErrorKind(err)
	var upstreams, upstreamErrors string
	var uf *upstreamsFailedError
	var se *refreshStageError
	if errors.As(err, &uf) {
		stage, kind = uf.stage, uf.kind()
		upstreams, upstreamErrors = uf.upstreams(), uf.upstreamErrors()
	} else if errors.As(err, &se) {
		stage = se.stage
	}
	attrs := []any{"zone", zone, "stage", stage, "kind", kind}
	if upstreams != "" {
		attrs = append(attrs, "upstreams", upstreams)
	}
	attrs = append(attrs, "attempts", attempts, "since", since.UTC().Format(time.RFC3339), "error", err)
	if upstreamErrors != "" {
		attrs = append(attrs, "upstream_errors", upstreamErrors)
	}
	return attrs
}

// refreshRunState is a zone's run of failed refreshes and, apart from it, its
// run of deferred ones. The failure run is what lets the one ERROR say how long
// the zone has been failing: RefreshError cannot, because the first-load retry
// clears it before every attempt. The deferral run is what lets a deferral
// that does not end reach ERROR (noteRefreshDeferral).
//
// In memory and per ZoneData. Its own mutex rather than zd.mu: it is written
// from the pool's workers and from the engine goroutine, and nothing else needs
// to agree with it.
type refreshRunState struct {
	mu            sync.Mutex
	failures      int
	failingSince  time.Time
	deferrals     int
	deferredSince time.Time
	// escalated: this deferral run has logged at ERROR, at escalatedAt last.
	escalated   bool
	escalatedAt time.Time
}

// refreshStagedErrorAfter is how many deferrals in a row a staged change may
// cause before they are logged at ERROR, unless txHoldLimit comes first.
// Nothing bounds ErrRefreshStaged: the change waits for a pass that can
// publish it, and until then the zone takes no refresh at all. At the 5 s
// retry (refreshHeldRetrySeconds) the two bounds are about the same.
const refreshStagedErrorAfter = 6

// refreshDeferralReminder is how often a deferral run already at ERROR says so
// again. The deferrals in between stay in the log, at WARN.
const refreshDeferralReminder = 5 * time.Minute

// refreshDeferralOverdue reports whether a run of n deferrals, held for that
// long, has gone on longer than a deferral can for a healthy zone.
//
// A staged change: N deferrals or the hold limit. An open transaction: only
// past txHoldAgeCap, the longest a hold can keep a published zone. Not by
// count, because a legitimate hold is retried about six times within its
// limit.
func refreshDeferralOverdue(err error, n int, held time.Duration) bool {
	if errors.Is(err, ErrRefreshStaged) {
		return n >= refreshStagedErrorAfter || held > txHoldLimit
	}
	return held > txHoldAgeCap
}

// noteRefreshDeferral logs one deferred refresh. INFO while the deferral is
// one a healthy zone has; ERROR once it is overdue, and again every
// refreshDeferralReminder; WARN for the deferrals in between.
func noteRefreshDeferral(zd *ZoneData, zone string, err error) {
	now := time.Now()
	r := &zd.refreshRun
	r.mu.Lock()
	if r.deferrals == 0 {
		r.deferredSince = now
	}
	r.deferrals++
	n, since := r.deferrals, r.deferredSince
	level := slog.LevelInfo
	switch {
	case !r.escalated && refreshDeferralOverdue(err, n, now.Sub(since)):
		r.escalated, r.escalatedAt = true, now
		level = slog.LevelError
	case r.escalated && now.Sub(r.escalatedAt) >= refreshDeferralReminder:
		r.escalatedAt = now
		level = slog.LevelError
	case r.escalated:
		level = slog.LevelWarn
	}
	r.mu.Unlock()

	msg := "zone refresh deferred"
	if level == slog.LevelError {
		msg = "zone refresh deferred too long; the zone is taking no refreshes"
	}
	lgEngine.Log(context.Background(), level, msg, "zone", zone, "deferrals", n,
		"since", since.UTC().Format(time.RFC3339), "reason", err)
}

// endRefreshDeferral closes a deferral run. One that reached ERROR says it has
// ended, with its totals.
func endRefreshDeferral(zd *ZoneData, zone string) {
	r := &zd.refreshRun
	r.mu.Lock()
	n, since, escalated := r.deferrals, r.deferredSince, r.escalated
	r.deferrals, r.deferredSince, r.escalated, r.escalatedAt = 0, time.Time{}, false, time.Time{}
	r.mu.Unlock()
	if escalated {
		lgEngine.Warn("zone refresh no longer deferred", "zone", zone, "deferrals", n,
			"since", since.UTC().Format(time.RFC3339))
	}
}

// noteFailed counts a failed refresh and returns the run so far.
func (r *refreshRunState) noteFailed(now time.Time) (attempts int, since time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failures == 0 {
		r.failingSince = now
	}
	r.failures++
	return r.failures, r.failingSince
}

// refreshConfirmed reports whether a refresh that returned no error proves the
// zone healthy, which is what may end its runs. A primary's does: it read its
// file. A secondary's only if it saw a usable SOA. When every primary answers
// REFUSED or SERVFAIL the refresh returns no error either (DoTransfer's quiet
// back-off), and that proves nothing. noteSuccessfulRefresh stamps
// LatestRefresh on exactly the usable SOAs, so a stamp that moved is the proof.
func refreshConfirmed(zd *ZoneData, stampBefore time.Time) bool {
	return zd.ZoneType != Secondary || !zd.lastRefresh().Equal(stampBefore)
}

// noteRefreshSuccess closes both runs after a refresh that succeeded.
func noteRefreshSuccess(zd *ZoneData, zone string) {
	endRefreshDeferral(zd, zone)
	r := &zd.refreshRun
	r.mu.Lock()
	n, since := r.failures, r.failingSince
	r.failures, r.failingSince = 0, time.Time{}
	r.mu.Unlock()
	if n > 0 {
		lgEngine.Info("zone refresh recovered", "zone", zone, "failed_attempts", n,
			"since", since.UTC().Format(time.RFC3339))
	}
}
