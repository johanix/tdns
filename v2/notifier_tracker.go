/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"sort"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// NOTIFY resend state, per target (#1007).
//
// RFC 1996 §3.6: a NOTIFY that gets no answer is sent again, until one comes or
// a bounded number of tries runs out. tdns used to send once and move on, so
// one lost packet left a secondary stale until its SOA refresh timer, which
// can be hours.
//
// Only no answer at all counts. A reply of any kind, REFUSED included, ends the
// tries: asking again would get the same reply. A request whose caller waits
// for the answer is not tracked here at all (see Notifier).

const (
	// DefaultNotifyRetries is how many times an unanswered NOTIFY is sent
	// again: RFC 1996 §3.6's suggested maximum of five retransmissions.
	DefaultNotifyRetries = 5
	// DefaultNotifyRetryInterval is the wait before the first resend; each
	// later one waits twice as long (10s, 20s, 40s, 80s, 160s). Shorter than
	// the RFC's suggested flat 60s at the start, so a single lost packet costs
	// seconds rather than a minute, and longer than it towards the end.
	DefaultNotifyRetryInterval = 10 * time.Second
)

type notifyKey struct {
	zone   string
	target string
	rrtype uint16
}

// notifyTargetState is one (zone, target, NOTIFY type)'s delivery state.
type notifyTargetState struct {
	zd *ZoneData
	// attempts counts the sends for the version being notified, the first
	// included. A newer version starts it again.
	attempts int
	// due is when the next resend goes out; zero when none is scheduled.
	due      time.Time
	inFlight bool
	// again: a newer request arrived while a send was in flight. When that
	// send returns, the newer one goes out at once, from attempt one.
	again       bool
	lastAttempt time.Time
	lastSuccess time.Time
	lastRcode   int
	lastError   string
	// failures counts consecutive sends that got no answer.
	failures int
	// givenUp is set when the tries ran out, and cleared by the next answer.
	// While set, a new version is still tried in full, but giving up again is
	// not logged again: the log gets the edges, not the steady state (#528).
	givenUp bool
}

// NotifyTracker holds the per-target NOTIFY state and the pending set of
// downstream NOTIFYs. One per daemon, created with the NOTIFY queue; the
// Notifier loop changes it, the API reads it for `zone desc`.
type NotifyTracker struct {
	mu      sync.Mutex
	targets map[notifyKey]*notifyTargetState
	// pending holds the latest downstream NOTIFY per zone, not yet taken by
	// the Notifier. Mark replaces; the Notifier takes them all on wake.
	pending map[string]NotifyRequest
	wake    chan struct{}

	// The server-wide resend settings (authengine), resolved when the
	// Notifier starts. A zone's own settings override them.
	retries  int
	interval time.Duration
}

func NewNotifyTracker() *NotifyTracker {
	return &NotifyTracker{
		targets:  map[notifyKey]*notifyTargetState{},
		pending:  map[string]NotifyRequest{},
		wake:     make(chan struct{}, 1),
		retries:  DefaultNotifyRetries,
		interval: DefaultNotifyRetryInterval,
	}
}

// setDefaults resolves the server-wide settings: nil and "" keep the defaults.
func (t *NotifyTracker) setDefaults(retries *int, interval string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if retries != nil && *retries >= 0 {
		t.retries = *retries
	}
	if d, ok := parseNotifyRetryInterval("authengine", interval); ok {
		t.interval = d
	}
}

// parseNotifyRetryInterval parses a notify-retry-interval setting. Empty is not
// set; a value that is not a positive duration is logged and ignored.
func parseNotifyRetryInterval(where, s string) (time.Duration, bool) {
	if s == "" {
		return 0, false
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		lgConfig.Error("notify-retry-interval is not a positive duration; ignored", "where", where, "value", s)
		return 0, false
	}
	return d, true
}

// notifyRetryPolicy returns the zone's resend settings: its own where set, the
// server's otherwise. Takes zd.mu, so never call it holding the tracker's lock
// (notifyIfServableLocked holds zd.mu when it calls Mark, which takes it).
func notifyRetryPolicy(zd *ZoneData, t *NotifyTracker) (int, time.Duration) {
	t.mu.Lock()
	retries, interval := t.retries, t.interval
	t.mu.Unlock()
	zd.mu.Lock()
	defer zd.mu.Unlock()
	if zd.notifyRetries != nil {
		retries = *zd.notifyRetries
	}
	if zd.notifyRetryInterval > 0 {
		interval = zd.notifyRetryInterval
	}
	return retries, interval
}

// Mark queues a downstream NOTIFY for the zone, replacing one the Notifier has
// not taken yet: a burst of publishes becomes one NOTIFY carrying the latest
// SOA. It never blocks and never drops, which is why publishes use it instead
// of the queue -- a full queue used to drop the NOTIFY, and a dropped NOTIFY is
// one that is never resent.
func (t *NotifyTracker) Mark(req NotifyRequest) {
	t.mu.Lock()
	t.pending[req.ZoneName] = req
	t.mu.Unlock()
	select {
	case t.wake <- struct{}{}:
	default:
	}
}

func (t *NotifyTracker) takePending() []NotifyRequest {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.pending) == 0 {
		return nil
	}
	out := make([]NotifyRequest, 0, len(t.pending))
	for _, req := range t.pending {
		out = append(out, req)
	}
	t.pending = map[string]NotifyRequest{}
	return out
}

// begin starts a new version's sends to one target, and reports whether to
// send now. A send already in flight is left to finish; the new version goes
// out when it returns.
func (t *NotifyTracker) begin(key notifyKey, zd *ZoneData) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.targets[key]
	if st == nil {
		st = &notifyTargetState{}
		t.targets[key] = st
	}
	st.zd = zd
	if st.inFlight {
		st.again = true
		return false
	}
	st.attempts = 1
	st.due = time.Time{}
	st.inFlight = true
	return true
}

// done records the outcome of one send and reports whether to send again at
// once (a newer version arrived while it was in flight). A resend after no
// answer is scheduled instead, and goes out through due.
func (t *NotifyTracker) done(key notifyKey, a notifyAttempt, retries int, interval time.Duration, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.targets[key]
	if st == nil {
		return false
	}
	st.inFlight = false
	st.lastAttempt = now
	zone, target, rrtype := key.zone, key.target, dns.TypeToString[key.rrtype]

	switch {
	case a.setupErr != nil:
		// Nothing was sent, and resending would fail the same way.
		st.lastError = a.setupErr.Error()
		st.due = time.Time{}
		lgDns.Error("NOTIFY: TSIG sign setup failed, not sending", "zone", zone, "target", target, "err", a.setupErr)

	case a.err != nil:
		st.failures++
		st.lastError = a.err.Error()
		if st.attempts <= retries {
			wait := interval << (st.attempts - 1)
			if wait <= 0 || wait > time.Hour {
				wait = time.Hour // a long retry list must not overflow the shift
			}
			st.due = now.Add(wait)
			lgDns.Debug("NOTIFY: no answer; sending again later", "zone", zone, "type", rrtype, "target", target,
				"attempt", st.attempts, "of", retries+1, "in", wait, "err", a.err)
		} else {
			st.due = time.Time{}
			if !st.givenUp {
				st.givenUp = true
				lgDns.Warn("NOTIFY: no answer after every try; giving up until the next change", "zone", zone,
					"type", rrtype, "target", target, "attempts", st.attempts, "err", a.err)
			}
		}

	default:
		if st.givenUp {
			lgDns.Info("NOTIFY: target answers again", "zone", zone, "type", rrtype, "target", target)
		}
		st.givenUp = false
		st.failures = 0
		st.lastSuccess = now
		st.lastRcode = a.rcode
		st.lastError = ""
		st.due = time.Time{}
		if a.rcode != dns.RcodeSuccess {
			st.lastError = dns.RcodeToString[a.rcode]
			lgDns.Warn("NOTIFY: bad rcode from target", "zone", zone, "type", rrtype, "target", target,
				"rcode", dns.RcodeToString[a.rcode])
		} else {
			lgDns.Debug("NOTIFY: got NOERROR back", "zone", zone, "type", rrtype, "target", target, "tcp", a.overTCP)
		}
	}

	if st.again {
		st.again = false
		st.attempts = 1
		st.due = time.Time{}
		st.inFlight = true
		return true
	}
	return false
}

type notifyDueJob struct {
	key notifyKey
	zd  *ZoneData
}

// due takes every resend whose time has come, marking it in flight.
func (t *NotifyTracker) due(now time.Time) []notifyDueJob {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []notifyDueJob
	for key, st := range t.targets {
		if st.inFlight || st.due.IsZero() || now.Before(st.due) {
			continue
		}
		st.due = time.Time{}
		st.attempts++
		st.inFlight = true
		out = append(out, notifyDueJob{key: key, zd: st.zd})
	}
	return out
}

// nextDue returns the earliest scheduled resend.
func (t *NotifyTracker) nextDue() (time.Time, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	var next time.Time
	found := false
	for _, st := range t.targets {
		if st.inFlight || st.due.IsZero() {
			continue
		}
		if !found || st.due.Before(next) {
			next, found = st.due, true
		}
	}
	return next, found
}

// NotifyTargetStatus is one row of `zone desc`'s "Downstream notifies" block
// (#528): one target's NOTIFY delivery state.
type NotifyTargetStatus struct {
	Target      string
	RRtype      string
	State       string // "ok", "sending", "retrying", "given up"
	Attempts    int    // sends for the version being notified
	Failures    int    // consecutive sends without an answer
	LastAttempt time.Time
	LastSuccess time.Time
	NextAttempt time.Time
	LastError   string
}

// Status returns the zone's per-target NOTIFY state, sorted by type and target.
func (t *NotifyTracker) Status(zone string) []NotifyTargetStatus {
	if t == nil {
		return nil
	}
	zone = dns.Fqdn(zone)
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []NotifyTargetStatus
	for key, st := range t.targets {
		if !equalFoldFqdn(key.zone, zone) {
			continue
		}
		s := NotifyTargetStatus{
			Target:      key.target,
			RRtype:      dns.TypeToString[key.rrtype],
			Attempts:    st.attempts,
			Failures:    st.failures,
			LastAttempt: st.lastAttempt,
			LastSuccess: st.lastSuccess,
			NextAttempt: st.due,
			LastError:   st.lastError,
		}
		switch {
		case st.inFlight:
			s.State = "sending"
		case st.givenUp:
			s.State = "given up"
		case !st.due.IsZero():
			s.State = "retrying"
		default:
			s.State = "ok"
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RRtype != out[j].RRtype {
			return out[i].RRtype > out[j].RRtype // SOA first
		}
		return out[i].Target < out[j].Target
	})
	return out
}

func equalFoldFqdn(a, b string) bool {
	return len(a) == len(b) && dns.CanonicalName(a) == dns.CanonicalName(b)
}
