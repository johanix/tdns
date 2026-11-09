/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"container/heap"
	"sort"
	"sync"
	"time"

	core "github.com/johanix/tdns/v2/core"
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
	// setupFailed: the last try could not even be signed, so nothing was sent.
	setupFailed bool
	// retired: the target is no longer one of the zone's downstreams, or the
	// zone is gone. Set on one with a send in flight; the state is dropped when
	// that send returns.
	retired bool
	// downstream: the state comes from a publish's NOTIFY to the zone's
	// downstreams (Mark), whose request names the whole downstream set. Only
	// such state is retired when a target leaves that set; a NOTIFY an app
	// sent through the queue to a target of its own choosing is not.
	downstream bool
}

// NotifyTracker holds the per-target NOTIFY state and the pending set of
// downstream NOTIFYs. One per daemon, created with the NOTIFY queue; the
// Notifier loop changes it, the API reads it for `zone desc`.
type NotifyTracker struct {
	mu      sync.Mutex
	targets map[notifyKey]*notifyTargetState
	// byZone indexes targets by canonical zone name, so a zone's own state is
	// found without scanning every zone's.
	byZone map[string]map[notifyKey]struct{}
	// schedule orders the scheduled resends by time, so the next one is found
	// without scanning every target. An entry is not removed when its resend
	// is taken, moved or cancelled; one that no longer matches its target's
	// due time is dropped when it reaches the top.
	schedule notifySchedule
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
		byZone:   map[string]map[notifyKey]struct{}{},
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
	if r := validNotifyRetries("authengine", retries); r != nil {
		t.retries = *r
	}
	if d, ok := parseNotifyRetryInterval("authengine", interval); ok {
		t.interval = d
	}
}

// validNotifyRetries returns a notify-retries setting, or nil when it is unset
// or negative. A negative count is logged and ignored, so the next level's
// setting applies, rather than read as "give up after one send".
func validNotifyRetries(where string, retries *int) *int {
	if retries == nil {
		return nil
	}
	if *retries < 0 {
		lgConfig.Error("notify-retries is negative; ignored", "where", where, "value", *retries)
		return nil
	}
	return retries
}

// zoneNotifyRetrySettings resolves a zone's own resend settings from its
// config, for ZoneData's notifyRetries and notifyRetryInterval. Every path
// that builds a zone from config uses it, static and dynamic alike.
func zoneNotifyRetrySettings(zname string, zc *ZoneConf) (*int, time.Duration) {
	where := "zone " + zname
	interval, _ := parseNotifyRetryInterval(where, zc.NotifyRetryInterval)
	return validNotifyRetries(where, zc.NotifyRetries), interval
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
func (t *NotifyTracker) begin(key notifyKey, zd *ZoneData, downstream bool) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.targets[key]
	if st == nil {
		st = &notifyTargetState{}
		t.addLocked(key, st)
	}
	st.zd = zd
	st.retired = false
	st.downstream = downstream
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
// once (a newer version arrived while it was in flight), and with which
// ZoneData: the one the newer version came with, which may have replaced the
// one this send used. A resend after no answer is scheduled instead, and goes
// out through due.
func (t *NotifyTracker) done(key notifyKey, a notifyAttempt, retries int, interval time.Duration, now time.Time) (bool, *ZoneData) {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.targets[key]
	if st == nil {
		return false, nil
	}
	st.inFlight = false
	if st.retired {
		t.deleteLocked(key)
		return false, nil
	}
	st.lastAttempt = now
	st.setupFailed = false
	zone, target, rrtype := key.zone, key.target, dns.TypeToString[key.rrtype]

	switch {
	case a.setupErr != nil:
		// Nothing was sent, and resending would fail the same way.
		st.setupFailed = true
		st.lastError = a.setupErr.Error()
		st.due = time.Time{}
		lgDns.Error("NOTIFY: TSIG sign setup failed, not sending", "zone", zone, "target", target, "err", a.setupErr)

	case a.err != nil:
		st.failures++
		st.lastError = a.err.Error()
		if st.attempts <= retries {
			wait := notifyRetryWait(interval, st.attempts)
			t.scheduleLocked(key, st, now.Add(wait))
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
		return true, st.zd
	}
	return false, nil
}

// notifyRetryWait is the wait before the resend that follows send number
// attempt: interval after the first, doubled after each later one, up to an
// hour -- or up to interval itself, when that is set longer than an hour.
// Doubling stops at that ceiling, so a long retry list cannot overflow.
func notifyRetryWait(interval time.Duration, attempt int) time.Duration {
	if interval <= 0 {
		interval = DefaultNotifyRetryInterval
	}
	ceiling := max(interval, time.Hour)
	wait := interval
	for i := 1; i < attempt && wait < ceiling; i++ {
		wait *= 2
	}
	return min(wait, ceiling)
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
	for t.schedule.Len() > 0 {
		e := t.schedule[0]
		st, live := t.scheduledLocked(e)
		if live && now.Before(e.due) {
			break
		}
		heap.Pop(&t.schedule)
		if !live {
			continue
		}
		st.due = time.Time{}
		st.attempts++
		st.inFlight = true
		out = append(out, notifyDueJob{key: e.key, zd: st.zd})
	}
	return out
}

// nextDue returns the earliest scheduled resend.
func (t *NotifyTracker) nextDue() (time.Time, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for t.schedule.Len() > 0 {
		e := t.schedule[0]
		if _, live := t.scheduledLocked(e); live {
			return e.due, true
		}
		heap.Pop(&t.schedule)
	}
	return time.Time{}, false
}

// notifyScheduled is one scheduled resend.
type notifyScheduled struct {
	due time.Time
	key notifyKey
}

// notifySchedule is a min-heap of scheduled resends, earliest first.
type notifySchedule []notifyScheduled

func (s notifySchedule) Len() int           { return len(s) }
func (s notifySchedule) Less(i, j int) bool { return s[i].due.Before(s[j].due) }
func (s notifySchedule) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s *notifySchedule) Push(x any)        { *s = append(*s, x.(notifyScheduled)) }
func (s *notifySchedule) Pop() any {
	old := *s
	e := old[len(old)-1]
	*s = old[:len(old)-1]
	return e
}

// scheduleLocked sets a target's next resend and enters it in the schedule.
func (t *NotifyTracker) scheduleLocked(key notifyKey, st *notifyTargetState, due time.Time) {
	st.due = due
	heap.Push(&t.schedule, notifyScheduled{due: due, key: key})
}

// scheduledLocked reports whether a schedule entry still stands: its target is
// still tracked, not in flight, and due at exactly that time.
func (t *NotifyTracker) scheduledLocked(e notifyScheduled) (*notifyTargetState, bool) {
	st := t.targets[e.key]
	if st == nil || st.inFlight || !st.due.Equal(e.due) {
		return nil, false
	}
	return st, true
}

func (t *NotifyTracker) addLocked(key notifyKey, st *notifyTargetState) {
	t.targets[key] = st
	z := core.CanonicalizeName(key.zone)
	if t.byZone[z] == nil {
		t.byZone[z] = map[notifyKey]struct{}{}
	}
	t.byZone[z][key] = struct{}{}
}

func (t *NotifyTracker) deleteLocked(key notifyKey) {
	delete(t.targets, key)
	z := core.CanonicalizeName(key.zone)
	delete(t.byZone[z], key)
	if len(t.byZone[z]) == 0 {
		delete(t.byZone, z)
	}
}

// retire drops the zone's downstream state for targets of this NOTIFY type
// that are no longer among its downstreams, so a removed peer is neither resent
// to nor remembered. One with a send in flight is dropped when that send
// returns. targets is the zone's full downstream set, as a publish's request
// carries it; empty when the last downstream was removed.
func (t *NotifyTracker) retire(zone string, rrtype uint16, targets []string) {
	keep := make(map[string]bool, len(targets))
	for _, dst := range targets {
		keep[dst] = true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for key := range t.byZone[core.CanonicalizeName(zone)] {
		st := t.targets[key]
		if key.rrtype != rrtype || keep[key.target] || !st.downstream {
			continue
		}
		if st.inFlight {
			st.retired = true
		} else {
			t.deleteLocked(key)
		}
	}
}

// dropIfRetired reports whether a queued job's target was retired while the
// job waited, and if so drops the target's state: the job is not sent.
func (t *NotifyTracker) dropIfRetired(key notifyKey) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.targets[key]
	if st == nil || !st.retired {
		return false
	}
	t.deleteLocked(key)
	return true
}

// tracks reports whether the tracker holds any state for the zone.
func (t *NotifyTracker) tracks(zone string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.byZone[core.CanonicalizeName(zone)]) > 0
}

// prune releases state nobody needs any more. Two kinds:
//
//   - A zone no longer served, or served by another ZoneData (deleted and
//     added again). Only state at rest goes: a send in flight or a resend
//     still scheduled runs its course, which the retry limit bounds.
//   - A downstream target no longer among the zone's downstreams, as after a
//     reload of its configuration with no publish since. That one goes at
//     once, scheduled resend included; one in flight is retired.
//
// current looks a zone up (Zones.Get; a test may pass its own), and
// downstreams returns a zone's downstream targets. Both are called without
// the tracker's lock held.
func (t *NotifyTracker) prune(current func(zone string) (*ZoneData, bool), downstreams func(zd *ZoneData) []string) int {
	type cand struct {
		key        notifyKey
		zd         *ZoneData
		downstream bool
	}
	t.mu.Lock()
	cands := make([]cand, 0, len(t.targets))
	for key, st := range t.targets {
		cands = append(cands, cand{key, st.zd, st.downstream})
	}
	t.mu.Unlock()

	type verdict struct {
		cand
		removedTarget bool // the zone is current, this target is not
	}
	var gone []verdict
	keep := map[*ZoneData]map[string]bool{}
	for _, c := range cands {
		if zd, ok := current(c.key.zone); !ok || zd != c.zd {
			gone = append(gone, verdict{c, false})
			continue
		}
		if !c.downstream {
			continue
		}
		targets, seen := keep[c.zd]
		if !seen {
			targets = map[string]bool{}
			for _, dst := range downstreams(c.zd) {
				targets[dst] = true
			}
			keep[c.zd] = targets
		}
		if !targets[c.key.target] {
			gone = append(gone, verdict{c, true})
		}
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for _, v := range gone {
		st := t.targets[v.key]
		// Still the same zone data: nothing began a new version for it while
		// the lock was released.
		if st == nil || st.zd != v.zd {
			continue
		}
		switch {
		case v.removedTarget && st.inFlight:
			st.retired = true
		case v.removedTarget, !st.inFlight && st.due.IsZero():
			t.deleteLocked(v.key)
			n++
		}
	}
	return n
}

// NotifyTargetStatus is one row of `zone desc`'s "Downstream notifies" block
// (#528): one target's NOTIFY delivery state.
type NotifyTargetStatus struct {
	Target      string
	RRtype      string
	State       string // "ok", "sending", "retrying", "given up", "cannot sign"
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
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []NotifyTargetStatus
	for key := range t.byZone[core.CanonicalizeName(zone)] {
		st := t.targets[key]
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
		// A retry scheduled for a new version outranks giving up on an old
		// one: the latch is for the log, and stays set until an answer comes.
		switch {
		case st.inFlight:
			s.State = "sending"
		case st.setupFailed:
			s.State = "cannot sign"
		case !st.due.IsZero():
			s.State = "retrying"
		case st.givenUp:
			s.State = "given up"
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
