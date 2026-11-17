/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	core "github.com/johanix/tdns/v2/core"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// The delegation-sync log answers the question a parent's operator is asked
// when a child says "I sent the change, and nothing happened": what did the
// parent receive, by which mechanism, and what did it do with it. One event is
// recorded per UPDATE from a child, per scan a NOTIFY started, per scan a poll
// started that found something, per NOTIFY refused before any scan, and per
// DSYNC API write. Events are rare -- never one per query -- and are kept in
// one bounded ring for the whole server, in memory only.

// DefaultSyncLogSize is childsync.sync-log when it is not set: the log is on by
// default. 0 turns it off.
const DefaultSyncLogSize = 10000

// Mechanisms: how the change reached the parent.
const (
	SyncMechUpdate      = "UPDATE"
	SyncMechUpdateKey   = "UPDATE(KEY)" // child key material for the truststore
	SyncMechNotifyCDS   = "NOTIFY(CDS)"
	SyncMechNotifyCSYNC = "NOTIFY(CSYNC)"
	SyncMechScanCDS     = "scan(CDS)"
	SyncMechScanCSYNC   = "scan(CSYNC)"
	SyncMechAPI         = "API"
)

// Outcomes. "applied" means the parent's data changed and nothing else: a scan
// that decided on a change is "queued" or "apply failed" until the change has
// actually landed.
const (
	SyncApplied       = "applied"
	SyncApplyFailed   = "apply failed"
	SyncQueued        = "queued"
	SyncNoChange      = "no change"
	SyncNotProcessed  = "not processed"
	SyncRefused       = "refused"
	SyncOutcomeUnsure = "unknown"
)

// SyncLogEvent is one thing that happened to a child's delegation at the parent.
type SyncLogEvent struct {
	Time      time.Time `json:"time"`
	Parent    string    `json:"parent,omitempty"`
	Child     string    `json:"child"`
	Mechanism string    `json:"mechanism"`
	Outcome   string    `json:"outcome"`
	Changes   string    `json:"changes,omitempty"`
	Rcode     string    `json:"rcode,omitempty"`
	EDE       string    `json:"ede,omitempty"`
	Reason    string    `json:"reason,omitempty"`
}

// SyncLogQuery selects events. Empty fields match everything; Limit 0 means
// all.
type SyncLogQuery struct {
	Parent string
	Child  string
	Since  time.Time
	Limit  int
}

// SyncLogReport is what the log returns: the events that matched, newest
// first, and enough about the log itself to read a gap correctly.
type SyncLogReport struct {
	Enabled bool           `json:"enabled"`
	Size    int            `json:"size"`
	Since   time.Time      `json:"since"`   // when this log started
	Dropped uint64         `json:"dropped"` // events overwritten because the ring was full
	Events  []SyncLogEvent `json:"events"`
}

// DelegationSyncLog is the ring. It grows as events arrive, up to size, and
// then overwrites the oldest: a server that never syncs a delegation keeps
// nothing.
type DelegationSyncLog struct {
	mu      sync.Mutex
	size    int
	events  []SyncLogEvent
	next    int // the oldest event, once the ring is full
	since   time.Time
	dropped uint64

	// lastPoll remembers the last poll result recorded per child and scan
	// type, so that a poll repeating the same refusal every round is recorded
	// once an hour rather than every 90 seconds (see AddPoll).
	lastPoll map[string]pollMemo
}

type pollMemo struct {
	key string
	at  time.Time
}

// pollRepeatInterval is how often an unchanged poll result is recorded again.
const pollRepeatInterval = time.Hour

// maxPollMemo bounds lastPoll. It is cleared when it would grow past this,
// which at worst records a repeated result once more.
const maxPollMemo = 4096

func newDelegationSyncLog(size int) *DelegationSyncLog {
	return &DelegationSyncLog{size: size, since: time.Now(), lastPoll: map[string]pollMemo{}}
}

var syncLogPtr atomic.Pointer[DelegationSyncLog]

// syncLog is the server's delegation-sync log, or nil when it is off. Every
// method is safe on nil, so a hook is simply syncLog().Add(ev).
func syncLog() *DelegationSyncLog { return syncLogPtr.Load() }

// installSyncLog sets the log's size from childsync.sync-log. 0 turns it off. A
// changed size starts a new ring that keeps the newest events of the old one.
func installSyncLog(size int) {
	if size <= 0 {
		syncLogPtr.Store(nil)
		return
	}
	cur := syncLogPtr.Load()
	if cur != nil && cur.size == size {
		return
	}
	nl := newDelegationSyncLog(size)
	if cur != nil {
		old := cur.Query(SyncLogQuery{})
		nl.since = old.Since
		nl.dropped = old.Dropped
		for i := len(old.Events) - 1; i >= 0; i-- { // oldest first
			nl.Add(old.Events[i])
		}
	}
	syncLogPtr.Store(nl)
}

// Add records ev. A zero Time is set to now.
func (l *DelegationSyncLog) Add(ev SyncLogEvent) {
	if l == nil {
		return
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.addLocked(ev)
}

func (l *DelegationSyncLog) addLocked(ev SyncLogEvent) {
	if len(l.events) < l.size {
		l.events = append(l.events, ev)
		return
	}
	l.events[l.next] = ev
	l.next = (l.next + 1) % l.size
	l.dropped++
}

// AddPoll records the result of a scan a poll started. A poll that finds
// nothing to do is not recorded at all -- with many children that would be
// most of the log -- and a result that repeats the last one recorded for the
// same child and scan type is recorded again only after pollRepeatInterval.
// Changes are always recorded.
func (l *DelegationSyncLog) AddPoll(ev SyncLogEvent) {
	if l == nil || ev.Outcome == SyncNoChange {
		return
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if ev.Outcome == SyncNotProcessed {
		child := dns.CanonicalName(ev.Child) + "|" + ev.Mechanism
		key := ev.Reason
		if m, ok := l.lastPoll[child]; ok && m.key == key && ev.Time.Sub(m.at) < pollRepeatInterval {
			return
		}
		if len(l.lastPoll) >= maxPollMemo {
			l.lastPoll = map[string]pollMemo{}
		}
		l.lastPoll[child] = pollMemo{key: key, at: ev.Time}
	}
	l.addLocked(ev)
}

// Query returns the events matching q, newest first.
func (l *DelegationSyncLog) Query(q SyncLogQuery) SyncLogReport {
	if l == nil {
		return SyncLogReport{}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	rep := SyncLogReport{Enabled: true, Size: l.size, Since: l.since, Dropped: l.dropped}
	n := len(l.events)
	for i := 0; i < n; i++ {
		// Newest first: the newest event is just before next once the ring
		// is full, and the last one appended until then.
		ev := l.events[(l.next-1-i+2*n)%n]
		if q.Parent != "" && !sameSyncLogName(ev.Parent, q.Parent) {
			continue
		}
		if q.Child != "" && !sameSyncLogName(ev.Child, q.Child) {
			continue
		}
		if !q.Since.IsZero() && ev.Time.Before(q.Since) {
			continue
		}
		rep.Events = append(rep.Events, ev)
		if q.Limit > 0 && len(rep.Events) >= q.Limit {
			break
		}
	}
	return rep
}

// sameSyncLogName compares two names as DNS names: case-insensitively, with or
// without the final dot.
func sameSyncLogName(a, b string) bool {
	return core.EqualNames(dns.Fqdn(a), dns.Fqdn(b))
}

// syncLogChangeCounts formats adds and removes by kind, leaving out kinds with
// neither: "ds +1 -1, ns +1 -0".
type syncLogChangeCounts struct {
	kinds []string
	adds  map[string]int
	rems  map[string]int
}

func newSyncLogChangeCounts() *syncLogChangeCounts {
	return &syncLogChangeCounts{adds: map[string]int{}, rems: map[string]int{}}
}

func (c *syncLogChangeCounts) note(kind string, add bool, n int) {
	if n == 0 {
		return
	}
	if c.adds[kind] == 0 && c.rems[kind] == 0 {
		c.kinds = append(c.kinds, kind)
	}
	if add {
		c.adds[kind] += n
	} else {
		c.rems[kind] += n
	}
}

func (c *syncLogChangeCounts) String() string {
	parts := make([]string, 0, len(c.kinds))
	for _, k := range c.kinds {
		parts = append(parts, fmt.Sprintf("%s +%d -%d", k, c.adds[k], c.rems[k]))
	}
	return strings.Join(parts, ", ")
}

// syncLogKind is the column an RR type is counted under.
func syncLogKind(rrtype uint16) string {
	switch rrtype {
	case dns.TypeDS:
		return "ds"
	case dns.TypeNS:
		return "ns"
	case dns.TypeA, dns.TypeAAAA:
		return "glue"
	case dns.TypeKEY:
		return "key"
	default:
		return strings.ToLower(dns.TypeToString[rrtype])
	}
}

// syncLogUpdateChanges counts an UPDATE's update section: a record in class
// INET is an add, NONE or ANY a removal.
func syncLogUpdateChanges(ns []dns.RR) string {
	c := newSyncLogChangeCounts()
	for _, rr := range ns {
		c.note(syncLogKind(rr.Header().Rrtype), rr.Header().Class == dns.ClassINET, 1)
	}
	return c.String()
}

// syncLogScanChanges counts what a scan found.
func syncLogScanChanges(resp ScanTupleResponse) string {
	c := newSyncLogChangeCounts()
	c.note("ds", true, len(resp.DSAdds))
	c.note("ds", false, len(resp.DSRemoves))
	c.note("ns", true, len(resp.NSAdds))
	c.note("ns", false, len(resp.NSRemoves))
	c.note("glue", true, len(resp.GlueAdds))
	c.note("glue", false, len(resp.GlueRemoves))
	return c.String()
}

// syncLogEDE names an EDE code for the log.
func syncLogEDE(code uint16) string {
	if code == 0 {
		return ""
	}
	if s, ok := edns0.EDEToString(code); ok {
		return fmt.Sprintf("%d (%s)", code, s)
	}
	return fmt.Sprintf("%d", code)
}

// syncLogResponseEDE is the first EDE in m, formatted for the log.
func syncLogResponseEDE(m *dns.Msg) string {
	if m == nil {
		return ""
	}
	opt := m.IsEdns0()
	if opt == nil {
		return ""
	}
	for _, o := range opt.Option {
		if e, ok := o.(*dns.EDNS0_EDE); ok {
			s := syncLogEDE(e.InfoCode)
			if e.ExtraText != "" {
				s += ": " + e.ExtraText
			}
			return s
		}
	}
	return ""
}

// scanMechanism names the mechanism of a scan: a poll, or a NOTIFY.
func scanMechanism(scanType ScanType, polled bool) string {
	switch {
	case scanType == ScanCDS && polled:
		return SyncMechScanCDS
	case scanType == ScanCDS:
		return SyncMechNotifyCDS
	case polled:
		return SyncMechScanCSYNC
	default:
		return SyncMechNotifyCSYNC
	}
}

// scanSyncLogEvent is the event for what a scan decided, before any change it
// found has been applied: the caller settles the outcome of a change.
func scanSyncLogEvent(parent *ZoneData, scanType ScanType, resp ScanTupleResponse, polled bool) SyncLogEvent {
	ev := SyncLogEvent{
		Parent:    parent.ZoneName,
		Child:     resp.Qname,
		Mechanism: scanMechanism(scanType, polled),
	}
	switch {
	case resp.Error && resp.ErrorMsg == errCsyncNotImmediate.Error():
		// Not acted on by design, but exactly what an operator looks for
		// when a child's CSYNC is ignored.
		ev.Outcome = SyncNotProcessed
		ev.Reason = resp.ErrorMsg
	case resp.Error:
		ev.Outcome = SyncNotProcessed
		ev.Reason = resp.ErrorMsg
	case scanResponseChangesDelegation(resp):
		ev.Outcome = SyncQueued
		ev.Changes = syncLogScanChanges(resp)
		ev.Reason = resp.ValidationReason
	default:
		ev.Outcome = SyncNoChange
	}
	if len(resp.GlueSkipped) > 0 {
		skipped := "glue skipped: " + strings.Join(resp.GlueSkipped, "; ")
		if ev.Reason == "" {
			ev.Reason = skipped
		} else {
			ev.Reason += "; " + skipped
		}
	}
	return ev
}

// recordScan records a scan's event: a NOTIFY-started scan always, a poll
// through AddPoll.
func recordScan(ev SyncLogEvent, polled bool) {
	if polled {
		syncLog().AddPoll(ev)
		return
	}
	syncLog().Add(ev)
}

// recordNotifyRefusal records a NOTIFY(CDS) or NOTIFY(CSYNC) that was refused
// before any scan started. A NOTIFY that starts a scan is recorded by the scan.
func recordNotifyRefusal(ntype uint16, parent, child string, rcode int, ede uint16, reason string) {
	mech := SyncMechNotifyCSYNC
	if ntype == dns.TypeCDS {
		mech = SyncMechNotifyCDS
	}
	syncLog().Add(SyncLogEvent{
		Parent:    parent,
		Child:     child,
		Mechanism: mech,
		Outcome:   SyncRefused,
		Rcode:     dns.RcodeToString[rcode],
		EDE:       syncLogEDE(ede),
		Reason:    reason,
	})
}

// syncLogUpdateWriter records the answer to an UPDATE from a child, whenever it
// is written: a refusal at once, an approved update only after it has been
// applied, possibly from another goroutine. UpdateResponder sets child and
// mechanism once it has classified the update; an update that is not a child's
// is not recorded.
type syncLogUpdateWriter struct {
	dns.ResponseWriter
	parent    string
	child     string
	mechanism string
	changes   string
	once      sync.Once
}

// setChild marks the update as a child's, and so as one to record.
func (w *syncLogUpdateWriter) setChild(parent, child, mechanism string, ns []dns.RR) {
	w.parent, w.child, w.mechanism = parent, child, mechanism
	w.changes = syncLogUpdateChanges(ns)
}

// Unwrap gives the writer underneath, for code that looks for the connection's
// TLS state (connectionState).
func (w *syncLogUpdateWriter) Unwrap() dns.ResponseWriter { return w.ResponseWriter }

func (w *syncLogUpdateWriter) WriteMsg(m *dns.Msg) error {
	if w.child != "" && m != nil {
		w.once.Do(func() {
			ev := SyncLogEvent{
				Parent:    w.parent,
				Child:     w.child,
				Mechanism: w.mechanism,
				Changes:   w.changes,
				Rcode:     dns.RcodeToString[m.Rcode],
				EDE:       syncLogResponseEDE(m),
			}
			switch m.Rcode {
			case dns.RcodeSuccess:
				ev.Outcome = SyncApplied
			case dns.RcodeServerFailure:
				ev.Outcome = SyncApplyFailed
			default:
				ev.Outcome = SyncRefused
			}
			syncLog().Add(ev)
		})
	}
	return w.ResponseWriter.WriteMsg(m)
}

// delegationSyncLogReport answers the /delegation "sync-log" command. The error
// string is empty on success.
func delegationSyncLogReport(dp DelegationPost) (*SyncLogReport, string) {
	l := syncLog()
	if l == nil {
		return nil, "the delegation-sync log is off (childsync.sync-log: 0)"
	}
	q := SyncLogQuery{Limit: dp.Limit}
	if z := strings.TrimSpace(dp.Zone); z != "" {
		q.Parent = dns.Fqdn(z)
	}
	if c := strings.TrimSpace(dp.Child); c != "" {
		q.Child = dns.Fqdn(c)
	}
	if s := strings.TrimSpace(dp.Since); s != "" {
		if d, err := time.ParseDuration(s); err == nil {
			q.Since = time.Now().Add(-d)
		} else if t, err := time.Parse(time.RFC3339, s); err == nil {
			q.Since = t
		} else {
			return nil, fmt.Sprintf("since %q is neither a duration (10m) nor an RFC 3339 time", s)
		}
	}
	rep := l.Query(q)
	return &rep, ""
}
