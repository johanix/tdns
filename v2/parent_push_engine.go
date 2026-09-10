/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// ParentPushEngine is the childsync-proxy's outbound half: it takes what the
// store says a delegation should be, and what the served parent zone says it
// is, and pushes the difference to the parent primary through the zone's
// writer. The same for the agent's own DSYNC advertisement.
//
// It exists because acceptance is decoupled from publication (design D-2):
// ApplyChildUpdate records the child's intent and returns, the child hears
// NOERROR, and delivery happens here -- off the ZoneUpdater goroutine, which
// serves every zone on the server and must never wait on a primary.
//
// A request names WHAT to reconcile, never what to send. The delta is
// recomputed at push time from the store and the served zone, so a request
// is idempotent, several for one child collapse into one push, and a request
// that was dropped on a full queue is recovered by the next refresh, which
// re-derives the same delta (§5.4, §5.5, amendment A-2).
//
// One worker per zone, started on demand and gone when its zone has nothing
// pending. The engine goroutine itself only dispatches, so a primary that is
// slow or silent costs that zone's worker and nobody else.

// ParentPushKind says what a push request asks the engine to reconcile.
type ParentPushKind int

const (
	// ParentPushChildren reconciles the named children from the store.
	ParentPushChildren ParentPushKind = iota + 1
	// ParentPushAdvertisement reconciles this agent's own DSYNC advertisement.
	ParentPushAdvertisement
	// ParentPushReconcile reconciles every child the store holds rows for
	// against the served zone (§6.4). Enqueued by the refresh hook.
	ParentPushReconcile
)

func (k ParentPushKind) String() string {
	switch k {
	case ParentPushChildren:
		return "children"
	case ParentPushAdvertisement:
		return "advertisement"
	case ParentPushReconcile:
		return "reconcile"
	}
	return fmt.Sprintf("kind(%d)", int(k))
}

// ParentPushRequest asks the engine to bring the parent primary up to date.
type ParentPushRequest struct {
	Kind     ParentPushKind
	ZoneData *ZoneData
	Children []string // ParentPushChildren only
	Reason   string   // for the log
}

// The subject a push failure is filed under when it is not a child.
const parentPushAdvertisementSubject = "advertisement"

// enqueueParentPush hands a request to the engine without blocking. A full
// queue is logged and the request dropped: the refresh reconciler re-derives
// the delta, so nothing is lost -- the argument ProxyDelegationPostRefresh
// makes for its own dropped enqueue.
func enqueueParentPush(req ParentPushRequest) bool {
	q := Conf.Internal.ParentPushQ
	if q == nil || req.ZoneData == nil {
		return false
	}
	select {
	case q <- req:
		return true
	default:
		lg.Warn("parent push queue is full; dropping a push request, the next refresh reconciles it",
			"zone", req.ZoneData.ZoneName, "kind", req.Kind.String(), "children", req.Children, "reason", req.Reason)
		return false
	}
}

// ParentPushEngine dispatches push requests to per-zone workers. Standard
// engine shape (CONTEXT.md): exits on ctx.Done() or a closed queue, never
// blocks on a worker.
func ParentPushEngine(ctx context.Context, conf *Config) error {
	q := conf.Internal.ParentPushQ
	if q == nil {
		return fmt.Errorf("ParentPushEngine: no push queue")
	}
	lg.Info("ParentPushEngine: starting")
	for {
		select {
		case <-ctx.Done():
			lg.Info("ParentPushEngine: shutting down")
			return nil
		case req, ok := <-q:
			if !ok {
				lg.Info("ParentPushEngine: queue closed")
				return nil
			}
			if req.ZoneData == nil {
				continue
			}
			req.ZoneData.schedulePush(ctx, req)
		}
	}
}

// parentPushState is a zone's outbound bookkeeping: what is waiting, whether
// a worker is running, and what last went wrong per subject.
type parentPushState struct {
	mu        sync.Mutex
	running   bool
	pending   map[string]bool
	advertise bool
	reconcile bool
	failures  map[string]*ParentPushFailure
	lastPush  time.Time
	lastOK    time.Time
	// lastReconcile is when the last walk of the store's children finished,
	// pushes included: the completion signal for a queued reconcile.
	lastReconcile time.Time
}

// ParentPushFailure is the operator-visible record of a push that did not
// land: `zone childsync proxy-status` shows these.
type ParentPushFailure struct {
	Subject  string    `json:"subject"` // a child name, or "advertisement"
	Attempts int       `json:"attempts"`
	LastErr  string    `json:"last_error"`
	At       time.Time `json:"at"`
	// Terminal: the primary answered and said no (REFUSED, NOTAUTH), or the
	// writer refused locally. Retrying without a change will not help.
	Terminal bool `json:"terminal"`
}

// ParentPushStatus is the operator's view of a zone's outbound pushes.
type ParentPushStatus struct {
	Pending  []string  `json:"pending"`
	Running  bool      `json:"running"`
	LastPush time.Time `json:"last_push,omitempty"`
	LastOK   time.Time `json:"last_ok,omitempty"`
	// LastChildReconcile is when the last refresh reconcile of the store's
	// children completed, pushes included.
	LastChildReconcile time.Time           `json:"last_child_reconcile,omitempty"`
	Failures           []ParentPushFailure `json:"failures,omitempty"`
}

func (zd *ZoneData) parentPush() *parentPushState {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	if zd.pushState == nil {
		zd.pushState = &parentPushState{pending: map[string]bool{}, failures: map[string]*ParentPushFailure{}}
	}
	return zd.pushState
}

// ParentPushStatus reports the zone's push state for the operator surface.
func (zd *ZoneData) ParentPushStatus() ParentPushStatus {
	st := zd.parentPush()
	st.mu.Lock()
	defer st.mu.Unlock()
	out := ParentPushStatus{Running: st.running, LastPush: st.lastPush, LastOK: st.lastOK, LastChildReconcile: st.lastReconcile}
	for c := range st.pending {
		out.Pending = append(out.Pending, c)
	}
	if st.advertise {
		out.Pending = append(out.Pending, parentPushAdvertisementSubject)
	}
	if st.reconcile {
		out.Pending = append(out.Pending, "reconcile")
	}
	sort.Strings(out.Pending)
	for _, f := range st.failures {
		out.Failures = append(out.Failures, *f)
	}
	sort.Slice(out.Failures, func(i, j int) bool { return out.Failures[i].Subject < out.Failures[j].Subject })
	return out
}

// schedulePush merges a request into the zone's pending set and starts the
// zone's worker if none is running.
func (zd *ZoneData) schedulePush(ctx context.Context, req ParentPushRequest) {
	st := zd.parentPush()
	st.mu.Lock()
	defer st.mu.Unlock()
	switch req.Kind {
	case ParentPushChildren:
		for _, c := range req.Children {
			st.pending[dns.Fqdn(c)] = true
		}
	case ParentPushAdvertisement:
		st.advertise = true
	case ParentPushReconcile:
		st.reconcile = true
	default:
		lg.Warn("ParentPushEngine: unknown request kind, ignoring", "zone", zd.ZoneName, "kind", int(req.Kind))
		return
	}
	lg.Debug("ParentPushEngine: push scheduled", "zone", zd.ZoneName, "kind", req.Kind.String(),
		"children", req.Children, "reason", req.Reason, "workerRunning", st.running)
	if !st.running {
		st.running = true
		go zd.runParentPushes(ctx)
	}
}

// runParentPushes is the zone's worker: it drains the pending set, pushes
// each subject, and exits when nothing is left. Pending work that arrives
// while it runs is picked up on the next round, which is how several
// updates for one child become one push.
func (zd *ZoneData) runParentPushes(ctx context.Context) {
	st := zd.parentPush()
	for {
		st.mu.Lock()
		// Before the drain, not after: a cancelled worker leaves the pending
		// set where it is rather than taking it and dropping it.
		if ctx.Err() != nil {
			st.running = false
			st.mu.Unlock()
			return
		}
		children := make([]string, 0, len(st.pending))
		for c := range st.pending {
			children = append(children, c)
		}
		st.pending = map[string]bool{}
		advertise, reconcile := st.advertise, st.reconcile
		st.advertise, st.reconcile = false, false
		if len(children) == 0 && !advertise && !reconcile {
			st.running = false
			st.mu.Unlock()
			return
		}
		st.mu.Unlock()

		sort.Strings(children)
		for _, child := range children {
			if ctx.Err() != nil {
				break
			}
			zd.pushChild(ctx, child)
		}
		if advertise && ctx.Err() == nil {
			zd.pushAdvertisement(ctx)
		}
		if reconcile && ctx.Err() == nil {
			zd.reconcileKnownChildren(ctx)
		}
	}
}

// reconcileKnownChildren is §6.4 for the children: every child the store
// holds rows for is compared against the served zone and pushed if they
// differ. This is what recovers a push dropped on a full queue, one the
// primary silently declined, an operator's edit at the primary that
// contradicts recorded intent, and a restart with an empty in-flight queue.
//
// A child with NO rows is never touched. An empty store must never be able
// to empty a parent zone -- and with an external store an empty result is
// also what a fresh database, a wrong table prefix or a schema restored from
// nothing looks like.
//
// One store read per known child, on every refresh. On a parent with very
// many children a per-child revision in the store is the way to make this
// incremental; deferred.
func (zd *ZoneData) reconcileKnownChildren(ctx context.Context) {
	_, store, ok := zd.asyncParentWriter()
	if !ok {
		return
	}
	children, err := store.ListChildren(zd.ZoneName)
	if err != nil {
		lg.Error("childsync-proxy: cannot list the store's children for reconciliation", "zone", zd.ZoneName, "err", err)
		return
	}
	pushed := 0
	for _, child := range children {
		if ctx.Err() != nil {
			return
		}
		if zd.pushChild(ctx, child) {
			pushed++
		}
	}
	lg.Info("childsync-proxy: reconciled the known children against the served zone",
		"zone", zd.ZoneName, "children", len(children), "pushed", pushed)
	st := zd.parentPush()
	st.mu.Lock()
	st.lastReconcile = time.Now()
	st.mu.Unlock()
}

// asyncParentWriter is the zone's writer when pushes go through this engine:
// a composed backend whose writer speaks to the network. Zones whose writer
// runs inline (zonefile) or have none report false, and the engine leaves
// them alone.
func (zd *ZoneData) asyncParentWriter() (ParentZoneWriter, DelegationStore, bool) {
	zd.mu.Lock()
	b := zd.DelegationBackend
	zd.mu.Unlock()
	c, ok := b.(*composedDelegationBackend)
	if !ok || c.writer == nil || !c.async {
		return nil, nil, false
	}
	return c.writer, c.store, true
}

// pushChild reconciles one child. Reports whether a push was attempted.
func (zd *ZoneData) pushChild(ctx context.Context, child string) bool {
	writer, store, ok := zd.asyncParentWriter()
	if !ok {
		return false
	}
	actions, err := zd.childDelegationDelta(store, child)
	if err != nil {
		zd.recordPushFailure(child, 1, err, false)
		return false
	}
	if len(actions) == 0 {
		lg.Debug("ParentPushEngine: nothing to push, the parent already serves the intended delegation",
			"zone", zd.ZoneName, "child", child)
		zd.recordPushSuccess(child)
		return false
	}
	zd.deliver(ctx, writer, child, actions, "delegation of "+child)
	return true
}

func (zd *ZoneData) pushAdvertisement(ctx context.Context) {
	writer, _, ok := zd.asyncParentWriter()
	if !ok {
		return
	}
	actions, err := zd.childSyncAdvertisementDelta()
	if err != nil {
		zd.recordPushFailure(parentPushAdvertisementSubject, 1, err, false)
		return
	}
	if len(actions) == 0 {
		zd.recordPushSuccess(parentPushAdvertisementSubject)
		return
	}
	zd.deliver(ctx, writer, parentPushAdvertisementSubject, actions, "DSYNC advertisement")
}

// Retry defaults: the delegation-sync schedule (delsync_retry.go), short
// enough that a failing subject does not hold its zone's worker for long. The
// refresh reconciler retries again later, on the zone's own timer.
const (
	defaultParentPushAttempts = 5
	defaultParentPushInterval = 5 * time.Second
)

func pushRetryParams(w ParentZoneWriter) (attempts int, delay time.Duration) {
	attempts, delay = defaultParentPushAttempts, defaultParentPushInterval
	if d, ok := w.(*ddnsParentZoneWriter); ok {
		if d.maxAttempts > 0 {
			attempts = d.maxAttempts
		}
		if d.retryInterval > 0 {
			delay = d.retryInterval
		}
	}
	return attempts, delay
}

// deliver makes the push, with backoff on a transport failure or a SERVFAIL
// and an immediate stop on anything terminal: the primary's policy rejecting
// us is an operator problem, and hammering it changes nothing.
func (zd *ZoneData) deliver(ctx context.Context, writer ParentZoneWriter, subject string, actions []dns.RR, desc string) {
	attempts, delay := pushRetryParams(writer)
	var terminal bool
	n := 0
	err := retryWithBackoff(ctx, attempts, delay, func(attempt int) (bool, error) {
		n = attempt
		werr := writer.Write(ctx, zd.ZoneName, actions, desc)
		if werr == nil {
			return true, nil
		}
		var rej *WriteRejected
		if errors.As(werr, &rej) && !rej.Transient() {
			terminal = true
			return true, werr
		}
		var local *WriteRefusedLocally
		if errors.As(werr, &local) {
			terminal = true
			return true, werr
		}
		lg.Warn("ParentPushEngine: push failed, will retry", "zone", zd.ZoneName, "subject", subject,
			"attempt", attempt, "of", attempts, "err", werr)
		return false, werr
	})
	if err == nil {
		lg.Info("ParentPushEngine: pushed to the parent primary", "zone", zd.ZoneName, "subject", subject,
			"actions", len(actions), "attempt", n)
		zd.recordPushSuccess(subject)
		return
	}
	zd.recordPushFailure(subject, n, err, terminal)
}

const parentPushWarningPrefix = "push to the parent primary failed: "

func (zd *ZoneData) recordPushFailure(subject string, attempts int, err error, terminal bool) {
	st := zd.parentPush()
	st.mu.Lock()
	st.lastPush = time.Now()
	st.failures[subject] = &ParentPushFailure{Subject: subject, Attempts: attempts, LastErr: err.Error(), At: time.Now(), Terminal: terminal}
	st.mu.Unlock()
	lg.Error("ParentPushEngine: push to the parent primary failed", "zone", zd.ZoneName, "subject", subject,
		"attempts", attempts, "terminal", terminal, "err", err)
	// The zone carries the warning; the store keeps the intent, and the next
	// refresh reconciles again. DelegationSyncWarning is not
	// service-impacting: a degraded advertisement or a stuck push does not
	// take the zone dark or make it refuse NOTIFY.
	zd.SetError(DelegationSyncWarning, "%s%s: %v", parentPushWarningPrefix, subject, err)
}

func (zd *ZoneData) recordPushSuccess(subject string) {
	st := zd.parentPush()
	st.mu.Lock()
	st.lastPush, st.lastOK = time.Now(), time.Now()
	delete(st.failures, subject)
	remaining := len(st.failures)
	st.mu.Unlock()
	if remaining == 0 {
		zd.clearPrefixedWarning(parentPushWarningPrefix)
	}
}

// clearPrefixedWarning clears a DelegationSyncWarning this source set, and
// only that: the category is shared by several sources.
func (zd *ZoneData) clearPrefixedWarning(prefix string) {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	if ze, ok := zd.Errors[DelegationSyncWarning]; ok && strings.HasPrefix(ze.Msg, prefix) {
		zd.clearErrorLocked(DelegationSyncWarning)
	}
}

// childDelegationDelta is the declarative per-child delta (§5.5 step 2): the
// store is the intended state, the served zone the actual, and the actions
// are what turns the second into the first. Scoped to the delegation types
// the parent holds for a child -- NS and DS at the cut, addresses below it --
// so a store row of any other type is never pushed and never loops.
func (zd *ZoneData) childDelegationDelta(store DelegationStore, child string) ([]dns.RR, error) {
	intended, err := store.GetDelegationData(zd.ZoneName, child)
	if err != nil {
		return nil, fmt.Errorf("reading the store for %s: %w", child, err)
	}
	want := adoptableDelegationRR(child)
	zd.mu.Lock()
	served, serr := zd.servedDelegationDataLocked(child, want)
	zd.mu.Unlock()
	if serr != nil {
		return nil, fmt.Errorf("reading the served zone for %s: %w", child, serr)
	}
	return diffDelegation(intended, served, zd.childUpdateTTL(), want), nil
}

// childUpdateTTL is the TTL a pushed add carries: the store keeps none, and
// the child's update policy is where the parent says what TTL it gives
// delegation records.
func (zd *ZoneData) childUpdateTTL() uint32 {
	if ttl := zd.UpdatePolicy.Child.TTL; ttl > 0 {
		return ttl
	}
	return 3600
}

// diffDelegation turns (intended, served) into RFC 2136 actions: removes
// (class NONE) for what is served and not intended, adds (class INET, ttl)
// for what is intended and not served. Records are compared on owner, type
// and RDATA; TTL and class are not identity. Removes come first, sorted, then
// adds, sorted, so the same delta always produces the same message.
func diffDelegation(intended, served map[string]map[uint16][]dns.RR, ttl uint32, want func(owner string, rrtype uint16) bool) []dns.RR {
	index := func(data map[string]map[uint16][]dns.RR) map[string]dns.RR {
		out := map[string]dns.RR{}
		for owner, byType := range data {
			for rrtype, rrs := range byType {
				if want != nil && !want(owner, rrtype) {
					continue
				}
				for _, rr := range rrs {
					out[delegationRRKey(rr)] = rr
				}
			}
		}
		return out
	}
	haveIntended, haveServed := index(intended), index(served)

	var removes, adds []dns.RR
	for k, rr := range haveServed {
		if _, ok := haveIntended[k]; ok {
			continue
		}
		c := dns.Copy(rr)
		c.Header().Class = dns.ClassNONE
		c.Header().Ttl = 0
		removes = append(removes, c)
	}
	for k, rr := range haveIntended {
		if _, ok := haveServed[k]; ok {
			continue
		}
		c := dns.Copy(rr)
		c.Header().Class = dns.ClassINET
		c.Header().Ttl = ttl
		adds = append(adds, c)
	}
	byString := func(rrs []dns.RR) { sort.Slice(rrs, func(i, j int) bool { return rrs[i].String() < rrs[j].String() }) }
	byString(removes)
	byString(adds)
	return append(removes, adds...)
}

// delegationRRKey identifies a record by owner, type and RDATA.
func delegationRRKey(rr dns.RR) string {
	c := dns.Copy(rr)
	c.Header().Ttl = 0
	c.Header().Class = dns.ClassINET
	c.Header().Name = dns.CanonicalName(c.Header().Name)
	return c.String()
}

// childSyncAdvertisementDelta is what the agent's own advertisement still
// lacks in the served parent zone: the DSYNC publication plus the receiver
// KEY, as the reconciler computes it (childsync_proxy.go).
func (zd *ZoneData) childSyncAdvertisementDelta() ([]dns.RR, error) {
	actions, _, err := zd.advertisementDelta()
	return actions, err
}

// affectedChildren names the children an update's actions touch.
func affectedChildren(parentZone string, actions []dns.RR) []string {
	seen := map[string]bool{}
	var out []string
	for _, rr := range actions {
		c := childZoneFromOwner(rr.Header().Name, parentZone)
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return out
}
