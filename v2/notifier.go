/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

type NotifyRequest struct {
	ZoneName string
	ZoneData *ZoneData
	RRtype   uint16
	Targets  []string // []addr:port
	Urgent   bool
	Response chan NotifyResponse
	// Ctx, when set, is the waiting caller's context. A send for the request
	// still queued when it is done is not made: nobody is listening for it.
	Ctx context.Context
	// Downstream marks a publish's NOTIFY to the zone's downstreams, naming
	// the whole downstream set. The pending set holds only those; on the
	// queue, which a daemon without a tracker uses for them, it tells them
	// apart from the rest.
	Downstream bool
}

type NotifyResponse struct {
	Msg      string
	Rcode    int
	Error    bool
	ErrorMsg string
	// EDE carries any Extended DNS Errors returned by the parent's
	// NOTIFY response. On any-success-wins overall outcome, EDE is
	// populated from the first NOERROR target's response (typically
	// empty). On overall failure, EDE is populated from the most
	// recent failing target's response. The rollover engine's
	// parent-rejected category surfaces these for operator
	// diagnostics.
	EDE []dns.EDNS0_EDE
}

// notifyTimeout bounds one NOTIFY exchange. A variable so a test can shorten
// it; nothing else changes it.
var notifyTimeout = 5 * time.Second

// notifyMaxInFlight bounds the NOTIFY exchanges on the wire at once.
const notifyMaxInFlight = 16

// notifyPruneInterval is how often the Notifier releases the state of zones it
// no longer serves.
const notifyPruneInterval = 10 * time.Minute

// notifyResponseWait bounds how long an answer waits for a caller that has
// stopped listening; after that it is dropped.
var notifyResponseWait = time.Minute

// Notifier drains the NOTIFY queue and sends outbound NOTIFYs, signing each with
// the matching notify-peer's TSIG key (Improvement 2). conf is threaded for the
// key store. NOTE: tdns-mp pins a published tdns/v2 and calls Notifier at four
// sites (start_signer/agent/auditor/combiner) — when it bumps the dependency,
// pass its conf.Config: Notifier(ctx, conf.Config, conf.Config.Internal.NotifyQ).
//
// It resends a NOTIFY that gets no answer (#1007, RFC 1996 §3.6), with a
// growing interval and a bounded number of tries, per target. The sends run
// beside the loop rather than in it: one exchange can wait out notifyTimeout,
// and a loop that waited on each in turn held every other zone's NOTIFY behind
// one unreachable downstream. See notifier_tracker.go for the per-target state.
//
// Requests come from two places. Downstream NOTIFY(SOA) for a publish arrives
// through the tracker's pending set (NotifyTracker.Mark), which coalesces a
// burst per zone and never drops one. Everything else -- NOTIFY(CDS/CSYNC) to a
// parent, NOTIFY(DNSKEY) to a multi-signer controller -- arrives on the queue.
//
// A request with a Response channel is sent once per target and answered with
// the any-success-wins aggregate, exactly as before. Its caller -- the KSK
// rollover's DS push -- waits on that answer with a deadline and retries on its
// own schedule, so resending here as well would retry twice and outlive the
// caller's deadline. A request without one has nobody to retry it, and is
// resent here.
func Notifier(ctx context.Context, conf *Config, notifyreqQ chan NotifyRequest) error {

	lgDns.Info("NotifierEngine: starting")
	tracker := conf.Internal.NotifyTracker
	if tracker == nil {
		// A daemon that did not create one still resends; it only has no
		// pending set (its publishes use the queue) and no state to show.
		tracker = NewNotifyTracker()
	}
	tracker.setDefaults(conf.AuthEngine.NotifyRetries, conf.AuthEngine.NotifyRetryInterval)
	n := &notifier{
		ctx:     ctx,
		conf:    conf,
		tracker: tracker,
		results: make(chan notifyResult, notifyMaxInFlight),
	}
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	prune := time.NewTicker(notifyPruneInterval)
	defer prune.Stop()

	for {
		select {
		case <-ctx.Done():
			lgDns.Info("NotifierEngine: terminating due to context cancelled")
			return nil
		case nr, ok := <-notifyreqQ:
			if !ok {
				lgDns.Info("NotifierEngine: terminating due to notifyreqQ closed")
				return nil
			}
			n.handle(nr, nr.Downstream)
		case <-tracker.wake:
			for _, nr := range tracker.takePending() {
				n.handle(nr, true)
			}
		case r := <-n.results:
			n.finish(r)
		case <-timer.C:
			n.resendDue()
		case <-prune.C:
			if gone := tracker.prune(Zones.Get, zoneDownstreams); gone > 0 {
				lgDns.Debug("NotifierEngine: released the NOTIFY state of zones no longer served", "targets", gone)
			}
		}
		n.armTimer(timer)
	}
}

// notifier is the Notifier loop's own state. Only the loop goroutine touches
// it; the tracker it points at has its own lock.
type notifier struct {
	ctx     context.Context
	conf    *Config
	tracker *NotifyTracker
	results chan notifyResult
	// running counts the sends on the wire. The rest wait in the two queues,
	// as jobs rather than goroutines, so a burst costs memory per job and no
	// more than notifyMaxInFlight goroutines. urgent holds the jobs a caller
	// waits on, which go first: that caller has a deadline. A tracked target
	// has at most one job queued or running (begin and due see to that), so
	// waiting never holds more jobs than there are targets.
	running int
	urgent  []notifyJob
	waiting []notifyJob
}

// notifyJob is one NOTIFY to one target. batch is set for a request whose
// caller waits for the aggregate answer; nil for a tracked, resent one.
type notifyJob struct {
	zd     *ZoneData
	rrtype uint16
	target string
	batch  *notifyBatch
}

type notifyResult struct {
	job     notifyJob
	attempt notifyAttempt
}

// notifyBatch collects the per-target outcomes of one request whose caller is
// waiting for the aggregate.
type notifyBatch struct {
	req  NotifyRequest
	left int
	agg  notifyAggregate
}

// handle starts a request's sends. downstream: it is a publish's NOTIFY to the
// zone's downstreams, from the pending set, naming the whole downstream set.
func (n *notifier) handle(nr NotifyRequest, downstream bool) {
	zd := nr.ZoneData
	if zd == nil {
		return
	}
	// A publish's request carries the zone's whole downstream set, so a
	// target missing from it has been removed: no more resends to it. An empty
	// set -- the last downstream removed -- retires them all, and there is
	// nothing to send.
	if downstream {
		n.tracker.retire(zd.ZoneName, nr.RRtype, nr.Targets)
		if len(nr.Targets) == 0 {
			return
		}
	}
	lgDns.Info("NotifierEngine: will notify", "zone", zd.ZoneName, "type", dns.TypeToString[nr.RRtype], "targets", len(nr.Targets))

	if rcode, err := zd.notifyPrecheck(nr.RRtype, nr.Targets); err != nil {
		if nr.Response != nil {
			n.respond(nr, rcode, nil, err)
		} else {
			lgDns.Warn("NotifierEngine: not sending", "zone", zd.ZoneName, "err", err)
		}
		return
	}

	if nr.Response != nil {
		b := &notifyBatch{req: nr, left: len(nr.Targets)}
		if b.left == 0 {
			// No target, so no job will finish the batch: answer now, as
			// SendNotify does, rather than leave the caller to its deadline.
			rcode, ede, err := b.agg.result(zd.ZoneName, nr.RRtype, 0)
			n.respond(nr, rcode, ede, err)
			return
		}
		for _, dst := range nr.Targets {
			n.launch(notifyJob{zd: zd, rrtype: nr.RRtype, target: dst, batch: b})
		}
		return
	}
	for _, dst := range nr.Targets {
		if n.tracker.begin(notifyKey{zone: zd.ZoneName, target: dst, rrtype: nr.RRtype}, zd, downstream) {
			n.launch(notifyJob{zd: zd, rrtype: nr.RRtype, target: dst})
		}
	}
}

// launch queues one NOTIFY to send beside the loop; see notifier.running.
func (n *notifier) launch(job notifyJob) {
	if job.batch != nil {
		n.urgent = append(n.urgent, job)
	} else {
		n.waiting = append(n.waiting, job)
	}
	n.pump()
}

// pump starts queued sends while there is room on the wire. Each hands its
// outcome back on n.results.
func (n *notifier) pump() {
	for n.running < notifyMaxInFlight {
		var job notifyJob
		switch {
		case len(n.urgent) > 0:
			job, n.urgent = n.urgent[0], n.urgent[1:]
		case len(n.waiting) > 0:
			job, n.waiting = n.waiting[0], n.waiting[1:]
		default:
			return
		}
		if n.dropStale(job) {
			continue
		}
		n.running++
		go func() {
			lgDns.Debug("NOTIFY: sending", "type", dns.TypeToString[job.rrtype], "zone", job.zd.ZoneName, "target", job.target)
			a := job.zd.notifyOne(n.ctx, n.conf, job.rrtype, job.target)
			select {
			case n.results <- notifyResult{job: job, attempt: a}:
			case <-n.ctx.Done():
			}
		}()
	}
}

// dropStale reports whether a queued job is no longer wanted, and settles it:
// a tracked target retired while its job waited (its state is dropped), or a
// waiting caller that has gone (its slot in the batch counts as failed, so the
// batch still completes).
func (n *notifier) dropStale(job notifyJob) bool {
	if b := job.batch; b != nil {
		ctx := b.req.Ctx
		if ctx == nil || ctx.Err() == nil {
			return false
		}
		n.settle(job, notifyAttempt{err: fmt.Errorf("not sent: the caller stopped waiting: %w", ctx.Err())})
		return true
	}
	return n.tracker.dropIfRetired(notifyKey{zone: job.zd.ZoneName, target: job.target, rrtype: job.rrtype})
}

func (n *notifier) finish(r notifyResult) {
	n.running--
	defer n.pump()
	n.settle(r.job, r.attempt)
}

// settle records one job's outcome: in its batch, or in the tracker.
func (n *notifier) settle(job notifyJob, attempt notifyAttempt) {
	if b := job.batch; b != nil {
		b.agg.add(job.zd.ZoneName, job.target, job.rrtype, attempt)
		b.left--
		if b.left == 0 {
			rcode, ede, err := b.agg.result(job.zd.ZoneName, job.rrtype, len(b.req.Targets))
			n.respond(b.req, rcode, ede, err)
		}
		return
	}
	retries, interval := notifyRetryPolicy(job.zd, n.tracker)
	key := notifyKey{zone: job.zd.ZoneName, target: job.target, rrtype: job.rrtype}
	// The newer version goes out with the ZoneData it came with, not the one
	// this send used: the zone may have been replaced in between.
	if again, zd := n.tracker.done(key, attempt, retries, interval, time.Now()); again {
		n.launch(notifyJob{zd: zd, rrtype: job.rrtype, target: job.target})
	}
}

// respond hands a waiting caller its answer. At once when the caller's channel
// has room; otherwise from its own goroutine, for at most notifyResponseWait:
// the caller may have stopped listening (its deadline passed), and neither the
// loop nor that goroutine may wait on it for ever.
func (n *notifier) respond(nr NotifyRequest, rcode int, ede []dns.EDNS0_EDE, err error) {
	resp := NotifyResponse{Rcode: rcode, EDE: ede}
	if err != nil {
		resp.Error = true
		resp.ErrorMsg = err.Error()
	} else {
		resp.Msg = "OK"
	}
	select {
	case nr.Response <- resp:
		return
	default:
	}
	go func() {
		wait := time.NewTimer(notifyResponseWait)
		defer wait.Stop()
		select {
		case nr.Response <- resp:
		case <-wait.C:
			lgDns.Warn("NotifierEngine: nobody took the NOTIFY response; dropped", "zone", nr.ZoneName)
		case <-n.ctx.Done():
			lgDns.Warn("NotifierEngine: context cancelled while sending NOTIFY response", "zone", nr.ZoneName)
		}
	}()
}

func (n *notifier) resendDue() {
	for _, job := range n.tracker.due(time.Now()) {
		n.launch(notifyJob{zd: job.zd, rrtype: job.key.rrtype, target: job.key.target})
	}
}

func (n *notifier) armTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	if next, ok := n.tracker.nextDue(); ok {
		timer.Reset(max(time.Until(next), 0))
	}
}

// notifyPrecheck refuses a request that cannot be sent at all, with the rcode
// and error SendNotify has always returned for it.
func (zd *ZoneData) notifyPrecheck(ntype uint16, targets []string) (int, error) {
	if zd.ZoneName == "." {
		return dns.RcodeServerFailure, fmt.Errorf("zone %q: error: zone name not specified. Ignoring notify request", zd.ZoneName)
	}

	switch ntype {
	case dns.TypeSOA:
		// We send to the targets passed in by the caller (derived from the
		// zone's notify peers), so validate that slice — not zd.Notify, which
		// can diverge from the actual targets for this request.
		if len(targets) == 0 {
			return dns.RcodeServerFailure, fmt.Errorf("zone %q: error: no downstreams. Ignoring notify request", zd.ZoneName)
		}

	case dns.TypeCSYNC, dns.TypeCDS:
		// Here we need the parent notify receiver addresses
		if _, err := zd.ResolveParent(); err != nil {
			return dns.RcodeServerFailure, fmt.Errorf("zone %q: error: failure locating parent zone name (%v). Ignoring notify request", zd.ZoneName, err)
		}

	case dns.TypeDNSKEY:
	//		lookupzone = zonename
	//		lookupserver = childpri

	default:
		lgDns.Error("unsupported notify type", "type", dns.TypeToString[ntype])
	}
	return dns.RcodeSuccess, nil
}

// SendNotify sends NOTIFY to every target and aggregates with
// any-success-wins semantics. On a successful overall outcome (at
// least one target NOERROR), the returned rcode is NOERROR and EDE
// is populated from the first NOERROR target's response (typically
// empty). On overall failure, the returned rcode is the rcode of the
// most recent failing target's response (or SERVFAIL with err if
// every target's transport failed) and EDE comes from that target's
// response. err is non-nil only when no target produced a usable
// response at all (transport-level failure across the board).
//
// One attempt per target, in turn, and no resend: the Notifier does that, for
// the requests it owns. This is the synchronous form, for a caller that wants
// the answer in hand.
//
// ctx bounds the per-target loop, but does NOT interrupt a send already on the
// wire. On daemon shutdown the loop stops at the next iteration boundary --
// each target is preceded by a ctx.Err() check -- while whichever send is in
// flight runs to completion.
//
// The distinction is not pedantic and this comment used to get it wrong, by
// claiming the loop also exits "via ExchangeContext returning early".
// ExchangeContext hands the context to the dial and then uses only
// ctx.Deadline() to tighten the socket deadlines; it never watches ctx.Done().
// The client's Timeout (notifyTimeout) bounds the wait instead.
//
// Bounded and short, so it is a known cost rather than a hang. Interrupting it
// would mean closing the connection on cancellation, as SendUpdate does via
// exchangeCancellable in childsync_utils.go.
func (zd *ZoneData) SendNotify(ctx context.Context, conf *Config, ntype uint16, targets []string) (int, []dns.EDNS0_EDE, error) {
	if rcode, err := zd.notifyPrecheck(ntype, targets); err != nil {
		return rcode, nil, err
	}

	var agg notifyAggregate
	for i, dst := range targets {
		// Honor cancellation between targets so daemon shutdown
		// doesn't block for len(targets)*Timeout.
		if err := ctx.Err(); err != nil {
			lgDns.Warn("NOTIFY: context cancelled, aborting remaining targets", "zone", zd.ZoneName, "remaining", len(targets)-i, "err", err)
			break
		}
		lgDns.Info("NOTIFY: sending", "type", dns.TypeToString[ntype], "zone", zd.ZoneName, "target", dst)
		agg.add(zd.ZoneName, dst, ntype, zd.notifyOne(ctx, conf, ntype, dst))
	}
	return agg.result(zd.ZoneName, ntype, len(targets))
}

// notifyAttempt is the outcome of one NOTIFY to one target.
type notifyAttempt struct {
	rcode int
	ede   []dns.EDNS0_EDE
	// err: no usable reply -- a timeout or a network error. Worth resending.
	err error
	// setupErr: the message could not be signed, so nothing was sent. A
	// configuration error; resending changes nothing.
	setupErr error
	overTCP  bool
}

// notifyOne sends one NOTIFY to one target. An ICMP port unreachable on UDP
// (ECONNREFUSED on the connected socket) is answered with one immediate try over
// TCP, as BIND does: the receiver may listen on TCP alone, and a refusal is not
// a lost packet that waiting would cure.
func (zd *ZoneData) notifyOne(ctx context.Context, conf *Config, ntype uint16, dst string) notifyAttempt {
	a := zd.notifyOneOver(ctx, conf, ntype, dst, "udp")
	if a.err != nil && errors.Is(a.err, syscall.ECONNREFUSED) {
		lgDns.Debug("NOTIFY: refused over UDP; retrying over TCP", "zone", zd.ZoneName, "target", dst)
		a = zd.notifyOneOver(ctx, conf, ntype, dst, "tcp")
		a.overTCP = true
	}
	return a
}

// notifyOneOver builds, signs and sends one NOTIFY over network. Built afresh
// for every attempt: a resend needs a new TSIG time stamp (a reused one goes
// stale and is refused as BADTIME) and the SOA as served now.
func (zd *ZoneData) notifyOneOver(ctx context.Context, conf *Config, ntype uint16, dst, network string) notifyAttempt {
	m := zd.notifyMsg(ntype)

	// Sign the NOTIFY with the matching notify-peer's key (NOKEY => unsigned).
	provider, serr := SignForPeer(m, zd.notifyKeyFor(dst), conf)
	if serr != nil {
		return notifyAttempt{setupErr: serr}
	}
	if network == "udp" {
		dropOversizedNotifySOA(m, zd.ZoneName)
	}
	c := &dns.Client{Net: network, Timeout: notifyTimeout, TsigProvider: provider}

	lgDns.Debug("sending NOTIFY message", "msg", m.String())

	res, _, err := c.ExchangeContext(ctx, m, dst)
	if err != nil {
		return notifyAttempt{err: err}
	}
	return notifyAttempt{rcode: res.Rcode, ede: extractEDEFromMsg(res)}
}

// notifyAggregate folds per-target outcomes into SendNotify's any-success-wins
// answer. See SendNotify for the contract.
type notifyAggregate struct {
	successCount      int
	firstSuccessEDE   []dns.EDNS0_EDE
	lastFailRcode     int
	lastFailEDE       []dns.EDNS0_EDE
	haveLastFailRcode bool
	lastSetupErr      error
	attemptedTargets  int
}

func (g *notifyAggregate) add(zone, dst string, ntype uint16, a notifyAttempt) {
	switch {
	case a.setupErr != nil:
		lgDns.Error("NOTIFY: TSIG sign setup failed, skipping target", "zone", zone, "target", dst, "err", a.setupErr)
		g.lastSetupErr = a.setupErr
		return
	case a.err != nil:
		g.attemptedTargets++
		lgDns.Warn("NOTIFY: dns.Exchange failed, trying next target", "target", dst, "type", dns.TypeToString[ntype], "err", a.err)
		return
	}
	g.attemptedTargets++
	if a.rcode != dns.RcodeSuccess {
		lgDns.Warn("NOTIFY: bad rcode from target", "target", dst, "rcode", dns.RcodeToString[a.rcode])
		g.lastFailRcode = a.rcode
		g.lastFailEDE = a.ede
		g.haveLastFailRcode = true
		return
	}
	lgDns.Debug("NOTIFY: got NOERROR back", "target", dst)
	if g.successCount == 0 {
		g.firstSuccessEDE = a.ede
	}
	g.successCount++
}

func (g *notifyAggregate) result(zone string, ntype uint16, total int) (int, []dns.EDNS0_EDE, error) {
	if g.successCount == 0 {
		if g.haveLastFailRcode {
			// Parent replied — just with a non-NOERROR rcode. Return
			// the rcode/EDE without an error: this is "parent
			// rejected" (parent-rejected category), not "transport
			// failed". The caller categorises from the rcode and
			// EDE; making this an error would force the rollover
			// engine into the transport bucket and lose the EDE
			// context that's the whole point of Phase 4 plumbing.
			return g.lastFailRcode, g.lastFailEDE, nil
		}
		// No target was attempted at all because every one's TSIG sign setup failed
		// (e.g. an unknown key): surface that real cause rather than a generic "no
		// response". If at least one target WAS attempted (signed) but failed
		// transport, fall through to the no-response error below.
		if g.attemptedTargets == 0 && g.lastSetupErr != nil {
			return dns.RcodeServerFailure, nil, fmt.Errorf("TSIG setup failed for NOTIFY target(s): %w", g.lastSetupErr)
		}
		// No response from any target at all → genuine transport
		// failure. err is non-nil only on this branch.
		return dns.RcodeServerFailure, nil, fmt.Errorf("error: no response from any NOTIFY target to NOTIFY(%q)", dns.TypeToString[ntype])
	}
	lgDns.Info("NOTIFY: successfully sent", "type", dns.TypeToString[ntype], "zone", zone, "succeeded", g.successCount, "total", total)
	return dns.RcodeSuccess, g.firstSuccessEDE, nil
}

// notifySOA returns a copy of the SOA the zone is serving, or nil when nothing
// is published. A copy, because the snapshot's SOA is shared with every reader.
func (zd *ZoneData) notifySOA() dns.RR {
	snap := zd.publishedSnapshot()
	if snap == nil || snap.SOA == nil {
		return nil
	}
	return dns.Copy(snap.SOA)
}

// notifyMsg builds the NOTIFY for ntype, unsigned.
//
// A NOTIFY(SOA) carries the SOA being served (RFC 1996 §3.7). It is optional
// in the RFC and required here: without it the receiver cannot tell whether it
// already holds that serial, so it always queries back, and BIND logs "no
// serial" for every NOTIFY. It is a copy (notifySOA), and goes in before the
// TSIG stamp, so the signature covers it. The other NOTIFY types carry
// nothing: their receiver fetches and validates the RRset itself.
func (zd *ZoneData) notifyMsg(ntype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetNotify(zd.ZoneName)
	m.Question = []dns.Question{{Name: zd.ZoneName, Qtype: ntype, Qclass: dns.ClassINET}}
	if ntype == dns.TypeSOA {
		if soa := zd.notifySOA(); soa != nil {
			m.Answer = []dns.RR{soa}
		} else {
			lgDns.Debug("NOTIFY: no published SOA to include", "zone", zd.ZoneName)
		}
	}
	return m
}

// notifyTsigMACRoom is the room left for a TSIG MAC when sizing a signed
// NOTIFY: the TSIG record is attached before sending but its MAC is computed
// as the message is packed, and SHA-512's is the largest.
const notifyTsigMACRoom = 64

// dropOversizedNotifySOA leaves the SOA out of a NOTIFY that would not fit in
// the 512 octets a UDP message without EDNS may use (RFC 1035 §4.2.1). The SOA
// is only a hint, and a NOTIFY without it is still a NOTIFY. Called after the
// TSIG record is attached, so its size is counted; room for its MAC is added
// only when there is one.
func dropOversizedNotifySOA(m *dns.Msg, zone string) {
	if len(m.Answer) == 0 {
		return
	}
	size := m.Len()
	if m.IsTsig() != nil {
		size += notifyTsigMACRoom
	}
	if size > dns.MinMsgSize {
		lgDns.Info("NOTIFY: leaving out the SOA, which would take the message past 512 octets",
			"zone", zone, "size", size)
		m.Answer = nil
	}
}

// extractEDEFromMsg pulls every EDNS0_EDE option out of a DNS message's
// OPT record and returns them as typed values. Returns nil when the
// message has no OPT or no EDEs.
func extractEDEFromMsg(msg *dns.Msg) []dns.EDNS0_EDE {
	if msg == nil {
		return nil
	}
	opt := msg.IsEdns0()
	if opt == nil {
		return nil
	}
	var out []dns.EDNS0_EDE
	for _, o := range opt.Option {
		if e, ok := o.(*dns.EDNS0_EDE); ok && e != nil {
			out = append(out, *e)
		}
	}
	return out
}

// zoneDownstreams returns the zone's downstream NOTIFY targets, as a publish
// computes them.
func zoneDownstreams(zd *ZoneData) []string {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	return peerAddrs(zd.Notify)
}
