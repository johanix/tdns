/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package peer

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// envelopeRRs is how many RRs go into one transfer envelope. Small enough that
// a message never has to be split, large enough that a rig zone still arrives
// in several envelopes — the receiving side's multi-envelope path is the one a
// single-envelope test never reaches.
const envelopeRRs = 100

// XferObs is one transfer the upstream peer served. The rig reads these to
// answer "did the SUT ask incrementally, and did it get an incremental
// answer" — a question neither side's logs answer directly.
type XferObs struct {
	At           time.Time
	From         string
	Qtype        uint16 // dns.TypeAXFR or dns.TypeIXFR
	ClientSerial uint32 // IXFR only: the serial in the client's authority SOA
	Outcome      string // axfr | ixfr | uptodate | fallback | refused
	Sequences    int    // difference sequences in an IXFR answer
	CurSerial    uint32
	// Err is set when the response could not be written. A transfer that
	// produced nothing on the wire must not read as a transfer that succeeded:
	// the client sees only a timeout, and the reason lives here.
	Err string
}

// NotifySendObs is one NOTIFY the upstream peer sent to the SUT.
type NotifySendObs struct {
	At     time.Time
	Target string
	Serial uint32 // what we were serving when we sent it (NOT on the wire; see §2.4)
	Rcode  int
	Err    string
}

// NotifyRecvObs is a NOTIFY somebody sent TO this peer. A primary should never
// receive one; answering it as though the question were an ordinary SOA query
// would let a SUT that misdirects its NOTIFYs at its own primary look entirely
// healthy, so they are recorded instead.
type NotifyRecvObs struct {
	At   time.Time
	From string
}

// Upstream is the rig's own primary: authoritative for the test zone, holding
// the version history the rig authored, answering SOA/AXFR/IXFR, and sending
// NOTIFY to the SUT on demand.
type Upstream struct {
	Origin string

	// OnNotify, when set, is called (on its own goroutine) for each inbound
	// NOTIFY for this peer's zone, before the reply is written.
	OnNotify func(from string)

	mu       sync.Mutex
	hist     *History
	xfrs     []XferObs
	notifies []NotifySendObs
	inbound  []NotifyRecvObs

	addr   string
	udp    *dns.Server
	tcp    *dns.Server
	closed sync.Once
}

// NewUpstream binds the listeners and seeds the history. A ":0" port is
// resolved to a real one — bound on TCP first and then reused for UDP, so the
// two halves of the peer are always reachable at the same address.
func NewUpstream(origin, listen string, seed *Zone, historyCap int) (*Upstream, error) {
	u := &Upstream{Origin: dns.Fqdn(origin), hist: NewHistory(origin, historyCap)}
	if err := u.hist.Seed(seed); err != nil {
		return nil, err
	}

	l, pc, err := bindPair(listen)
	if err != nil {
		return nil, fmt.Errorf("upstream peer: listening on %s: %w", listen, err)
	}
	u.addr = l.Addr().String()
	u.tcp = &dns.Server{Listener: l, Handler: dns.HandlerFunc(u.handle)}
	u.udp = &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(u.handle)}
	return u, nil
}

// Start serves until Stop. The listeners are already bound by NewUpstream, so
// there is no window in which the address is advertised but not accepting.
func (u *Upstream) Start() {
	go func() { _ = u.tcp.ActivateAndServe() }()
	go func() { _ = u.udp.ActivateAndServe() }()
}

func (u *Upstream) Stop() {
	u.closed.Do(func() {
		_ = u.tcp.Shutdown()
		_ = u.udp.Shutdown()
	})
}

func (u *Upstream) Addr() string { return u.addr }

// Apply authors the next version. It does not notify: the rig decides when to
// announce, because the gap between "changed" and "announced" is one of the
// things being measured.
func (u *Upstream) Apply(c Change) (*Version, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.hist.Apply(c)
}

func (u *Upstream) Current() *Version {
	u.mu.Lock()
	defer u.mu.Unlock()
	v := *u.hist.Current()
	return &v
}

func (u *Upstream) Transfers() []XferObs {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]XferObs(nil), u.xfrs...)
}

func (u *Upstream) NotifiesSent() []NotifySendObs {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]NotifySendObs(nil), u.notifies...)
}

// NotifiesReceived returns the NOTIFYs sent to this peer. Non-empty means a
// NOTIFY went to a primary.
func (u *Upstream) NotifiesReceived() []NotifyRecvObs {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]NotifyRecvObs(nil), u.inbound...)
}

// Publish installs a whole new version, deriving the delta from the current
// one. Apply is for an edit; this is for a state already in hand.
func (u *Upstream) Publish(z *Zone) (*Version, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.hist.AppendZone(z)
}

// Notify sends one NOTIFY(SOA) to the SUT and records the response. The
// message carries no SOA in the answer section — that is what miekg's
// SetNotify builds and what tdns itself sends, and the rig deliberately
// behaves the same rather than sending something the SUT will never see in
// production.
func (u *Upstream) Notify(ctx context.Context, target string) (int, error) {
	u.mu.Lock()
	serial := u.hist.Current().Serial
	u.mu.Unlock()

	m := new(dns.Msg)
	m.SetNotify(u.Origin)
	c := &dns.Client{Timeout: 5 * time.Second}
	r, _, err := c.ExchangeContext(ctx, m, target)

	obs := NotifySendObs{At: time.Now(), Target: target, Serial: serial}
	if err != nil {
		obs.Err = err.Error()
	} else {
		obs.Rcode = r.Rcode
	}
	u.mu.Lock()
	u.notifies = append(u.notifies, obs)
	u.mu.Unlock()

	if err != nil {
		return 0, err
	}
	return r.Rcode, nil
}

// --- server side -----------------------------------------------------------

func (u *Upstream) handle(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) != 1 {
		u.refuse(w, r, dns.RcodeFormatError)
		return
	}
	q := r.Question[0]
	if !equalName(q.Name, u.Origin) {
		u.refuse(w, r, dns.RcodeRefused)
		return
	}
	if r.Opcode == dns.OpcodeNotify {
		u.mu.Lock()
		u.inbound = append(u.inbound, NotifyRecvObs{At: time.Now(), From: w.RemoteAddr().String()})
		hook := u.OnNotify
		u.mu.Unlock()
		if hook != nil {
			go hook(w.RemoteAddr().String())
		}
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		_ = w.WriteMsg(m)
		return
	}
	switch q.Qtype {
	case dns.TypeAXFR:
		u.serveAXFR(w, r)
	case dns.TypeIXFR:
		u.serveIXFR(w, r)
	default:
		u.serveQuery(w, r, q)
	}
}

func (u *Upstream) refuse(w dns.ResponseWriter, r *dns.Msg, rcode int) {
	m := new(dns.Msg)
	m.SetRcode(r, rcode)
	_ = w.WriteMsg(m)
}

// serveQuery answers ordinary queries against the current version. The SUT
// only ever asks for the apex SOA, but a peer that answered nothing else would
// be awkward to debug by hand.
func (u *Upstream) serveQuery(w dns.ResponseWriter, r *dns.Msg, q dns.Question) {
	u.mu.Lock()
	z := u.hist.Current().Zone
	u.mu.Unlock()

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	for _, rr := range z.RRs() {
		h := rr.Header()
		if equalName(h.Name, q.Name) && h.Rrtype == q.Qtype {
			m.Answer = append(m.Answer, rr)
		}
	}
	if len(m.Answer) == 0 {
		if soa := z.SOA(); soa != nil {
			m.Ns = append(m.Ns, soa)
		}
	}
	_ = w.WriteMsg(m)
}

func (u *Upstream) serveAXFR(w dns.ResponseWriter, r *dns.Msg) {
	u.mu.Lock()
	z := u.hist.Current().Zone
	serial := z.Serial()
	u.xfrs = append(u.xfrs, XferObs{
		At: time.Now(), From: w.RemoteAddr().String(),
		Qtype: dns.TypeAXFR, Outcome: "axfr", CurSerial: serial,
	})
	u.mu.Unlock()

	u.writeTransfer(w, r, axfrRRs(z))
}

// serveIXFR answers per RFC 1995. Three outcomes, and the rig records which:
// an incremental answer, a single SOA when the client is already current, and
// an AXFR fallback when the client's serial is unknown or has aged out.
func (u *Upstream) serveIXFR(w dns.ResponseWriter, r *dns.Msg) {
	clientSerial, ok := clientSerialFromIXFR(r)
	if !ok {
		u.refuse(w, r, dns.RcodeFormatError)
		return
	}

	u.mu.Lock()
	cur := u.hist.Current().Zone
	curSerial := cur.Serial()
	deltas, known := u.hist.DeltasSince(clientSerial)
	var rrs []dns.RR
	obs := XferObs{
		At: time.Now(), From: w.RemoteAddr().String(),
		Qtype: dns.TypeIXFR, ClientSerial: clientSerial, CurSerial: curSerial,
	}
	switch {
	case !known:
		obs.Outcome = "fallback"
		rrs = axfrRRs(cur)
	case len(deltas) == 0:
		obs.Outcome = "uptodate"
		rrs = []dns.RR{cur.SOA()}
	default:
		obs.Outcome = "ixfr"
		obs.Sequences = len(deltas)
		rrs = u.ixfrRRsLocked(cur, deltas)
	}
	u.xfrs = append(u.xfrs, obs)
	u.mu.Unlock()

	u.writeTransfer(w, r, rrs)
}

// ixfrRRsLocked builds the RFC 1995 §4 stream: the current SOA, then one
// difference sequence per delta (old SOA, deletions, new SOA, additions), then
// the current SOA again. Called with u.mu held.
func (u *Upstream) ixfrRRsLocked(cur *Zone, deltas []Delta) []dns.RR {
	out := []dns.RR{cur.SOA()}
	for _, d := range deltas {
		from := u.hist.VersionBySerial(d.From)
		to := u.hist.VersionBySerial(d.To)
		if from == nil || to == nil {
			// Cannot happen: DeltasSince only returns deltas between versions
			// it still holds. Falling back to AXFR beats emitting a stream
			// with a missing SOA that the client would misparse.
			return axfrRRs(cur)
		}
		out = append(out, from.Zone.SOA())
		out = append(out, d.Removed...)
		out = append(out, to.Zone.SOA())
		out = append(out, d.Added...)
	}
	return append(out, cur.SOA())
}

// axfrRRs is the whole zone with the SOA first and last, as AXFR requires.
func axfrRRs(z *Zone) []dns.RR {
	soa := z.SOA()
	out := []dns.RR{soa}
	for _, rr := range z.RRs() {
		if isApexSOA(rr, z.Origin) {
			continue
		}
		out = append(out, rr)
	}
	return append(out, soa)
}

// writeTransfer chunks rrs into envelopes and hands them to miekg's Out. The
// channel is pre-filled and closed rather than fed by a goroutine: Out returns
// early on a write error, and a producer goroutine would then block forever on
// a channel nobody drains.
func (u *Upstream) writeTransfer(w dns.ResponseWriter, r *dns.Msg, rrs []dns.RR) {
	envs := make([]*dns.Envelope, 0, len(rrs)/envelopeRRs+1)
	for i := 0; i < len(rrs); i += envelopeRRs {
		end := min(i+envelopeRRs, len(rrs))
		envs = append(envs, &dns.Envelope{RR: rrs[i:end]})
	}
	ch := make(chan *dns.Envelope, len(envs))
	for _, e := range envs {
		ch <- e
	}
	close(ch)
	tr := new(dns.Transfer)
	if err := tr.Out(w, r, ch); err != nil {
		u.mu.Lock()
		if n := len(u.xfrs); n > 0 {
			u.xfrs[n-1].Err = err.Error()
		}
		u.mu.Unlock()
	}
}

// clientSerialFromIXFR reads the serial the client says it holds, from the SOA
// in the authority section (RFC 1995 §3).
func clientSerialFromIXFR(r *dns.Msg) (uint32, bool) {
	for _, rr := range r.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa.Serial, true
		}
	}
	return 0, false
}

// VersionBySerial finds a still-held version. Returns nil once it has aged out
// past the history cap.
func (h *History) VersionBySerial(serial uint32) *Version {
	for i := range h.versions {
		if h.versions[i].Serial == serial {
			return &h.versions[i]
		}
	}
	return nil
}
