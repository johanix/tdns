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

// NotifyObs is one NOTIFY the SUT sent us.
//
// ProbeSerial is a PROBE, not a read: tdns's outbound NOTIFY carries no SOA in
// the answer section (design §2.4), so the only way to learn which state was
// being announced is to ask, and that question races the SUT's next publish.
// The NOTIFY count is always exact — it is a packet count. Only the serial
// attribution can be uncertain, and Raced says when it is.
type NotifyObs struct {
	Seq         int
	At          time.Time
	From        string
	Rcode       int
	ProbeAt     time.Time
	ProbeSerial uint32
	ProbeErr    string
	// Raced is set when a LATER NOTIFY's probe came back with a serial STRICTLY
	// LOWER than this one's: the serial went backwards between two probes, so
	// neither can be trusted to describe the state its own NOTIFY announced.
	//
	// Two NOTIFYs probing the SAME serial is deliberately NOT flagged. It is
	// ambiguous on its own -- either one version announced twice, or a probe
	// that overshot and saw the next version -- and the count of states the
	// peer actually transferred settles it. Flagging it here would turn the
	// evidence into an excuse for saying nothing.
	Raced bool
}

// DownstreamXfer is one transfer this peer pulled from the SUT.
type DownstreamXfer struct {
	At            time.Time
	TriggeredBy   int // NotifyObs.Seq, or 0 for a transfer the rig asked for directly
	RequestedIXFR bool
	RequestSerial uint32
	Kind          TransferKind
	Serial        uint32
	Deltas        []Delta
	Zone          *Zone // whole-zone answers only; Zone() holds the running state
	// State is the zone as this peer held it AFTER applying the transfer: the
	// content the SUT was serving at Serial. Kept per transfer, not only as
	// the running state, because N3 and N7 are about the SEQUENCE of published
	// states -- an intermediate one that is only ever overwritten is exactly
	// the state worth reporting on.
	State *Zone
	Err   string
}

// Downstream is the rig's own secondary: it accepts the SUT's NOTIFYs, probes
// what the SUT is serving, and transfers the result for analysis.
//
// It transfers once per NOTIFY rather than coalescing the way a real secondary
// would. Coalescing is correct behaviour and wrong instrumentation: an
// intermediate published state that no transfer observed is a state the rig
// cannot report on.
type Downstream struct {
	Origin string
	SUT    string // addr:port to probe and transfer from

	// Delay is how long to sit on a NOTIFY before answering it. Zero by
	// default. Non-zero provokes the hazard in design §2.2 — NotifyDownstreams
	// runs under zd.mu, so a slow downstream holds the SUT's zone lock.
	Delay time.Duration

	mu       sync.Mutex
	notifies []NotifyObs
	xfers    []DownstreamXfer
	zone     *Zone
	serial   uint32

	xferMu sync.Mutex // serializes transfers, whoever starts them

	addr    string
	udp     *dns.Server
	tcp     *dns.Server
	queue   chan int
	dropped int
	wg      sync.WaitGroup
	closed  sync.Once
}

// NewDownstream binds the NOTIFY listeners. As with the upstream peer, TCP is
// bound first and UDP reuses its port, so a ":0" address still names one peer.
func NewDownstream(origin, listen, sut string) (*Downstream, error) {
	d := &Downstream{
		Origin: dns.Fqdn(origin),
		SUT:    sut,
		queue:  make(chan int, 256),
	}
	l, pc, err := bindPair(listen)
	if err != nil {
		return nil, fmt.Errorf("downstream peer: listening on %s: %w", listen, err)
	}
	d.addr = l.Addr().String()
	d.tcp = &dns.Server{Listener: l, Handler: dns.HandlerFunc(d.handle)}
	d.udp = &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(d.handle)}
	return d, nil
}

func (d *Downstream) Start() {
	go func() { _ = d.tcp.ActivateAndServe() }()
	go func() { _ = d.udp.ActivateAndServe() }()
	d.wg.Add(1)
	go d.transferWorker()
}

// Stop shuts the listeners down and waits for the in-flight transfer. The
// queue is closed only once, so a double Stop is safe.
func (d *Downstream) Stop() {
	d.closed.Do(func() {
		_ = d.tcp.Shutdown()
		_ = d.udp.Shutdown()
		close(d.queue)
	})
	d.wg.Wait()
}

func (d *Downstream) Addr() string { return d.addr }

func (d *Downstream) Notifies() []NotifyObs {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]NotifyObs(nil), d.notifies...)
}

func (d *Downstream) Transfers() []DownstreamXfer {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]DownstreamXfer(nil), d.xfers...)
}

// Dropped counts transfers the queue could not accept. Non-zero means the rig
// under-observed and its state counts are lower bounds.
func (d *Downstream) Dropped() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dropped
}

// Zone returns the last zone state this peer holds, and its serial.
func (d *Downstream) Zone() (*Zone, uint32) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.zone == nil {
		return nil, 0
	}
	return d.zone.Clone(), d.serial
}

// Reset clears the observation record and the held zone, so each round is
// scored on its own observations rather than on the run so far.
func (d *Downstream) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.notifies = nil
	d.xfers = nil
	d.dropped = 0
}

// --- NOTIFY side -----------------------------------------------------------

func (d *Downstream) handle(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	if r.Opcode != dns.OpcodeNotify || len(r.Question) != 1 || !equalName(r.Question[0].Name, d.Origin) {
		m.Rcode = dns.RcodeRefused
		_ = w.WriteMsg(m)
		return
	}

	// Probe BEFORE answering: the SUT's next publish may be moments away, and
	// the earlier the probe the better its chance of describing the state this
	// NOTIFY was about.
	probeAt := time.Now()
	serial, err := d.probeSerial()

	d.mu.Lock()
	obs := NotifyObs{
		Seq: len(d.notifies) + 1, At: probeAt, From: w.RemoteAddr().String(),
		Rcode: dns.RcodeSuccess, ProbeAt: probeAt, ProbeSerial: serial,
	}
	if err != nil {
		obs.ProbeErr = err.Error()
	}
	// A serial that went BACKWARDS between two probes makes both unusable.
	for i := range d.notifies {
		if d.notifies[i].ProbeErr == "" && err == nil && d.notifies[i].ProbeSerial > serial {
			d.notifies[i].Raced = true
		}
	}
	d.notifies = append(d.notifies, obs)
	seq := obs.Seq
	d.mu.Unlock()

	select {
	case d.queue <- seq:
	default:
		d.mu.Lock()
		d.dropped++
		d.mu.Unlock()
	}

	if d.Delay > 0 {
		time.Sleep(d.Delay)
	}
	_ = w.WriteMsg(m)
}

func (d *Downstream) probeSerial() (uint32, error) {
	m := new(dns.Msg)
	m.SetQuestion(d.Origin, dns.TypeSOA)
	m.SetEdns0(1232, false)
	c := &dns.Client{Timeout: 3 * time.Second}
	r, _, err := c.Exchange(m, d.SUT)
	if err != nil {
		return 0, err
	}
	for _, rr := range r.Answer {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa.Serial, nil
		}
	}
	return 0, fmt.Errorf("no SOA in the SUT's answer (rcode %s)", dns.RcodeToString[r.Rcode])
}

// --- transfer side ---------------------------------------------------------

func (d *Downstream) transferWorker() {
	defer d.wg.Done()
	for seq := range d.queue {
		_, _ = d.transfer(context.Background(), seq)
	}
}

// Transfer pulls once, on the rig's initiative rather than a NOTIFY's. Used
// for a round's baseline and for the final reconcile after quiescence.
func (d *Downstream) Transfer(ctx context.Context) (DownstreamXfer, error) {
	return d.transfer(ctx, 0)
}

// transfer requests IXFR from the serial this peer holds, falling back to AXFR
// when it holds nothing yet, and records what came back.
func (d *Downstream) transfer(ctx context.Context, triggeredBy int) (DownstreamXfer, error) {
	d.xferMu.Lock()
	defer d.xferMu.Unlock()

	d.mu.Lock()
	from := d.serial
	d.mu.Unlock()

	x := DownstreamXfer{
		At: time.Now(), TriggeredBy: triggeredBy,
		RequestedIXFR: from != 0, RequestSerial: from,
	}

	m := new(dns.Msg)
	if x.RequestedIXFR {
		m.SetIxfr(d.Origin, from, "ns."+d.Origin, "hostmaster."+d.Origin)
	} else {
		m.SetAxfr(d.Origin)
	}

	rrs, err := d.exchangeTransfer(ctx, m)
	if err != nil {
		x.Err = err.Error()
		d.record(x)
		return x, err
	}

	res, err := ParseTransfer(d.Origin, rrs, x.RequestedIXFR)
	if err != nil {
		x.Err = err.Error()
		x.Kind = KindUnparseable
		d.record(x)
		return x, err
	}
	x.Kind = res.Kind
	x.Serial = res.Serial
	x.Deltas = res.Deltas
	x.Zone = res.Zone

	d.mu.Lock()
	switch res.Kind {
	case KindAXFR, KindFallback:
		d.zone = res.Zone
		d.serial = res.Serial
	case KindIXFR:
		// Apply the deltas to what we hold. Reconstructing rather than
		// re-AXFRing is deliberate: it means the zone this peer reports is the
		// one the SUT's own deltas produce, so a delta that does not say what
		// it should shows up as a content difference rather than being papered
		// over by a whole-zone refetch.
		if d.zone == nil {
			d.mu.Unlock()
			err := fmt.Errorf("IXFR of %s applied to no baseline zone", d.Origin)
			x.Err = err.Error()
			d.record(x)
			return x, err
		}
		z := d.zone.Clone()
		for _, delta := range res.Deltas {
			for _, rr := range delta.Removed {
				z.Remove(rr)
			}
			for _, rr := range delta.Added {
				z.Add(rr)
			}
		}
		if err := z.SetSerial(res.Serial); err != nil {
			d.mu.Unlock()
			x.Err = err.Error()
			d.record(x)
			return x, err
		}
		d.zone = z
		d.serial = res.Serial
	case KindUpToDate:
		// Nothing changed; keep what we hold.
	}
	if d.zone != nil {
		x.State = d.zone.Clone()
	}
	d.mu.Unlock()

	d.record(x)
	return x, nil
}

func (d *Downstream) record(x DownstreamXfer) {
	d.mu.Lock()
	d.xfers = append(d.xfers, x)
	d.mu.Unlock()
}

// exchangeTransfer runs the transfer and drains it. miekg's Transfer.In takes
// no context and its receive loop can block for ReadTimeout, so the connection
// is closed on cancellation to unblock the range — the same pattern the churn
// family's AXFR actor uses.
func (d *Downstream) exchangeTransfer(ctx context.Context, m *dns.Msg) ([]dns.RR, error) {
	tr := &dns.Transfer{DialTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second}
	ch, err := tr.In(m, d.SUT)
	if err != nil {
		return nil, err
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			tr.Close()
		case <-done:
		}
	}()

	var out []dns.RR
	for env := range ch {
		if env.Error != nil {
			return nil, env.Error
		}
		out = append(out, env.RR...)
	}
	return out, nil
}
