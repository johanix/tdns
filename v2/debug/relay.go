/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package debug

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"sort"
	"strings"
	"time"

	"github.com/johanix/tdns/v2/debug/peer"
	"github.com/miekg/dns"
)

// The relay family. See docs/2026-09-05-notify-semantics-rig.md.
//
// The rig sits on both sides of the SUT: it authors a change upstream, NOTIFYs
// the SUT, serves the transfer the SUT asks for, then receives the SUT's own
// NOTIFYs and transfers the result back. One inbound change; count what comes
// out.

// RelayConfig parameterizes a relay run.
type RelayConfig struct {
	Zone             string
	SUT              string // addr:port of the tdns-auth under test
	UpstreamListen   string
	DownstreamListen string

	Rounds       int
	Settle       time.Duration // quiet period that ends a round
	RoundTimeout time.Duration // hard cap on one round
	HistoryCap   int
	Seed         int64
	// DownstreamDelay makes the downstream peer sit on each NOTIFY before
	// answering, provoking the lock-holding hazard in design §2.2. Zero by
	// default; nothing scores it yet.
	DownstreamDelay time.Duration

	Tool   string
	TestId string
}

// Verdict is three-valued on purpose. The rig races the server it measures: a
// defective intermediate state lasts only as long as a signing pass, and not
// observing it is not evidence it did not happen. A round the observations
// cannot decide is reported as a skip, never as a pass.
type Verdict struct {
	Result string `json:"result"` // pass | fail | inconclusive
	Detail string `json:"detail,omitempty"`
}

const (
	VerdictPass         = "pass"
	VerdictFail         = "fail"
	VerdictInconclusive = "inconclusive"
)

func pass() Verdict                      { return Verdict{Result: VerdictPass} }
func fail(f string, a ...any) Verdict    { return Verdict{VerdictFail, fmt.Sprintf(f, a...)} }
func unknown(f string, a ...any) Verdict { return Verdict{VerdictInconclusive, fmt.Sprintf(f, a...)} }

// StateObs is one published state the downstream peer actually inspected.
type StateObs struct {
	Serial uint32    `json:"serial"`
	At     time.Time `json:"at"`
	zone   *peer.Zone
}

// RoundResult is one authored change and everything that followed it. The
// human table and the JSON are the same record; there is no third rendering.
type RoundResult struct {
	Round          int                `json:"round"`
	Change         string             `json:"change"`
	UpstreamSerial uint32             `json:"upstream_serial"`
	BaseSerial     uint32             `json:"base_serial"` // what the SUT served before the change
	Notifies       int                `json:"notifies"`
	NotifySerials  []uint32           `json:"notify_serials"`
	RacedNotifies  int                `json:"raced_notifies"`
	NewSerials     []uint32           `json:"new_serials"` // distinct serials newer than BaseSerial
	States         []StateObs         `json:"states"`
	Transfers      int                `json:"transfers"`
	AxfrFallbacks  int                `json:"axfr_fallbacks"`
	DroppedXfers   int                `json:"dropped_transfers"`
	Quiesced       bool               `json:"quiesced"`
	Verdicts       map[string]Verdict `json:"verdicts"`
}

// RelayResult is the whole run, and becomes the report's Detail.
type RelayResult struct {
	Zone     string        `json:"zone"`
	SUT      string        `json:"sut"`
	Upstream string        `json:"upstream"`
	Down     string        `json:"downstream"`
	Rounds   []RoundResult `json:"rounds"`
}

// invariants, in report order.
var relayInvariants = []string{"N1", "N2", "N3", "N4", "N5", "N6", "N7"}

var invariantSummary = map[string]string{
	"N1": "one inbound change produces exactly one new published serial",
	"N2": "exactly one NOTIFY per published serial",
	"N3": "every announced state is fully signed",
	"N4": "content equals upstream, modulo DNSSEC and the SOA serial",
	"N5": "the deltas served express exactly the authored change",
	"N6": "the final state is internally consistent",
	"N7": "no version is signed twice",
}

type relay struct {
	cfg  RelayConfig
	up   *peer.Upstream
	down *peer.Downstream
	rep  *Report
	gen  *changeGen
}

// NewRelayPeers builds the rig's two peers from cfg and seeds the upstream.
//
// Separate from RunRelay so a caller can learn the peers' addresses before the
// run starts -- which is what makes the family testable against a controlled
// stand-in for the SUT, on ephemeral ports, with no port guessed in advance.
func NewRelayPeers(cfg RelayConfig) (*peer.Upstream, *peer.Downstream, error) {
	zone := dns.Fqdn(cfg.Zone)
	if cfg.HistoryCap <= 0 {
		cfg.HistoryCap = 32
	}
	if cfg.UpstreamListen == "" {
		cfg.UpstreamListen = "127.0.0.1:5361"
	}
	if cfg.DownstreamListen == "" {
		cfg.DownstreamListen = "127.0.0.1:5362"
	}

	// Seed the upstream ahead of wall-clock rather than at 1. The SUT may
	// already hold this zone at a serial of its own from an earlier run, and
	// RFC 1982 arithmetic would make a lower one look like no change at all --
	// the run would then measure nothing and read as clean.
	seedZone, err := buildSeedZone(zone, uint32(time.Now().Unix()))
	if err != nil {
		return nil, nil, err
	}
	up, err := peer.NewUpstream(zone, cfg.UpstreamListen, seedZone, cfg.HistoryCap)
	if err != nil {
		return nil, nil, err
	}
	down, err := peer.NewDownstream(zone, cfg.DownstreamListen, cfg.SUT)
	if err != nil {
		up.Stop()
		return nil, nil, err
	}
	down.Delay = cfg.DownstreamDelay
	return up, down, nil
}

// RunRelay executes a relay run to completion against peers the caller has
// built and started.
func RunRelay(ctx context.Context, cfg RelayConfig, up *peer.Upstream, down *peer.Downstream) (*Report, *RelayResult, error) {
	if cfg.Rounds <= 0 {
		cfg.Rounds = 12
	}
	if cfg.Settle <= 0 {
		cfg.Settle = 10 * time.Second
	}
	if cfg.RoundTimeout <= 0 {
		cfg.RoundTimeout = 2 * time.Minute
	}
	zone := dns.Fqdn(cfg.Zone)

	rep := NewReport(cfg.Tool, "relay")
	rep.TestId = cfg.TestId
	rep.Zone = zone
	rep.Seed = cfg.Seed

	// Section 0 before anything else: a comparator that cannot report a
	// difference makes every PASS below it worthless.
	if err := section0(); err != nil {
		return nil, nil, fmt.Errorf("section 0 self-check failed, so no verdict below it would mean anything: %w", err)
	}
	rep.Stat("section0.checks", int64(section0Checks))

	r := &relay{cfg: cfg, up: up, down: down, rep: rep, gen: newChangeGen(zone, cfg.Seed)}

	if _, err := querySOASerial(ctx, cfg.SUT, zone); err != nil {
		return nil, nil, fmt.Errorf("pre-flight: %s does not answer SOA for %s (%w); "+
			"the SUT must be configured as a secondary of %s with %s as its only notify target "+
			"-- see `tdns-debug test relay --generate-config`",
			cfg.SUT, zone, err, up.Addr(), down.Addr())
	}

	// Prime: get the SUT onto our version of the zone and the downstream peer
	// onto the SUT's, so round 1 starts from a known baseline rather than from
	// whatever either happened to hold.
	if err := r.prime(ctx); err != nil {
		return nil, nil, fmt.Errorf("priming the SUT: %w", err)
	}

	res := &RelayResult{Zone: zone, SUT: cfg.SUT, Upstream: up.Addr(), Down: down.Addr()}
	for i := 1; i <= cfg.Rounds; i++ {
		rr, err := r.round(ctx, i)
		if err != nil {
			return nil, nil, fmt.Errorf("round %d: %w", i, err)
		}
		res.Rounds = append(res.Rounds, *rr)
		r.score(rr)
		if ctx.Err() != nil {
			break
		}
	}

	rep.Duration = time.Since(rep.StartedAt)
	rep.Detail = res
	return rep, res, nil
}

// prime brings the SUT up to our zone and the downstream peer up to the SUT's.
func (r *relay) prime(ctx context.Context) error {
	if _, err := r.up.Notify(ctx, r.cfg.SUT); err != nil {
		return fmt.Errorf("the SUT did not accept a NOTIFY: %w", err)
	}
	r.waitQuiescent(ctx, 0)
	if _, err := r.down.Transfer(ctx); err != nil {
		return fmt.Errorf("could not transfer %s from the SUT: %w", r.cfg.Zone, err)
	}
	if _, serial := r.down.Zone(); serial == 0 {
		return fmt.Errorf("the SUT served no usable zone for %s", r.cfg.Zone)
	}
	return nil
}

// round authors one change, announces it, waits for quiescence, and evaluates.
func (r *relay) round(ctx context.Context, n int) (*RoundResult, error) {
	_, base := r.down.Zone()
	r.down.Reset()

	c := r.gen.Next()
	v, err := r.up.Apply(c)
	if err != nil {
		return nil, err
	}
	rr := &RoundResult{Round: n, Change: c.String(), UpstreamSerial: v.Serial, BaseSerial: base}

	if _, err := r.up.Notify(ctx, r.cfg.SUT); err != nil {
		// A NOTIFY the SUT did not take is a setup problem for this round, not
		// a violation: nothing was announced, so nothing can be counted.
		rr.Verdicts = map[string]Verdict{}
		for _, inv := range relayInvariants {
			rr.Verdicts[inv] = unknown("the SUT did not accept the NOTIFY: %v", err)
		}
		return rr, nil
	}

	rr.Quiesced = r.waitQuiescent(ctx, base)

	// Reconcile: one last transfer, so the round's final state is observed even
	// if every NOTIFY-triggered transfer landed mid-flight.
	if _, err := r.down.Transfer(ctx); err != nil {
		r.rep.Stat("relay.reconcile_errors", 1)
	}

	r.collect(rr)
	r.evaluate(rr, c)
	return rr, nil
}

// waitQuiescent blocks until neither the NOTIFY count nor the SUT's serial has
// moved for cfg.Settle, or the round times out. Quiescence is what makes "how
// many states did THIS change produce" a question with an answer.
func (r *relay) waitQuiescent(ctx context.Context, base uint32) bool {
	const tick = 250 * time.Millisecond
	deadline := time.Now().Add(r.cfg.RoundTimeout)
	lastN, lastS := -1, base
	quietSince := time.Now()

	for {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(tick):
		}
		n := len(r.down.Notifies())
		s, err := querySOASerial(ctx, r.cfg.SUT, r.cfg.Zone)
		if err != nil {
			s = lastS // an unanswered probe is not evidence of movement
		}
		if n != lastN || s != lastS {
			lastN, lastS = n, s
			quietSince = time.Now()
		}
		if time.Since(quietSince) >= r.cfg.Settle {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
	}
}

// collect reduces the round's raw observations to the record the verdicts read.
func (r *relay) collect(rr *RoundResult) {
	seen := map[uint32]bool{}
	for _, o := range r.down.Notifies() {
		rr.Notifies++
		if o.Raced {
			rr.RacedNotifies++
		}
		if o.ProbeErr != "" {
			continue
		}
		rr.NotifySerials = append(rr.NotifySerials, o.ProbeSerial)
		if o.ProbeSerial != rr.BaseSerial {
			seen[o.ProbeSerial] = true
		}
	}

	for _, x := range r.down.Transfers() {
		rr.Transfers++
		if x.Kind == peer.KindFallback {
			rr.AxfrFallbacks++
		}
		if x.Err != "" || x.Kind == peer.KindUpToDate || x.State == nil {
			continue
		}
		if x.Serial != rr.BaseSerial {
			seen[x.Serial] = true
		}
		// One entry per distinct serial: several transfers can land on the
		// same published state, and that is not several states.
		dup := false
		for _, st := range rr.States {
			if st.Serial == x.Serial {
				dup = true
				break
			}
		}
		if !dup {
			rr.States = append(rr.States, StateObs{Serial: x.Serial, At: x.At, zone: x.State})
		}
	}
	sort.Slice(rr.States, func(i, j int) bool { return rr.States[i].At.Before(rr.States[j].At) })

	for s := range seen {
		rr.NewSerials = append(rr.NewSerials, s)
	}
	sort.Slice(rr.NewSerials, func(i, j int) bool { return rr.NewSerials[i] < rr.NewSerials[j] })
	rr.DroppedXfers = r.down.Dropped()
}

// evaluate decides each invariant for one round. Every branch that cannot
// decide says so rather than defaulting either way.
func (r *relay) evaluate(rr *RoundResult, c peer.Change) {
	rr.Verdicts = map[string]Verdict{}
	final, finalSerial := r.down.Zone()
	newStates := len(rr.NewSerials)

	// --- N1: one change, one new published serial.
	switch {
	case !rr.Quiesced:
		rr.Verdicts["N1"] = unknown("the round never went quiet; more states may still have been coming")
	case rr.DroppedXfers > 0:
		rr.Verdicts["N1"] = unknown("%d transfer(s) were dropped, so a published state may have gone unobserved", rr.DroppedXfers)
	case newStates == 1:
		rr.Verdicts["N1"] = pass()
	case newStates == 0:
		rr.Verdicts["N1"] = fail("the change was never published: the SUT still serves serial %d", rr.BaseSerial)
	default:
		rr.Verdicts["N1"] = fail("one inbound change produced %d new serials (%s)", newStates, serialList(rr.NewSerials))
	}

	// --- N2: one NOTIFY per published serial.
	//
	// Decided from the two counts, not from probe attribution. The NOTIFY
	// count is a packet count and therefore exact; the state count is a lower
	// bound from what the downstream actually saw. More announcements than
	// states means at least one version was announced twice, and that holds
	// however the individual probes landed.
	switch {
	case !rr.Quiesced:
		rr.Verdicts["N2"] = unknown("the round never went quiet")
	case rr.DroppedXfers > 0:
		rr.Verdicts["N2"] = unknown("%d transfer(s) were dropped, so a published state may have gone unobserved", rr.DroppedXfers)
	case rr.RacedNotifies > 0:
		rr.Verdicts["N2"] = unknown("the SUT's serial went backwards between probes (%d affected), so no serial can be attributed", rr.RacedNotifies)
	case rr.Notifies == newStates:
		rr.Verdicts["N2"] = pass()
	case rr.Notifies > newStates:
		rr.Verdicts["N2"] = fail("%d NOTIFYs for %d published serial(s) — at least one version was announced twice (probed serials: %s)",
			rr.Notifies, newStates, serialList(rr.NotifySerials))
	default:
		rr.Verdicts["N2"] = fail("%d NOTIFYs for %d published serial(s) — a version was published without being announced",
			rr.Notifies, newStates)
	}

	// --- N3: every announced state is fully signed.
	switch {
	case len(rr.States) == 0:
		rr.Verdicts["N3"] = unknown("no published state was inspected")
	case len(rr.States) < newStates:
		rr.Verdicts["N3"] = unknown("only %d of %d published states were inspected; an unsigned one may have been superseded before it could be transferred",
			len(rr.States), newStates)
	default:
		var bad []string
		for _, st := range rr.States {
			rep := peer.CheckSigning(st.zone)
			if !rep.FullySigned() {
				bad = append(bad, fmt.Sprintf("serial %d: %s", st.Serial, firstLine(rep.String())))
			}
		}
		if len(bad) > 0 {
			rr.Verdicts["N3"] = fail("%d announced state(s) were not fully signed: %s", len(bad), strings.Join(bad, "; "))
		} else {
			rr.Verdicts["N3"] = pass()
		}
	}

	// --- N4: content equality with upstream.
	cur := r.up.Current()
	switch {
	case final == nil:
		rr.Verdicts["N4"] = unknown("the downstream peer holds no zone")
	case finalSerial == rr.BaseSerial:
		rr.Verdicts["N4"] = unknown("the SUT never advanced past serial %d, so there is no new content to compare", rr.BaseSerial)
	default:
		if d := peer.CompareContent(cur.Zone, final); d.Equal() {
			rr.Verdicts["N4"] = pass()
		} else {
			rr.Verdicts["N4"] = fail("%s", d)
		}
	}

	// --- N5: the deltas express the authored change.
	var deltas []peer.Delta
	for _, x := range r.down.Transfers() {
		deltas = append(deltas, x.Deltas...)
	}
	switch {
	case rr.AxfrFallbacks > 0:
		rr.Verdicts["N5"] = unknown("%d whole-zone fallback(s) in this round carry no deltas to compare", rr.AxfrFallbacks)
	case len(deltas) == 0:
		rr.Verdicts["N5"] = unknown("no deltas were served")
	default:
		if d := peer.CompareDelta(c, deltas); d.Equal() {
			rr.Verdicts["N5"] = pass()
		} else {
			rr.Verdicts["N5"] = fail("%s", d)
		}
	}

	// --- N6: the final state is internally consistent.
	if final == nil {
		rr.Verdicts["N6"] = unknown("the downstream peer holds no zone")
	} else {
		rep := peer.CheckSigning(final)
		switch {
		case !rep.Signed:
			rr.Verdicts["N6"] = fail("the served zone carries no signatures at all")
		case len(rep.Issues) > 0:
			rr.Verdicts["N6"] = fail("%s", firstLine(rep.String()))
		case rep.ChainSkipped != "":
			rr.Verdicts["N6"] = Verdict{VerdictPass, "coverage checked; chain skipped: " + rep.ChainSkipped}
		default:
			rr.Verdicts["N6"] = pass()
		}
	}

	// --- N7: no version signed twice.
	//
	// The rig cannot see a signing pass. It can see its fingerprint: two
	// successive states whose content is identical modulo DNSSEC, but whose
	// RRSIGs differ, can only be one version signed twice.
	if len(rr.States) < 2 {
		rr.Verdicts["N7"] = unknown("fewer than two published states were inspected")
	} else {
		var dup []string
		for i := 1; i < len(rr.States); i++ {
			a, b := rr.States[i-1], rr.States[i]
			if !peer.CompareContent(a.zone, b.zone).Equal() {
				continue
			}
			if sigsEqual(a.zone, b.zone) {
				continue
			}
			dup = append(dup, fmt.Sprintf("serial %d re-signs the content already published at serial %d", b.Serial, a.Serial))
		}
		if len(dup) > 0 {
			rr.Verdicts["N7"] = fail("%s", strings.Join(dup, "; "))
		} else {
			rr.Verdicts["N7"] = pass()
		}
	}
}

// score folds a round's verdicts into the run report.
func (r *relay) score(rr *RoundResult) {
	r.rep.Stat("relay.rounds", 1)
	r.rep.Stat("relay.notifies", int64(rr.Notifies))
	r.rep.Stat("relay.new_serials", int64(len(rr.NewSerials)))
	r.rep.Stat("relay.states_inspected", int64(len(rr.States)))
	r.rep.Stat("relay.axfr_fallbacks", int64(rr.AxfrFallbacks))
	if !rr.Quiesced {
		r.rep.Stat("relay.rounds_not_quiesced", 1)
	}
	for _, inv := range relayInvariants {
		v := rr.Verdicts[inv]
		switch v.Result {
		case VerdictFail:
			r.rep.Stat("relay."+inv+".fail", 1)
			r.rep.Violate(inv, fmt.Sprintf("round %d: %s", rr.Round, invariantSummary[inv]), v.Detail)
		case VerdictInconclusive:
			r.rep.Stat("relay."+inv+".inconclusive", 1)
			r.rep.Skip(fmt.Sprintf("%s round %d", inv, rr.Round), v.Detail)
		default:
			r.rep.Stat("relay."+inv+".pass", 1)
		}
	}
}

// --- helpers ---------------------------------------------------------------

func sigsEqual(a, b *peer.Zone) bool {
	return strings.Join(rrsigTexts(a), "\n") == strings.Join(rrsigTexts(b), "\n")
}

func rrsigTexts(z *peer.Zone) []string {
	var out []dns.RR
	for _, rr := range z.RRs() {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			out = append(out, rr)
		}
	}
	return peer.SortedTexts(out)
}

func serialList(s []uint32) string {
	parts := make([]string, 0, len(s))
	for _, v := range s {
		parts = append(parts, fmt.Sprint(v))
	}
	return strings.Join(parts, ", ")
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i]) + " (…)"
	}
	return s
}

// buildSeedZone is the zone every run starts from: an apex, one nameserver,
// and a handful of hosts for the change generator to work on.
func buildSeedZone(zone string, serial uint32) (*peer.Zone, error) {
	lines := []string{
		fmt.Sprintf("%s 3600 IN SOA ns.%s hostmaster.%s %d 7200 1800 604800 3600", zone, zone, zone, serial),
		fmt.Sprintf("%s 3600 IN NS ns.%s", zone, zone),
		fmt.Sprintf("ns.%s 3600 IN A 127.0.0.1", zone),
	}
	for i := 1; i <= 5; i++ {
		lines = append(lines, fmt.Sprintf("host%02d.%s 3600 IN A 10.0.0.%d", i, zone, i))
	}
	var rrs []dns.RR
	for _, l := range lines {
		rr, err := dns.NewRR(l)
		if err != nil {
			return nil, fmt.Errorf("building the seed zone: %w", err)
		}
		rrs = append(rrs, rr)
	}
	return peer.ZoneFromRRs(zone, rrs), nil
}

// changeGen produces the round's edits from a seeded RNG, so a run is
// reproducible from --seed alone.
type changeGen struct {
	zone string
	rng  *rand.Rand
	live []dns.RR // what this generator has added and not yet removed
	seq  int
}

func newChangeGen(zone string, seed int64) *changeGen {
	return &changeGen{zone: dns.Fqdn(zone), rng: rand.New(rand.NewSource(seed))}
}

// Next returns one edit. The four shapes are not arbitrary: "grow" exists
// because it is the only one where a delta must carry a removal AND an
// addition for the same owner and type, which is where an IXFR applier is
// most easily wrong.
func (g *changeGen) Next() peer.Change {
	kind := g.rng.Intn(4)
	if len(g.live) == 0 {
		kind = 0
	}
	switch kind {
	case 1:
		i := g.rng.Intn(len(g.live))
		rr := g.live[i]
		g.live = append(g.live[:i], g.live[i+1:]...)
		return peer.Change{Label: "delete", Remove: []dns.RR{rr}}
	case 2:
		i := g.rng.Intn(len(g.live))
		old := g.live[i]
		g.seq++
		fresh := g.rr(old.Header().Name)
		g.live[i] = fresh
		return peer.Change{Label: "replace", Remove: []dns.RR{old}, Add: []dns.RR{fresh}}
	case 3:
		owner := g.live[g.rng.Intn(len(g.live))].Header().Name
		g.seq++
		extra := g.rr(owner)
		g.live = append(g.live, extra)
		return peer.Change{Label: "grow", Add: []dns.RR{extra}}
	default:
		g.seq++
		rr := g.rr(fmt.Sprintf("r%03d.%s", g.seq, g.zone))
		g.live = append(g.live, rr)
		return peer.Change{Label: "add", Add: []dns.RR{rr}}
	}
}

func (g *changeGen) rr(owner string) dns.RR {
	rr, err := dns.NewRR(fmt.Sprintf("%s 3600 IN A 10.%d.%d.%d",
		dns.Fqdn(owner), 100+g.seq/65536, (g.seq/256)%256, g.seq%256))
	if err != nil {
		// Unreachable: the owner came from a parsed RR and the rdata is
		// generated. Panicking beats returning a nil RR into a Change.
		panic(fmt.Sprintf("changeGen: building %s: %v", owner, err))
	}
	return rr
}

// RenderRounds prints the per-round table. The verdict columns are the same
// values the JSON carries; the table is a view of the record, not a summary.
func RenderRounds(w io.Writer, res *RelayResult) {
	fmt.Fprintf(w, "\nrelay rounds (zone %s, SUT %s, upstream %s, downstream %s)\n",
		res.Zone, res.SUT, res.Upstream, res.Down)
	fmt.Fprintf(w, "%-5s %-28s %8s %8s %7s  %s\n", "round", "change", "notifies", "serials", "states", "verdicts")
	for _, rr := range res.Rounds {
		var v []string
		for _, inv := range relayInvariants {
			switch rr.Verdicts[inv].Result {
			case VerdictPass:
				v = append(v, inv+":ok")
			case VerdictFail:
				v = append(v, inv+":FAIL")
			default:
				v = append(v, inv+":?")
			}
		}
		fmt.Fprintf(w, "%-5d %-28s %8d %8d %7d  %s\n",
			rr.Round, truncate(rr.Change, 28), rr.Notifies, len(rr.NewSerials), len(rr.States),
			strings.Join(v, " "))
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
