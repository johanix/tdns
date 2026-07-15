/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package debug

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// PerfConfig configures the adaptive max-QPS finder (tdns-debug perf qps). It
// stresses ONLY the query path: it queries the zone apex for SOA at a given
// rate for Duration, drains for Timeout, and counts exactly how many correct
// answers came back. A step is "clean" iff the drop fraction is <= MaxDropRate.
// The search doubles the rate while clean (to bracket the ceiling), then
// bisects between the last clean rate and the first dropping rate until the gap
// is below Threshold.
type PerfConfig struct {
	Tool        string
	Target      string        // DNS server addr (ip or ip:port; default port 53)
	Zone        string        // apex; queried as SOA
	UDP         bool          // drive the rate search over UDP
	TCP         bool          // also send 10% of the UDP rate over TCP (reported separately)
	InitialQPS  int           // starting rate
	Threshold   int           // stop bisect when (firstBad - lastGood) < Threshold
	Duration    time.Duration // send window per rate step
	Timeout     time.Duration // straggler drain after each send window
	MaxDropRate float64       // step clean iff (sent-correct)/sent <= this
	MaxQPS      int           // safety cap
}

// PerfStep is one rate step's EXACT accounting. Every query and every correct
// response is counted — a single drop out of 100k is visible.
type PerfStep struct {
	Rate        int
	Sent        int64
	Received    int64   // any datagram back
	Correct     int64   // valid NOERROR SOA response for the apex
	Bad         int64   // received but SERVFAIL / malformed / truncated / wrong
	Lost        int64   // sent - received
	DropRate    float64 // (sent - correct) / sent
	AchievedQPS float64 // sent / duration (flags a client that couldn't reach the target)
	Clean       bool

	// TCP parallel stressor (only when cfg.TCP); reported separately, does NOT
	// drive the search.
	TCPOffered      int64
	TCPCompleted    int64
	TCPCorrect      int64
	TCPBad          int64
	TCPUndispatched int64 // offered but no worker free to dial (TCP path saturated)
}

// RunQPS runs the adaptive search and returns a Report with the final numbers.
// It prints a live per-step table (exact counts) to stdout as it runs.
func RunQPS(ctx context.Context, cfg PerfConfig) (*Report, error) {
	if !cfg.UDP && !cfg.TCP {
		cfg.UDP = true
	}
	if !cfg.UDP {
		return nil, fmt.Errorf("--tcp requires --udp: UDP drives the rate search, TCP is only a parallel stressor")
	}
	if cfg.InitialQPS <= 0 {
		cfg.InitialQPS = 1000
	}
	if cfg.Duration <= 0 {
		cfg.Duration = 5 * time.Second
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = time.Second
	}
	if cfg.Threshold <= 0 {
		cfg.Threshold = 1000
	}
	if cfg.MaxDropRate <= 0 {
		cfg.MaxDropRate = 0.005
	}
	if cfg.MaxQPS <= 0 {
		cfg.MaxQPS = 1_000_000
	}
	if _, _, err := net.SplitHostPort(cfg.Target); err != nil {
		cfg.Target = net.JoinHostPort(cfg.Target, "53")
	}

	rep := NewReport(cfg.Tool, "perf-qps")
	rep.Zone = cfg.Zone

	// Pre-flight: one SOA must succeed, else this is a setup error (exit 2).
	if _, err := querySOASerial(ctx, cfg.Target, cfg.Zone); err != nil {
		return nil, fmt.Errorf("pre-flight SOA query to %s for %s failed: %w", cfg.Target, cfg.Zone, err)
	}
	query, err := buildSOAQuery(cfg.Zone)
	if err != nil {
		return nil, fmt.Errorf("building SOA query: %w", err)
	}

	var w io.Writer = os.Stdout
	fmt.Fprintf(w, "== perf qps: %s @ %s (apex SOA) | step=%s drain=%s | clean<=%.3f%% drop | threshold=%d qps ==\n",
		cfg.Zone, cfg.Target, cfg.Duration, cfg.Timeout, cfg.MaxDropRate*100, cfg.Threshold)
	if cfg.TCP {
		fmt.Fprintf(w, "   TCP parallel stressor at 10%% of the UDP rate (reported separately; does not drive the search)\n")
	}

	lastGood := 0 // highest clean rate seen
	firstBad := 0 // lowest dropping rate seen (0 = none yet)
	rate := cfg.InitialQPS
	doubling := true

	for {
		if ctx.Err() != nil {
			fmt.Fprintln(w, "interrupted")
			break
		}
		if rate > cfg.MaxQPS {
			rate = cfg.MaxQPS
		}
		if rate < 1 {
			rate = 1
		}

		step := runUDPStep(ctx, cfg, rate, query)
		if cfg.TCP {
			applyTCP(&step, runTCPLoad(ctx, cfg, rate/10))
		}
		step.Clean = step.DropRate <= cfg.MaxDropRate
		printStep(w, cfg, step)

		if step.Clean {
			lastGood = rate
			if doubling {
				if rate >= cfg.MaxQPS {
					fmt.Fprintf(w, "-- reached --max-qps cap (%d) with no drops --\n", cfg.MaxQPS)
					break
				}
				rate *= 2
			} else {
				if firstBad-lastGood < cfg.Threshold {
					break
				}
				rate = lastGood + (firstBad-lastGood)/2
			}
		} else {
			firstBad = rate
			doubling = false
			if firstBad-lastGood < cfg.Threshold {
				break
			}
			rate = lastGood + (firstBad-lastGood)/2
		}
	}

	fmt.Fprintf(w, "\n== RESULT ==\n")
	fmt.Fprintf(w, "max sustainable UDP qps (<= %.3f%% drop): %d\n", cfg.MaxDropRate*100, lastGood)
	if firstBad > 0 {
		fmt.Fprintf(w, "first rate with drops: %d  (bisect gap %d < threshold %d)\n", firstBad, firstBad-lastGood, cfg.Threshold)
	}
	rep.Stat("max-sustainable-qps", int64(lastGood))
	if firstBad > 0 {
		rep.Stat("first-drop-qps", int64(firstBad))
	}
	if lastGood == 0 {
		rep.Skip("perf-qps", fmt.Sprintf("server dropped above %.3f%% even at the lowest tested rate (%d qps)", cfg.MaxDropRate*100, cfg.InitialQPS))
	}
	return rep, nil
}

// runUDPStep sends `rate` qps for cfg.Duration (evenly paced), drains for
// cfg.Timeout, and returns exact counts. A fresh connected socket per step
// isolates responses so late answers from a prior step cannot leak in.
func runUDPStep(ctx context.Context, cfg PerfConfig, rate int, query []byte) PerfStep {
	step := PerfStep{Rate: rate}
	apex := dns.Fqdn(cfg.Zone)
	conn, err := net.Dial("udp", cfg.Target)
	if err != nil {
		return step
	}
	defer conn.Close()

	var received, correct, bad int64
	recvDone := make(chan struct{})
	_ = conn.SetReadDeadline(time.Now().Add(cfg.Duration + cfg.Timeout))
	go func() {
		defer close(recvDone)
		buf := make([]byte, 4096)
		for {
			n, rerr := conn.Read(buf)
			if rerr != nil {
				return // read deadline (send window + drain) elapsed
			}
			atomic.AddInt64(&received, 1)
			if validSOAResponse(buf[:n], apex) {
				atomic.AddInt64(&correct, 1)
			} else {
				atomic.AddInt64(&bad, 1)
			}
		}
	}()

	// Even pacing: each tick, send up to the cumulative target for the elapsed
	// time. Self-corrects for jitter; not a burst.
	q := make([]byte, len(query))
	copy(q, query)
	var sent int64
	var id uint16
	start := time.Now()
	end := start.Add(cfg.Duration)
	tick := time.NewTicker(time.Millisecond)
	for {
		now := <-tick.C
		if !now.Before(end) {
			break
		}
		if ctx.Err() != nil {
			break
		}
		target := int64(float64(rate) * now.Sub(start).Seconds())
		for sent < target {
			id++
			q[0] = byte(id >> 8)
			q[1] = byte(id)
			if _, werr := conn.Write(q); werr != nil {
				break // kernel send buffer full (client/loopback limit) — surfaces as achieved<target
			}
			sent++
		}
	}
	tick.Stop()
	<-recvDone

	step.Sent = sent
	step.Received = atomic.LoadInt64(&received)
	step.Correct = atomic.LoadInt64(&correct)
	step.Bad = atomic.LoadInt64(&bad)
	step.Lost = step.Sent - step.Received
	if step.Lost < 0 {
		step.Lost = 0
	}
	if secs := cfg.Duration.Seconds(); secs > 0 {
		step.AchievedQPS = float64(step.Sent) / secs
	}
	if step.Sent > 0 {
		step.DropRate = float64(step.Sent-step.Correct) / float64(step.Sent)
	}
	return step
}

type tcpStats struct{ offered, completed, correct, bad, undispatched int64 }

// runTCPLoad runs a paced TCP query load at tcpRate for cfg.Duration via a
// bounded worker pool. Reported separately; never drives the UDP search.
func runTCPLoad(ctx context.Context, cfg PerfConfig, tcpRate int) tcpStats {
	var st tcpStats
	if tcpRate < 1 {
		return st
	}
	nworkers := tcpRate
	if nworkers > 200 {
		nworkers = 200
	}
	jobs := make(chan struct{}, nworkers*2)
	var completed, correct, bad int64
	var wg sync.WaitGroup
	for i := 0; i < nworkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
				atomic.AddInt64(&completed, 1)
				if tcpQueryOnce(cfg.Target, cfg.Zone, cfg.Timeout) {
					atomic.AddInt64(&correct, 1)
				} else {
					atomic.AddInt64(&bad, 1)
				}
			}
		}()
	}
	start := time.Now()
	end := start.Add(cfg.Duration)
	var queued, undispatched int64
	tick := time.NewTicker(time.Millisecond)
	for {
		now := <-tick.C
		if !now.Before(end) {
			break
		}
		if ctx.Err() != nil {
			break
		}
		target := int64(float64(tcpRate) * now.Sub(start).Seconds())
		for queued < target {
			select {
			case jobs <- struct{}{}:
			default:
				undispatched++ // all workers busy: TCP path can't keep up
			}
			queued++
		}
	}
	tick.Stop()
	close(jobs)
	wg.Wait()
	st.offered = queued
	st.completed = atomic.LoadInt64(&completed)
	st.correct = atomic.LoadInt64(&correct)
	st.bad = atomic.LoadInt64(&bad)
	st.undispatched = undispatched
	return st
}

func applyTCP(step *PerfStep, t tcpStats) {
	step.TCPOffered = t.offered
	step.TCPCompleted = t.completed
	step.TCPCorrect = t.correct
	step.TCPBad = t.bad
	step.TCPUndispatched = t.undispatched
}

func tcpQueryOnce(target, zone string, timeout time.Duration) bool {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(zone), dns.TypeSOA)
	m.SetEdns0(1232, false)
	c := &dns.Client{Net: "tcp", Timeout: timeout}
	r, _, err := c.Exchange(m, target)
	if err != nil || r == nil || r.Rcode != dns.RcodeSuccess {
		return false
	}
	apex := dns.Fqdn(zone)
	for _, rr := range r.Answer {
		if soa, ok := rr.(*dns.SOA); ok && strings.EqualFold(soa.Hdr.Name, apex) {
			return true
		}
	}
	return false
}

func buildSOAQuery(zone string) ([]byte, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(zone), dns.TypeSOA)
	m.SetEdns0(1232, false)
	return m.Pack()
}

// validSOAResponse reports whether wire is a well-formed NOERROR answer that
// actually carries the apex SOA. A SERVFAIL, a malformed packet, a truncated
// answer, or a wrong/empty answer all count as NOT correct.
func validSOAResponse(wire []byte, apex string) bool {
	var m dns.Msg
	if err := m.Unpack(wire); err != nil {
		return false
	}
	if !m.Response || m.Truncated || m.Rcode != dns.RcodeSuccess {
		return false
	}
	for _, rr := range m.Answer {
		if soa, ok := rr.(*dns.SOA); ok && strings.EqualFold(soa.Hdr.Name, apex) {
			return true
		}
	}
	return false
}

func printStep(w io.Writer, cfg PerfConfig, s PerfStep) {
	tag := "CLEAN"
	if !s.Clean {
		tag = "DROP"
	}
	fmt.Fprintf(w, "[udp] target=%-7d sent=%-8d recv=%-8d correct=%-8d bad=%-5d lost=%-6d drop=%.3f%% achieved=%.0fqps -> %s\n",
		s.Rate, s.Sent, s.Received, s.Correct, s.Bad, s.Lost, s.DropRate*100, s.AchievedQPS, tag)
	if cfg.TCP {
		fmt.Fprintf(w, "      [tcp@10%%] offered=%d completed=%d correct=%d bad=%d undispatched=%d\n",
			s.TCPOffered, s.TCPCompleted, s.TCPCorrect, s.TCPBad, s.TCPUndispatched)
	}
}
