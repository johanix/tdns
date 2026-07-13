/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package debug

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// ChurnConfig parameterizes a churn run (design doc §10.1). Cadences with a
// zero value disable that actor.
type ChurnConfig struct {
	Zone         string
	ChurnKeyName string // _churn.<zone> (SIG(0) signer name)
	DnsServer    string // addr:port for DNS actors
	KeyFile      string // SIG(0) KEY RR file
	PrivFile     string // SIG(0) PEM private key file

	UpdateCadence time.Duration
	AxfrCadence   time.Duration
	QueryQPS      int
	QueryWorkers  int
	Duration      time.Duration
	Delta         time.Duration // I2/boundary tolerance
	SettleWait    time.Duration // wait past a publish cadence before the final reconcile
	Seed          int64
	Tool          string // tool name+version for the report
	TestId        string
}

// churn holds the shared state of a running churn test.
type churn struct {
	cfg    ChurnConfig
	signer *Sig0Signer
	ledger *Ledger
	check  *Checker
	report *Report

	suffix string // "_churn.<zone>."
	rng    *rand.Rand

	mu       sync.Mutex
	seq      int
	owners   []string // every owner ever added (for the query hammer)
}

// RunChurn executes a churn test to completion and returns the filled report.
// Only the pure-DNS actors run here (update-sender, AXFR poller, query hammer);
// the optional bump/resign/txlog actors are M3.
func RunChurn(ctx context.Context, cfg ChurnConfig) (*Report, error) {
	if cfg.UpdateCadence <= 0 {
		cfg.UpdateCadence = time.Second
	}
	if cfg.AxfrCadence <= 0 {
		cfg.AxfrCadence = 3 * time.Second
	}
	if cfg.Delta <= 0 {
		cfg.Delta = 2 * time.Second
	}
	if cfg.SettleWait <= 0 {
		cfg.SettleWait = 25 * time.Second
	}
	if cfg.QueryWorkers <= 0 && cfg.QueryQPS > 0 {
		cfg.QueryWorkers = 8
	}

	signer, err := LoadSig0Signer(cfg.Zone, cfg.ChurnKeyName, cfg.KeyFile, cfg.PrivFile)
	if err != nil {
		return nil, err
	}

	rep := NewReport(cfg.Tool, "churn")
	rep.TestId = cfg.TestId
	rep.Zone = cfg.Zone
	rep.Seed = cfg.Seed
	ledger := NewLedger()

	c := &churn{
		cfg:    cfg,
		signer: signer,
		ledger: ledger,
		check:  NewChecker(ledger, rep, cfg.Delta),
		report: rep,
		suffix: "_churn." + dns.Fqdn(cfg.Zone),
		rng:    rand.New(rand.NewSource(cfg.Seed)),
	}

	// Pre-flight: the zone must be reachable and answer SOA, or this is a
	// setup error (exit 2), not a violation.
	if _, err := querySOASerial(ctx, cfg.DnsServer, cfg.Zone); err != nil {
		return nil, fmt.Errorf("pre-flight SOA query failed: %w", err)
	}

	runCtx, cancel := context.WithTimeout(ctx, cfg.Duration)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); c.runUpdater(runCtx) }()
	wg.Add(1)
	go func() { defer wg.Done(); c.runAxfrPoller(runCtx) }()
	if cfg.QueryQPS > 0 {
		perWorker := time.Duration(float64(cfg.QueryWorkers) / float64(cfg.QueryQPS) * float64(time.Second))
		if perWorker <= 0 {
			perWorker = time.Millisecond
		}
		for i := 0; i < cfg.QueryWorkers; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); c.runQueryWorker(runCtx, perWorker) }()
		}
	} else {
		rep.Skip("query-hammer", "no --qps set")
	}
	wg.Wait()

	// Settle past a publish cadence, then a final reconcile (I3).
	c.finalReconcile(ctx)

	rep.Duration = time.Since(rep.StartedAt)
	rep.Stats["ops.accepted"] = int64(ledger.AcceptedCount())
	return rep, nil
}

func (c *churn) nextOwner() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seq++
	owner := fmt.Sprintf("%d._churn.%s", c.seq, dns.Fqdn(c.cfg.Zone))
	c.owners = append(c.owners, owner)
	return owner
}

func (c *churn) randomOwner() (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.owners) == 0 {
		return "", false
	}
	return c.owners[c.rng.Intn(len(c.owners))], true
}

// runUpdater sends one add-or-delete per cadence; on NOERROR it records the op
// in the ledger. Deletes target a currently-accepted-present record (so the
// zone churns rather than only growing); when none is present it adds.
func (c *churn) runUpdater(ctx context.Context) {
	t := time.NewTicker(c.cfg.UpdateCadence)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.report.Stats["updates.attempted"]++
			doDelete := false
			if _, ok := c.ledger.PickPresent(); ok {
				doDelete = c.rng.Float64() < 0.4 // mostly grow, sometimes shrink
			}
			if doDelete {
				c.sendDelete(ctx)
			} else {
				c.sendAdd(ctx)
			}
		}
	}
}

func (c *churn) sendAdd(ctx context.Context) {
	owner := c.nextOwner()
	rec := ChurnRecord{Owner: owner, Rdata: fmt.Sprintf("seq=%d t=%s seed=%d", c.seq, time.Now().Format(time.RFC3339Nano), c.cfg.Seed)}
	rr, err := churnTXT(rec)
	if err != nil {
		c.report.Stats["updates.builderr"]++
		return
	}
	rcode, err := c.signer.Send(ctx, c.cfg.DnsServer, []dns.RR{rr}, nil)
	if err != nil {
		c.report.Stats["updates.senderr"]++
		return
	}
	if rcode == dns.RcodeSuccess {
		c.ledger.RecordAccepted(OpAdd, rec, time.Now())
		c.report.Stats["updates.accepted"]++
	} else {
		c.report.Stats["updates.rejected"]++
	}
}

func (c *churn) sendDelete(ctx context.Context) {
	rec, ok := c.ledger.PickPresent()
	if !ok {
		return
	}
	rr, err := churnTXT(rec)
	if err != nil {
		c.report.Stats["updates.builderr"]++
		return
	}
	// RFC 2136 individual-RR delete (class NONE) via miekg's Remove.
	rcode, err := c.signer.Send(ctx, c.cfg.DnsServer, nil, []dns.RR{rr})
	if err != nil {
		c.report.Stats["updates.senderr"]++
		return
	}
	if rcode == dns.RcodeSuccess {
		c.ledger.RecordAccepted(OpDel, rec, time.Now())
		c.report.Stats["updates.accepted"]++
	} else {
		c.report.Stats["updates.rejected"]++
	}
}

// runAxfrPoller transfers the zone each cadence and feeds a full observation.
func (c *churn) runAxfrPoller(ctx context.Context) {
	t := time.NewTicker(c.cfg.AxfrCadence)
	defer t.Stop()
	var lastSerial uint32
	haveLast := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			recs, openSOA, closeSOA, err := axfrChurn(ctx, c.cfg.DnsServer, c.cfg.Zone, c.suffix)
			if err != nil {
				c.report.Stats["axfr.errors"]++
				continue
			}
			c.report.Stats["axfr.count"]++
			if haveLast && openSOA != lastSerial {
				c.report.Stats["publish.boundaries"]++
			}
			lastSerial, haveLast = openSOA, true
			c.check.Observe(Observation{
				Stream: "axfr", At: time.Now(), Serial: openSOA, Full: true,
				Churn: recs, HasSOA: true, OpenSOA: openSOA, CloseSOA: closeSOA,
			})
		}
	}
}

// runQueryWorker hammers TXT queries (concurrent read load at the publish
// flip) and feeds name observations. Serial comes from a paired SOA query;
// the small SOA-vs-name race is absorbed by δ and by repetition.
func (c *churn) runQueryWorker(ctx context.Context, cadence time.Duration) {
	t := time.NewTicker(cadence)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			owner, ok := c.randomOwner()
			if !ok {
				continue
			}
			serial, err := querySOASerial(ctx, c.cfg.DnsServer, c.cfg.Zone)
			if err != nil {
				c.report.Stats["query.errors"]++
				continue
			}
			present, rec, err := queryName(ctx, c.cfg.DnsServer, owner)
			if err != nil {
				c.report.Stats["query.errors"]++
				continue
			}
			c.report.Stats["query.count"]++
			c.check.Observe(Observation{
				Stream: "query", At: time.Now(), Serial: serial,
				Name: dns.Fqdn(owner), Present: present, Rec: rec,
			})
		}
	}
}

// finalReconcile waits past one publish cadence for the last updates to
// publish, then runs the I3 end-of-run check against a final AXFR.
func (c *churn) finalReconcile(ctx context.Context) {
	select {
	case <-ctx.Done():
	case <-time.After(c.cfg.SettleWait):
	}
	recs, openSOA, closeSOA, err := axfrChurn(ctx, c.cfg.DnsServer, c.cfg.Zone, c.suffix)
	if err != nil {
		c.report.Skip("I3 final reconcile", "final AXFR failed: "+err.Error())
		return
	}
	// A torn final transfer is itself an I7 signal; still feed it.
	c.check.Observe(Observation{
		Stream: "axfr", At: time.Now(), Serial: openSOA, Full: true,
		Churn: recs, HasSOA: true, OpenSOA: openSOA, CloseSOA: closeSOA,
	})
	c.check.Finalize(recs, closeSOA)
}
