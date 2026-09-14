/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

// The parent's periodic scan of its children.
//
// A NOTIFY(CDS) or NOTIFY(CSYNC) starts a scan of one child. A child that never
// sends one -- its software does not, or it follows RFC 7344 and RFC 7477 as
// written, which leave the looking to the parent -- is scanned only by a poll.
// With scanner.poll.enabled set, a poll round runs on the scanner's ticker
// (scanner.interval) over every child of every parent zone that allows child
// updates (pollParents):
//
//   - a child with a DS is scanned for CSYNC, then for CDS;
//   - a child without a DS is not scanned for CSYNC, and not for CDS either
//     unless scanner.poll.bootstrap is set. With it set a poll can give a child
//     its first DS, under the parent zone's delegation policy like any other
//     scan; with it off, the default, a poll never does.
//
// Each scan is the one a NOTIFY starts (ProcessCSYNCNotify, ProcessCDSNotify),
// and a change it finds is applied the same way, through OnDelegationChange.
// A round scans at most scanner.poll.concurrency children at once and does not
// start while the previous one is still running. It is not recorded as a
// scanner job: rounds repeat without end, and Jobs is never pruned.
//
// The log says whether the server polls: the settings when the engine starts
// and whenever they change, and one line per round.

// defaultPollConcurrency is how many children a round scans at once when
// scanner.poll.concurrency is unset. Every query to a child goes through the
// one AuthQueryEngine, so a higher number mostly adds waiting.
const defaultPollConcurrency = 4

type scannerPollConf struct {
	Enabled     bool
	Bootstrap   bool
	Concurrency int
}

func readScannerPollConf() scannerPollConf {
	c := scannerPollConf{
		Enabled:     viper.GetBool("scanner.poll.enabled"),
		Bootstrap:   viper.GetBool("scanner.poll.bootstrap"),
		Concurrency: viper.GetInt("scanner.poll.concurrency"),
	}
	if c.Concurrency < 1 {
		c.Concurrency = defaultPollConcurrency
	}
	return c
}

// scannerPollState is the Scanner's poll bookkeeping. running is shared with
// the round's goroutine; logged and last belong to the engine's.
type scannerPollState struct {
	running atomic.Bool // a round is in progress
	logged  bool
	last    scannerPollConf
}

// notePollConf logs the poll settings the first time and whenever they differ
// from the last ones logged.
func (scanner *Scanner) notePollConf(conf scannerPollConf, interval time.Duration) {
	if scanner.poll.logged && scanner.poll.last == conf {
		return
	}
	scanner.poll.logged, scanner.poll.last = true, conf
	lg.Info("ScannerEngine: poll settings", "enabled", conf.Enabled, "interval", interval,
		"bootstrap", conf.Bootstrap, "concurrency", conf.Concurrency)
}

// pollParents returns the zones a poll round covers: those that allow child
// updates, have a delegation backend to read the current delegation from, and
// have no error that stops them being served.
func pollParents(zones map[string]*ZoneData) []*ZoneData {
	var parents []*ZoneData
	for _, zd := range zones {
		if zd == nil || !zd.Options[OptAllowChildUpdates] || zd.DelegationBackend == nil || zd.HasServiceImpactingError() {
			continue
		}
		parents = append(parents, zd)
	}
	return parents
}

// currentDelegationDS returns the DS RRset the parent's delegation backend
// holds for child, or nil when it holds none. An error means the backend could
// not be read, which is not the same as no DS (see DelegationBackend): taken
// for "no DS", it would send a child that has one down the first-DS path.
func currentDelegationDS(parent *ZoneData, child string) (*core.RRset, error) {
	data, err := parent.DelegationBackend.GetDelegationData(parent.ZoneName, child)
	if err != nil {
		return nil, err
	}
	var ds []dns.RR
	for _, byType := range data {
		ds = append(ds, byType[dns.TypeDS]...)
	}
	if len(ds) == 0 {
		return nil, nil
	}
	return &core.RRset{Name: child, RRtype: dns.TypeDS, RRs: ds}, nil
}

// startPollRound starts a poll round in the background unless the previous one
// is still running, and reports whether it started one.
func (scanner *Scanner) startPollRound(ctx context.Context, parents []*ZoneData, conf scannerPollConf) bool {
	if !scanner.poll.running.CompareAndSwap(false, true) {
		return false
	}
	go func() {
		defer scanner.poll.running.Store(false)
		scanner.pollRound(ctx, parents, conf)
	}()
	return true
}

// pollRound scans the children of parents, at most conf.Concurrency at a time,
// and returns once every scan it started has finished.
func (scanner *Scanner) pollRound(ctx context.Context, parents []*ZoneData, conf scannerPollConf) {
	started := time.Now()

	type pollJob struct {
		parent *ZoneData
		tuple  ScanTuple
	}
	jobs := make(chan pollJob)
	var (
		wg                     sync.WaitGroup
		mu                     sync.Mutex
		scans, changes, failed int
	)
	for i := 0; i < conf.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				s, c, f := scanner.pollChild(ctx, job.parent, job.tuple)
				mu.Lock()
				scans, changes, failed = scans+s, changes+c, failed+f
				mu.Unlock()
			}
		}()
	}

	var queued, withoutDS, unreadable int
feed:
	for _, parent := range parents {
		children, err := parent.DelegationBackend.ListChildren(parent.ZoneName)
		if err != nil {
			lg.Error("ScannerEngine: poll: cannot list the children of a parent zone", "parent", parent.ZoneName, "error", err)
			continue
		}
		for _, child := range children {
			child = dns.Fqdn(child)
			if !parent.IsChildDelegation(child) {
				continue
			}
			ds, err := currentDelegationDS(parent, child)
			if err != nil {
				lg.Warn("ScannerEngine: poll: cannot read the delegation, not scanning the child", "parent", parent.ZoneName, "child", child, "error", err)
				unreadable++
				continue
			}
			if ds == nil && !conf.Bootstrap {
				withoutDS++
				continue
			}
			select {
			case jobs <- pollJob{parent: parent, tuple: ScanTuple{Zone: child, CurrentData: CurrentScanData{DS: ds}}}:
				queued++
			case <-ctx.Done():
				break feed
			}
		}
	}
	close(jobs)
	wg.Wait()

	lg.Info("ScannerEngine: poll round done", "parents", len(parents), "children", queued, "withoutDS", withoutDS,
		"unreadable", unreadable, "scans", scans, "changes", changes, "errors", failed,
		"duration", time.Since(started).Round(time.Millisecond))
}

// pollChild scans one child, CSYNC before CDS, and applies what each scan
// finds. A child without a DS -- polled only for bootstrap -- gets the CDS scan
// alone.
func (scanner *Scanner) pollChild(ctx context.Context, parent *ZoneData, tuple ScanTuple) (scans, changes, errs int) {
	types := []ScanType{ScanCDS}
	if tuple.CurrentData.DS != nil {
		types = []ScanType{ScanCSYNC, ScanCDS}
	}
	for _, scanType := range types {
		if ctx.Err() != nil {
			break
		}
		// Every return path of both functions sends exactly one response.
		ch := make(chan ScanTupleResponse, 1)
		if scanType == ScanCSYNC {
			scanner.ProcessCSYNCNotify(ctx, tuple, parent, scanType, nil, ch)
		} else {
			scanner.ProcessCDSNotify(ctx, tuple, parent, scanType, nil, ch)
		}
		resp := <-ch
		scans++
		if resp.Error {
			errs++
		}
		if scanner.OnDelegationChange != nil && scanResponseChangesDelegation(resp) {
			scanner.OnDelegationChange(parent.ZoneName, parent, resp)
			changes++
		}
	}
	return scans, changes, errs
}
