/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// The parent's periodic scan of its children.
//
// A NOTIFY(CDS) or NOTIFY(CSYNC) starts a scan of one child. A child that never
// sends one -- its software does not, or it follows RFC 7344 and RFC 7477 as
// written, which leave the looking to the parent -- is scanned only by a poll.
// With polling on, a poll round runs on the scanner's ticker (scanner.interval)
// over every child of every parent zone that allows child updates
// (pollParents):
//
//   - a child with a DS is scanned for CSYNC, then for CDS;
//   - a child without a DS is not scanned for CSYNC, and not for CDS either
//     unless scanner.poll.bootstrap is set. With it set a poll can give a child
//     its first DS, under the parent zone's delegation policy like any other
//     scan; with it off, the default, a poll never does.
//
// Each scan goes through scanChildAndApply, as a NOTIFY-started one does: under
// the child's lock, so a poll and a NOTIFY of the same child do not overlap,
// and its change is applied before the lock is released. A round scans at most
// scanner.poll.concurrency children at once and does not start while the
// previous one is still running. It is not recorded as a scanner job: rounds
// repeat without end, and Jobs is never pruned.
//
// Whether polling is on is scanner.poll.enabled, unless the switch says
// otherwise. The switch is set while tdns-auth runs, through POST /scanner/poll
// or "tdns-cli auth scanner poll on|off|follow-config" (scanner_poll_api.go),
// and overrides the config until follow-config or a restart. It is not
// persisted. Switching polling off also stops a round in progress from starting
// any more children.
//
// The log says whether the server polls: the settings when the engine starts
// and whenever they change, the switch whenever it is set, and one line per
// round.

// defaultPollConcurrency is how many children a round scans at once when
// scanner.poll.concurrency is unset. Every query to a child goes through the
// one AuthQueryEngine, so a higher number mostly adds waiting.
const defaultPollConcurrency = 4

type scannerPollConf struct {
	Enabled     bool
	Bootstrap   bool
	Concurrency int
}

// readScannerPollConf reads the poll settings from the runtime-config snapshot
// (runtime_config.go), which a config reload replaces whole. Reading viper here,
// on the engine's goroutine at every tick, would race the reload writing it.
func readScannerPollConf() scannerPollConf {
	live := ConfLive()
	c := scannerPollConf{
		Enabled:     live.ScannerPollEnabled,
		Bootstrap:   live.ScannerPollBootstrap,
		Concurrency: live.ScannerPollConcurrency,
	}
	if c.Concurrency < 1 {
		c.Concurrency = defaultPollConcurrency
	}
	return c
}

// pollSwitch is the runtime switch for polling: follow the config, or force
// polling on or off.
type pollSwitch int32

const (
	pollSwitchConfig pollSwitch = iota // follow scanner.poll.enabled
	pollSwitchOn
	pollSwitchOff
)

func (s pollSwitch) String() string {
	switch s {
	case pollSwitchOn:
		return "on"
	case pollSwitchOff:
		return "off"
	default:
		return "follow-config"
	}
}

// scannerPollState is the Scanner's poll bookkeeping.
//   - interval is set before the scanner is published and never changes.
//   - running and switched are shared with the API and the round's goroutine.
//   - logged, last and lastSwitch belong to the engine's goroutine.
type scannerPollState struct {
	interval time.Duration
	running  atomic.Bool  // a round is in progress
	switched atomic.Int32 // a pollSwitch

	logged     bool
	last       scannerPollConf
	lastSwitch pollSwitch
}

// pollConf is the poll settings the scanner acts on: the running config's,
// with enabled overridden when the switch is set.
func (scanner *Scanner) pollConf() scannerPollConf {
	c := readScannerPollConf()
	switch scanner.pollSwitch() {
	case pollSwitchOn:
		c.Enabled = true
	case pollSwitchOff:
		c.Enabled = false
	}
	return c
}

func (scanner *Scanner) pollSwitch() pollSwitch { return pollSwitch(scanner.poll.switched.Load()) }

// setPollSwitch sets the runtime switch. Polling follows it from the next tick;
// switching off also stops a round in progress from starting more children.
func (scanner *Scanner) setPollSwitch(s pollSwitch) {
	scanner.poll.switched.Store(int32(s))
	lg.Info("ScannerEngine: poll switch set", "switch", s.String(), "enabled", scanner.pollConf().Enabled)
}

// notePollConf logs the poll settings the first time and whenever they, or the
// switch, differ from the last ones logged. The switch counts on its own:
// switching on a server whose config already polls changes no setting.
func (scanner *Scanner) notePollConf(conf scannerPollConf) {
	sw := scanner.pollSwitch()
	if scanner.poll.logged && scanner.poll.last == conf && scanner.poll.lastSwitch == sw {
		return
	}
	scanner.poll.logged, scanner.poll.last, scanner.poll.lastSwitch = true, conf, sw
	lg.Info("ScannerEngine: poll settings", "enabled", conf.Enabled, "switch", sw.String(),
		"interval", scanner.poll.interval, "bootstrap", conf.Bootstrap, "concurrency", conf.Concurrency)
}

// pollParents returns the zones a poll round covers: those that allow child
// updates, have a delegation backend to read the current delegation from, and
// have no error that stops them being served. Options and DelegationBackend are
// read under zd.mu, which a config reload holds while it changes them.
func pollParents(zones map[string]*ZoneData) []*ZoneData {
	var parents []*ZoneData
	for _, zd := range zones {
		if zd == nil {
			continue
		}
		zd.mu.Lock()
		allowChildUpdates := zd.Options[OptAllowChildUpdates]
		hasBackend := zd.DelegationBackend != nil
		zd.mu.Unlock()
		if !allowChildUpdates || !hasBackend || zd.HasServiceImpactingError() {
			continue
		}
		parents = append(parents, zd)
	}
	return parents
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
// and returns once every scan it started has finished. It stops starting
// children when polling is switched off.
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
				s, c, f := scanner.pollChild(ctx, job.parent, job.tuple, conf.Bootstrap)
				mu.Lock()
				scans, changes, failed = scans+s, changes+c, failed+f
				mu.Unlock()
			}
		}()
	}

	var queued, withoutDS, unreadable int
	var stopped bool
feed:
	for _, parent := range parents {
		children, err := parent.DelegationBackend.ListChildren(parent.ZoneName)
		if err != nil {
			lg.Error("ScannerEngine: poll: cannot list the children of a parent zone", "parent", parent.ZoneName, "error", err)
			continue
		}
		for _, child := range children {
			if scanner.pollSwitch() == pollSwitchOff {
				stopped = true
				break feed
			}
			child = dns.Fqdn(child)
			if !parent.IsChildDelegation(child) {
				continue
			}
			// Whether the child has a DS decides whether it is polled. The DS a
			// CDS scan compares against is read again, under the child's lock.
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
		"unreadable", unreadable, "scans", scans, "changes", changes, "errors", failed, "stopped", stopped,
		"duration", time.Since(started).Round(time.Millisecond))
}

// pollChild scans one child, CSYNC before CDS, each through scanChildAndApply.
// A child without a DS -- polled only for bootstrap -- gets the CDS scan alone.
// Each scan checks the DS again under the child's lock (pollScan).
func (scanner *Scanner) pollChild(ctx context.Context, parent *ZoneData, tuple ScanTuple, bootstrap bool) (scans, changes, errs int) {
	types := []ScanType{ScanCDS}
	if tuple.CurrentData.DS != nil {
		types = []ScanType{ScanCSYNC, ScanCDS}
	}
	for _, scanType := range types {
		if ctx.Err() != nil {
			break
		}
		resp := scanner.scanChildAndApply(ctx, parent, scanType, tuple, nil, &pollScan{bootstrap: bootstrap})
		scans++
		if resp.Error {
			errs++
		}
		if scanResponseChangesDelegation(resp) {
			changes++
		}
	}
	return scans, changes, errs
}
