/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

var lg = Logger("zones")

// ErrZoneNotReady is returned by GetOwner/GetRRset when the zone data
// has not been loaded yet (zd.Ready == false). Callers that need to
// handle initial-load gracefully can check with errors.Is.
var ErrZoneNotReady = errors.New("zone data is not yet ready")

// Refresh reloads the zone: from its file for a primary, from an upstream for a
// secondary. ctx bounds the whole operation -- primary resolution, the SOA
// probe, and the transfer itself -- so a shutdown or a cancelled request stops
// in-flight work instead of running to completion against a dead engine.
func (zd *ZoneData) Refresh(ctx context.Context, verbose, debug, force bool, conf *Config) (bool, error) {
	var updated bool

	// Collect dynamic RRs before refresh (they will be lost during refresh)
	dynamicRRs := zd.CollectDynamicRRs(conf)

	// zd.Logger.Printf("zd.Refresh(): refreshing zone %s (%s) force=%v.", zd.ZoneName,
	// 	ZoneTypeToString[zd.ZoneType], force)

	// if zd.FoldCase {
	if zd.Options[OptFoldCase] {
		lg.Debug("folding case for zone", "zone", zd.ZoneName)
		zd.ZoneName = strings.ToLower(zd.ZoneName)
	}

	switch zd.ZoneType {
	case Primary:
		// zd.Logger.Printf("zd.Refresh(): Should reload zone %s from file %s", zd.ZoneName, zd.ZoneFile)

		updated, err := zd.FetchFromFile(ctx, verbose, debug, force, dynamicRRs)
		if err != nil {
			return false, err
		}
		return updated, err

	case Secondary:
		// D1: re-resolve hostname primaries each refresh, so a transient
		// resolution failure self-heals and a changed primary address is
		// followed. Literal-IP primaries pass through unchanged (no lookup). If
		// nothing resolves this cycle (IMR not up yet at startup, or the name is
		// temporarily unreachable), keep the previous upstreams; DoTransfer then
		// surfaces a refresh error and we retry next cycle — never a permanent
		// quarantine.
		if len(zd.PrimariesConf) > 0 {
			if res := resolvePrimaries(ctx, conf.Internal.ImrEngine, zd.PrimariesConf); len(res.Resolved) > 0 {
				zd.Upstreams = res.Resolved
			} else {
				lg.Warn("zone refresh: no primary resolved this cycle, will retry next refresh", "zone", zd.ZoneName, "unresolved", res.Unresolved)
			}
		}
		do_transfer, upstream_serial, err := zd.DoTransfer(ctx, conf)
		if err != nil {
			return false, err
		}

		if do_transfer || force {
			if do_transfer {
				lg.Info("upstream serial has increased", "zone", zd.ZoneName, "old", zd.IncomingSerial, "new", upstream_serial)
			} else if force {
				lg.Debug("forced retransfer regardless of SOA serial", "zone", zd.ZoneName)
			}
			updated, err = zd.FetchFromUpstream(ctx, verbose, debug, force, dynamicRRs, conf)
			if err != nil {
				lg.Error("FetchZone failed", "zone", zd.ZoneName, "upstream", firstUpstreamAddr(zd.Upstreams), "err", err)
				return false, err
			}
			return updated, nil // zone updated, no error
		}

		lg.Debug("upstream serial is unchanged", "zone", zd.ZoneName, "serial", zd.IncomingSerial)

	default:
		return false, fmt.Errorf("error: cannot refresh zone %s of unknown type %d", zd.ZoneName, zd.ZoneType)
	}

	return false, nil
}

// firstUpstreamAddr returns the first transfer target, or "" if none configured.
func firstUpstreamAddr(upstreams []PeerConf) string {
	if len(upstreams) == 0 {
		return ""
	}
	return upstreams[0].Addr
}

// Return shouldTransfer, new upstream serial, error
//
// The SOA probe iterates zd.Upstreams, advancing to the next address whenever
// the current one does not yield a usable SOA — a transport error OR a
// non-usable rcode (REFUSED/SERVFAIL/NXDOMAIN/empty). Different primaries are
// independent servers that may answer differently (e.g. per-primary ACLs), so
// one primary refusing does not mean the zone is unavailable from a sibling.
// A usable NOERROR+SOA from any primary is honoured (transfer decided on
// serial). If every primary answered but none gave a usable SOA, we back off
// quietly (no transfer, no error); only all-unreachable is a hard error.
func (zd *ZoneData) DoTransfer(ctx context.Context, conf *Config) (bool, uint32, error) {
	if zd == nil {
		panic("DoTransfer: zd == nil")
	}

	if len(zd.Upstreams) == 0 {
		return false, 0, fmt.Errorf("DoTransfer: zone %s has no upstreams configured", zd.ZoneName)
	}

	// zd.Upstreams is mutated in place under zd.mu by the refresh engine, so
	// range over a copy rather than the live slice.
	zd.mu.Lock()
	upstreams := make([]PeerConf, len(zd.Upstreams))
	copy(upstreams, zd.Upstreams)
	zd.mu.Unlock()

	// Phase 1 -- resolve everything that reads config, under a single read
	// lock, with NO network I/O. conf is the mutable global and a reload
	// replaces its contents wholesale; resolving per-upstream inside the probe
	// loop below would let a reload landing midway hand later primaries
	// TLS/TSIG material from a different config generation than earlier ones.
	// Snapshot once, then probe. (Same shape as ProbeUpstreamSerials; this is
	// the live path that motivated it.)
	//
	// The lock is NOT held across the exchanges: a probe blocks until the peer
	// answers or times out, and holding confMu for that would stall every
	// config reload behind an unreachable primary.
	type probePlan struct {
		up       PeerConf
		upstream string
		client   *dns.Client
		keyName  string
		tsigAlgo string
		err      error // config-resolution failure; this upstream is skipped
	}
	plans := make([]probePlan, 0, len(upstreams))

	confMu.RLock()
	for _, up := range upstreams {
		p := probePlan{up: up, upstream: up.Addr}
		if _, _, err := net.SplitHostPort(p.upstream); err != nil {
			// If error, assume no port was specified
			p.upstream = net.JoinHostPort(p.upstream, defaultPortForPeer(up))
			lg.Debug("DoTransfer: no port specified for upstream, using transport default", "zone", zd.ZoneName, "upstream", p.upstream)
		}
		p.client = new(dns.Client)
		// XoT peer: probe the SOA over the same verified-TLS channel the
		// transfer itself will use (same pin/dane/pkix gate).
		if tlsCfg, terr := conf.ClientTLSConfigForPeer(up); terr != nil {
			p.err = terr
			plans = append(plans, p)
			continue
		} else if tlsCfg != nil {
			p.client.Net = "tcp-tls"
			p.client.TLSConfig = tlsCfg
		}
		provider, algo, serr := TsigMaterialForPeer(up.Key, conf)
		if serr != nil {
			p.err = serr
			plans = append(plans, p)
			continue
		}
		p.client.TsigProvider = provider // nil for NOKEY => plain exchange (no MAC)
		if provider != nil {
			p.keyName, p.tsigAlgo = up.Key, algo
		}
		plans = append(plans, p)
	}
	confMu.RUnlock()

	// Phase 2 -- network only. Nothing here reads shared config.
	sawResponse := false
	var lastErr error
	for i := range plans {
		p := &plans[i]
		up, upstream := p.up, p.upstream

		if p.err != nil {
			lg.Error("DoTransfer: peer config setup failed, trying next upstream", "zone", zd.ZoneName, "upstream", upstream, "key", up.Key, "err", p.err)
			lastErr = p.err
			continue
		}
		// Nobody is waiting for this result any more; stop walking upstreams.
		if cerr := ctx.Err(); cerr != nil {
			return false, 0, fmt.Errorf("DoTransfer %s: %w", zd.ZoneName, cerr)
		}

		// Fresh message per attempt: TSIG signing adds an RR with a per-attempt
		// timestamp and this upstream's key. Stamped here, not during the
		// snapshot above: the probes are sequential and each can block until it
		// times out, so a timestamp taken in phase 1 could be outside the fudge
		// window by the time a later message is sent, and the peer would answer
		// BADTIME.
		m := new(dns.Msg)
		m.SetQuestion(zd.ZoneName, dns.TypeSOA)
		if p.keyName != "" {
			StampTsigForPeer(m, p.keyName, p.tsigAlgo)
		}
		c := p.client
		r, _, err := c.ExchangeContext(ctx, m, upstream)
		if err != nil {
			// A cancelled exchange is not a sick primary: every sibling would
			// fail the same way. Return it as cancellation rather than letting
			// the loop treat it as "try the next one".
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return false, 0, fmt.Errorf("DoTransfer %s: %w", zd.ZoneName, err)
			}
			// Transport failure (or a TSIG response-verify failure) — try the next sibling.
			lg.Warn("DoTransfer: SOA probe failed, trying next upstream", "zone", zd.ZoneName, "upstream", upstream, "err", err)
			lastErr = err
			continue
		}
		sawResponse = true
		switch r.MsgHdr.Rcode {
		case dns.RcodeSuccess:
			if len(r.Answer) == 0 {
				lg.Debug("DoTransfer: NOERROR but empty answer section, trying next upstream", "zone", zd.ZoneName, "upstream", upstream)
				continue
			}
			if soa, ok := r.Answer[0].(*dns.SOA); ok {
				lg.Info("DoTransfer: serial check", "zone", zd.ZoneName, "upstream", upstream, "notify_serial", soa.Serial, "incoming_serial", zd.IncomingSerial, "current_serial", zd.CurrentSerial)
				if soa.Serial <= zd.IncomingSerial {
					return false, soa.Serial, nil
				}
				return true, soa.Serial, nil
			}
			// NOERROR but the first answer is not a SOA — try the next sibling.
			continue
		default:
			// REFUSED / SERVFAIL / NXDOMAIN / etc. This primary will not give a
			// usable SOA, but a sibling may (e.g. differing per-primary ACLs).
			lg.Debug("DoTransfer: non-usable SOA rcode, trying next upstream", "zone", zd.ZoneName, "upstream", upstream, "rcode", dns.RcodeToString[r.MsgHdr.Rcode])
			continue
		}
	}

	if sawResponse {
		// At least one primary answered, but none gave a usable SOA (e.g. all
		// REFUSED). Back off quietly — no transfer this cycle, not an error.
		return false, 0, nil
	}
	// No primary was even reachable.
	lg.Error("DoTransfer: SOA probe failed on all upstreams (unreachable)", "zone", zd.ZoneName, "count", len(zd.Upstreams), "err", lastErr)
	return false, 0, fmt.Errorf("SOA probe of %s failed: all %d upstream(s) unreachable: %w", zd.ZoneName, len(zd.Upstreams), lastErr)
}

// newTransferScratchZone builds the throwaway ZoneData an inbound AXFR is
// received into. The transfer must not write into the live zone until it has
// succeeded, so it lands here first and is flipped in afterwards.
//
// It is a PARTIAL copy, and that is the trap: anything ZoneTransferIn reads off
// its receiver has to be listed here, or the transfer silently runs without it.
// transfer-src was added to ZoneData and to the config, plumbed all the way
// through provisioning, persistence and reload -- and then dropped here, one
// line before the call that uses it. The feature was inert on every AXFR while
// looking correct everywhere an operator could inspect it.
//
// TransferSrc is resolved on the LIVE zone rather than copied raw: the live zone
// is the one holding both the per-zone value and the KeyDB carrying the global
// default, so this hands over an already-resolved list and the scratch zone does
// not need a KeyDB of its own.
//
// Anything added to ZoneTransferIn's reads of zd belongs in this function.
func newTransferScratchZone(zd *ZoneData) ZoneData {
	srcs, tier := zd.EffectiveTransferSrcWithSource()
	return ZoneData{
		ZoneName:        zd.ZoneName,
		ZoneType:        zd.ZoneType,
		ZoneStore:       zd.ZoneStore,
		XfrType:         zd.XfrType,
		IncomingSerial:  zd.IncomingSerial,
		CurrentSerial:   zd.CurrentSerial,
		Logger:          zd.Logger,
		Verbose:         zd.Verbose,
		Debug:           zd.Debug,
		Options:         zd.Options,
		TransferSrc:     srcs,
		TransferSrcTier: tier,
		Ready:           true, // this is only used by the checks for changes to DNSKEYs, HSYNC, etc.
		// FoldCase:       zd.FoldCase, // Must be here, as this is an instruction to the zone reader
	}
}

// zoneFileLooksUntouched answers the cheap half of "did the file change?": has
// anything written to this file at all since tdns last looked at it?
//
// It is a CACHE, not a detector. It can only ever say "do not bother looking";
// every file it lets through is still judged on its ZONEMD digest, so no
// reformatted file is ever mistaken for a changed one. That asymmetry is what
// makes it compatible with the design's rejection of byte-level comparison:
// the objection there is to false POSITIVES from reordering, comments and
// whitespace, and the only error this can make is a false negative -- a file
// rewritten to exactly the same size with its mtime restored, which is not
// something an editor or a zone generator does.
//
// The alternative is not free. Deciding on content means parsing and digesting
// the whole zone, measured at ~9 seconds for a 1.1M-record zone (the digest
// being some 80% of it), and the refresh ticker calls that inline in the
// refresh engine, where every other zone waits behind it. Paying that once per
// refresh interval per zone to learn that nothing happened is a poor trade for
// closing a hole that takes deliberate effort to fall into -- and a restart, or
// `zone reload --force`, closes it anyway.
//
// A zero fileModTime means "not looked at in this process", which is every
// zone's first load.
func (zd *ZoneData) zoneFileLooksUntouched(fname string, st os.FileInfo) bool {
	if zd == nil || st == nil {
		return false
	}
	zd.mu.Lock()
	defer zd.mu.Unlock()
	if zd.fileModTime.IsZero() || zd.fileStatPath != path.Clean(fname) {
		return false
	}
	return zd.fileSize == st.Size() && zd.fileModTime.Equal(st.ModTime())
}

// recordZoneFileStat remembers the stat of the file just read or written.
//
// Recorded whether or not the file was ADOPTED, unlike the digest identity,
// which describes the file the zone is SERVING and so is recorded only when
// the file is adopted. Without that difference a merely reformatted file would
// be re-parsed on every refresh forever: its mtime differs, its content does
// not, and nothing would ever record that we had already looked.
func (zd *ZoneData) recordZoneFileStat(fname string, st os.FileInfo) {
	if zd == nil || st == nil {
		return
	}
	zd.mu.Lock()
	zd.fileStatPath = path.Clean(fname)
	zd.fileModTime = st.ModTime()
	zd.fileSize = st.Size()
	zd.mu.Unlock()
}

// forgetZoneFileStat drops the cached stat, so the next refresh reads the file
// again instead of trusting that nothing has happened to it.
//
// Called when a load could not finish dealing with the file it read. The
// recorded identity is deliberately left stale in that case so the next load
// sees the file as changed and retries; the cached stat would otherwise stop
// that next load from ever looking.
func (zd *ZoneData) forgetZoneFileStat() {
	if zd == nil {
		return
	}
	zd.mu.Lock()
	zd.fileStatPath = ""
	zd.fileModTime = time.Time{}
	zd.fileSize = 0
	zd.mu.Unlock()
}

// Return updated, error
func (zd *ZoneData) FetchFromFile(ctx context.Context, verbose, debug, force bool, dynamicRRs []*core.RRset) (bool, error) {

	// The cheap question first, and BEFORE the read: has anything touched the
	// file since we last looked? Taken before rather than after so that a file
	// replaced while we are reading it records the OLDER stat -- the next
	// refresh then re-reads, which is the safe direction to be wrong in.
	//
	// A stat we could not take is not a reason to skip; ReadZoneFile below
	// reports the real error with the real message.
	st, statErr := os.Stat(zd.Zonefile)
	if statErr != nil {
		st = nil
	}
	if !force && zd.zoneFileLooksUntouched(zd.Zonefile, st) {
		lg.Debug("zone file untouched since tdns last looked at it; not re-reading",
			"zone", zd.ZoneName, "file", zd.Zonefile)
		return false, nil
	}

	// log.Printf("Reading zone %s from file %s\n", zd.ZoneName, zd.Zonefile)
	// Capture prior status so an error or no-op (unchanged) file read of an
	// already-ready zone is restored to it, not left stuck in `loading`.
	// Parsing a large zone file is not instant, and neither is the publish +
	// callback work below. A cancelled refresh must not go on to apply data to
	// a daemon that is shutting down.
	if cerr := ctx.Err(); cerr != nil {
		return false, fmt.Errorf("FetchFromFile %s: %w", zd.ZoneName, cerr)
	}

	prevStatus := zd.GetStatus()
	zd.SetStatus(ZoneStatusLoading)

	new_zd := ZoneData{
		ZoneName:       zd.ZoneName,
		ZoneStore:      zd.ZoneStore,
		ZoneType:       zd.ZoneType,
		XfrType:        zd.XfrType,
		IncomingSerial: zd.IncomingSerial,
		CurrentSerial:  zd.CurrentSerial,
		Logger:         zd.Logger,
		Verbose:        zd.Verbose,
		Debug:          zd.Debug,
		Options:        zd.Options,
		// FoldCase:       zd.FoldCase, // Must be here, as this is an instruction to the zone reader
	}

	// Parse the WHOLE file, always. The parser's own short-circuit answers "has
	// the SOA serial moved?", which is not the question this path has to
	// answer: a zone file can be edited, regenerated or restored from backup
	// without its serial moving, and the recorded content digest exists
	// precisely to catch that. Reaching the digest at all means parsing past
	// the SOA -- so parse unconditionally here and decide below, on content.
	//
	// This is the reload half of #362. With the serial deciding, a file whose
	// SOA serial matched the one last read was not read at all: an edit that
	// changed records without moving the serial past it simply did not load,
	// while `zone reload` reported success. --force did not help either -- it
	// parsed the file to validate it and then reported "not updated", so the
	// parse was thrown away.
	serialMoved, _, err := new_zd.ReadZoneFile(ctx, zd.Zonefile, true)
	if err != nil {
		lg.Error("ReadZoneFile failed", "zone", zd.ZoneName, "err", err)
		zd.SetStatus(prevStatus)
		return false, err
	}

	// zd.Logger.Printf("FetchFromFile: Zone %s: zone file read, updated=%v delegation sync=%v", zd.ZoneName, updated, zd.Optoins["delegationsync"])

	// We have now looked at this file, whatever we go on to decide about it.
	zd.recordZoneFileStat(zd.Zonefile, st)

	// Is this the file tdns last read or wrote? Asked of the file just parsed,
	// against the identity recorded for the zone -- file against file, never
	// file against the in-memory zone, which carries freshly minted signatures
	// and would report every signed zone as modified.
	verdict := ZoneFileUnknown
	var prev *ZoneFileIdentity
	var verr error
	if zd.KeyDB != nil {
		verdict, prev, verr = zd.KeyDB.CompareZoneFileDigest(zd.ZoneName, new_zd.fileDigest)
		if verr != nil {
			// Not fatal, and not evidence of a change: a zone that cannot be
			// compared falls back to the serial below, which is what this path
			// did before the digest existed. reconcileZoneFileWithJournal
			// reports the failure once, further down.
			verdict = ZoneFileUnknown
		}
	}

	// A load that has published nothing must adopt the file whatever the
	// verdict says. "Unchanged" means the file is what the ZONE ALREADY HAS,
	// and a zone serving nothing has nothing -- the recorded identity is the
	// previous process's, and every restart of an untouched zone would
	// otherwise decline to load it at all.
	updated := force || zd.publishedSnapshot() == nil
	switch verdict {
	case ZoneFileChanged:
		updated = true
	case ZoneFileUnchanged:
		// The file's CONTENT is what the zone already has. Reordering,
		// re-commenting and reflowing all land here, and republishing for
		// those would churn the serial and NOTIFY every secondary over a
		// change that is not one. The refresh ticker calls this path on every
		// refresh interval, so that would be perpetual.
	default: // ZoneFileUnknown
		// No basis for a content comparison: nothing recorded for this zone
		// yet, no database, or the digest could not be computed. Fall back to
		// the serial.
		updated = updated || serialMoved
	}

	if !updated {
		zd.SetStatus(prevStatus)
		return false, nil // new zone not loaded, but not returning any error
	}

	// verify-zonemd, on the zone about to be adopted and not yet on the zone
	// being served. This is the last point at which a refusal still means
	// anything. See gateIncomingZonemd.
	if err := zd.gateIncomingZonemd(ctx, &new_zd, "the zone file"); err != nil {
		zd.SetStatus(prevStatus)
		// Drop the cached stat, for the same reason the failed-adoption path
		// below does: this file was considered and declined, so the next
		// refresh has to look at it again rather than skip it as untouched.
		// Without this a primary that fixes its digest is never picked up.
		zd.forgetZoneFileStat()
		return false, err
	}

	new_zd.Ready = true

	// Re-check before the hard flip: parsing the file may have taken a while,
	// and publishing a replacement (plus running the refresh callbacks) after
	// the engine has been cancelled applies data to a daemon on its way out.
	// Checked here rather than only up front so a long parse cannot slip
	// through the earlier gate.
	if cerr := ctx.Err(); cerr != nil {
		// Same reasoning as the gate after the callbacks below: the stat was
		// recorded by the read above, and we are not adopting the file, so
		// leaving it behind would make the next refresh skip a change that was
		// never applied. Narrower window than that gate, identical consequence.
		zd.forgetZoneFileStat()
		zd.SetStatus(prevStatus)
		return false, fmt.Errorf("FetchFromFile %s: %w", zd.ZoneName, cerr)
	}

	// Pre-refresh callbacks: analysis of old vs new zone data + modification of new_zd.
	// MP roles (agent, combiner, signer) register callbacks to detect HSYNC/DNSKEY/delegation
	// changes, add combiner contributions, populate MP data, etc. — all before the hard flip.
	for _, cb := range zd.OnZonePreRefresh {
		cb(zd, &new_zd)
	}

	// Last gate before the hard flip, after the callbacks have run. See the
	// matching comment on the upstream path.
	if cerr := ctx.Err(); cerr != nil {
		// Drop the cached stat recorded by the read above. We parsed the file
		// but are NOT adopting it, so leaving the stat behind would make the
		// next refresh see an unchanged file and skip it -- the zone would
		// silently never pick up this edit. Same reason the persist-failure
		// path below forgets it.
		zd.forgetZoneFileStat()
		zd.SetStatus(prevStatus)
		return false, fmt.Errorf("FetchFromFile %s: %w", zd.ZoneName, cerr)
	}

	// Publish replacement: working set from refreshed data + dynamic RRs.
	zd.mu.Lock()
	firstLoad := zd.FirstZoneLoad
	if err := zd.applyRefreshReplacementLocked(&new_zd, dynamicRRs, firstLoad, true); err != nil {
		zd.mu.Unlock()
		// Nothing was published: the only error that path returns comes from
		// persisting the outgoing serial, which happens before the working set
		// is swapped in, so the zone still serves exactly what it did before.
		//
		// Put the status back, as the two failure returns above already do.
		// Leaving it at `loading` reports a zone as mid-load forever, on the
		// strength of one failed database write.
		zd.SetStatus(prevStatus)
		// And drop the cached stat. It was recorded when the file was read,
		// which is right for a file we merely declined to adopt -- but this
		// file we tried to adopt and could not, so the next refresh has to look
		// again. Without this it would see an untouched file, skip it, and the
		// zone would never pick that file up at all. Same coupling as a failed
		// reconciliation, one step earlier.
		zd.forgetZoneFileStat()
		lg.Error("failed to persist outgoing serial", "zone", zd.ZoneName, "err", err)
		return false, err
	}
	zd.mu.Unlock()

	// Reconcile the journal with the file that was just adopted -- the same
	// function a first load reaches, from the verdict already in hand.
	//
	// Not on a first load, though: that path reconciles from
	// completeFirstZonePolicyAndLoad, AFTER the DNSSEC policy is bound.
	// Reconciling here would re-sign the RRsets it touches with no policy
	// bound, which sigLifetime turns into five-minute RRSIGs that nothing on
	// the normal path renews.
	//
	// Before the post-refresh callbacks, for the reason drainAndRunOnFirstLoad
	// runs after replay on the load path: a callback should see the zone's
	// actual content, not the file before the journal was applied to it.
	if !firstLoad {
		zd.reconcileZoneFileWithJournal(verdict, prev, verr)
	}

	// Post-refresh callbacks: queue sends and notifications that need the live zone pointer.
	for _, cb := range zd.OnZonePostRefresh {
		cb(zd)
	}

	return true, nil
}

// shouldDiscardUnchangedTransfer reports whether a completed transfer should be
// thrown away because it carries the serial we already have.
//
// The force exemption is the §9 forced-transfer contract: a forced transfer
// MUST apply whatever upstream has, including a serial equal to (or lower than)
// our own. Without it a forced retransfer of an already-current zone silently
// did nothing while reporting success — so `force` did not mean force.
//
// That matters beyond tidiness: a forced retransfer is the only remedy for a
// downstream wedged behind a secondary whose serial stepped backwards (see the
// migration section of the design doc), and the only escape hatch from a zone
// holding corrupt data under a current serial.
func shouldDiscardUnchangedTransfer(incomingSerial, currentSerial uint32, force bool) bool {
	return incomingSerial == currentSerial && !force
}

// FetchFromUpstream pulls the zone from one of its configured primaries.
// Returns whether the zone was updated.
//
// force means the operator explicitly asked for a retransfer, so the zone is
// re-fetched and re-applied even when upstream's serial has not moved. See the
// unchanged-serial check below for why that matters.
func (zd *ZoneData) FetchFromUpstream(ctx context.Context, verbose, debug, force bool, dynamicRRs []*core.RRset, conf *Config) (bool, error) {

	if len(zd.Upstreams) == 0 {
		return false, fmt.Errorf("FetchFromUpstream: zone %s has no upstreams configured", zd.ZoneName)
	}
	// Capture the prior status so a no-op (serial unchanged) or all-failed
	// refresh of an already-ready zone is restored to it, not left stuck in
	// `loading` until some later successful transfer flips it back.
	prevStatus := zd.GetStatus()
	zd.SetStatus(ZoneStatusLoading)

	// Iterate the resolved upstreams, advancing to the next on ANY failure —
	// a transport error, a REFUSED/NOTAUTH/SERVFAIL xfr rcode, or bad zone data.
	// allow-transfer ACLs commonly differ per primary, so one primary refusing
	// us says nothing about a sibling. A fresh new_zd per attempt keeps a failed
	// transfer from polluting the next try; the live zd.IncomingSerial is only
	// touched in the hard flip below, after a success.
	var new_zd ZoneData
	transferred := false
	var lastErr error
	// zd.Upstreams is mutated in place under zd.mu by the refresh engine, so
	// walk a copy rather than the live slice -- the same race DoTransfer and
	// ProbeUpstreamSerials already copy to avoid.
	zd.mu.Lock()
	upstreams := make([]PeerConf, len(zd.Upstreams))
	copy(upstreams, zd.Upstreams)
	zd.mu.Unlock()
	for _, up := range upstreams {
		// Stop the fallback walk once the caller has given up. Without this, a
		// shutdown that cancels mid-transfer would go on to start a FRESH AXFR
		// attempt against every remaining upstream -- each one dialling, each
		// one immediately cancelled -- which is the opposite of what
		// cancellation is for.
		if cerr := ctx.Err(); cerr != nil {
			// Restore the prior status: a cancelled refresh has not changed
			// anything, and leaving the zone in `loading` would misreport a
			// perfectly good zone for as long as the process lives.
			zd.SetStatus(prevStatus)
			return false, fmt.Errorf("AXFR of %s: %w", zd.ZoneName, cerr)
		}
		upstream := up.Addr
		lg.Info("transferring zone via AXFR", "zone", zd.ZoneName, "upstream", upstream)
		new_zd = newTransferScratchZone(zd)
		if _, err := new_zd.ZoneTransferIn(ctx, up, zd.IncomingSerial, "axfr", conf); err != nil {
			lg.Warn("FetchFromUpstream: AXFR from upstream failed, trying next", "zone", zd.ZoneName, "upstream", upstream, "err", err)
			lastErr = err
			continue
		}
		transferred = true
		break
	}
	if !transferred {
		lg.Error("FetchFromUpstream: AXFR failed on all upstreams", "zone", zd.ZoneName, "count", len(zd.Upstreams), "err", lastErr)
		zd.SetStatus(prevStatus) // still serving prior data; failure surfaces as RefreshError
		return false, fmt.Errorf("AXFR of %s failed: tried all %d upstream(s): %w", zd.ZoneName, len(zd.Upstreams), lastErr)
	}

	// A forced transfer MUST apply whatever upstream has, including a serial
	// equal to (or lower than) our own. Without the force exemption here, a
	// forced retransfer of an already-current zone silently did nothing while
	// reporting success — so `force` did not mean force.
	//
	// This is load-bearing for the strict-passthrough migration: a forced
	// retransfer is the ONLY remedy for a downstream wedged behind a secondary
	// whose serial stepped backwards, and the only escape hatch from a zone
	// with corrupt-but-current-serial data. The lower-serial case already
	// worked, but only incidentally (DoTransfer returns do_transfer=false
	// without an error, and the caller's `do_transfer || force` lets it
	// through); it is now pinned by a regression test.
	if shouldDiscardUnchangedTransfer(new_zd.IncomingSerial, zd.IncomingSerial, force) {
		lg.Debug("FetchFromUpstream: upstream serial is unchanged", "zone", zd.ZoneName, "serial", zd.IncomingSerial)
		zd.SetStatus(prevStatus) // no-op refresh — nothing changed, restore prior status
		return false, nil
	}
	if new_zd.IncomingSerial == zd.IncomingSerial {
		lg.Info("FetchFromUpstream: forced retransfer, re-applying zone despite unchanged serial",
			"zone", zd.ZoneName, "serial", zd.IncomingSerial)
	}

	// verify-zonemd, on what upstream just sent and before it is adopted. The
	// case the option exists for: a secondary cannot re-derive a digest it was
	// not given, so checking the one it WAS given is the only assurance it has
	// that the zone it is about to serve is the zone its primary published.
	if err := zd.gateIncomingZonemd(ctx, &new_zd, "upstream"); err != nil {
		zd.SetStatus(prevStatus)
		return false, err
	}

	new_zd.Ready = true

	// Pre-refresh callbacks: analysis of old vs new zone data + modification of new_zd.
	for _, cb := range zd.OnZonePreRefresh {
		cb(zd, &new_zd)
	}

	// Last gate before the hard flip. The transfer and the pre-refresh
	// callbacks both take real time -- an AXFR of a large zone, then MP roles
	// doing HSYNC/DNSKEY analysis -- so cancellation can land after the earlier
	// checks passed. Publishing replacement data into a daemon that is shutting
	// down is exactly what the caller asked us not to do.
	if cerr := ctx.Err(); cerr != nil {
		zd.SetStatus(prevStatus)
		return false, fmt.Errorf("FetchFromUpstream %s: %w", zd.ZoneName, cerr)
	}

	// Publish replacement: working set from transferred data + dynamic RRs.
	zd.mu.Lock()
	firstLoad := zd.FirstZoneLoad
	if err := zd.applyRefreshReplacementLocked(&new_zd, dynamicRRs, firstLoad, false); err != nil {
		zd.mu.Unlock()
		lg.Error("failed to persist outgoing serial", "zone", zd.ZoneName, "err", err)
		return false, err
	}
	zd.mu.Unlock()

	// Post-refresh callbacks: queue sends and notifications that need the live zone pointer.
	for _, cb := range zd.OnZonePostRefresh {
		cb(zd)
	}

	if ConfLive().ServiceDebug {
		fname, err := zd.ZoneFileName()
		if err != nil {
			lg.Error("ZoneFileName failed", "zone", zd.ZoneName, "err", err)
		} else {
			_, err := new_zd.WriteFile(fname)
			if err != nil {
				lg.Error("WriteFile failed", "zone", zd.ZoneName, "err", err)
			} else {
				// zd.Logger.Printf("FetchFromUpstream: Zone %s: zone file written to %s", zd.ZoneName, f)
			}
		}
	}

	return true, nil
}

// ZoneFileName returns the path to use for this zone's file. Only zones with zonefile: set
// (in config) are written to disk; autozones and secondaries without zonefile are not persisted.
func (zd *ZoneData) ZoneFileName() (string, error) {
	if zd.Zonefile == "" {
		return "", fmt.Errorf("zone has no zonefile (autozone or secondary not persisted); not written to disk")
	}
	fname := path.Clean(zd.Zonefile)
	dirname := path.Dir(fname)
	if _, err := os.Stat(dirname); os.IsNotExist(err) {
		if err := os.MkdirAll(dirname, 0755); err != nil {
			return "", fmt.Errorf("zoneFileName: failed to create missing directory %s: %v", dirname, err)
		}
	}
	return fname, nil
}

func (zd *ZoneData) WriteZone(tosource bool, force bool) (string, error) {
	var fname string
	var err error
	if tosource {
		fname = zd.Zonefile
	} else {
		fname, err = zd.ZoneFileName()
		if err != nil {
			return err.Error(), err
		}
	}
	if !zd.Options[OptDirty] && !force {
		return fmt.Sprintf("Zone %s not modified, writing to disk not needed", zd.ZoneName), nil
	}
	_, wroteSerial, err := zd.WriteFileWithSerial(fname)
	if err == nil {
		zd.mu.Lock()
		// The same question the dirty flag asks, captured once under the lock
		// and reused for the identity record below: is the file still what the
		// zone is serving?
		fileIsCurrent := zd.CurrentSerial == wroteSerial
		// Clean only if the file caught up with what the zone is serving. A
		// publish can land WHILE this write runs: we then wrote serial 11 while
		// the zone moved to 12, and clearing the flag unconditionally would
		// report the zone as written out when the file is a serial behind.
		// The next `zone write` would answer "not modified, writing to disk not
		// needed" and decline to fix it. (No content is lost -- serial 12's
		// delta is bounded by serial, so it survives the drop below and replays
		// -- but the operator is told the file is current when it is not.)
		if fileIsCurrent {
			zd.Options[OptDirty] = false
		}
		// The file now carries this serial, so that is what a future journal
		// anchors to. Without this the next change would chain from the serial
		// the file had BEFORE this write, and the load after that would refuse
		// the journal.
		if wroteSerial != 0 {
			zd.fileSerial = wroteSerial
		}
		zd.mu.Unlock()

		// The file we have just written is a file we have looked at, so the
		// next refresh can skip it. Without this every write-out would cost one
		// full parse and digest at the following refresh.
		if wst, werr := os.Stat(fname); werr == nil {
			zd.recordZoneFileStat(fname, wst)
		}

		// Record the file's new identity: this is the other end of the
		// comparison the next load makes. The digest is of the published
		// snapshot, which is exactly what WriteZoneToFile just serialised, so
		// reading this file back must reproduce it.
		//
		// Best-effort, and deliberately not fatal: the file is written and
		// being served, and the cost of a missing record is that the next load
		// reports "no basis for comparison" instead of "unchanged". Failing the
		// write here would turn a bookkeeping problem into an operational one.
		// Gated on the same condition, and for the same reason. ZoneDigestOfPublished
		// digests the snapshot published NOW, not the one WriteFileWithSerial
		// serialised, so it only describes this file while the two serials
		// agree. Recording it after a publish landed mid-write would store a
		// digest of serial 12 as the identity of a file holding serial 11 --
		// and the next load, finding a mismatch, would report the file as
		// CHANGED and merge the journal over a file nobody edited, lifting the
		// serial and possibly writing a .rejected artefact.
		//
		// wroteSerial != 0 for the same reason the fileSerial assignment above
		// refuses zero: recording serial 0 as the file's identity is worse than
		// recording nothing, which merely reads as "no basis for comparison".
		if zd.KeyDB != nil && fileIsCurrent && wroteSerial != 0 {
			if digest, derr := zd.ZoneDigestOfPublished(); derr != nil {
				lg.Warn("zone written but its digest could not be computed;"+
					" the next load will have no basis for comparison",
					"zone", zd.ZoneName, "error", derr)
			} else if !zd.serialStillIs(wroteSerial) {
				// fileIsCurrent was decided before the lock was dropped, and
				// ZoneDigestOfPublished digests whatever is published when it
				// runs. A publish landing in between leaves a digest of the
				// newer zone about to be recorded as the identity of the file
				// we wrote -- the very mismatch the gate above exists to
				// prevent, one step later. Recording nothing is safe: the next
				// load reads "no basis for comparison" and re-establishes it.
				lg.Warn("zone written but a publish landed before its identity could be"+
					" recorded; leaving the file unidentified rather than recording a"+
					" digest of different content",
					"zone", zd.ZoneName, "wrote_serial", wroteSerial)
			} else if rerr := zd.RecordZoneFileState(wroteSerial, digest); rerr != nil {
				lg.Warn("zone written but its file identity could not be recorded;"+
					" the next load will have no basis for comparison",
					"zone", zd.ZoneName, "error", rerr)
			}
		}

		// Phase 2: the changes are now IN the file, which is the source of
		// truth. The persisted deltas exist only to carry changes the file
		// does not yet have, so replaying them over this file on the next load
		// would apply everything a second time. Drop them.
		//
		// Order matters and is deliberate: the file write must succeed first.
		// Dropping the deltas before a failed write would lose the changes
		// entirely -- they would be neither in the file nor in the database.
		// This is also why freeze/sync/write-zone need no delta handling of
		// their own; they all reach the file through here.
		//
		// A failure to drop them is not fatal. The file is correct and being
		// served; the cost is that a restart replays changes the file already
		// contains. Adds are idempotent, deletes of absent records are
		// no-ops, so the replayed result matches -- but it is still wrong
		// enough to log loudly.
		if zd.KeyDB != nil {
			// Bound the drop by the serial actually WRITTEN, not by a ceiling
			// read beforehand. A ceiling has a window: a publish can land in
			// the file after the ceiling is read, and its delta row then
			// survives the drop and fails the chain check on the next load.
			// "Is this change already in the file?" is answered by the file's
			// serial, and that has no window at all.
			if n, derr := zd.KeyDB.DeleteZoneDeltasThroughSerial(zd.ZoneName, wroteSerial); derr != nil {
				lg.Error("zone written to file but its persisted deltas could not be dropped;"+
					" a restart will replay changes the file already contains",
					"zone", zd.ZoneName, "file", fname, "error", derr)
			} else if n > 0 {
				lg.Info("zone written to file; persisted deltas dropped",
					"zone", zd.ZoneName, "file", fname, "rows", n)
			}
		}
	}
	return fmt.Sprintf("Zone %s written to %s", zd.ZoneName, fname), err
}

func (zd *ZoneData) SetOption(option ZoneOption, value bool) {
	zd.mu.Lock()
	zd.Options[option] = value
	zd.mu.Unlock()
}

// getOwnerFrom reads an owner from an ALREADY-PINNED snapshot. Response paths
// (QueryResponder, ZoneTransferOut) pin one snapshot at the top and read
// everything through the *From helpers, so every read in one response comes from
// the same serial — no intra-response tearing. snap==nil yields nil (the caller
// SERVFAILs / refuses).
func getOwnerFrom(snap *zoneSnapshot, qname string) *OwnerData {
	if snap == nil {
		return nil
	}
	return snap.Data[qname]
}

// getRRsetFrom reads one RRset from a pinned snapshot.
func getRRsetFrom(snap *zoneSnapshot, qname string, rrtype uint16) *core.RRset {
	owner := getOwnerFrom(snap, qname)
	if owner == nil {
		return nil
	}
	if rrset, ok := owner.RRtypes.Get(rrtype); ok {
		return &rrset
	}
	return nil
}

// nameExistsFrom reports whether qname exists in a pinned snapshot.
func nameExistsFrom(snap *zoneSnapshot, qname string) bool {
	if snap == nil {
		return false
	}
	_, ok := snap.Data[qname]
	return ok
}

func (zd *ZoneData) NameExists(qname string) bool {
	if zd.ZoneStore != MapZone {
		return false
	}
	return nameExistsFrom(zd.publishedSnapshot(), qname)
}

func (zd *ZoneData) GetOwner(qname string) (*OwnerData, error) {
	if !zd.Ready {
		return nil, fmt.Errorf("getOwner: zone %s: %w", zd.ZoneName, ErrZoneNotReady)
	}
	if zd.ZoneStore != MapZone {
		return nil, fmt.Errorf("getOwner: only supported for MapZone, not %s",
			ZoneStoreToString[zd.ZoneStore])
	}
	return getOwnerFrom(zd.publishedSnapshot(), qname), nil
}

func (zd *ZoneData) GetRRset(qname string, rrtype uint16) (*core.RRset, error) {
	if zd == nil {
		return nil, fmt.Errorf("getRRset: zone data is nil, this should not happen")
	}
	owner, err := zd.GetOwner(qname)
	if err != nil {
		return nil, err
	}
	if owner == nil && zd.ZoneName != qname {
		return nil, nil // this can happen if qname does not exist in the zone
	}
	if owner == nil {
		// XXX: This can not happen, as there should always be data at the zone apez
		panic(fmt.Sprintf("GetRRset: owner data is nil for zone apex %s. This should not happen", zd.ZoneName))
	}
	// dump.P(owner)
	if rrset, exists := owner.RRtypes.Get(rrtype); exists {
		return &rrset, nil
	} else {
		return nil, nil
	}
}

func (zd *ZoneData) GetOwnerNames() ([]string, error) {
	if zd.ZoneStore != MapZone {
		return nil, fmt.Errorf("getOwnerNames: only supported for MapZone, not %s",
			ZoneStoreToString[zd.ZoneStore])
	}
	snap := zd.publishedSnapshot()
	if snap == nil || len(snap.Data) == 0 {
		return nil, nil
	}
	names := make([]string, 0, len(snap.Data))
	for name := range snap.Data {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

// XXX: Is qname the name of a zone cut for a child zone?
func (zd *ZoneData) IsChildDelegation(qname string) bool {
	lg.Debug("IsChildDelegation: checking delegation", "qname", qname, "zone", zd.ZoneName)
	owner, err := zd.GetOwner(qname)
	if err != nil || owner == nil || qname == zd.ZoneName {
		return false
	}
	if _, exists := owner.RRtypes.Get(dns.TypeNS); !exists {
		return false
	}
	if len(owner.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs) == 0 {
		return false
	}
	// zd.Logger.Printf("IsChildDelegation: %s is an existing child of %s",
	// 	qname, zd.ZoneName)
	return true
}

func (zd *ZoneData) GetSOA() (*dns.SOA, error) {
	// For new secondary zones that haven't been transferred yet, return synthetic SOA
	// This allows the refresh engine to proceed with the first transfer without error.
	// Primary zones must load from disk and should not use synthetic SOA.
	if !zd.Ready && zd.ZoneType == Secondary && zd.IncomingSerial == 0 {
		// Return synthetic SOA with serial 0 and default refresh interval
		// Serial 0 ensures the first transfer will always proceed (any real serial > 0)
		lg.Debug("GetSOA: new secondary zone not yet transferred, returning synthetic SOA with serial 0", "zone", zd.ZoneName)
		return &dns.SOA{
			Hdr: dns.RR_Header{
				Name:   zd.ZoneName,
				Rrtype: dns.TypeSOA,
				Class:  dns.ClassINET,
				Ttl:    86400,
			},
			Ns:      "invalid.",
			Mbox:    "hostmaster." + zd.ZoneName,
			Serial:  0,
			Refresh: 300,     // 5 minutes default
			Retry:   1800,    // 30 minutes
			Expire:  1209600, // 2 weeks
			Minttl:  86400,   // 1 day
		}, nil
	}

	// For all other cases (primary zones, ready zones, catalog zones), require real data.
	// GetSOA must never return (nil, nil): a nil SOA with no error is a landmine for
	// callers that read soa.* only in the err==nil branch (e.g. RefreshEngine). During a
	// concurrent reload the apex owner can be transiently absent — surface that as an
	// error, not a nil SOA.
	if snap := zd.publishedSnapshot(); snap != nil && snap.SOA != nil {
		return snap.SOA, nil
	}
	owner, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return nil, err
	}
	if owner == nil {
		return nil, fmt.Errorf("GetSOA: zone %s: apex owner not found", zd.ZoneName)
	}
	soaSet := owner.RRtypes.GetOnlyRRSet(dns.TypeSOA)
	if len(soaSet.RRs) == 0 {
		return nil, fmt.Errorf("GetSOA: zone %s: no SOA record at apex", zd.ZoneName)
	}
	soa, ok := soaSet.RRs[0].(*dns.SOA)
	if !ok {
		return nil, fmt.Errorf("GetSOA: zone %s: apex SOA record is not a *dns.SOA (got %T)", zd.ZoneName, soaSet.RRs[0])
	}
	return soa, nil
}

func (zd *ZoneData) PrintOwners() {
	names, err := zd.GetOwnerNames()
	if err != nil {
		return
	}
	for _, key := range names {
		fmt.Printf("%s\n", key)
	}
}

func (zd *ZoneData) NotifyDownstreams() error {
	// zd.Logger.Printf("NotifyDownstreams: Zone %s has downstreams: %v", zd.ZoneName, zd.Downstreams)
	if zd == nil {
		lg.Error("NotifyDownstreams: zonedata is nil")
		return fmt.Errorf("zonedata is nil")
	}
	for _, d := range zd.Notify {

		// log.Printf("%s: Notifying downstream server %s about new SOA serial", zd.ZoneName, d.Addr)

		m := new(dns.Msg)
		m.SetNotify(zd.ZoneName)
		r, err := dns.Exchange(m, d.Addr)
		if err != nil {
			// well, we tried
			lg.Error("downstream NOTIFY failed", "downstream", d.Addr, "zone", zd.ZoneName, "err", err)
			continue
		}
		if r.Opcode != dns.OpcodeNotify {
			// well, we tried
			lg.Error("unexpected opcode from downstream on NOTIFY", "downstream", d.Addr, "zone", zd.ZoneName, "opcode", dns.OpcodeToString[r.Opcode])
		}
	}
	return nil
}

func WildcardReplace(rrs []dns.RR, qname, origqname string) []dns.RR {
	res := []dns.RR{}
	for _, rr := range rrs {
		newrr := dns.Copy(rr)
		newrr.Header().Name = origqname
		res = append(res, newrr)
	}
	return res
}

func IsIxfr(rrs []dns.RR) bool {
	first_soa := false

	if len(rrs) < 3 {
		return false
	}

	if _, ok := rrs[0].(*dns.SOA); ok {
		first_soa = true
	}

	if _, ok := rrs[1].(*dns.SOA); ok {
		if first_soa {
			return true
		}
	}
	return false
}

// Find the closest enclosing auth zone that has qname below it (qname is either auth data
// in the zone or located further down in a child zone that we are not auth for).
// Return zone, case fold used to match
func FindZone(qname string) (*ZoneData, bool) {
	var tzone string
	labels := strings.Split(qname, ".")
	for i := 0; i < len(labels)-1; i++ {
		tzone = strings.Join(labels[i:], ".")
		if zd, ok := Zones.Get(tzone); ok {
			return zd, false
		}
	}

	// if no match for exact qname, let's try with a case folded version
	qname = strings.ToLower(qname)
	labels = strings.Split(qname, ".")

	for i := 0; i < len(labels)-1; i++ {
		tzone = strings.Join(labels[i:], ".")
		if zd, ok := Zones.Get(tzone); ok {
			return zd, true
		}
	}
	lg.Debug("FindZone: no zone found", "qname", qname)
	return nil, false
}

func FindZoneNG(qname string) *ZoneData {
	i := strings.Index(qname, ".")
	for {
		if i == -1 {
			break // done
		}
		if zd, ok := Zones.Get(qname[i:]); ok {
			return zd
		}
		i = strings.Index(qname[i:], ".")
	}
	return nil
}

// EffectiveOutboundSoaSerial resolves the outbound serial mode actually in
// force for this zone, newest tier first:
//
//  1. the per-zone setting (zones: <z>: outbound_soa_serial, possibly
//     inherited from the zone's template via ExpandTemplate's gap-fill);
//  2. the server-global dnsengine.outbound_soa_serial (resolved onto the
//     KeyDB at parse time by applyOutboundSoaSerial);
//  3. OutboundSoaSerialKeep, the documented default.
//
// Every consumer of the mode MUST go through this rather than reading
// zd.KeyDB.OutboundSoaSerial directly, so the per-zone tier is honoured.
// Suppression for a non-originating tdns-auth secondary is deliberately NOT
// applied here — this answers "what mode is configured", not "may this zone
// act on it"; the callers pair it with the origination predicate.
// EffectiveTransferSrc returns the source addresses to bind when dialling this
// zone's upstreams, resolving the per-zone value over the server-global
// dnsengine.transfer_src. Empty means "let the kernel choose", which is the
// behaviour every zone had before this existed.
func (zd *ZoneData) EffectiveTransferSrc() []string {
	srcs, _ := zd.EffectiveTransferSrcWithSource()
	return srcs
}

// EffectiveTransferSrcWithSource is EffectiveTransferSrc plus the tier that
// supplied it ("zone", "global" or "default"), for display by `zone desc`. Both
// live in one function for the same reason as the outbound-serial pair below:
// so the precedence chain cannot be stated twice and silently diverge.
func (zd *ZoneData) EffectiveTransferSrcWithSource() (srcs []string, source string) {
	if len(zd.TransferSrc) > 0 {
		if zd.TransferSrcTier != "" {
			return zd.TransferSrc, zd.TransferSrcTier // already resolved upstream
		}
		return zd.TransferSrc, "zone" // per-zone, possibly via its template
	}
	if zd.KeyDB != nil {
		if srcs := zd.KeyDB.TransferSrcList(); len(srcs) > 0 {
			return srcs, "global" // dnsengine.transfer_src
		}
	}
	return nil, "default"
}

func (zd *ZoneData) EffectiveOutboundSoaSerial() string {
	mode, _ := zd.EffectiveOutboundSoaSerialWithSource()
	return mode
}

// EffectiveOutboundSoaSerialWithSource is EffectiveOutboundSoaSerial plus the
// tier that supplied the value ("zone", "global" or "default"), for display by
// `zone desc`. Both live here, in one function, so the precedence chain cannot
// be stated twice and silently diverge — which would make `zone desc` report a
// source that does not match the value actually in force.
func (zd *ZoneData) EffectiveOutboundSoaSerialWithSource() (mode, source string) {
	if zd.OutboundSoaSerial != "" {
		return zd.OutboundSoaSerial, "zone" // per-zone, possibly via its template
	}
	if zd.KeyDB != nil {
		if mode := zd.KeyDB.OutboundSoaSerialMode(); mode != "" {
			return mode, "global" // dnsengine.outbound_soa_serial
		}
	}
	return OutboundSoaSerialKeep, "default"
}

// nextOutboundSerial returns the next SOA serial that should be advertised
// to downstreams given zd.CurrentSerial and the effective outbound_soa_serial
// mode (per-zone, else server-global):
//   - "" / "keep" / "persist": prev + 1 (legacy behaviour; "persist" only
//     differs in that the resulting serial is also written to OutgoingSerials)
//   - "unixtime": time.Now().Unix(), unless that would not advance the serial
//     (e.g. multiple bumps within the same wallclock second), in which case
//     fall back to prev + 1 to preserve monotonicity.
func nextOutboundSerial(zd *ZoneData) uint32 {
	// A mirroring secondary never rewrites its serial into timestamp space —
	// MUST-NOT-MODIFY is absolute, not keep-mode-only. (Reaching here at all on
	// such a zone means something staged a publish-with-bump on it, which the
	// other gates should have prevented; +1 is the conservative fallback.)
	if zoneMayOriginateContent(zd) && zd.EffectiveOutboundSoaSerial() == OutboundSoaSerialUnixtime {
		s := uint32(time.Now().Unix())
		if s > zd.CurrentSerial {
			return s
		}
	}
	return zd.CurrentSerial + 1
}

// BumpSerialOnly advances the SOA serial per the configured
// outbound_soa_serial mode and rewrites the apex SOA RR (and its
// RRSIG, when the zone is signed). Does not notify downstreams.
// Use when the caller will handle notification separately or when
// notification is not appropriate (e.g. inside a NOTIFY handler
// where triggering downstream NOTIFYs could cause side effects).
func (zd *ZoneData) BumpSerialOnly() (BumperResponse, error) {
	lg.Debug("BumpSerialOnly: bumping SOA serial", "zone", zd.ZoneName)
	return zd.publishSync()
}

func (zd *ZoneData) BumpSerial() (BumperResponse, error) {
	return zd.BumpSerialOnly()
}

func (zd *ZoneData) FetchChildDelegationData(childname string) (*ChildDelegationData, error) {
	lg.Debug("FetchChildDelegationData: fetching delegation data", "child", childname)
	if !zd.IsChildDelegation(childname) {
		return nil, fmt.Errorf("FetchChildDelegationData: %s is not a child of %s", childname, zd.ZoneName)
	}
	//	if zd.Children[childname] != nil {
	//		if zd.Children[childname].ParentSerial == zd.CurrentSerial || time.Since(zd.Children[childname].Timestamp) < 24*time.Hour {
	//			return nil
	//		}
	//	}
	cdd := ChildDelegationData{
		ChildName:    childname,
		ParentSerial: zd.CurrentSerial,
		Timestamp:    time.Now(),
		RRsets:       make(map[string]map[uint16]core.RRset),
		NS_rrs:       []dns.RR{},
		A_glue:       []dns.RR{},
		AAAA_glue:    []dns.RR{},
	}

	owner, err := zd.GetOwner(childname)
	if err != nil {
		return nil, fmt.Errorf("fetchChildDelegationData: error getting owner for %s: %v", childname, err)
	}

	cdd.RRsets[childname] = map[uint16]core.RRset{
		dns.TypeNS: owner.RRtypes.GetOnlyRRSet(dns.TypeNS),
		dns.TypeDS: owner.RRtypes.GetOnlyRRSet(dns.TypeDS),
	}

	cdd.NS_rrs = owner.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs

	bns, err := BailiwickNS(childname, owner.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs)
	if err != nil {
		return nil, fmt.Errorf("FetchChildDelegationData: error getting in bailiwick NS for %s: %v", childname, err)
	}

	for _, ns := range bns {
		nsowner, err := zd.GetOwner(ns)
		if err != nil {
			return nil, fmt.Errorf("fetchChildDelegationData: error getting owner for %s: %v", ns, err)
		}
		cdd.RRsets[ns] = map[uint16]core.RRset{
			dns.TypeA:    nsowner.RRtypes.GetOnlyRRSet(dns.TypeA),
			dns.TypeAAAA: nsowner.RRtypes.GetOnlyRRSet(dns.TypeAAAA),
		}
		cdd.A_glue = append(cdd.A_glue, nsowner.RRtypes.GetOnlyRRSet(dns.TypeA).RRs...)
		cdd.AAAA_glue = append(cdd.AAAA_glue, nsowner.RRtypes.GetOnlyRRSet(dns.TypeAAAA).RRs...)
	}

	zd.Children[childname] = &cdd
	return &cdd, nil
}

func (zd *ZoneData) SetupZoneSync(delsyncq chan<- DelegationSyncRequest) error {
	wantsSync := zd.Options[OptDelSyncParent] || zd.Options[OptDelSyncChild] || zd.Options[OptDelSyncProxy]

	// Dynamic parentsync=agent detection removed — handled by tdns-mp
	// MPPostRefresh (hsync_utils.go) and OnFirstLoad (start_agent.go).

	if !wantsSync {
		lg.Debug("SetupZoneSync: zone does not require delegation sync", "zone", zd.ZoneName)
		return nil
	}
	lg.Debug("SetupZoneSync: zone requests delegation sync", "zone", zd.ZoneName)

	// Is this a parent zone and should we then publish a DSYNC RRset?
	if zd.Options[OptDelSyncParent] {
		// For the moment we receive both updates and notifies on the same address as the rest of
		// the DNS service. Doesn't have to be that way, but for now it is.

		// The _dsync owner is no longer read here: PublishDsyncRRs looks it up
		// itself, and reading it here only ever served the all-or-nothing guard
		// removed below.

		// PublishDsyncRRs is called unconditionally, and decides per scheme
		// what is missing.
		//
		// This used to skip the call entirely when any DSYNC record existed,
		// on the reasoning that an existing RRset is the operator's and should
		// not be rewritten. That reasoning is right and the guard was in the
		// wrong place: it is now inside PublishDsyncRRs, per scheme, so adding
		// a scheme to a zone that already publishes DSYNC actually publishes
		// it. With the guard here, that case did nothing at all -- no record,
		// no error, no warning -- and the documented remedy was to unpublish
		// the whole RRset and republish, which discards the operator's own
		// records.
		lg.Debug("SetupZoneSync: reconciling the DSYNC RRset", "zone", zd.ZoneName)
		if err := zd.PublishDsyncRRs(); err != nil {
			lg.Error("PublishDsyncRRs failed", "zone", zd.ZoneName, "err", err)
			return err
		}

		// Figure out if there is a DSYNC RR with scheme UPDATE; if so, we need to ensure that
		// we generate a SIG(0) key pair for the target and publish the public key in the zone.
		//
		// An unset target means this parent does not offer the UPDATE scheme
		// — which used to be unusual and is now ordinary, since a parent may
		// offer only API. Without the guard the empty template expands to ".",
		// which is a syntactically valid domain name, and the zone would get a
		// SIG(0) keypair generated for the root.
		updateTargetTpl := DelegationSyncConfig().Parent.Update.Target
		updateTarget := dns.Fqdn(strings.Replace(updateTargetTpl, "{ZONENAME}", zd.ZoneName, 1))
		if updateTargetTpl == "" {
			lg.Debug("SetupZoneSync: no DSYNC update target configured, skipping SIG(0) key prep", "zone", zd.ZoneName)
		} else if _, ok := dns.IsDomainName(updateTarget); !ok {
			lg.Error("SetupZoneSync: invalid DSYNC update target", "zone", zd.ZoneName, "target", updateTarget)
		} else {
			lg.Debug("SetupZoneSync: DSYNC update target", "zone", zd.ZoneName, "target", updateTarget)
			err := zd.ParentSig0KeyPrep(updateTarget, zd.KeyDB)
			if err != nil {
				lg.Error("ParentSig0KeyPrep failed", "target", updateTarget, "err", err)
				return err
			}
		}
	}

	// If this is a child zone and we have the delegation-sync-child option set, we need to
	// ensure that there is a SIG(0) keypair and that the public key is published in the zone.
	// delegation-sync-child is valid for auth (standalone) or agent+multi-provider zones.
	// Combiner and signer roles don't do child delegation sync.
	if zd.Options[OptDelSyncChild] &&
		((Globals.App.Type == AppTypeAuth && !zd.Options[OptMultiProvider]) ||
			(Globals.App.Type == AppTypeAgent && zd.Options[OptMultiProvider])) {
		schemes := DelegationSyncConfig().Child.Schemes
		if len(schemes) == 0 {
			lg.Error("SetupZoneSync: zone has delegation-sync-child enabled but delegationsync.child.schemes is not configured — delegation sync will not work", "zone", zd.ZoneName)
			zd.SetError(ConfigError, "delegation-sync-child enabled but delegationsync.child.schemes is not configured")
			return fmt.Errorf("delegation-sync-child enabled but delegationsync.child.schemes is not configured for zone %s", zd.ZoneName)
		}
		for _, scheme := range schemes {
			switch scheme {
			case "update":
				delsyncq <- DelegationSyncRequest{
					Command:  "DELEGATION-SYNC-SETUP",
					ZoneName: zd.ZoneName,
					ZoneData: zd,
					// Response:   make(chan DelegationSyncStatus),
				}

			case "notify":
				// CSYNC and CDS are published proactively when the zone is modified
				// (via zone_updater.go and delegation_sync.go).
			default:
			}
		}
	}

	// delegation-sync-proxy: a tdns-agent acting as a SECONDARY for a zone
	// whose primary is DSYNC-unaware (BIND/Knot). The agent inspects incoming
	// transfers for CDS/CSYNC (and NS/glue/DNSKEY) changes and forwards
	// NOTIFY(CDS/CSYNC) — and, when the parent advertises UPDATE and the agent's
	// KEY is published at the apex, DNS UPDATEs — to the parent on the primary's
	// behalf. Valid only for agent + secondary zones; reject other combinations
	// so a misconfiguration is loud rather than silently inert.
	if zd.Options[OptDelSyncProxy] {
		if Globals.App.Type != AppTypeAgent || zd.ZoneType != Secondary {
			lg.Error("SetupZoneSync: delegation-sync-proxy is only valid for a tdns-agent secondary zone",
				"zone", zd.ZoneName, "app", Globals.App.Type, "zonetype", zd.ZoneType)
			zd.SetError(ConfigError, "delegation-sync-proxy is only valid for an agent secondary zone")
			return fmt.Errorf("delegation-sync-proxy on zone %s requires a tdns-agent secondary zone", zd.ZoneName)
		}
		lg.Info("SetupZoneSync: delegation-sync-proxy enabled (agent secondary)", "zone", zd.ZoneName)
		// Run the UPDATE-proxy precondition check (§10.8) off the refresh path,
		// via the DelegationSyncher: it does DSYNC discovery (network) and may
		// generate a SIG(0) key, so it must not run inline here. The check is a
		// no-op for the NOTIFY proxy, which needs no key.
		if delsyncq != nil {
			delsyncq <- DelegationSyncRequest{
				Command:  "PROXY-UPDATE-SETUP",
				ZoneName: zd.ZoneName,
				ZoneData: zd,
			}
		}
	}

	return nil
}

// CollectDynamicRRs collects all dynamically generated RRsets for a zone that need to be
// repopulated after refresh. These RRs are stored outside ZoneData (in database or generated
// from config) and will be lost when the zone is reloaded.
//
// Returns a slice of RRsets that should be repopulated into the zone after refresh:
// - DNSKEY records (from DnssecKeyStore database, if online-signing enabled)
// - SIG(0) KEY records (from Sig0KeyStore database, if needed)
// - Transport signals (SVCB/TSYNC) - if Config provided and add-transport-signal enabled
func (zd *ZoneData) CollectDynamicRRs(conf *Config) []*core.RRset {
	var dynamicRRs []*core.RRset

	if (!zd.Options[OptAllowUpdates] && !zd.Options[OptOnlineSigning] && !zd.Options[OptInlineSigning]) || zd.KeyDB == nil {
		return dynamicRRs
	}

	// 1. Collect DNSKEY records (if signing enabled)
	if zd.Options[OptOnlineSigning] || zd.Options[OptInlineSigning] {
		dak, err := zd.KeyDB.GetDnssecKeys(zd.ZoneName, DnskeyStateActive)
		if err != nil {
			lg.Error("CollectDynamicRRs: failed to get DNSSEC keys", "zone", zd.ZoneName, "err", err)
		} else if dak != nil {
			var publishkeys []dns.RR
			for _, ksk := range dak.KSKs {
				publishkeys = append(publishkeys, dns.RR(&ksk.DnskeyRR))
			}
			for _, zsk := range dak.ZSKs {
				// If a ZSK has flags = 257 then it is a clone of a KSK and should not be included twice
				if zsk.DnskeyRR.Flags == 257 {
					continue
				}
				publishkeys = append(publishkeys, dns.RR(&zsk.DnskeyRR))
			}

			// Use the shared FetchZoneDnskeysSql (ops_dnskey.go) so
			// the snapshot here exactly matches PublishDnskeyRRs's
			// served RRset. Centralizing the predicate prevents the
			// two from drifting apart again.
			rows, err := zd.KeyDB.Query(FetchZoneDnskeysSql, zd.ZoneName)
			if err != nil {
				lg.Error("CollectDynamicRRs: failed to query DNSKEYs", "zone", zd.ZoneName, "err", err)
			} else {
				defer rows.Close()
				for rows.Next() {
					var keyid, flags, algorithm string
					var keyrr string
					if err := rows.Scan(&keyid, &flags, &algorithm, &keyrr); err != nil {
						lg.Error("CollectDynamicRRs: failed to scan DNSKEY row", "zone", zd.ZoneName, "err", err)
						continue
					}
					if rr, err := dns.NewRR(keyrr); err == nil {
						publishkeys = append(publishkeys, rr)
					} else {
						lg.Error("CollectDynamicRRs: failed to parse DNSKEY RR", "keyrr", keyrr, "zone", zd.ZoneName, "err", err)
					}
				}
				if err := rows.Err(); err != nil {
					lg.Error("CollectDynamicRRs: DNSKEY row iteration failed", "zone", zd.ZoneName, "err", err)
				}
			}

			if len(publishkeys) > 0 {
				dynamicRRs = append(dynamicRRs, &core.RRset{
					Name:   zd.ZoneName,
					Class:  dns.ClassINET,
					RRtype: dns.TypeDNSKEY,
					RRs:    publishkeys,
				})
			}
		}
	}

	// 2. Collect SIG(0) KEY records (if they should be published)
	if !zd.Options[OptDontPublishKey] {
		sak, err := zd.KeyDB.GetSig0Keys(zd.ZoneName, Sig0StateActive)
		if err != nil {
			// Not an error if no SIG(0) keys exist
			lg.Debug("CollectDynamicRRs: no active SIG(0) keys for zone (or error)", "zone", zd.ZoneName, "err", err)
		} else if sak != nil && len(sak.Keys) > 0 {
			var keyRRs []dns.RR
			for _, pkc := range sak.Keys {
				if strings.HasSuffix(pkc.KeyRR.Header().Name, zd.ZoneName) {
					keyRRs = append(keyRRs, &pkc.KeyRR)
				}
			}
			if len(keyRRs) > 0 {
				dynamicRRs = append(dynamicRRs, &core.RRset{
					Name:   zd.ZoneName,
					Class:  dns.ClassINET,
					RRtype: dns.TypeKEY,
					RRs:    keyRRs,
				})
			}
		}
	}

	// 3. Preserve stored transport-signal owner RRsets across a refresh replace.
	// A refresh rebuilds the working set from the freshly transferred zone data,
	// which does not include server-synthesized _dns.<ns> signals; carry them
	// over so they survive until the transport postpass regenerates them. (The
	// synthesized-fallback map is carried separately in applyRefreshReplacementLocked.)
	if zd.Options[OptAddTransportSignal] {
		snap := zd.publishedSnapshot()
		if snap == nil {
			return dynamicRRs
		}
		for owner, od := range snap.Data {
			if od == nil || !strings.HasPrefix(owner, "_dns.") {
				continue
			}
			if svcbRRset, exists := od.RRtypes.Get(dns.TypeSVCB); exists && len(svcbRRset.RRs) > 0 {
				svcbClone := &core.RRset{
					Name:   owner,
					Class:  dns.ClassINET,
					RRtype: dns.TypeSVCB,
					RRs:    make([]dns.RR, len(svcbRRset.RRs)),
					RRSIGs: make([]dns.RR, len(svcbRRset.RRSIGs)),
				}
				for i, rr := range svcbRRset.RRs {
					svcbClone.RRs[i] = dns.Copy(rr)
				}
				for i, rr := range svcbRRset.RRSIGs {
					svcbClone.RRSIGs[i] = dns.Copy(rr)
				}
				dynamicRRs = append(dynamicRRs, svcbClone)
			}
			if tsyncRRset, exists := od.RRtypes.Get(core.TypeTSYNC); exists && len(tsyncRRset.RRs) > 0 {
				tsyncClone := &core.RRset{
					Name:   owner,
					Class:  dns.ClassINET,
					RRtype: core.TypeTSYNC,
					RRs:    make([]dns.RR, len(tsyncRRset.RRs)),
					RRSIGs: make([]dns.RR, len(tsyncRRset.RRSIGs)),
				}
				for i, rr := range tsyncRRset.RRs {
					tsyncClone.RRs[i] = dns.Copy(rr)
				}
				for i, rr := range tsyncRRset.RRSIGs {
					tsyncClone.RRSIGs[i] = dns.Copy(rr)
				}
				dynamicRRs = append(dynamicRRs, tsyncClone)
			}
		}
	}

	return dynamicRRs
}

// repopulateWorkingSetLocked merges dynamic RRsets into the working set.
// Caller must hold zd.mu and have initialized zd.workingSet.
func (zd *ZoneData) repopulateWorkingSetLocked(dynamicRRs []*core.RRset) {
	if len(dynamicRRs) == 0 {
		return
	}

	for _, rrset := range dynamicRRs {
		if rrset == nil || len(rrset.RRs) == 0 {
			continue
		}

		owner := zd.stagedOwner(rrset.Name)
		if owner == nil {
			if zd.ZoneStore != MapZone {
				lg.Error("RepopulateDynamicRRs: failed to get/create owner", "owner", rrset.Name, "zone", zd.ZoneName)
				continue
			}
			owner = zd.getOrCreateWorkingOwner(rrset.Name)
		}

		existing, exists := owner.RRtypes.Get(rrset.RRtype)
		if exists {
			// Get returns an RRset whose RRs slice shares the published
			// snapshot's backing array; copy it before appending so a
			// spare-capacity append cannot mutate the live snapshot.
			merged := append([]dns.RR(nil), existing.RRs...)
			for _, newRR := range rrset.RRs {
				present := false
				for _, oldRR := range merged {
					if dns.IsDuplicate(newRR, oldRR) {
						present = true
						break
					}
				}
				if !present {
					merged = append(merged, newRR)
				}
			}
			existing.RRs = merged
			if len(rrset.RRSIGs) > 0 {
				existing.RRSIGs = rrset.RRSIGs
			}
			zd.stageRRsetLocked(rrset.Name, existing)
		} else {
			zd.stageRRsetLocked(rrset.Name, cloneRRset(*rrset))
		}
	}

	lg.Info("RepopulateDynamicRRs: repopulated dynamic RRsets", "count", len(dynamicRRs), "zone", zd.ZoneName)

	apexCdsRRs := 0
	if owner := zd.stagedOwner(zd.ZoneName); owner != nil {
		if rs, ok := owner.RRtypes.Get(dns.TypeCDS); ok {
			apexCdsRRs = len(rs.RRs)
		}
	}
	lgRollover.Debug("post-refresh apex CDS observation",
		"zone", zd.ZoneName, "apex_cds_rrs", apexCdsRRs)
}

// RepopulateDynamicRRs repopulates dynamically generated RRsets and publishes.
func (zd *ZoneData) RepopulateDynamicRRs(dynamicRRs []*core.RRset) {
	if len(dynamicRRs) == 0 {
		return
	}
	zd.mu.Lock()
	defer zd.mu.Unlock()
	zd.ensureWorkingSet()
	zd.repopulateWorkingSetLocked(dynamicRRs)
	zd.publishWorkingSetLocked(zd.generation.Load(), false)
}

func (zd *ZoneData) SetupZoneSigning(resignq chan<- *ZoneData) error {
	if Globals.App.Type == AppTypeAgent {
		return nil // agents never sign
	}

	if !zd.Options[OptOnlineSigning] && !zd.Options[OptInlineSigning] {
		return nil // this zone should not be signed (at least not by us)
	}

	if zd.ZoneType != Primary && !zd.Options[OptInlineSigning] {
		return nil // non-primary zones require inline-signing to be signed
	}

	kdb := zd.KeyDB
	newrrsigs, err := zd.SignZone(kdb, false)
	if err != nil {
		lg.Error("SignZone failed", "zone", zd.ZoneName, "err", err)
		return err
	}

	lg.Info("SetupZoneSigning: zone signed", "zone", zd.ZoneName, "newRRSIGs", newrrsigs)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	select {
	case resignq <- zd:
	case <-ctx.Done():
		lg.Error("SetupZoneSigning: timeout sending zone to resign queue", "zone", zd.ZoneName)
	}

	return nil
}

// reloadWouldLoseChanges reports whether re-reading the zone file would discard
// in-memory changes nothing else holds.
//
// "The zone is dirty" used to be the whole answer and a reload was refused on
// it alone. With the delta journal that is the wrong answer: dirty means
// memory differs from the file, which is the NORMAL state of a zone with
// journalled changes -- ReplayPersistedDeltas and MergeJournalOverNewFile both
// set the flag themselves, at every load. Refusing on it makes `zone reload`
// permanently unavailable to exactly the zones reconciliation exists for,
// which is the same "reload is not wired into the design" gap as #362.
//
// What the refusal protects is a change that only memory holds. The publish
// path refuses any change it could not journal (see publishWorkingSetLocked),
// so with a database and an active journal, dirty means "in the journal" and a
// reload merges rather than discards. Without them -- `journal: active: false`,
// or no keystore at all -- memory really is the only copy and the refusal
// still earns its keep.
func reloadWouldLoseChanges(zd *ZoneData) bool {
	if zd == nil {
		return false
	}
	// Under zd.mu. Options is a MAP, replaced wholesale by a config reload and
	// written into by the updater, WriteZone and both load paths, all under
	// that lock -- while this runs on the API goroutine and on the refresh
	// engine, neither of which holds it. An unguarded read is a concurrent map
	// access, which Go turns into a process-wide fatal error rather than a
	// stale answer.
	zd.mu.Lock()
	dirty := zd.Options[OptDirty]
	zd.mu.Unlock()
	if !dirty {
		return false
	}
	// After the unlock: JournalActive takes the config lock, and there is no
	// reason to hold two.
	return zd.KeyDB == nil || !JournalActive()
}

func (zd *ZoneData) ReloadZone(refreshCh chan<- ZoneRefresher, force bool, wait bool, timeoutStr string) (string, error) {
	if reloadWouldLoseChanges(zd) {
		return "", fmt.Errorf("zone %s: the zone has changes that only memory holds, because the"+
			" delta journal is not recording them; a reload would discard them. Write them out"+
			" first with `zone sync`", zd.ZoneName)
	}

	// Re-read and re-parse the dnssec: block from the config file so this zone
	// is re-applied against the CURRENT policy definitions — an edited policy is
	// picked up without a separate `config reload`. Cheap; a parse error keeps
	// the previous policies. Updates the server-wide policy structs, but only
	// this zone is re-applied here — other zones converge when reloaded.
	confMu.Lock()
	if err := Conf.reloadDnssecFromFile(); err != nil {
		lg.Error("ReloadZone: failed to re-parse dnssec config, keeping previous policies", "zone", zd.ZoneName, "err", err)
	} else {
		// Publish only on success — on a parse error the old policies are kept,
		// so a republish would just re-snapshot the same state (matches
		// ReloadConfig).
		Conf.publishRuntimeConfig()
	}
	confMu.Unlock()

	var respch = make(chan RefresherResponse, 1)
	refreshCh <- ZoneRefresher{
		Name:     zd.ZoneName,
		Response: respch,
		Force:    force,
		Wait:     wait,
	}

	var resp RefresherResponse

	timeout := 2 * time.Second
	if wait {
		timeout = 10 * time.Second // default for --error mode
		if timeoutStr != "" {
			if d, err := time.ParseDuration(timeoutStr); err == nil {
				timeout = d
			}
		}
	}

	select {
	case resp = <-respch:
	case <-time.After(timeout):
		return fmt.Sprintf("Zone %s: timeout waiting for response from RefreshEngine", zd.ZoneName), fmt.Errorf("zone %s: timeout waiting for response from RefreshEngine", zd.ZoneName)
	}

	if resp.Error {
		lg.Error("ReloadZone: error from RefreshEngine", "err", resp.ErrorMsg)
		return "", fmt.Errorf("%s", resp.ErrorMsg)
	}

	if resp.Msg == "" {
		resp.Msg = fmt.Sprintf("Zone %s: reloaded", zd.ZoneName)
	}
	return resp.Msg, nil
}

type DelegationData struct {
	CurrentNS *core.RRset
	AddedNS   *core.RRset
	RemovedNS *core.RRset

	BailiwickNS []string
	A_glue      map[string]*core.RRset // map[nsname]
	AAAA_glue   map[string]*core.RRset // map[nsname]
	Actions     []dns.RR               // actions are DNS UPDATE actions that modify delegation data
	Time        time.Time
}

func (zd *ZoneData) DelegationData() (*DelegationData, error) {
	dd := DelegationData{
		Time:      time.Now(),
		AddedNS:   &core.RRset{},
		RemovedNS: &core.RRset{Name: zd.ZoneName},
		A_glue:    map[string]*core.RRset{},
		AAAA_glue: map[string]*core.RRset{},
	}

	rrset, err := zd.GetRRset(zd.ZoneName, dns.TypeNS)
	if err != nil {
		return nil, err
	}
	if len(rrset.RRs) == 0 {
		return nil, err
	}

	dd.CurrentNS = rrset

	// Get the in-bailiwick nameserver names
	dd.BailiwickNS, err = BailiwickNS(zd.ZoneName, dd.CurrentNS.RRs)
	if err != nil {
		return nil, err
	}

	for _, nsname := range dd.BailiwickNS {
		owner, err := zd.GetOwner(nsname)
		if err != nil {
			return nil, err
		}
		// XXX: Note that it *is* possible to have an nsname that isn't present in the zone.
		//      I.e. a broken config with an in-bailiwick NS w/o any address.
		if owner == nil {
			lg.Error("in-bailiwick NS without any address RRs", "zone", zd.ZoneName, "ns", nsname)
			continue
		}

		if rrset, exist := owner.RRtypes.Get(dns.TypeA); exist {
			if len(rrset.RRs) > 0 {
				dd.A_glue[nsname] = &rrset
			}
		}
		if rrset, exist := owner.RRtypes.Get(dns.TypeAAAA); exist {
			if len(rrset.RRs) > 0 {
				dd.AAAA_glue[nsname] = &rrset
			}
		}
	}
	return &dd, nil
}

func isValidIP(addr string) bool {
	ip := net.ParseIP(addr)
	return ip != nil
}

func (kdb *KeyDB) CreateAutoZone(zonename string, addrs []string, nsNames []string) (*ZoneData, error) {
	if zonename == "" {
		return nil, fmt.Errorf("zonename cannot be empty")
	}
	if !dns.IsFqdn(zonename) {
		return nil, fmt.Errorf("zonename must be fully qualified (end with dot)")
	}

	lg.Info("CreateAutoZone", "zone", zonename)

	// Create a fake zone for the sidecar identity just to be able to
	// to use to generate the TLSA.
	// Use "invalid." as the NS record for all autozones (RFC 9432 recommendation)
	tmpl := `
$ORIGIN {ZONENAME}
$TTL 86400
{ZONENAME}    IN SOA ns1.{ZONENAME} hostmaster.{ZONENAME} (
          {SERIAL}   ; serial
          3600       ; refresh (1 hour)
          1800       ; retry (30 minutes)
          1209600    ; expire (2 weeks)
          86400      ; minimum (1 day)
          )
{ZONENAME}     IN NS  invalid.
`
	currentTime := fmt.Sprintf("%d", time.Now().Unix())
	zonedatastr := strings.ReplaceAll(tmpl, "{ZONENAME}", zonename)
	zonedatastr = strings.ReplaceAll(zonedatastr, "{SERIAL}", currentTime)

	// Explicit nameserver hostnames (no glue): use for NS RRset only
	if len(nsNames) > 0 {
		lg.Debug("CreateAutoZone: using configured nameservers (no glue)", "nameservers", nsNames)
		nsLines := ""
		for _, n := range nsNames {
			nsLines += fmt.Sprintf("%s     IN NS  %s\n", zonename, dns.Fqdn(n))
		}
		zonedatastr = strings.ReplaceAll(zonedatastr, zonename+"     IN NS  invalid.\n", nsLines)
	} else if len(addrs) > 0 {
		// Add address records if addresses are provided (NS ns.{zone} + glue)
		lg.Debug("CreateAutoZone: adding address records", "addrs", addrs)

		// Update NS record to point to ns.{zonename} instead of invalid. when addresses are provided
		// This ensures the NS and glue records use the same owner name (no orphaned records)
		nsTarget := fmt.Sprintf("ns.%s", zonename)
		zonedatastr = strings.ReplaceAll(zonedatastr, "invalid.", nsTarget)

		for _, addr := range addrs {
			if !isValidIP(addr) {
				lg.Error("CreateAutoZone: invalid IP address", "addr", addr)
				return nil, fmt.Errorf("invalid IP address: %s", addr)
			}
			if strings.Contains(addr, ":") {
				// IPv6 address
				zonedatastr += fmt.Sprintf("ns.%s IN AAAA %s\n", zonename, addr)
			} else {
				// IPv4 address
				zonedatastr += fmt.Sprintf("ns.%s IN A %s\n", zonename, addr)
			}
		}
	}

	lg.Debug("CreateAutoZone: template zone data", "data", zonedatastr)

	zd := &ZoneData{
		ZoneName:  zonename,
		ZoneStore: MapZone,
		Logger:    log.Default(),
		ZoneType:  Primary,
		Options:   map[ZoneOption]bool{OptAutomaticZone: true},
		KeyDB:     kdb,
	}

	lg.Debug("CreateAutoZone: reading zone data", "zone", zonename)
	_, _, err := zd.ReadZoneData(zonedatastr, false)
	if err != nil {
		return nil, fmt.Errorf("failed to read zone data: %v", err)
	}

	zd.InstallInitialSnapshot()
	Zones.Set(zonename, zd)

	return zd, nil
}

// Extract the addresses we listen on from the dnsengine configuration. Exclude localhost and non-standard ports.
func (conf *Config) FindDnsEngineAddrs() ([]string, error) {
	addrs := []string{}
	lg.Debug("FindDnsEngineAddrs: dnsengine addresses", "addresses", conf.DnsEngine.Addresses)
	for _, ns := range conf.DnsEngine.Addresses {
		addr, port, err := net.SplitHostPort(ns)
		if err != nil {
			// return nil, fmt.Errorf("FindDnsEngineAddrs: failed to split host and port from address '%s': %v", ns, err)
			// Assume error was missing port, so add it
			addr, port = ns, "53"
		}
		if port != "53" {
			continue
		}
		// if addr == "127.0.0.1" || addr == "::1" {
		// 	continue
		// }
		if addr == "" {
			continue
		}
		addrs = append(addrs, addr)
	}
	return addrs, nil
}

type HsyncStatus struct {
	Time         time.Time
	ZoneName     string
	Command      string
	Status       bool
	Error        bool
	ErrorMsg     string
	Msg          string
	HsyncAdds    []dns.RR // Changed from Adds
	HsyncRemoves []dns.RR // Changed from Removes
}
