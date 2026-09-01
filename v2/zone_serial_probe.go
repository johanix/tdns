/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Read-only per-primary SOA probing, for `zone desc` serial visibility.
 * See docs/2026-07-25-secondary-zones-immutable.md §7.
 */
package tdns

import (
	"context"
	"fmt"
	"net"

	"github.com/miekg/dns"
)

// ProbeUpstreamSerials asks EVERY configured primary for the zone's SOA and
// reports what each one answered.
//
// This is deliberately not DoTransfer. DoTransfer probes to DECIDE — it
// short-circuits on the first usable answer, because for transferring purposes
// one good primary is enough. Here the disagreement IS the signal: the failure
// that motivated the MUST-NOT-MODIFY work was two masters serving the same zone
// at different serials, with edge nodes silently always fetching from the
// higher one. Seeing "this master says 42, that one says 5000" is the whole
// point, so every primary is probed and every answer kept, including failures
// (an unreachable master is itself diagnostic).
//
// Read-only: it mutates no zone state and makes no transfer decision. Costs one
// query per primary, so it belongs on the single-zone `zone desc` path rather
// than in a bulk listing.
//
// ctx is the caller's context (the HTTP request's, from the zone API handler)
// and is checked BETWEEN probes, which is what bounds this: the probes are
// sequential, so with the library's 2s default timeout a zone with several
// unreachable primaries would otherwise pin the handler for
// len(Upstreams) x 2s. On cancellation the remaining primaries are reported as
// such rather than silently omitted.
//
// A probe already on the wire is a different matter, and this comment used to
// overstate it by saying ctx was "honoured per probe via ExchangeContext". A
// DEADLINE on ctx is honoured that way, since ExchangeWithConnContext tightens
// the socket deadlines from ctx.Deadline(). Plain cancellation is not:
// ExchangeContext never watches ctx.Done(), and this client sets no Timeout, so
// a cancelled request still waits out the current probe's 2s before the loop
// notices. The worst case is therefore one probe, not len(Upstreams).
func (zd *ZoneData) ProbeUpstreamSerials(ctx context.Context, conf *Config) []UpstreamSerial {
	if zd == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	// zd.Upstreams is mutated in place under zd.mu by the refresh engine
	// (refreshengine.go), so take a copy under that lock rather than ranging
	// over the live slice -- confMu guards the config, not zone data.
	//
	// Deliberately NOT held together with confMu below. The two locks are
	// nested nowhere else in the tree, and a read-only diagnostic path is a
	// poor reason to introduce an ordering constraint that every future
	// writer would then have to respect.
	zd.mu.Lock()
	upstreams := make([]PeerConf, len(zd.Upstreams))
	copy(upstreams, zd.Upstreams)
	zd.mu.Unlock()

	if len(upstreams) == 0 {
		return nil
	}

	// Phase 1 -- resolve everything that reads config, under a single read
	// lock, with NO network I/O. ProbeUpstreamSerials receives the mutable
	// global &Conf, and a reload replaces its contents wholesale; resolving
	// per-upstream inside the probe loop would let a reload landing midway
	// hand later primaries TLS/TSIG material from a different config
	// generation than earlier ones. Snapshot once, then probe.
	//
	// The lock is NOT held across the exchanges below: a probe blocks until
	// the peer answers or the request deadline expires, and holding confMu
	// for that would stall every config reload behind an unreachable primary.
	type probePlan struct {
		res      UpstreamSerial
		client   *dns.Client
		upstream string
		keyName  string
		tsigAlgo string
		failed   bool
	}
	plans := make([]probePlan, 0, len(upstreams))

	confMu.RLock()
	for _, up := range upstreams {
		p := probePlan{res: UpstreamSerial{Addr: up.Addr}, upstream: up.Addr}
		if _, _, err := net.SplitHostPort(p.upstream); err != nil {
			p.upstream = net.JoinHostPort(p.upstream, defaultPortForPeer(up))
		}
		p.client = new(dns.Client)

		// Probe over the same verified channel the transfer itself would use,
		// so an XoT peer is not silently probed in plaintext and a TSIG
		// mismatch surfaces here rather than at transfer time.
		if tlsCfg, terr := conf.ClientTLSConfigForPeer(up); terr != nil {
			p.res.Err = fmt.Sprintf("TLS setup failed: %v", terr)
			p.failed = true
			plans = append(plans, p)
			continue
		} else if tlsCfg != nil {
			p.client.Net = "tcp-tls"
			p.client.TLSConfig = tlsCfg
		}

		provider, algo, serr := TsigMaterialForPeer(up.Key, conf)
		if serr != nil {
			p.res.Err = fmt.Sprintf("TSIG sign setup failed: %v", serr)
			p.failed = true
			plans = append(plans, p)
			continue
		}
		p.client.TsigProvider = provider // nil for NOKEY => plain exchange
		if provider != nil {
			p.keyName, p.tsigAlgo = up.Key, algo
		}
		plans = append(plans, p)
	}
	confMu.RUnlock()

	// Phase 2 -- network only. Nothing here reads shared config.
	out := make([]UpstreamSerial, 0, len(plans))
	for i := range plans {
		p := &plans[i]
		if p.failed {
			out = append(out, p.res)
			continue
		}

		// Stop probing once the caller has given up, but still record the
		// remaining primaries: "not probed" is honest, silence is not.
		if err := ctx.Err(); err != nil {
			p.res.Err = fmt.Sprintf("not probed: %v", err)
			out = append(out, p.res)
			continue
		}

		m := new(dns.Msg)
		m.SetQuestion(zd.ZoneName, dns.TypeSOA)
		// Stamped here, not in phase 1: the probes are sequential and each can
		// block until the deadline, so a timestamp taken during the snapshot
		// could be well outside the fudge window by the time the last message
		// is sent, and the peer would answer BADTIME.
		if p.keyName != "" {
			StampTsigForPeer(m, p.keyName, p.tsigAlgo)
		}

		r, _, err := p.client.ExchangeContext(ctx, m, p.upstream)
		switch {
		case err != nil:
			p.res.Err = err.Error()
		case r.MsgHdr.Rcode != dns.RcodeSuccess:
			p.res.Err = dns.RcodeToString[r.MsgHdr.Rcode]
		case len(r.Answer) == 0:
			p.res.Err = "NOERROR but empty answer section"
		default:
			if soa, ok := r.Answer[0].(*dns.SOA); ok {
				p.res.Serial = soa.Serial
			} else {
				p.res.Err = "first answer is not a SOA"
			}
		}
		out = append(out, p.res)
	}
	return out
}

// (The value/source pair is resolved by EffectiveOutboundSoaSerialWithSource in
// zone_utils.go — deliberately one function, so the precedence chain is not
// stated twice and cannot drift.)
