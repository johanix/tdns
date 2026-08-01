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
// and is honoured per probe via ExchangeContext. That matters because the
// probes are sequential: with the library's 2s default timeout, a zone with
// several unreachable primaries would otherwise pin the handler for
// len(Upstreams) x 2s regardless of the request deadline. On cancellation the
// remaining primaries are reported as such rather than silently omitted.
func (zd *ZoneData) ProbeUpstreamSerials(ctx context.Context, conf *Config) []UpstreamSerial {
	if zd == nil || len(zd.Upstreams) == 0 {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
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
	plans := make([]probePlan, 0, len(zd.Upstreams))

	confMu.RLock()
	for _, up := range zd.Upstreams {
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
