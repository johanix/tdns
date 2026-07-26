/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Read-only per-primary SOA probing, for `zone desc` serial visibility.
 * See docs/2026-07-25-secondary-zones-immutable.md §7.
 */
package tdns

import (
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
func (zd *ZoneData) ProbeUpstreamSerials(conf *Config) []UpstreamSerial {
	if zd == nil || len(zd.Upstreams) == 0 {
		return nil
	}

	out := make([]UpstreamSerial, 0, len(zd.Upstreams))
	for _, up := range zd.Upstreams {
		res := UpstreamSerial{Addr: up.Addr}

		upstream := up.Addr
		if _, _, err := net.SplitHostPort(upstream); err != nil {
			upstream = net.JoinHostPort(upstream, defaultPortForPeer(up))
		}

		m := new(dns.Msg)
		m.SetQuestion(zd.ZoneName, dns.TypeSOA)
		c := new(dns.Client)

		// Probe over the same verified channel the transfer itself would use,
		// so an XoT peer is not silently probed in plaintext and a TSIG
		// mismatch surfaces here rather than at transfer time.
		if tlsCfg, terr := conf.ClientTLSConfigForPeer(up); terr != nil {
			res.Err = fmt.Sprintf("TLS setup failed: %v", terr)
			out = append(out, res)
			continue
		} else if tlsCfg != nil {
			c.Net = "tcp-tls"
			c.TLSConfig = tlsCfg
		}
		provider, serr := SignForPeer(m, up.Key, conf)
		if serr != nil {
			res.Err = fmt.Sprintf("TSIG sign setup failed: %v", serr)
			out = append(out, res)
			continue
		}
		c.TsigProvider = provider // nil for NOKEY => plain exchange

		r, _, err := c.Exchange(m, upstream)
		switch {
		case err != nil:
			res.Err = err.Error()
		case r.MsgHdr.Rcode != dns.RcodeSuccess:
			res.Err = dns.RcodeToString[r.MsgHdr.Rcode]
		case len(r.Answer) == 0:
			res.Err = "NOERROR but empty answer section"
		default:
			if soa, ok := r.Answer[0].(*dns.SOA); ok {
				res.Serial = soa.Serial
			} else {
				res.Err = "first answer is not a SOA"
			}
		}
		out = append(out, res)
	}
	return out
}

// outboundSoaSerialSource names which tier supplied the zone's effective
// outbound serial mode, so `zone desc` can show the value AND why it applies.
func (zd *ZoneData) outboundSoaSerialSource() string {
	if zd.OutboundSoaSerial != "" {
		return "zone" // per-zone setting, possibly inherited from its template
	}
	if zd.KeyDB != nil && zd.KeyDB.OutboundSoaSerial != "" {
		return "global" // dnsengine.outbound_soa_serial
	}
	return "default"
}
