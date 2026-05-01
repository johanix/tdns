/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

type NotifyRequest struct {
	ZoneName string
	ZoneData *ZoneData
	RRtype   uint16
	Targets  []string // []addr:port
	Urgent   bool
	Response chan NotifyResponse
}

type NotifyResponse struct {
	Msg      string
	Rcode    int
	Error    bool
	ErrorMsg string
	// EDE carries any Extended DNS Errors returned by the parent's
	// NOTIFY response. On any-success-wins overall outcome, EDE is
	// populated from the first NOERROR target's response (typically
	// empty). On overall failure, EDE is populated from the most
	// recent failing target's response. The rollover engine's
	// parent-rejected category surfaces these for operator
	// diagnostics.
	EDE []dns.EDNS0_EDE
}

// XXX: The whole point with the NotifierEngine is to be able to control the max rate of send notifications per
// zone. This is not yet implemented, but this is where to do it.
func Notifier(ctx context.Context, notifyreqQ chan NotifyRequest) error {

	lgDns.Info("NotifierEngine: starting")
	for {
		select {
		case <-ctx.Done():
			lgDns.Info("NotifierEngine: terminating due to context cancelled")
			return nil
		case nr, ok := <-notifyreqQ:
			if !ok {
				lgDns.Info("NotifierEngine: terminating due to notifyreqQ closed")
				return nil
			}

			zd := nr.ZoneData

			lgDns.Info("NotifierEngine: will notify downstreams", "zone", zd.ZoneName)

			rcode, ede, sendErr := zd.SendNotify(nr.RRtype, nr.Targets)

			if nr.Response != nil {
				resp := NotifyResponse{
					Rcode: rcode,
					EDE:   ede,
				}
				if sendErr != nil {
					resp.Error = true
					resp.ErrorMsg = sendErr.Error()
				} else {
					resp.Msg = "OK"
				}
				select {
				case nr.Response <- resp:
				case <-ctx.Done():
					lgDns.Warn("NotifierEngine: context cancelled while sending NOTIFY response", "zone", zd.ZoneName)
					return nil
				}
			}
		}
	}
}

// SendNotify sends NOTIFY to every target and aggregates with
// any-success-wins semantics. On a successful overall outcome (at
// least one target NOERROR), the returned rcode is NOERROR and EDE
// is populated from the first NOERROR target's response (typically
// empty). On overall failure, the returned rcode is the rcode of the
// most recent failing target's response (or SERVFAIL with err if
// every target's transport failed) and EDE comes from that target's
// response. err is non-nil only when no target produced a usable
// response at all (transport-level failure across the board).
func (zd *ZoneData) SendNotify(ntype uint16, targets []string) (int, []dns.EDNS0_EDE, error) {
	if zd.ZoneName == "." {
		return dns.RcodeServerFailure, nil, fmt.Errorf("zone %q: error: zone name not specified. Ignoring notify request", zd.ZoneName)
	}

	var err error

	switch ntype {
	case dns.TypeSOA:
		// Here we only need the downstreams
		if len(zd.Downstreams) == 0 {
			return dns.RcodeServerFailure, nil, fmt.Errorf("zone %q: error: no downstreams. Ignoring notify request", zd.ZoneName)
		}

	case dns.TypeCSYNC, dns.TypeCDS:
		// Here we need the parent notify receiver addresses
		if zd.Parent == "." {
			if Globals.ImrEngine == nil {
				return dns.RcodeServerFailure, nil, fmt.Errorf("zone %q: error: ImrEngine not active. Ignoring notify request", zd.ZoneName)
			}
			zd.Parent, err = Globals.ImrEngine.ParentZone(zd.ZoneName)
			if err != nil {
				return dns.RcodeServerFailure, nil, fmt.Errorf("zone %q: error: failure locating parent zone name. Ignoring notify request", zd.ZoneName)
			}
		}

	case dns.TypeDNSKEY:
	//		lookupzone = zonename
	//		lookupserver = childpri

	default:
		lgDns.Error("unsupported notify type", "type", dns.TypeToString[ntype])
	}

	c := new(dns.Client)
	c.Timeout = 5 * time.Second

	successCount := 0
	var firstSuccessEDE []dns.EDNS0_EDE
	var lastFailRcode int
	var lastFailEDE []dns.EDNS0_EDE
	haveLastFailRcode := false

	for _, dst := range targets {
		lgDns.Info("NOTIFY: sending", "type", dns.TypeToString[ntype], "zone", zd.ZoneName, "target", dst)

		m := new(dns.Msg)
		m.SetNotify(zd.ZoneName)

		// remove SOA, add ntype
		m.Question = []dns.Question{dns.Question{Name: zd.ZoneName, Qtype: ntype, Qclass: dns.ClassINET}}

		lgDns.Debug("sending NOTIFY message", "msg", m.String())

		res, _, exErr := c.Exchange(m, dst)
		if exErr != nil {
			lgDns.Warn("NOTIFY: dns.Exchange failed, trying next target", "target", dst, "type", dns.TypeToString[ntype], "err", exErr)
			continue
		}

		ede := extractEDEFromMsg(res)

		if res.Rcode != dns.RcodeSuccess {
			lgDns.Warn("NOTIFY: bad rcode from target", "target", dst, "rcode", dns.RcodeToString[res.Rcode])
			lastFailRcode = res.Rcode
			lastFailEDE = ede
			haveLastFailRcode = true
		} else {
			lgDns.Debug("NOTIFY: got NOERROR back", "target", dst)
			if successCount == 0 {
				firstSuccessEDE = ede
			}
			successCount++
			// Continue to send NOTIFYs to all targets, don't return early
		}
	}
	if successCount == 0 {
		if haveLastFailRcode {
			// Parent replied — just with a non-NOERROR rcode. Return
			// the rcode/EDE without an error: this is "parent
			// rejected" (parent-rejected category), not "transport
			// failed". The caller categorises from the rcode and
			// EDE; making this an error would force the rollover
			// engine into the transport bucket and lose the EDE
			// context that's the whole point of Phase 4 plumbing.
			return lastFailRcode, lastFailEDE, nil
		}
		// No response from any target at all → genuine transport
		// failure. err is non-nil only on this branch.
		return dns.RcodeServerFailure, nil, fmt.Errorf("error: no response from any NOTIFY target to NOTIFY(%q)", dns.TypeToString[ntype])
	}
	lgDns.Info("NOTIFY: successfully sent", "type", dns.TypeToString[ntype], "zone", zd.ZoneName, "succeeded", successCount, "total", len(targets))
	return dns.RcodeSuccess, firstSuccessEDE, nil
}

// extractEDEFromMsg pulls every EDNS0_EDE option out of a DNS message's
// OPT record and returns them as typed values. Returns nil when the
// message has no OPT or no EDEs.
func extractEDEFromMsg(msg *dns.Msg) []dns.EDNS0_EDE {
	if msg == nil {
		return nil
	}
	opt := msg.IsEdns0()
	if opt == nil {
		return nil
	}
	var out []dns.EDNS0_EDE
	for _, o := range opt.Option {
		if e, ok := o.(*dns.EDNS0_EDE); ok && e != nil {
			out = append(out, *e)
		}
	}
	return out
}
