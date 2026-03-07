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

			zd.SendNotify(nr.RRtype, nr.Targets)

			if nr.Response != nil {
				select {
				case nr.Response <- NotifyResponse{Msg: "OK", Rcode: dns.RcodeSuccess, Error: false, ErrorMsg: ""}:
				case <-ctx.Done():
					lgDns.Warn("NotifierEngine: context cancelled while sending NOTIFY response", "zone", zd.ZoneName)
					return nil
				}
			}
		}
	}
}

func (zd *ZoneData) SendNotify(ntype uint16, targets []string) (int, error) {
	if zd.ZoneName == "." {
		return dns.RcodeServerFailure, fmt.Errorf("zone %q: error: zone name not specified. Ignoring notify request", zd.ZoneName)
	}

	var err error

	switch ntype {
	case dns.TypeSOA:
		// Here we only need the downstreams
		if len(zd.Downstreams) == 0 {
			return dns.RcodeServerFailure, fmt.Errorf("zone %q: error: no downstreams. Ignoring notify request", zd.ZoneName)
		}

	case dns.TypeCSYNC, dns.TypeCDS:
		// Here we need the parent notify receiver addresses
		if zd.Parent == "." {
			if Globals.ImrEngine == nil {
				return dns.RcodeServerFailure, fmt.Errorf("zone %q: error: ImrEngine not active. Ignoring notify request", zd.ZoneName)
			}
			zd.Parent, err = Globals.ImrEngine.ParentZone(zd.ZoneName)
			if err != nil {
				return dns.RcodeServerFailure, fmt.Errorf("zone %q: error: failure locating parent zone name. Ignoring notify request", zd.ZoneName)
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
	for _, dst := range targets {
		lgDns.Info("NOTIFY: sending", "type", dns.TypeToString[ntype], "zone", zd.ZoneName, "target", dst)

		m := new(dns.Msg)
		m.SetNotify(zd.ZoneName)

		// remove SOA, add ntype
		m.Question = []dns.Question{dns.Question{Name: zd.ZoneName, Qtype: ntype, Qclass: dns.ClassINET}}

		lgDns.Debug("sending NOTIFY message", "msg", m.String())

		res, _, err := c.Exchange(m, dst)
		if err != nil {
			lgDns.Warn("NOTIFY: dns.Exchange failed, trying next target", "target", dst, "type", dns.TypeToString[ntype], "err", err)
			continue
		}

		if res.Rcode != dns.RcodeSuccess {
			lgDns.Warn("NOTIFY: bad rcode from target", "target", dst, "rcode", dns.RcodeToString[res.Rcode])
		} else {
			lgDns.Debug("NOTIFY: got NOERROR back", "target", dst)
			successCount++
			// Continue to send NOTIFYs to all targets, don't return early
		}
	}
	if successCount == 0 {
		return dns.RcodeServerFailure, fmt.Errorf("error: no response from any NOTIFY target to NOTIFY(%q)", dns.TypeToString[ntype])
	}
	lgDns.Info("NOTIFY: successfully sent", "type", dns.TypeToString[ntype], "zone", zd.ZoneName, "succeeded", successCount, "total", len(targets))
	return dns.RcodeSuccess, nil
}
