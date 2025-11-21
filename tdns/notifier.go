/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"fmt"
	"log"

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

	log.Printf("*** NotifierEngine: starting")
	for {
		select {
		case <-ctx.Done():
			log.Println("NotifierEngine: terminating due to context cancelled")
			return nil
		case nr, ok := <-notifyreqQ:
			if !ok {
				log.Println("NotifierEngine: terminating due to notifyreqQ closed")
				return nil
			}

			zd := nr.ZoneData

			log.Printf("NotifierEngine: Zone %q: will notify downstreams", zd.ZoneName)

			zd.SendNotify(nr.RRtype, nr.Targets)

			if nr.Response != nil {
				select {
				case nr.Response <- NotifyResponse{Msg: "OK", Rcode: dns.RcodeSuccess, Error: false, ErrorMsg: ""}:
				case <-ctx.Done():
					log.Printf("NotifierEngine: Context cancelled while sending response for zone %q NOTIFY request", zd.ZoneName)
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
			zd.Parent, err = ParentZone(zd.ZoneName, Globals.IMR)
			if err != nil {
				return dns.RcodeServerFailure, fmt.Errorf("zone %q: error: failure locating parent zone name. Ignoring notify request", zd.ZoneName)
			}
		}

	case dns.TypeDNSKEY:
	//		lookupzone = zonename
	//		lookupserver = childpri

	default:
		log.Printf("Error: Unsupported notify type: %q", dns.TypeToString[ntype])
	}

	for _, dst := range targets {
		if Globals.Verbose {
			log.Printf("Sending NOTIFY(%q) to %q\n", dns.TypeToString[ntype], dst)
		}

		m := new(dns.Msg)
		m.SetNotify(zd.ZoneName)

		// remove SOA, add ntype
		m.Question = []dns.Question{dns.Question{Name: zd.ZoneName, Qtype: ntype, Qclass: dns.ClassINET}}

		if Globals.Debug {
			fmt.Printf("Sending Notify:\n%s\n", m.String())
		}

		res, err := dns.Exchange(m, dst)
		if err != nil {
			log.Printf("Error from dns.Exchange(%q, NOTIFY(%q)): %v. Trying next NOTIFY target.", dst, dns.TypeToString[ntype], err)
			continue
		}

		if res.Rcode != dns.RcodeSuccess {
			if Globals.Verbose {
				fmt.Printf("... and got rcode %q back (bad)\n", dns.RcodeToString[res.Rcode])
			}
			log.Printf("Error: Rcode: %q", dns.RcodeToString[res.Rcode])
		} else {
			if Globals.Verbose {
				fmt.Printf("... and got rcode NOERROR back (good)\n")
			}
			return res.Rcode, nil
		}
	}
	return dns.RcodeServerFailure, fmt.Errorf("Error: No response from any NOTIFY target to NOTIFY(%q)", dns.TypeToString[ntype])
}
