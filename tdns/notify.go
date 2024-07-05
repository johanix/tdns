/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/miekg/dns"
)

type NotifyRequest struct {
	ZoneName string
	ZoneData *ZoneData
	RRType   uint16
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
func NotifierEngine(notifyreqQ chan NotifyRequest) error {

	var nr NotifyRequest

	log.Printf("*** NotifierEngine: starting")
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		for {
			select {
			case nr = <-notifyreqQ:
				zd := nr.ZoneData

				log.Printf("NotifierEngine: Zone %s: will notify downstreams", zd.ZoneName)

				zd.SendNotify(nr.RRType, nr.Targets)

				if nr.Response != nil {
					nr.Response <- NotifyResponse{Msg: "OK", Rcode: dns.RcodeSuccess, Error: false, ErrorMsg: ""}
				}
				continue

				//			default:
				//				log.Printf("NotifierEngine: Zone %s: We should not get here. Ignoring.", nr.ZoneName)
			}
		}
	}()
	wg.Wait()

	log.Println("*** NotifierEngine: terminating")
	return nil
}

func xxxSendNotify(parentname, childname string, ntype string, dsynctarget *DsyncTarget) (int, error) {
	if parentname == "." {
		return dns.RcodeServerFailure, fmt.Errorf("Error: parent zone name not specified. Terminating.")
	}

	if childname == "." {
		return dns.RcodeServerFailure, fmt.Errorf("Error: child zone name not specified. Terminating.")
	}

	switch ntype {
	//	case "DNSKEY":
	//		lookupzone = zonename
	//		lookupserver = childpri
	default:
		// lookupzone = lib.ParentZone(zonename, lib.Globals.IMR)
		if Globals.ParentZone == "" {
			log.Fatalf("Error: parent zone name not specified.")
		}
	}

	for _, dst := range dsynctarget.Addresses {
		if Globals.Verbose {
			fmt.Printf("Sending NOTIFY(%s) to %s on address %s:%d\n",
				ntype, dsynctarget.Name, dst, dsynctarget.Port)
		}

		m := new(dns.Msg)
		m.SetNotify(childname)

		// remove SOA, add ntype
		m.Question = []dns.Question{dns.Question{childname, dns.StringToType[ntype], dns.ClassINET}}

		if Globals.Debug {
			fmt.Printf("Sending Notify:\n%s\n", m.String())
		}

		dst = net.JoinHostPort(dst, fmt.Sprintf("%d", dsynctarget.Port))
		res, err := dns.Exchange(m, dst)
		if err != nil {
			log.Printf("Error from dns.Exchange(%s, NOTIFY(%s)): %v. Trying next parent server", dst, ntype, err)
			continue
		}

		if res.Rcode != dns.RcodeSuccess {
			if Globals.Verbose {
				fmt.Printf("... and got rcode %s back (bad)\n",
					dns.RcodeToString[res.Rcode])
			}
			log.Printf("Error: Rcode: %s", dns.RcodeToString[res.Rcode])
		} else {
			if Globals.Verbose {
				fmt.Printf("... and got rcode NOERROR back (good)\n")
			}
			return res.Rcode, nil
		}
	}
	return dns.RcodeServerFailure, fmt.Errorf("Error: No response from any parent address for NOTIFY(%s)", ntype)
}

func (zd *ZoneData) SendNotify(ntype uint16, targets []string) (int, error) {
	if zd.ZoneName == "." {
		return dns.RcodeServerFailure, fmt.Errorf("Error: zone name not specified. Ignoring notify request.")
	}

	var err error

	switch ntype {
	case dns.TypeSOA:
		// Here we only need the downstreams
		if len(zd.Downstreams) == 0 {
			return dns.RcodeServerFailure, fmt.Errorf("Zone %s: Error: no downstreams. Ignoring notify request.", zd.ZoneName)
		}

	case dns.TypeCSYNC, dns.TypeCDS:
		// Here we need the parent notify receiver addresses
		if zd.Parent == "." {
			zd.Parent, err = ParentZone(zd.ZoneName, Globals.IMR)
			if err != nil {
				return dns.RcodeServerFailure, fmt.Errorf("Zone %s: Error: failure locating parent zone name. Ignoring notify request.", zd.ZoneName)
			}
		}

	case dns.TypeDNSKEY:
	//		lookupzone = zonename
	//		lookupserver = childpri

	default:
		log.Printf("Error: Unsupported notify type: %s", dns.TypeToString[ntype])
	}

	for _, dst := range targets {
		if Globals.Verbose {
			log.Printf("Sending NOTIFY(%s) to %s\n", ntype, dst)
		}

		m := new(dns.Msg)
		m.SetNotify(zd.ZoneName)

		// remove SOA, add ntype
		m.Question = []dns.Question{dns.Question{zd.ZoneName, ntype, dns.ClassINET}}

		if Globals.Debug {
			fmt.Printf("Sending Notify:\n%s\n", m.String())
		}

		res, err := dns.Exchange(m, dst)
		if err != nil {
			log.Printf("Error from dns.Exchange(%s, NOTIFY(%s)): %v. Trying next NOTIFY target.", dst, ntype, err)
			continue
		}

		if res.Rcode != dns.RcodeSuccess {
			if Globals.Verbose {
				fmt.Printf("... and got rcode %s back (bad)\n", dns.RcodeToString[res.Rcode])
			}
			log.Printf("Error: Rcode: %s", dns.RcodeToString[res.Rcode])
		} else {
			if Globals.Verbose {
				fmt.Printf("... and got rcode NOERROR back (good)\n")
			}
			return res.Rcode, nil
		}
	}
	return dns.RcodeServerFailure, fmt.Errorf("Error: No response from any NOTIFY target to NOTIFY(%s)", ntype)
}
