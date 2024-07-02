/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"
	"log"
	"net"

	"github.com/miekg/dns"
)

var childpri, parpri string

func SendNotify(parentname, childname string, ntype string, dsynctarget *DsyncTarget) (int, error) {
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
		// Globals.ParentZone = dns.Fqdn(Globals.ParentZone)

		// if parpri == "" {
		// 	log.Fatalf("Error: parent primary nameserver not specified.")
		// }
		// lookupzone = tdns.Globals.ParentZone
		// lookupserver = parpri
	}

	//	const notify_scheme = 1
	//	dsynctarget, err := tdns.LookupDSYNCTarget(lookupzone, lookupserver, dns.StringToType[ntype], notify_scheme)
	//	if err != nil {
	//	   log.Fatalf("Error from LookupDSYNCTarget(%s, %s): %v", lookupzone, lookupserver, err)
	//	}

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
