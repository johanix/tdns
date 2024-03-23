/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"
	"log"
	"strings"

	"github.com/miekg/dns"
)

func ParentZone(z, imr string) string {
	labels := strings.Split(z, ".")
	var parent string

	if len(labels) == 1 {
		return z
	} else if len(labels) > 1 {
		upone := dns.Fqdn(strings.Join(labels[1:], "."))

		m := new(dns.Msg)
		m.SetQuestion(upone, dns.TypeSOA)
		m.SetEdns0(4096, true)
		m.CheckingDisabled = true

		r, err := dns.Exchange(m, imr)
		if err != nil {
			return fmt.Sprintf("Error from dns.Exchange: %v\n", err)
		}
		if r != nil {
			if len(r.Answer) != 0 {
				parent = r.Answer[0].Header().Name
				return parent
			}
			if len(r.Ns) > 0 {
				for _, rr := range r.Ns {
					if rr.Header().Rrtype == dns.TypeSOA {
						parent = r.Ns[0].Header().Name
						return parent
					}
				}
			}

			log.Printf("ParentZone: ERROR: Failed to locate parent of '%s' via Answer and Authority. Now guessing.", z)
			return upone
		}
	}
	log.Printf("ParentZone: had difficulties splitting zone '%s'\n", z)
	return z
}
