/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package main

import (
	"fmt"
	"log"

	"github.com/spf13/viper"

	"github.com/johanix/tdns/tdns"
	"github.com/miekg/dns"
)

func ValidatorEngine(conf *Config, stopch chan struct{}) {
	var validatorch = conf.Internal.ValidatorCh

	if !viper.GetBool("validator.active") {
		log.Printf("ValidatorEngine is NOT active.")
		for {
			select {
			case <-validatorch: // ensure that we keep reading to keep the
				continue // channel open
			}
		}
	} else {
		log.Printf("ValidatorEngine: Starting")
	}

	var vr tdns.ValidatorRequest
	var rrset *tdns.RRset
	var rrtype string

	for {
		select {
		case vr = <-validatorch:
			rrset = vr.RRset
			resp := tdns.ValidatorResponse{}

			if rrset != nil {
				if len(rrset.RRs) > 0 {
					rrtype = dns.TypeToString[rrset.RRs[0].Header().Rrtype]
					log.Printf("ValidatorEngine: request to validate %s %s (%d RRs)",
						rrset.RRs[0].Header().Name, rrtype, len(rrset.RRs))
				}

				resp.Validated = true // placeholder
			}

			if vr.Response != nil {
				resp.Msg = fmt.Sprintf("ValidatorEngine: responding")
				vr.Response <- resp
			}
		}
	}
}
