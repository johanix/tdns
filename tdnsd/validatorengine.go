/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package main

import (
	"fmt"
	"log"
//	"time"

	"github.com/spf13/viper"

	"github.com/johanix/tdns/tdns"
//	"github.com/miekg/dns"
//	"github.com/orcaman/concurrent-map/v2"
)

// 1. Load trusted keys.
//    - DNSKEYs: only the trust anchors from file are trusted at startup,
//               all dynamic data needs to be fetched as needed.
//    - SIG(0):  All keys that we decide to trust will be kept in a DB table and
//               reloaded on restart.
// 2. Wait for request
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

//	LoadTrustedSig0Keys(conf)

	var vr tdns.ValidatorRequest
	var rrset *tdns.RRset

	for {
		select {
		case vr = <-validatorch:
			rrset = vr.RRset
			resp := tdns.ValidatorResponse{
			        }
			if rrset != nil {
			   resp.Validated = true	// placeholder
			}

			if vr.Response != nil {
			   resp.Msg = fmt.Sprintf("ValidatorEngine: reponding")
			   vr.Response <- resp
			}
		}
	}
}
