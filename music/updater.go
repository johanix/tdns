/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package music

import (
	"log"

	tdns "github.com/johanix/tdns/tdns"
	"github.com/miekg/dns"
)

// TODO: See if there is a better ways to give the insert/remove RRset
//
// Current implementation mimics dns.Insert()/.Remove() in the way that each
// entry in the first array is a call to these functions with the second
// array.
type Updater interface {
	SetChannels(fetch, update chan SignerOp)
	SetApi(api *tdns.ApiClient)
	GetApi() *tdns.ApiClient

	Update(signer *Signer, zone, fqdn string, inserts, removes *[][]dns.RR) error
	RemoveRRset(signer *Signer, zone, fqdn string, rrsets [][]dns.RR) error
	FetchRRset(signer *Signer, zone, fqdn string, rrtype uint16) ([]dns.RR, error)
}

var Updaters map[string]Updater = make(map[string]Updater)

func GetUpdater(type_ string) Updater {
	updater, ok := Updaters[type_]
	if !ok {
		log.Fatal("No updater type", type_)
	}
	return updater
}

func ListUpdaters() map[string]bool {
	res := map[string]bool{}
	for u := range Updaters {
		res[u] = true
	}
	return res
}
