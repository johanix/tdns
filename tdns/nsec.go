/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"
	"sort"
	"strings"
	"github.com/miekg/dns"
)

func NsecOps(cp CommandPost) (CommandResponse, error) {
     var resp CommandResponse
     var err error

     zd, exist := Zones.Get(cp.Zone)
     if !exist {
     	return resp, fmt.Errorf("Zone %s is unknown", cp.Zone)
     }

     resp.Zone = zd.ZoneName

     switch cp.SubCommand {
     case "generate":
     	  err := zd.GenerateNsecChain(false)
     	  if err != nil {
     	     return resp, err
     	  }
	  
     case "show":
     	  resp.Names, err = zd.ShowNsecChain()
	  if err != nil {
	     return resp, err
	  }
     
     default:
	return resp, fmt.Errorf("NsecOps: unknown sub command: \"%s\"", cp.SubCommand)
     }
     return resp, nil
}

func (zd *ZoneData) ShowNsecChain() ([]string, error) {
     var nsecrrs []string
     names, err := zd.GetOwnerNames()
     if err != nil {
     	return nsecrrs, err
     }
     sort.Strings(names)

     for _, name := range names {
     	 owner, err := zd.GetOwner(name)
	 if err != nil {
	    return nsecrrs, err
	 }
	 if name != zd.ZoneName {
	 rrs := owner.RRtypes[dns.TypeNSEC].RRs
	 if len(rrs) == 1 {
	    nsecrrs = append(nsecrrs, rrs[0].String())
	 }
	 }
     }

     return nsecrrs, nil
}

func (zd *ZoneData) GenerateNsecChain(AddRRSIG bool) error {

     names, err := zd.GetOwnerNames()
     if err != nil {
     	return err
     }
     sort.Strings(names)

     var nextidx int
     var nextname string

     var hasRRSIG bool

     for idx, name := range names {
     	 owner, err := zd.GetOwner(name)
	 if err != nil {
	    return err
	 }
	 nextidx = idx+1
	 if nextidx == len(names) {
	    nextidx = 0
	 }
	 nextname = names[nextidx]
	 tmap := make([]int, 1+len(owner.RRtypes))
	 tmap[0] = int(dns.TypeNSEC)
	 i := 1
	 for rrt, _ := range owner.RRtypes {
	     if rrt == dns.TypeRRSIG {
	     	hasRRSIG = true
	     }
	     if rrt != dns.TypeNSEC {
	     	tmap[i] = int(rrt)
	     	i++
	     }
	 }
	 if AddRRSIG && !hasRRSIG {
	    tmap = append(tmap, int(dns.TypeRRSIG))
	 }
	 
	 sort.Ints(tmap)	// unfortunately the NSEC TypeBitMap must be in order...
	 var rrts = make([]string, len(tmap))
	 for idx, t := range tmap {
	     rrts[idx] = dns.TypeToString[uint16(t)]
	 }

	 items := []string{name, "NSEC", nextname}
	 items = append(items, rrts...)
	 nsecrr, err := dns.NewRR(strings.Join(items, " "))
	 if err != nil {
	    return err
	 }
	 tmp := owner.RRtypes[dns.TypeNSEC]
	 tmp.RRs = []dns.RR{ nsecrr }
	 owner.RRtypes[dns.TypeNSEC] = tmp
     }

     return nil
}