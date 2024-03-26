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

func ComputeNsec(cp CommandPost) (CommandResponse, error) {
     var resp CommandResponse

     zd, exist := Zones.Get(cp.Zone)
     if !exist {
     	return resp, fmt.Errorf("Zone %s is unknown")
     }
     
     names, err := zd.GetOwnerNames()
     if err != nil {
     	resp.Error = true
	resp.ErrorMsg = err.Error()
     }
     sort.Strings(names)

     resp.Zone = zd.ZoneName

     var nextidx int
     var nextname string

     resp.Names = []string{ "potta" }

     for idx, name := range names {
     	 owner, err := zd.GetOwner(name)
	 if err != nil {
	    return resp, err
	 }
	 nextidx = idx+1
	 if nextidx == len(names) {
	    nextidx = 0
	 }
	 nextname = names[nextidx]
	 tmap := make([]string, 1+len(owner.RRtypes))
	 tmap[0] = "NSEC"
	 i := 1
	 for rrt, _ := range owner.RRtypes {
	     tmap[i] = dns.TypeToString[rrt]
	     i++
	 }
	 items := []string{name, "NSEC", nextname}
	 items = append(items, tmap...)
	 nsecrr, err := dns.NewRR(strings.Join(items, " "))
	 if err != nil {
	    return resp, err
	 }
	 if name == zd.ZoneName {
	    resp.Names[0] = nsecrr.String()
	 } else {
	    resp.Names = append(resp.Names, nsecrr.String())
	 }
     }

     return resp, nil
}