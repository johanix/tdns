/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"testing"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// A nameserver's AuthServer is one instance shared by every zone that names
// it. A referral that glues it for one zone updates that instance while other
// zones' queries read it and background address lookups add to it.
// ParseAdditionalForNSAddrs used to append to Addrs and set Expire directly,
// without the server's lock: under -race this test reported data races on
// both, and the glue writer could lose an address another goroutine had just
// added.
func TestGlueWriterSharesServerSafely(t *testing.T) {
	c := cache.NewRRsetCache(log.New(os.Stderr, "test", log.LstdFlags), false, false)
	imr := &Imr{Cache: c, Quiet: true}
	const (
		zone   = "glued.test."
		nsname = "ns1.glued.test."
		rounds = 200
	)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		// Referrals to zone, each gluing nsname with a new address.
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			r := new(dns.Msg)
			r.Extra = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: nsname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.IPv4(192, 0, 2, byte(i+1)),
			}}
			nsrrset := &core.RRset{Name: zone, Class: dns.ClassINET, RRtype: dns.TypeNS}
			if _, err := imr.ParseAdditionalForNSAddrs(context.Background(), "authority", nsrrset, zone,
				map[string]bool{nsname: true}, r); err != nil {
				t.Errorf("ParseAdditionalForNSAddrs: %v", err)
				return
			}
		}
	}()
	go func() {
		// What a background address lookup for another zone does meanwhile.
		defer wg.Done()
		srv := c.GetOrCreateAuthServer(nsname)
		for i := 0; i < rounds; i++ {
			srv.AddAddr(fmt.Sprintf("198.51.100.%d", i+1))
			_ = srv.GetAddrs()
			_ = srv.GetExpire()
		}
	}()
	wg.Wait()

	got := map[string]bool{}
	for _, a := range c.GetOrCreateAuthServer(nsname).GetAddrs() {
		got[a] = true
	}
	for i := 0; i < rounds; i++ {
		for _, want := range []string{fmt.Sprintf("192.0.2.%d", i+1), fmt.Sprintf("198.51.100.%d", i+1)} {
			if !got[want] {
				t.Errorf("%s lost address %s", nsname, want)
			}
		}
	}
}
