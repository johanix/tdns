/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package music

import (
	"fmt"
	"github.com/miekg/dns"
	"testing"
)

func TestRRsetEqualLength(t *testing.T) {
	reply1 := new(dns.Msg)
	reply2 := new(dns.Msg)
	message1 := new(dns.Msg)
	message2 := new(dns.Msg)

	message1.SetQuestion("test.se", dns.TypeNS)
	message2.SetQuestion("test.se", dns.TypeNS)
	reply1.SetReply(message1)
	reply2.SetReply(message2)

	ns1rr, err := dns.NewRR("test.se.       3600    IN      NS      ns1.test.se.")
	if err != nil {
		fmt.Println("did not create rr")
	}
	ns2rr, err := dns.NewRR("test.se.       3600    IN      NS      ns2.test.se.")
	if err != nil {
		fmt.Println("did not create rr")
	}
	reply1.Answer = append(reply1.Answer, ns1rr, ns2rr)
	reply2.Answer = append(reply2.Answer, ns1rr)

	t.Run("Compare matching RRsets", func(t *testing.T) {
		var reply1Extra []dns.RR
		var reply2Extra []dns.RR
		got, reply1Extra, reply2Extra := RRsetEqual(reply1.Answer, reply1.Answer)
		if !got {
			t.Errorf("got %t wanted true", got)
		}
		if len(reply1Extra) > 0 {
			t.Errorf("got %v wanted empty slice", reply1Extra)
		}
		if len(reply2Extra) > 0 {
			t.Errorf("got %v wanted empty slice", reply2Extra)
		}
	})

	t.Run("Compare non-matching RRsets", func(t *testing.T) {
		var reply1Extra []dns.RR
		var reply2Extra []dns.RR
		got, reply1Extra, reply2Extra := RRsetEqual(reply1.Answer, reply2.Answer)
		if got {
			t.Errorf("got %t wanted false", got)
		}
		if reply1Extra[0] != ns2rr {
			t.Errorf("got %v wanted %v", reply1Extra, ns2rr)
		}
		if len(reply2Extra) > 0 {
			t.Errorf("got %v wanted empty slice", reply2Extra)
		}

	})
}

func TestRRsetEqualType(t *testing.T) {
	reply1 := new(dns.Msg)
	reply2 := new(dns.Msg)
	message1 := new(dns.Msg)
	message2 := new(dns.Msg)

	message1.SetQuestion("test.se", dns.TypeNS)
	message2.SetQuestion("test.se", dns.TypeDNSKEY)

	reply1.SetReply(message1)
	reply2.SetReply(message2)

	ns1rr, err := dns.NewRR("test.se.       3600    IN      NS      ns1.test.se.")
	if err != nil {
		fmt.Println("did not create rr")
	}
	dnskey1rr, err := dns.NewRR("test.se.        300     IN      DNSKEY  257 3 13 oVlyvr3PcPsLxLnMYcsUrvOQ+fQOoqgT927RUB4Sk0Sc7MG3D14/QBvA 3k7+I1G2ho2oUU5LIkt1PZmaOZAOkQ==")
	if err != nil {
		fmt.Println("did not create rr")
	}
	reply1.Answer = append(reply1.Answer, ns1rr)
	reply2.Answer = append(reply2.Answer, dnskey1rr)

	t.Run("Compare non-matching qtype", func(t *testing.T) {
		var reply1Extra []dns.RR
		var reply2Extra []dns.RR
		got, reply1Extra, reply2Extra := RRsetEqual(reply1.Answer, reply2.Answer)
		if got {
			t.Errorf("got %t wanted false", got)
		}
		if reply1Extra[0] != ns1rr {
			t.Errorf("got %v wanted %v", reply1Extra, ns1rr)
		}
		if reply2Extra[0] != dnskey1rr {
			t.Errorf("got %v wanted %v", reply2Extra, dnskey1rr)
		}
	})
}

func TestRRsetEqualOwner(t *testing.T) {
	reply1 := new(dns.Msg)
	reply2 := new(dns.Msg)
	message1 := new(dns.Msg)

	message1.SetQuestion("test.se", dns.TypeNS)
	reply1.SetReply(message1)
	reply2.SetReply(message1)

	ns1rr, err := dns.NewRR("test.se.       3600    IN      NS      ns1.test.se.")
	if err != nil {
		fmt.Println("did not create rr")
	}
	ns2rr, err := dns.NewRR("testfail.se.       3600    IN      NS      ns2.test.se.")
	if err != nil {
		fmt.Println("did not create rr")
	}
	reply1.Answer = append(reply1.Answer, ns1rr)
	reply2.Answer = append(reply2.Answer, ns2rr)

	t.Run("Compare non-matching owner ", func(t *testing.T) {
		var reply1Extra []dns.RR
		var reply2Extra []dns.RR
		got, reply1Extra, reply2Extra := RRsetEqual(reply1.Answer, reply2.Answer)
		if got {
			t.Errorf("got %t wanted false", got)
		}
		if reply1Extra[0] != ns1rr {
			t.Errorf("got %v wanted %v", reply1Extra, ns1rr)
		}
		if reply2Extra[0] != ns2rr {
			t.Errorf("got %v wanted %v", reply2Extra, ns2rr)
		}
	})
}
