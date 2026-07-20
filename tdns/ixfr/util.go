package ixfr

import (
	"github.com/miekg/dns"
)

func makeRRSlice(rrs ...string) []dns.RR {
	rrSlice := make([]dns.RR, len(rrs))

	for i, r := range rrs {
		rr, err := dns.NewRR(r)
		if err != nil {
			panic("Oh no, could not create list!")
		}
		rrSlice[i] = rr
	}

	return rrSlice
}

func rrEquals(a, b []dns.RR) bool {
	if len(a) != len(b) {
		return false
	}

	diff := make(map[string]int, len(a))
	for _, _a := range a {
		if _a == nil {
			continue
		}
		diff[_a.String()]++
	}

	for _, _b := range b {
		if _b == nil {
			continue
		}
		_, ok := diff[_b.String()]
		if !ok {
			return false
		}
		diff[_b.String()]--
		if diff[_b.String()] == 0 {
			delete(diff, _b.String())
		}
	}

	return len(diff) == 0
}
