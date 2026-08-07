package ixfr

import (
	"testing"

	"github.com/miekg/dns"
)

func TestRrEquals(t *testing.T) {
	want := make([]dns.RR, 0)
	rr, _ := dns.NewRR("jain.ad.jp         SOA NS.JAIN.AD.JP. mohta.jain.ad.jp. 3 600 600 3600000 604800")
	want = append(want, rr)
	rr, _ = dns.NewRR("jain-bb.jain.ad.jp A   133.69.136.3")
	want = append(want, rr)

	otherWant := make([]dns.RR, 0)
	rr, _ = dns.NewRR("jain-bb.jain.ad.jp A   133.69.136.3")
	otherWant = append(otherWant, rr)
	rr, _ = dns.NewRR("jain.ad.jp         SOA NS.JAIN.AD.JP. mohta.jain.ad.jp. 3 600 600 3600000 604800")
	otherWant = append(otherWant, rr)

	if !rrEquals(want, otherWant) {
		t.Errorf("dns.RR Equality test failed!")
	}
}

func TestRrEqualsWhitespaceDiff(t *testing.T) {
	want := make([]dns.RR, 0)
	rr, _ := dns.NewRR("jain.ad.jp SOA NS.JAIN.AD.JP. mohta.jain.ad.jp. 3 600 600 3600000 604800")
	want = append(want, rr)
	rr, _ = dns.NewRR("jain-bb.jain.ad.jp A 133.69.136.3")
	want = append(want, rr)

	otherWant := make([]dns.RR, 0)
	rr, _ = dns.NewRR("jain-bb.jain.ad.jp A   133.69.136.3")
	otherWant = append(otherWant, rr)
	rr, _ = dns.NewRR("jain.ad.jp         SOA NS.JAIN.AD.JP. mohta.jain.ad.jp. 3 600 600 3600000 604800")
	otherWant = append(otherWant, rr)

	if !rrEquals(want, otherWant) {
		t.Errorf("dns.RR Equality test failed!")
	}
}
