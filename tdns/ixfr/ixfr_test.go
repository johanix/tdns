package ixfr

import (
	"testing"

	"github.com/miekg/dns"
)

func TestIxfr(t *testing.T) {
	/* Should be equivalent to the example in RFC 1995 */
	response := new(dns.Msg)
	response.Answer = makeRRSlice(
		"jain.ad.jp         SOA NS.JAIN.AD.JP. mohta.jain.ad.jp. 3 600 600 3600000 604800",
		"jain.ad.jp         SOA NS.JAIN.AD.JP. mohta.jain.ad.jp. 1 600 600 3600000 604800",
		"nezu.jain.ad.jp    A   133.69.136.5",
		"jain.ad.jp         SOA NS.JAIN.AD.JP. mohta.jain.ad.jp. 2 600 600 3600000 604800",
		"jain-bb.jain.ad.jp A   133.69.136.4",
		"jain-bb.jain.ad.jp A   192.41.197.2",
		"jain.ad.jp         SOA NS.JAIN.AD.JP. mohta.jain.ad.jp. 2 600 600 3600000 604800",
		"jain-bb.jain.ad.jp A   133.69.136.4",
		"jain.ad.jp         SOA NS.JAIN.AD.JP. mohta.jain.ad.jp. 3 600 600 3600000 604800",
		"jain-bb.jain.ad.jp A   133.69.136.3",
		"jain.ad.jp         SOA NS.JAIN.AD.JP. mohta.jain.ad.jp. 3 600 600 3600000 604800",
	)

	/* Should be equivalent to the example in RFC 1995 */
	wanted := Ixfr{
		InitialSOASerial: 1,
		FinalSOASerial:   3,
		DiffSequences:    []DiffSequence{},
	}
	tmp := CreateDiffSequence(1, 2)
	tmp.AddDeleted("nezu.jain.ad.jp A 133.69.136.5")
	tmp.AddAdded("jain-bb.jain.ad.jp A 133.69.136.4")
	tmp.AddAdded("jain-bb.jain.ad.jp A 192.41.197.2")
	wanted.AddDiffSequence(tmp)
	tmp = CreateDiffSequence(2, 3)
	tmp.AddDeleted("jain-bb.jain.ad.jp A 133.69.136.4")
	tmp.AddAdded("jain-bb.jain.ad.jp A   133.69.136.3")
	wanted.AddDiffSequence(tmp)

	ans := IxfrFromResponse(response)

	if !ans.Equals(wanted) {
		t.Errorf("Got:\n %+v\n Want:\n %+v", ans, wanted)
	}
}

func TestGetAdded(t *testing.T) {
	/* Should be equivalent to the example in RFC 1995 */
	response := new(dns.Msg)
	response.Answer = makeRRSlice(
		"jain.ad.jp         SOA NS.JAIN.AD.JP. mohta.jain.ad.jp. 3 600 600 3600000 604800",
		"jain.ad.jp         SOA NS.JAIN.AD.JP. mohta.jain.ad.jp. 1 600 600 3600000 604800",
		"nezu.jain.ad.jp    A   133.69.136.5",
		"jain.ad.jp         SOA NS.JAIN.AD.JP. mohta.jain.ad.jp. 2 600 600 3600000 604800",
		"jain-bb.jain.ad.jp A   133.69.136.4",
		"jain-bb.jain.ad.jp A   192.41.197.2",
		"jain.ad.jp         SOA NS.JAIN.AD.JP. mohta.jain.ad.jp. 2 600 600 3600000 604800",
		"jain-bb.jain.ad.jp A   133.69.136.4",
		"jain.ad.jp         SOA NS.JAIN.AD.JP. mohta.jain.ad.jp. 3 600 600 3600000 604800",
		"jain-bb.jain.ad.jp A   133.69.136.3",
		"jain.ad.jp         SOA NS.JAIN.AD.JP. mohta.jain.ad.jp. 3 600 600 3600000 604800",
	)

	wanted := makeRRSlice(
		"jain-bb.jain.ad.jp A   133.69.136.3",
		"jain-bb.jain.ad.jp A   192.41.197.2",
	)

	ans := IxfrFromResponse(response)

	added := ans.GetAdded()

	if !rrEquals(added, wanted) {
		t.Errorf("Got:\n %+v\n Want:\n %+v", added, wanted)
	}
}

func TestGetDeleted(t *testing.T) {
	/* Should be equivalent to the example in RFC 1995 */
	response := new(dns.Msg)
	response.Answer = makeRRSlice(
		"jain.ad.jp         SOA NS.JAIN.AD.JP. mohta.jain.ad.jp. 3 600 600 3600000 604800",
		"jain.ad.jp         SOA NS.JAIN.AD.JP. mohta.jain.ad.jp. 1 600 600 3600000 604800",
		"nezu.jain.ad.jp    A   133.69.136.5",
		"jain.ad.jp         SOA NS.JAIN.AD.JP. mohta.jain.ad.jp. 2 600 600 3600000 604800",
		"jain-bb.jain.ad.jp A   133.69.136.4",
		"jain-bb.jain.ad.jp A   192.41.197.2",
		"jain.ad.jp         SOA NS.JAIN.AD.JP. mohta.jain.ad.jp. 2 600 600 3600000 604800",
		"jain-bb.jain.ad.jp A   133.69.136.4",
		"jain.ad.jp         SOA NS.JAIN.AD.JP. mohta.jain.ad.jp. 3 600 600 3600000 604800",
		"jain-bb.jain.ad.jp A   133.69.136.3",
		"jain.ad.jp         SOA NS.JAIN.AD.JP. mohta.jain.ad.jp. 3 600 600 3600000 604800",
	)

	wanted := makeRRSlice("nezu.jain.ad.jp    A   133.69.136.5")

	ans := IxfrFromResponse(response)

	deleted := ans.GetDeleted()

	if !rrEquals(deleted, wanted) {
		t.Errorf("Got:\n %+v\n Want:\n %+v", deleted, wanted)
	}
}
