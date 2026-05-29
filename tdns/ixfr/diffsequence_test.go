package ixfr

import (
	"testing"
)

func TestDiffSequenceEquals(t *testing.T) {
	seq1 := CreateDiffSequence(2, 3)
	seq1.AddAdded("nezu.jain.ad.jp A 133.69.136.5")
	seq1.AddDeleted("jain-bb.jain.ad.jp A 133.69.136.4")
	seq1.AddDeleted("jain-bb.jain.ad.jp A 192.41.197.2")

	seq2 := CreateDiffSequence(2, 3)
	seq2.AddDeleted("jain-bb.jain.ad.jp A 192.41.197.2")
	seq2.AddDeleted("jain-bb.jain.ad.jp A 133.69.136.4")
	seq2.AddAdded("nezu.jain.ad.jp A 133.69.136.5")

	if !seq1.Equals(seq2) {
		t.Errorf("Sequences not equal!")
	}
}

func TestDiffSequenceGetAddedBasic(t *testing.T) {
	want := makeRRSlice(
		"example.com A 1.1.1.1",
		"example.org A 8.8.8.8",
	)

	input := CreateDiffSequence(0, 1)

	input.AddAdded("example.org A 8.8.8.8")
	input.AddAdded("example.com A 1.1.1.1")

	got := input.GetAdded()

	if !rrEquals(got, want) {
		t.Errorf("Got: %+v\n Want: %+v\n", got, want)
	}
}

func TestDiffSequenceGetDeletedBasic(t *testing.T) {
	want := makeRRSlice(
		"se.			172800	IN	NS	x.ns.se.",
		"se.			172800	IN	NS	y.ns.se.",
		"z.ns.se.		172800	IN	A	185.159.198.150",
		"y.ns.se.		172800	IN	A	185.159.197.150")

	input := CreateDiffSequence(0, 1)

	input.AddDeleted("y.ns.se. 172800 IN A 185.159.197.150")
	input.AddDeleted("se. 172800 IN NS x.ns.se.")
	input.AddDeleted("z.ns.se. 172800 IN A 185.159.198.150")
	input.AddDeleted("se. 172800 IN NS y.ns.se.")

	got := input.GetDeleted()
	if !rrEquals(got, want) {
		t.Errorf("Got: %+v\n Want: %+v\n", got, want)
	}
}

func TestDiffSequenceGetDeletedWithChanged(t *testing.T) {
	want := makeRRSlice("test.se        172800  IN  NS  a.dns.se")

	/* Test input representing one deleted delegation plus a change to a glue record */
	input := CreateDiffSequence(0, 1)
	input.AddDeleted("test.se        172800  IN  NS  a.dns.se")
	input.AddDeleted("z.ns.se. 172800 IN A 185.159.198.150")
	input.AddAdded("z.ns.se. 172800 IN A 1.1.1.1")

	got := input.GetDeleted()
	if !rrEquals(got, want) {
		t.Errorf("Got: %+v\n Want: %+v\n", got, want)
	}
}
