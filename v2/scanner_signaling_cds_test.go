package tdns

import (
	"log"
	"os"
	"testing"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// #688. The RFC 9615 signaling CDS lives at _dsboot.<child>._signal.<ns>, and
// the child's own CDS at the apex. They carry the same RDATA and different
// owners. core.RRsetDiffer compares whole RRs, and dns.IsDuplicate compares the
// owner name before the RDATA, so comparing them as they arrive can only ever
// report a difference -- which made the at-ns CDS bootstrap impossible to
// complete. cdsAtChildOwner re-owns the signaling copy first.
//
// A test written with equal owners passes with or without the fix, so the
// owners here differ on purpose.

const (
	testSignalCDSChild  = "child.example."
	testSignalCDSOwner  = "_dsboot.child.example._signal.ns.provider.com."
	testSignalCDSRdata  = "3600 IN CDS 64914 15 2 EFC0A2682A9328BDF7D13FD87FB784095818D89852B64982748A1FA29A358CEB"
	testSignalCDSOtherR = "3600 IN CDS 12345 15 2 AAAAA2682A9328BDF7D13FD87FB784095818D89852B64982748A1FA29A358CEB"
)

func mustCDS(t *testing.T, owner, rdata string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(owner + " " + rdata)
	if err != nil {
		t.Fatalf("dns.NewRR(%s): %v", owner, err)
	}
	return rr
}

func signalingRRset(t *testing.T, owner, rdata string) *core.RRset {
	t.Helper()
	return &core.RRset{
		Name:   owner,
		Class:  dns.ClassINET,
		RRtype: dns.TypeCDS,
		RRs:    []dns.RR{mustCDS(t, owner, rdata)},
		RRSIGs: []dns.RR{mustCDS(t, owner, rdata)}, // stand-in; must not survive
	}
}

func TestCdsAtChildOwnerMatchesApexCDS(t *testing.T) {
	lg := log.New(os.Stderr, "", 0)
	apex := []dns.RR{mustCDS(t, testSignalCDSChild, testSignalCDSRdata)}
	sig := signalingRRset(t, testSignalCDSOwner, testSignalCDSRdata)

	// The bug: identical RDATA, different owners, reported as different.
	if changed, _, _ := core.RRsetDiffer(testSignalCDSChild, sig.RRs, apex,
		dns.TypeCDS, lg, false, false); !changed {
		t.Fatal("expected an un-normalised signaling CDS to differ from the apex CDS; " +
			"if this no longer holds, RRsetDiffer's owner handling changed and this test needs rewriting")
	}

	// The fix: re-owned onto the child, the same RDATA matches.
	norm := cdsAtChildOwner(sig, testSignalCDSChild)
	if changed, adds, removes := core.RRsetDiffer(testSignalCDSChild, norm.RRs, apex,
		dns.TypeCDS, lg, false, false); changed {
		t.Fatalf("signaling CDS re-owned onto %s should match the apex CDS: adds=%d removes=%d",
			testSignalCDSChild, len(adds), len(removes))
	}
}

// A genuine RDATA difference must still be reported once the owners agree,
// so the fix cannot be mistaken for "compare nothing".
func TestCdsAtChildOwnerStillDetectsDifferentRdata(t *testing.T) {
	lg := log.New(os.Stderr, "", 0)
	apex := []dns.RR{mustCDS(t, testSignalCDSChild, testSignalCDSRdata)}
	sig := signalingRRset(t, testSignalCDSOwner, testSignalCDSOtherR)

	norm := cdsAtChildOwner(sig, testSignalCDSChild)
	if changed, _, _ := core.RRsetDiffer(testSignalCDSChild, norm.RRs, apex,
		dns.TypeCDS, lg, false, false); !changed {
		t.Fatal("a signaling CDS with different RDATA must still be reported as differing")
	}
}

// The IMR may hand out a cached RRset, so the original must be left alone.
func TestCdsAtChildOwnerDoesNotMutateInput(t *testing.T) {
	sig := signalingRRset(t, testSignalCDSOwner, testSignalCDSRdata)

	norm := cdsAtChildOwner(sig, testSignalCDSChild)

	if got := sig.RRs[0].Header().Name; got != testSignalCDSOwner {
		t.Errorf("input RR owner was rewritten to %q; a cached RRset would be corrupted", got)
	}
	if sig.Name != testSignalCDSOwner {
		t.Errorf("input RRset.Name was rewritten to %q", sig.Name)
	}
	if got := norm.RRs[0].Header().Name; got != testSignalCDSChild {
		t.Errorf("normalised RR owner = %q, want %q", got, testSignalCDSChild)
	}
	if norm.Name != testSignalCDSChild {
		t.Errorf("normalised RRset.Name = %q, want %q", norm.Name, testSignalCDSChild)
	}
	if len(norm.RRSIGs) != 0 {
		t.Errorf("RRSIGs survived re-owning: they cover the signaling owner and cannot cover the child")
	}
}

func TestCdsAtChildOwnerNil(t *testing.T) {
	if got := cdsAtChildOwner(nil, testSignalCDSChild); got != nil {
		t.Errorf("cdsAtChildOwner(nil) = %v, want nil", got)
	}
}
