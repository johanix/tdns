package tdns

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/johanix/tdns/v2/cache"
	"github.com/miekg/dns"
)

// RFC 9975 §3.2 through ProcessCSYNCNotify (helpers in scanner_trust_test.go):
// what the child's nameservers have to agree on, and what each of them is
// judged on by itself. The SOA serial, the CSYNC serial field and the
// soaminimum flag belong to the nameserver that serves them: the nameservers
// of a zone that several providers sign each count their own serial.

// providerNS is the second nameserver of trustParent's delegation; the first
// is ns1.<child>.
const providerNS = "ns.provider.net."

func soaWithSerial(t *testing.T, child string, serial uint32) []dns.RR {
	t.Helper()
	return rrs(t, fmt.Sprintf("%s 3600 IN SOA ns1.%s h.%s %d 3600 600 604800 300", child, child, child, serial))
}

// csyncWith is a CSYNC RRset: flags 1 is immediate, 3 immediate and
// soaminimum.
func csyncWith(t *testing.T, child string, serial uint32, flags int, types string) []dns.RR {
	t.Helper()
	return rrs(t, fmt.Sprintf("%s 3600 IN CSYNC %d %d %s", child, serial, flags, types))
}

// twoSigners is csyncMove for a child that two providers sign: ns1.<child>
// serves SOA serial 100 and providerNS serves 5000, and each has its own
// serial in the CSYNC it serves. Everything else they serve is the same.
func twoSigners(t *testing.T, child string) *trustNet {
	t.Helper()
	n := csyncMove(t, child)
	n.servedBy = map[string]map[string][]dns.RR{
		"ns1." + child: {
			trustKey(child, dns.TypeSOA):   soaWithSerial(t, child, 100),
			trustKey(child, dns.TypeCSYNC): csyncWith(t, child, 100, 1, "A NS AAAA"),
		},
		providerNS: {
			trustKey(child, dns.TypeSOA):   soaWithSerial(t, child, 5000),
			trustKey(child, dns.TypeCSYNC): csyncWith(t, child, 5000, 1, "A NS AAAA"),
		},
	}
	return n
}

// assertNSMoveApplied: the scan found csyncMove's change, ns.provider.net.
// replaced by ns2.provider.net., and it would be applied.
func assertNSMoveApplied(t *testing.T, resp ScanTupleResponse) {
	t.Helper()
	if resp.Error {
		t.Fatalf("error %q; want the NS change processed", resp.ErrorMsg)
	}
	if got := names(resp.NSAdds); len(got) != 1 || !strings.Contains(got[0], "ns2.provider.net.") {
		t.Errorf("NS adds %v, want ns2.provider.net.", got)
	}
	if got := names(resp.NSRemoves); len(got) != 1 || !strings.Contains(got[0], providerNS) {
		t.Errorf("NS removes %v, want %s", got, providerNS)
	}
	if !scanResponseChangesDelegation(resp) {
		t.Error("the NS change would not be applied")
	}
}

// assertNotProcessed: the scan stopped with an error that says want, changes
// nothing and is not remembered, so the next scan of the child tries again.
func assertNotProcessed(t *testing.T, resp ScanTupleResponse, child string, want ...string) {
	t.Helper()
	if !resp.Error {
		t.Fatalf("no error (changed %v); want the CSYNC not processed", resp.DataChanged)
	}
	for _, w := range want {
		if !strings.Contains(resp.ErrorMsg, w) {
			t.Errorf("error %q does not say %q", resp.ErrorMsg, w)
		}
	}
	if scanResponseChangesDelegation(resp) {
		t.Error("a CSYNC that was not processed would be applied")
	}
	if csyncMarkedProcessed(child) {
		t.Error("a CSYNC that was not processed was recorded as processed")
	}
}

// The nameservers of a child that two providers sign serve different SOA
// serials, and different serial fields in the CSYNC. Its NS change is
// processed: the serials are not compared between nameservers.
func TestScanCSYNCOfAChildWithTwoSignersIsProcessed(t *testing.T) {
	const child = "twosigners.example."
	n := twoSigners(t, child)

	resp := runCSYNC(t, trustScanner(n), trustParent(t, child, trustLax()), child)

	assertNSMoveApplied(t, resp)
	for ns, want := range map[string]uint32{"ns1." + child: 100, providerNS: 5000} {
		if serial, ok := csyncProcessedSerial(child, ns); !ok || serial != want {
			t.Errorf("CSYNC serial remembered for %s: %d, %v; want %d", ns, serial, ok, want)
		}
	}
}

// Under a policy that requires DNSSEC the SOA and the CSYNC of every
// nameserver are validated, each copy at the start and the SOA again at the
// end, and one copy that does not validate stops the scan.
func TestScanCSYNCValidatesWhatEveryNameserverServes(t *testing.T) {
	secure := func(n *trustNet, child string) {
		n.set(cache.ValidationStateSecure, trustKey(child, dns.TypeSOA), trustKey(child, dns.TypeCSYNC),
			trustKey(child, dns.TypeNS), trustKey("ns1."+child, dns.TypeA))
	}

	t.Run("every copy validates", func(t *testing.T) {
		const child = "twosecure.example."
		n := twoSigners(t, child)
		secure(n, child)

		resp := runCSYNC(t, trustScanner(n), trustParent(t, child, trustStrict()), child)

		assertNSMoveApplied(t, resp)
		if resp.Validation != ScanValidated {
			t.Errorf("validation %q, want validated", resp.Validation)
		}
		if got := n.validations(trustKey(child, dns.TypeSOA)); got != 4 {
			t.Errorf("the SOA was validated %d time(s), want 4: the start and the end SOA of each nameserver", got)
		}
		if got := n.validations(trustKey(child, dns.TypeCSYNC)); got != 2 {
			t.Errorf("the CSYNC was validated %d time(s), want 2: the copy of each nameserver", got)
		}
	})

	for i, tc := range []struct {
		name  string
		qtype uint16
		want  string
	}{
		{"the SOA of one nameserver does not validate", dns.TypeSOA, "SOA is bogus"},
		{"the CSYNC of one nameserver does not validate", dns.TypeCSYNC, "CSYNC is bogus"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			child := fmt.Sprintf("onebogus%d.example.", i)
			n := twoSigners(t, child)
			secure(n, child)
			bogus := n.servedBy[providerNS][trustKey(child, tc.qtype)][0]
			n.copyVerdict = map[string]cache.ValidationState{bogus.String(): cache.ValidationStateBogus}

			resp := runCSYNC(t, trustScanner(n), trustParent(t, child, trustStrict()), child)

			assertRefused(t, resp, tc.want)
			for _, want := range []string{`"strict"`, providerNS} {
				if !strings.Contains(resp.ValidationReason, want) {
					t.Errorf("reason %q does not name %s", resp.ValidationReason, want)
				}
			}
			if csyncMarkedProcessed(child) {
				t.Error("a refused CSYNC was recorded as processed")
			}
		})
	}
}

// A nameserver whose SOA serial is not the same after the analysis as before
// it served a zone that changed meanwhile. The CSYNC is not processed, and the
// reason, which is what the delegation sync log shows, names the nameserver.
func TestScanCSYNCStopsWhenANameserversSerialChangesDuringTheScan(t *testing.T) {
	const child = "moving.example."
	t.Cleanup(func() { forgetCsyncProcessed(child) })
	l := withSyncLog(t, 100)
	n := twoSigners(t, child)
	n.laterServedBy = map[string]map[string][]dns.RR{providerNS: {
		trustKey(child, dns.TypeSOA): soaWithSerial(t, child, 5001),
	}}
	sc := trustScanner(n)
	applied := false
	sc.OnDelegationChange = func(string, *ZoneData, ScanTupleResponse) delegationApplyResult {
		applied = true
		return delegationApplyResult{Applied: true}
	}

	resp := sc.scanChildAndApply(context.Background(), trustParent(t, child, trustLax()), ScanCSYNC, ScanTuple{Zone: child}, nil, nil)

	const want = "nameserver " + providerNS + ": SOA serial changed during the scan (5000 to 5001)"
	assertNotProcessed(t, resp, child, want)
	if applied {
		t.Error("the change was applied")
	}
	rep := l.Query(SyncLogQuery{Child: child})
	if len(rep.Events) != 1 || rep.Events[0].Outcome != SyncNotProcessed || rep.Events[0].Reason != want {
		t.Errorf("events %+v, want one, not processed, with the reason %q", rep.Events, want)
	}
}

// What the CSYNC asks for, its immediate flag and its type bitmap, has to be
// the same at every nameserver, and every nameserver has to serve one.
func TestScanCSYNCRequestMustBeTheSameAtEveryNameserver(t *testing.T) {
	const differs = "CSYNC immediate flag or type bitmap differs between nameservers"
	// ns1.<child> serves twoSigners' CSYNC: serial 100, immediate, A NS AAAA.
	for i, tc := range []struct {
		name  string
		other func(t *testing.T, child string) []dns.RR // the CSYNC RRset providerNS serves
		want  func(child string) string
	}{
		{name: "the type bitmaps differ",
			other: func(t *testing.T, child string) []dns.RR { return csyncWith(t, child, 5000, 1, "NS") },
			want:  func(string) string { return differs }},
		{name: "the immediate flags differ",
			other: func(t *testing.T, child string) []dns.RR { return csyncWith(t, child, 5000, 0, "A NS AAAA") },
			want:  func(string) string { return differs }},
		{name: "one nameserver serves no CSYNC",
			other: func(*testing.T, string) []dns.RR { return []dns.RR{} },
			want:  func(child string) string { return "CSYNC is served by ns1." + child + " and not by " + providerNS }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			child := fmt.Sprintf("request%d.example.", i)
			n := twoSigners(t, child)
			n.servedBy[providerNS][trustKey(child, dns.TypeCSYNC)] = tc.other(t, child)

			resp := runCSYNC(t, trustScanner(n), trustParent(t, child, trustLax()), child)

			assertNotProcessed(t, resp, child, tc.want(child))
			if n.queried[trustKey(child, dns.TypeNS)] != 0 {
				t.Error("the child's NS was asked for, but the CSYNC is not acted on")
			}
		})
	}
}

// The soaminimum flag holds a CSYNC back while its serial is above the SOA
// serial of the nameserver that serves it. Each nameserver is judged by its
// own flag, CSYNC serial and SOA serial, and they must come to one answer.
func TestScanCSYNCSoaMinimumIsJudgedPerNameserver(t *testing.T) {
	type csync struct {
		serial uint32
		flags  int
	}
	// The SOA serials are twoSigners': 100 at ns1.<child>, 5000 at providerNS.
	for i, tc := range []struct {
		name       string
		ns1, other csync
		outcome    string
		want       func(child string) []string
	}{
		// Held against the SOA of ns1, the CSYNC of providerNS would not be
		// processed: 5000 > 100.
		{name: "each CSYNC is at the SOA serial of its own nameserver",
			ns1: csync{100, 3}, other: csync{5000, 3}, outcome: "processed"},
		{name: "one nameserver's CSYNC is ahead of its SOA, the other sets no soaminimum",
			ns1: csync{101, 3}, other: csync{5000, 1}, outcome: "not processed",
			want: func(child string) []string {
				return []string{"nameservers disagree on whether the CSYNC may be processed",
					"ns1." + child + ": no, CSYNC serial 101 > SOA serial 100", providerNS + ": yes"}
			}},
		{name: "every nameserver's CSYNC is ahead of its SOA",
			ns1: csync{101, 3}, other: csync{5001, 3}, outcome: "held back"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			child := fmt.Sprintf("soamin%d.example.", i)
			n := twoSigners(t, child)
			key := trustKey(child, dns.TypeCSYNC)
			n.servedBy["ns1."+child][key] = csyncWith(t, child, tc.ns1.serial, tc.ns1.flags, "A NS AAAA")
			n.servedBy[providerNS][key] = csyncWith(t, child, tc.other.serial, tc.other.flags, "A NS AAAA")

			resp := runCSYNC(t, trustScanner(n), trustParent(t, child, trustLax()), child)

			switch tc.outcome {
			case "processed":
				assertNSMoveApplied(t, resp)
			case "not processed":
				assertNotProcessed(t, resp, child, tc.want(child)...)
			default:
				if resp.Error || resp.DataChanged || csyncMarkedProcessed(child) {
					t.Errorf("error %q, changed %v, remembered %v; want the CSYNC held back quietly, and looked at again next time",
						resp.ErrorMsg, resp.DataChanged, csyncMarkedProcessed(child))
				}
				if n.queried[trustKey(child, dns.TypeNS)] != 0 {
					t.Error("the child's NS was asked for, but the CSYNC is held back")
				}
			}
		})
	}
}

// The serial of the last CSYNC processed is remembered per nameserver: a
// serial one nameserver served is not held against the CSYNC of another.
func TestScanCSYNCProcessedSerialIsRememberedPerNameserver(t *testing.T) {
	serve := func(t *testing.T, n *trustNet, child string, ns1Serial, otherSerial uint32) {
		key := trustKey(child, dns.TypeCSYNC)
		n.servedBy["ns1."+child][key] = csyncWith(t, child, ns1Serial, 1, "A NS AAAA")
		n.servedBy[providerNS][key] = csyncWith(t, child, otherSerial, 1, "A NS AAAA")
	}

	t.Run("a nameserver that was down for the last scan", func(t *testing.T) {
		const child = "wasdown.example."
		n := twoSigners(t, child)
		zd := trustParent(t, child, trustLax())
		sc := trustScanner(n)

		// Only providerNS answers: its serial, 5000, is the one remembered.
		n.dead = map[string]bool{"ns1." + child: true}
		assertNSMoveApplied(t, runCSYNC(t, sc, zd, child))

		// ns1 is back, with its own serial, 100: lower, and not an older CSYNC.
		n.dead = nil
		assertNSMoveApplied(t, runCSYNC(t, sc, zd, child))
	})

	t.Run("one nameserver serves an older CSYNC than it did, the other a newer", func(t *testing.T) {
		const child = "wentback.example."
		n := twoSigners(t, child)
		zd := trustParent(t, child, trustLax())
		sc := trustScanner(n)
		assertNSMoveApplied(t, runCSYNC(t, sc, zd, child))

		serve(t, n, child, 99, 5001)
		resp := runCSYNC(t, sc, zd, child)

		if !resp.Error || !strings.Contains(resp.ErrorMsg, "nameservers disagree on whether the CSYNC may be processed") ||
			!strings.Contains(resp.ErrorMsg, "ns1."+child+": no, CSYNC serial 99 already processed") {
			t.Fatalf("error %v %q; want the nameservers to disagree, ns1 with an older CSYNC", resp.Error, resp.ErrorMsg)
		}
		if serial, _ := csyncProcessedSerial(child, providerNS); serial != 5000 {
			t.Errorf("CSYNC serial remembered for %s is %d, want it left at 5000", providerNS, serial)
		}
	})

	t.Run("every nameserver serves an older CSYNC than it did", func(t *testing.T) {
		const child = "allback.example."
		n := twoSigners(t, child)
		zd := trustParent(t, child, trustLax())
		sc := trustScanner(n)
		assertNSMoveApplied(t, runCSYNC(t, sc, zd, child))

		serve(t, n, child, 99, 4999)
		resp := runCSYNC(t, sc, zd, child)

		if resp.Error || resp.DataChanged {
			t.Fatalf("error %q, changed %v; want an older CSYNC skipped quietly", resp.ErrorMsg, resp.DataChanged)
		}
	})
}

// The data the CSYNC names is still compared between the nameservers: an NS
// RRset they do not agree on stops the scan.
func TestScanCSYNCNameserversMustAgreeOnTheNSRRset(t *testing.T) {
	const child = "nsdiffer.example."
	n := twoSigners(t, child)
	n.servedBy[providerNS][trustKey(child, dns.TypeNS)] = rrs(t, child+" 3600 IN NS ns1."+child, child+" 3600 IN NS ns3.provider.net.")

	resp := runCSYNC(t, trustScanner(n), trustParent(t, child, trustLax()), child)

	assertNotProcessed(t, resp, child, "child nameservers not in sync for NS")
}

// A child with one nameserver, and a child whose nameservers serve the same
// SOA and CSYNC, are processed as they were. Under a policy that requires
// DNSSEC an RRset the nameservers agree on is validated once, not once per
// nameserver.
func TestScanCSYNCOfNameserversThatAgreeIsUnchanged(t *testing.T) {
	t.Run("a single nameserver", func(t *testing.T) {
		const child = "single.example."
		n := csyncMove(t, child)

		resp := runCSYNC(t, trustScanner(n), trustParent(t, child, trustLax(), "ns1."+child), child)

		if resp.Error || resp.Validation != ScanUnvalidated {
			t.Fatalf("validation %q, error %q; want unvalidated", resp.Validation, resp.ErrorMsg)
		}
		if got := names(resp.NSAdds); len(got) != 1 || !strings.Contains(got[0], "ns2.provider.net.") || len(resp.NSRemoves) != 0 {
			t.Errorf("NS adds %v removes %v, want ns2.provider.net. added", got, names(resp.NSRemoves))
		}
		if serial, ok := csyncProcessedSerial(child, "ns1."+child); !ok || serial != 7 {
			t.Errorf("CSYNC serial remembered: %d, %v; want 7", serial, ok)
		}
	})

	t.Run("two nameservers that agree, validated", func(t *testing.T) {
		const child = "agree.example."
		n := csyncMove(t, child)
		soa, csync, ns, a := trustKey(child, dns.TypeSOA), trustKey(child, dns.TypeCSYNC), trustKey(child, dns.TypeNS), trustKey("ns1."+child, dns.TypeA)
		n.set(cache.ValidationStateSecure, soa, csync, ns, a)

		resp := runCSYNC(t, trustScanner(n), trustParent(t, child, trustStrict()), child)

		assertNSMoveApplied(t, resp)
		if want := []string{soa, csync, ns, a, soa}; !slices.Equal(n.validated, want) {
			t.Errorf("validated %v, want %v", n.validated, want)
		}
	})
}

// A nameserver that gives no answer is left out, as it always was, and the
// scan goes on with the ones that answer. No answer from any of them stops it.
func TestScanCSYNCLeavesOutANameserverThatDoesNotAnswer(t *testing.T) {
	t.Run("one of two is down", func(t *testing.T) {
		const child = "onedown.example."
		n := twoSigners(t, child)
		n.dead = map[string]bool{providerNS: true}

		resp := runCSYNC(t, trustScanner(n), trustParent(t, child, trustLax()), child)

		assertNSMoveApplied(t, resp)
	})

	t.Run("both are down", func(t *testing.T) {
		const child = "bothdown.example."
		n := twoSigners(t, child)
		n.dead = map[string]bool{"ns1." + child: true, providerNS: true}

		resp := runCSYNC(t, trustScanner(n), trustParent(t, child, trustLax()), child)

		assertNotProcessed(t, resp, child, "error querying SOA: no SOA RRsets retrieved from any nameserver")
	})
}

// A nameserver that answers one of the two SOA queries has no pair of serials
// to compare, and is left out of that comparison. The scan needs one
// nameserver that answered both. A CSYNC with soaminimum needs the SOA of the
// nameserver that serves it.
func TestScanCSYNCWithANameserverThatAnswersOnlySomeQueries(t *testing.T) {
	for i, tc := range []struct {
		name   string
		silent func(child string) func(ns, key string, nth int) bool
		flags  int
		want   string // empty: processed
	}{
		{name: "one nameserver gives no end SOA", flags: 1,
			silent: func(child string) func(string, string, int) bool {
				return func(ns, key string, nth int) bool {
					return ns == providerNS && key == trustKey(child, dns.TypeSOA) && nth > 1
				}
			}},
		{name: "no nameserver gives both a start and an end SOA", flags: 1,
			want: "no nameserver answered both the SOA query before the scan and the one after it",
			silent: func(child string) func(string, string, int) bool {
				return func(ns, key string, nth int) bool {
					if key != trustKey(child, dns.TypeSOA) {
						return false
					}
					return (ns == providerNS) == (nth > 1)
				}
			}},
		{name: "a CSYNC with soaminimum from a nameserver that gives no SOA", flags: 3,
			want: "nameserver " + providerNS + ": its CSYNC sets soaminimum, and it gave no SOA",
			silent: func(child string) func(string, string, int) bool {
				return func(ns, key string, nth int) bool {
					return ns == providerNS && key == trustKey(child, dns.TypeSOA)
				}
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			child := fmt.Sprintf("partial%d.example.", i)
			n := twoSigners(t, child)
			n.servedBy[providerNS][trustKey(child, dns.TypeCSYNC)] = csyncWith(t, child, 5000, tc.flags, "A NS AAAA")
			n.silent = tc.silent(child)

			resp := runCSYNC(t, trustScanner(n), trustParent(t, child, trustLax()), child)

			if tc.want == "" {
				assertNSMoveApplied(t, resp)
				return
			}
			assertNotProcessed(t, resp, child, tc.want)
		})
	}
}

// Without an IMR the addresses of the nameservers cannot be looked up. The
// query of each nameserver says so and the scan stops, as the compared query
// always did.
func TestScanCSYNCWithoutAnImrIsNotProcessed(t *testing.T) {
	const child = "noimr.example."
	sc := NewScanner(nil, false, false)
	sc.Log["CSYNC"] = discardLog

	resp := runCSYNC(t, sc, trustParent(t, child, trustLax()), child)

	assertNotProcessed(t, resp, child, "error querying SOA", "no IMR available yet")
}

func TestCsyncSameRequest(t *testing.T) {
	csync := func(serial uint32, flags uint16, types ...uint16) *dns.CSYNC {
		return &dns.CSYNC{Serial: serial, Flags: flags, TypeBitMap: types}
	}
	base := csync(7, 1, dns.TypeA, dns.TypeNS, dns.TypeAAAA)
	for _, tc := range []struct {
		name string
		b    *dns.CSYNC
		same bool
	}{
		{"another serial", csync(5000, 1, dns.TypeA, dns.TypeNS, dns.TypeAAAA), true},
		{"soaminimum set", csync(7, 3, dns.TypeA, dns.TypeNS, dns.TypeAAAA), true},
		{"the bitmap in another order", csync(7, 1, dns.TypeNS, dns.TypeAAAA, dns.TypeA), true},
		{"immediate not set", csync(7, 0, dns.TypeA, dns.TypeNS, dns.TypeAAAA), false},
		{"a type less", csync(7, 1, dns.TypeA, dns.TypeNS), false},
		{"another type", csync(7, 1, dns.TypeA, dns.TypeNS, dns.TypeTXT), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := csyncSameRequest(base, tc.b); got != tc.same {
				t.Errorf("same request: %v, want %v", got, tc.same)
			}
			if got := csyncSameRequest(tc.b, base); got != tc.same {
				t.Errorf("same request, the other way round: %v, want %v", got, tc.same)
			}
		})
	}
}
