package tdns

import (
	"context"
	"errors"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// D-3b, step 1: the RFC 7477 rules extracted from ProcessCSYNCNotify. These
// tests pin the scanner's behaviour as it was, quirks included, so the
// extraction can be reviewed against "the scanner behaves identically".

const csChild = "child.example."

// stubChild is a childRRsetFetcher backed by maps keyed "name/TYPE".
type stubChild struct {
	rrs    map[string][]dns.RR
	inSync map[string]bool // absent means in sync
	errs   map[string]error
	calls  []string
}

func (s *stubChild) fetch(_ context.Context, name string, qtype uint16) ([]dns.RR, bool, error) {
	k := name + "/" + dns.TypeToString[qtype]
	s.calls = append(s.calls, k)
	if err := s.errs[k]; err != nil {
		return nil, false, err
	}
	inSync := true
	if v, ok := s.inSync[k]; ok {
		inSync = v
	}
	return s.rrs[k], inSync, nil
}

// glueFrom is a currentGlueLookup over the delegation backend's map shape.
func glueFrom(data map[string]map[uint16][]dns.RR) currentGlueLookup {
	return func(owner string, qtype uint16) ([]dns.RR, bool) {
		od, ok := data[owner]
		if !ok {
			return nil, false
		}
		g, ok := od[qtype]
		return g, ok
	}
}

func rrs(t *testing.T, lines ...string) []dns.RR {
	t.Helper()
	out := make([]dns.RR, 0, len(lines))
	for _, l := range lines {
		out = append(out, mustRR(t, l))
	}
	return out
}

func quietLog() *log.Logger { return log.New(os.Stderr, "", 0) }

func names(rrs []dns.RR) []string {
	var out []string
	for _, rr := range rrs {
		out = append(out, rr.String())
	}
	return out
}

func TestCsyncFlags(t *testing.T) {
	cases := []struct {
		flags                    uint16
		immediate, soamin, isErr bool
	}{
		{0x00, false, false, false},
		{0x01, true, false, false},
		{0x02, false, true, false},
		{0x03, true, true, false},
		{0x04, false, false, true},
		{0x81, false, false, true},
	}
	for _, c := range cases {
		imm, som, err := csyncFlags(&dns.CSYNC{Flags: c.flags})
		if (err != nil) != c.isErr {
			t.Errorf("flags 0x%04x: err=%v, wantErr=%v", c.flags, err, c.isErr)
			continue
		}
		if err != nil {
			if !strings.Contains(err.Error(), "unknown CSYNC flags: 0x") {
				t.Errorf("flags 0x%04x: err text %q", c.flags, err)
			}
			continue
		}
		if imm != c.immediate || som != c.soamin {
			t.Errorf("flags 0x%04x: immediate=%v soamin=%v, want %v %v", c.flags, imm, som, c.immediate, c.soamin)
		}
	}
}

func TestCsyncSuppressedBySoaMinimum(t *testing.T) {
	c := &dns.CSYNC{Serial: 100}
	if csyncSuppressedBySoaMinimum(false, c, 1) {
		t.Error("flag off: never suppressed")
	}
	if csyncSuppressedBySoaMinimum(true, c, 100) || csyncSuppressedBySoaMinimum(true, c, 200) {
		t.Error("serial <= SOA serial: processed")
	}
	if !csyncSuppressedBySoaMinimum(true, c, 99) {
		t.Error("serial > SOA serial: suppressed")
	}
}

func TestCsyncTypesNSFirst(t *testing.T) {
	got := csyncTypes(&dns.CSYNC{TypeBitMap: []uint16{dns.TypeA, dns.TypeNS, dns.TypeAAAA}})
	want := []uint16{dns.TypeNS, dns.TypeA, dns.TypeAAAA}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
	// NS is processed even when the bitmap omits it, as it always was.
	if got := csyncTypes(&dns.CSYNC{TypeBitMap: []uint16{dns.TypeA}}); len(got) != 2 || got[0] != dns.TypeNS {
		t.Fatalf("bitmap without NS: %v", got)
	}
}

func TestInBailiwickNSNames(t *testing.T) {
	ns := rrs(t,
		"child.example. 3600 IN NS ns1.child.example.",
		"child.example. 3600 IN NS ns.provider.net.",
		"child.example. 3600 IN NS NS2.CHILD.EXAMPLE.",
	)
	got := inBailiwickNSNames(csChild, ns)
	if len(got) != 2 || got[0] != "ns1.child.example." || got[1] != "NS2.CHILD.EXAMPLE." {
		t.Fatalf("got %v", got)
	}
	// A sibling that merely shares a suffix string is not in bailiwick.
	if got := inBailiwickNSNames(csChild, rrs(t, "child.example. 3600 IN NS ns.evilchild.example.")); len(got) != 0 {
		t.Fatalf("suffix trap: %v", got)
	}
}

func TestComputeCsyncDeltaNS(t *testing.T) {
	ctx := context.Background()
	currentNS := rrs(t, "child.example. 3600 IN NS ns1.child.example.", "child.example. 3600 IN NS old.provider.net.")
	nsOnly := []uint16{dns.TypeNS}

	t.Run("NS changed", func(t *testing.T) {
		child := &stubChild{rrs: map[string][]dns.RR{
			csChild + "/NS": rrs(t, "child.example. 3600 IN NS ns1.child.example.", "child.example. 3600 IN NS new.provider.net."),
		}}
		d, err := computeCsyncDelta(ctx, csChild, nsOnly, currentNS, glueFrom(nil), child.fetch, quietLog(), false, false)
		if err != nil {
			t.Fatal(err)
		}
		if !d.Changed || len(d.NSAdds) != 1 || len(d.NSRemoves) != 1 {
			t.Fatalf("delta %+v", d)
		}
		if !strings.Contains(d.NSAdds[0].String(), "new.provider.net.") || !strings.Contains(d.NSRemoves[0].String(), "old.provider.net.") {
			t.Fatalf("adds %v removes %v", names(d.NSAdds), names(d.NSRemoves))
		}
	})

	t.Run("NS unchanged", func(t *testing.T) {
		child := &stubChild{rrs: map[string][]dns.RR{csChild + "/NS": currentNS}}
		d, err := computeCsyncDelta(ctx, csChild, nsOnly, currentNS, glueFrom(nil), child.fetch, quietLog(), false, false)
		if err != nil {
			t.Fatal(err)
		}
		if d.Changed || len(d.NSAdds) != 0 || len(d.NSRemoves) != 0 {
			t.Fatalf("delta %+v", d)
		}
	})

	t.Run("NS fetch error is terminal", func(t *testing.T) {
		child := &stubChild{errs: map[string]error{csChild + "/NS": errors.New("timeout")}}
		_, err := computeCsyncDelta(ctx, csChild, nsOnly, currentNS, glueFrom(nil), child.fetch, quietLog(), false, false)
		if err == nil || !strings.HasPrefix(err.Error(), "error querying NS: ") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("NS not in sync is terminal", func(t *testing.T) {
		child := &stubChild{rrs: map[string][]dns.RR{csChild + "/NS": currentNS}, inSync: map[string]bool{csChild + "/NS": false}}
		_, err := computeCsyncDelta(ctx, csChild, nsOnly, currentNS, glueFrom(nil), child.fetch, quietLog(), false, false)
		if err == nil || err.Error() != "child nameservers not in sync for NS" {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("empty NS RRset is rejected (RFC 7477)", func(t *testing.T) {
		child := &stubChild{}
		_, err := computeCsyncDelta(ctx, csChild, nsOnly, currentNS, glueFrom(nil), child.fetch, quietLog(), false, false)
		if err == nil || err.Error() != "empty NS RRset from child, rejected" {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestComputeCsyncDeltaGlue(t *testing.T) {
	ctx := context.Background()
	types := []uint16{dns.TypeNS, dns.TypeA, dns.TypeAAAA}

	// Parent holds: ns1 (in-bailiwick, kept), old (in-bailiwick, going away),
	// ns.provider.net. (out of bailiwick: never glue).
	currentNS := rrs(t,
		"child.example. 3600 IN NS ns1.child.example.",
		"child.example. 3600 IN NS old.child.example.",
		"child.example. 3600 IN NS ns.provider.net.",
	)
	current := map[string]map[uint16][]dns.RR{
		"ns1.child.example.": {
			dns.TypeA:    rrs(t, "ns1.child.example. 3600 IN A 192.0.2.1"),
			dns.TypeAAAA: rrs(t, "ns1.child.example. 3600 IN AAAA 2001:db8::1"),
		},
		"old.child.example.": {
			dns.TypeA: rrs(t, "old.child.example. 3600 IN A 192.0.2.9"),
		},
	}
	// Child now serves: ns1 (A changed, AAAA same), new (fresh in-bailiwick), provider.
	child := &stubChild{rrs: map[string][]dns.RR{
		csChild + "/NS": rrs(t,
			"child.example. 3600 IN NS ns1.child.example.",
			"child.example. 3600 IN NS new.child.example.",
			"child.example. 3600 IN NS ns.provider.net."),
		"ns1.child.example./A":    rrs(t, "ns1.child.example. 3600 IN A 192.0.2.2"),
		"ns1.child.example./AAAA": rrs(t, "ns1.child.example. 3600 IN AAAA 2001:db8::1"),
		"new.child.example./A":    rrs(t, "new.child.example. 3600 IN A 192.0.2.7"),
		"new.child.example./AAAA": nil, // no AAAA for new: nothing to add
	}}

	d, err := computeCsyncDelta(ctx, csChild, types, currentNS, glueFrom(current), child.fetch, quietLog(), false, false)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Changed {
		t.Fatal("expected a change")
	}
	// NS: +new -old
	if len(d.NSAdds) != 1 || len(d.NSRemoves) != 1 {
		t.Fatalf("NS adds %v removes %v", names(d.NSAdds), names(d.NSRemoves))
	}
	// Glue adds: ns1 new A, new's A. Removes: ns1 old A, old's A.
	adds, removes := strings.Join(names(d.GlueAdds), "\n"), strings.Join(names(d.GlueRemoves), "\n")
	for _, want := range []string{"ns1.child.example.\t3600\tIN\tA\t192.0.2.2", "new.child.example.\t3600\tIN\tA\t192.0.2.7"} {
		if !strings.Contains(adds, want) {
			t.Errorf("glue adds lack %q:\n%s", want, adds)
		}
	}
	for _, want := range []string{"ns1.child.example.\t3600\tIN\tA\t192.0.2.1", "old.child.example.\t3600\tIN\tA\t192.0.2.9"} {
		if !strings.Contains(removes, want) {
			t.Errorf("glue removes lack %q:\n%s", want, removes)
		}
	}
	if len(d.GlueAdds) != 2 || len(d.GlueRemoves) != 2 {
		t.Errorf("glue adds=%d removes=%d, want 2 and 2 (AAAA unchanged, provider never glue)", len(d.GlueAdds), len(d.GlueRemoves))
	}
	// The out-of-bailiwick nameserver is never asked for glue.
	for _, c := range child.calls {
		if strings.HasPrefix(c, "ns.provider.net./") {
			t.Errorf("glue fetched for an out-of-bailiwick NS: %s", c)
		}
	}
}

// Glue-side failures skip the nameserver rather than aborting; a kept
// nameserver whose glue cannot be read is left as it is.
func TestComputeCsyncDeltaGlueFailuresSkip(t *testing.T) {
	ctx := context.Background()
	types := []uint16{dns.TypeNS, dns.TypeA}
	currentNS := rrs(t, "child.example. 3600 IN NS ns1.child.example.", "child.example. 3600 IN NS ns2.child.example.")
	current := map[string]map[uint16][]dns.RR{
		"ns1.child.example.": {dns.TypeA: rrs(t, "ns1.child.example. 3600 IN A 192.0.2.1")},
		"ns2.child.example.": {dns.TypeA: rrs(t, "ns2.child.example. 3600 IN A 192.0.2.2")},
	}
	child := &stubChild{
		rrs: map[string][]dns.RR{
			csChild + "/NS":        currentNS,
			"ns1.child.example./A": rrs(t, "ns1.child.example. 3600 IN A 192.0.2.99"),
			"ns2.child.example./A": rrs(t, "ns2.child.example. 3600 IN A 192.0.2.98"),
		},
		errs:   map[string]error{"ns1.child.example./A": errors.New("timeout")},
		inSync: map[string]bool{"ns2.child.example./A": false},
	}
	d, err := computeCsyncDelta(ctx, csChild, types, currentNS, glueFrom(current), child.fetch, quietLog(), false, false)
	if err != nil {
		t.Fatalf("glue failures must not be terminal: %v", err)
	}
	if d.Changed || len(d.GlueAdds) != 0 || len(d.GlueRemoves) != 0 {
		t.Fatalf("both nameservers skipped, want no change: %+v", d)
	}
}

// A nameserver gone from the NS set loses its stored glue -- and an entry that
// exists but is empty still reports a change, as it always has.
func TestComputeCsyncDeltaRemovedNSGlue(t *testing.T) {
	ctx := context.Background()
	types := []uint16{dns.TypeNS, dns.TypeA}
	currentNS := rrs(t, "child.example. 3600 IN NS ns1.child.example.", "child.example. 3600 IN NS gone.child.example.")
	newNS := rrs(t, "child.example. 3600 IN NS ns1.child.example.")

	t.Run("stored glue is removed", func(t *testing.T) {
		current := map[string]map[uint16][]dns.RR{
			"ns1.child.example.":  {dns.TypeA: rrs(t, "ns1.child.example. 3600 IN A 192.0.2.1")},
			"gone.child.example.": {dns.TypeA: rrs(t, "gone.child.example. 3600 IN A 192.0.2.5")},
		}
		child := &stubChild{rrs: map[string][]dns.RR{
			csChild + "/NS":        newNS,
			"ns1.child.example./A": current["ns1.child.example."][dns.TypeA],
		}}
		d, err := computeCsyncDelta(ctx, csChild, types, currentNS, glueFrom(current), child.fetch, quietLog(), false, false)
		if err != nil {
			t.Fatal(err)
		}
		if len(d.GlueRemoves) != 1 || !strings.Contains(d.GlueRemoves[0].String(), "192.0.2.5") || len(d.GlueAdds) != 0 {
			t.Fatalf("glue adds %v removes %v", names(d.GlueAdds), names(d.GlueRemoves))
		}
	})

	t.Run("no stored glue entry: nothing to remove", func(t *testing.T) {
		current := map[string]map[uint16][]dns.RR{
			"ns1.child.example.": {dns.TypeA: rrs(t, "ns1.child.example. 3600 IN A 192.0.2.1")},
		}
		child := &stubChild{rrs: map[string][]dns.RR{
			csChild + "/NS":        newNS,
			"ns1.child.example./A": current["ns1.child.example."][dns.TypeA],
		}}
		d, err := computeCsyncDelta(ctx, csChild, types, currentNS, glueFrom(current), child.fetch, quietLog(), false, false)
		if err != nil {
			t.Fatal(err)
		}
		// The NS removal itself is the change; no glue moves.
		if len(d.GlueRemoves) != 0 || len(d.NSRemoves) != 1 {
			t.Fatalf("glue removes %v NS removes %v", names(d.GlueRemoves), names(d.NSRemoves))
		}
	})

	t.Run("present but empty entry still counts as a change", func(t *testing.T) {
		current := map[string]map[uint16][]dns.RR{
			"ns1.child.example.":  {dns.TypeA: rrs(t, "ns1.child.example. 3600 IN A 192.0.2.1")},
			"gone.child.example.": {dns.TypeA: {}},
		}
		child := &stubChild{rrs: map[string][]dns.RR{
			csChild + "/NS":        newNS,
			"ns1.child.example./A": current["ns1.child.example."][dns.TypeA],
		}}
		d, err := computeCsyncDelta(ctx, csChild, types, currentNS, glueFrom(current), child.fetch, quietLog(), false, false)
		if err != nil {
			t.Fatal(err)
		}
		if !d.Changed || len(d.GlueRemoves) != 0 {
			t.Fatalf("delta %+v", d)
		}
	})
}

func TestComputeCsyncDeltaIgnoresUnknownTypes(t *testing.T) {
	currentNS := rrs(t, "child.example. 3600 IN NS ns.provider.net.")
	child := &stubChild{rrs: map[string][]dns.RR{csChild + "/NS": currentNS}}
	d, err := computeCsyncDelta(context.Background(), csChild, []uint16{dns.TypeNS, dns.TypeTXT}, currentNS, glueFrom(nil), child.fetch, quietLog(), false, false)
	if err != nil {
		t.Fatal(err)
	}
	if d.Changed || len(child.calls) != 1 {
		t.Fatalf("delta %+v calls %v", d, child.calls)
	}
}

// computeCsyncDelta is a free function now, and its next caller is a different
// subsystem (the UPDATE path, step 2). A nil logger used to be a panic in the
// middle of a delegation decision; it is silence instead.
func TestComputeCsyncDeltaToleratesNilLogger(t *testing.T) {
	fetch := func(ctx context.Context, zone string, rrtype uint16) ([]dns.RR, bool, error) {
		if rrtype == dns.TypeNS {
			return []dns.RR{mustRR(t, "child.example. 3600 IN NS ns1.other.net.")}, true, nil
		}
		return nil, true, nil
	}
	noGlue := func(string, uint16) ([]dns.RR, bool) { return nil, false }

	// Would panic on the first lg.Printf if the default were not installed.
	d, err := computeCsyncDelta(context.Background(), "child.example.",
		[]uint16{dns.TypeNS}, nil, noGlue, fetch, nil, true, true)
	if err != nil {
		t.Fatalf("nil logger must not fail the computation: %v", err)
	}
	if !d.Changed {
		t.Error("fixture wrong: the delta should report a change")
	}
}
