package tdns

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
)

// A zero-tuple result means the query is never sent at all. It used to leave no
// trace beyond a phrase inside an error string, which is what made the
// stub-resolution failure so hard to diagnose: the server map was present and
// correct on every query, and there was no way to see why nothing was tried.
func TestExplainNoTuplesNamesTheReason(t *testing.T) {
	cases := []struct {
		name      string
		serverMap map[string]*cache.AuthServer
		want      string
	}{
		{
			name:      "empty map",
			serverMap: map[string]*cache.AuthServer{},
			want:      "no servers in the map",
		},
		{
			// The silent case: present in the map, named in every log line,
			// and yet unusable.
			name: "server with no addresses",
			serverMap: map[string]*cache.AuthServer{
				"ns1.example.": {Name: "ns1.example."},
			},
			want: "no addresses",
		},
		{
			name: "nil server entry",
			serverMap: map[string]*cache.AuthServer{
				"ns1.example.": nil,
			},
			want: "nil server entry",
		},
		{
			name: "server with addresses reports counts",
			serverMap: map[string]*cache.AuthServer{
				"ns1.example.": {Name: "ns1.example.", Addrs: []string{"192.0.2.1"}},
			},
			want: "1 addr(s)",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := explainNoTuples(tc.serverMap, nil, "www.example.", false)
			if !strings.Contains(got, tc.want) {
				t.Errorf("explanation %q does not mention %q", got, tc.want)
			}
		})
	}
}

// The explanation must name the server, so an operator knows which one to look
// at when a zone has several.
func TestExplainNoTuplesNamesTheServer(t *testing.T) {
	sm := map[string]*cache.AuthServer{
		"ns1.example.": {Name: "ns1.example."},
		"ns2.example.": {Name: "ns2.example.", Addrs: []string{"192.0.2.2"}},
	}
	got := explainNoTuples(sm, nil, "www.example.", false)
	for _, ns := range []string{"ns1.example.", "ns2.example."} {
		if !strings.Contains(got, ns) {
			t.Errorf("explanation %q does not name %s", got, ns)
		}
	}
}

// An unusable server must be reported once per interval, not per query: it is a
// standing state, not an event.
func TestNoteServerProblemIsReportedOncePerInterval(t *testing.T) {
	zone, ns, reason := "dedupe-test.example.", "ns1.dedupe-test.example.", "no addresses"
	key := zone + "|" + ns + "|" + reason

	unusableServersMu.Lock()
	delete(unusableServers, key)
	unusableServersMu.Unlock()
	t.Cleanup(func() {
		unusableServersMu.Lock()
		delete(unusableServers, key)
		unusableServersMu.Unlock()
	})

	noteServerProblem(zone, ns, reason)
	unusableServersMu.Lock()
	first, ok := unusableServers[key]
	unusableServersMu.Unlock()
	if !ok {
		t.Fatal("first report did not record the pair")
	}

	// A second call inside the interval must not refresh the timestamp, or a
	// server reported continuously would never be re-reported.
	noteServerProblem(zone, ns, reason)
	unusableServersMu.Lock()
	second := unusableServers[key]
	unusableServersMu.Unlock()
	if !second.Equal(first) {
		t.Error("a suppressed report still refreshed the timestamp")
	}
}

// Distinct reasons for the same server are tracked separately: a nil map entry
// and a server with no addresses are different faults.
func TestNoteServerProblemSeparatesReasons(t *testing.T) {
	zone, ns := "reasons.example.", "ns1.reasons.example."
	keys := []string{
		zone + "|" + ns + "|no addresses",
		zone + "|" + ns + "|nil server entry in the server map",
	}
	t.Cleanup(func() {
		unusableServersMu.Lock()
		for _, k := range keys {
			delete(unusableServers, k)
		}
		unusableServersMu.Unlock()
	})

	noteServerProblem(zone, ns, "no addresses")
	noteServerProblem(zone, ns, "nil server entry in the server map")

	unusableServersMu.Lock()
	defer unusableServersMu.Unlock()
	for _, k := range keys {
		if _, ok := unusableServers[k]; !ok {
			t.Errorf("reason not tracked separately: %s", k)
		}
	}
}

// The table must stay bounded. A resolver can meet an unbounded number of broken
// delegations, and a dedup cache that never evicts is a slow leak on an error
// path.
func TestNoteServerProblemBoundsItsState(t *testing.T) {
	unusableServersMu.Lock()
	saved := unusableServers
	unusableServers = map[string]time.Time{}
	unusableServersMu.Unlock()
	t.Cleanup(func() {
		unusableServersMu.Lock()
		unusableServers = saved
		unusableServersMu.Unlock()
	})

	for i := 0; i < unusableServerMaxKeys*2; i++ {
		noteServerProblem(fmt.Sprintf("zone%d.example.", i), "ns1.example.", "no addresses")
	}

	unusableServersMu.Lock()
	n := len(unusableServers)
	unusableServersMu.Unlock()
	if n > unusableServerMaxKeys {
		t.Errorf("dedup table holds %d entries, cap is %d; it grows without bound",
			n, unusableServerMaxKeys)
	}
	if n == 0 {
		t.Error("dedup table was emptied entirely; every server would be re-reported every query")
	}
}

// A nil entry in the server map must not crash the resolver, and must be
// reported as what it is. GetAddrs is nil-safe on its receiver, so this never
// panicked -- but "no addresses" was the wrong thing to say about it, and would
// send an operator looking for a nameserver that was never there.
func TestPrioritizeServersHandlesANilServerEntry(t *testing.T) {
	imr := newTestImr(t)

	serverMap := map[string]*cache.AuthServer{
		"ns1.example.": nil,
		"ns2.example.": {Name: "ns2.example.", Addrs: []string{"192.0.2.2"}},
	}

	// Must not panic, and the healthy server must still be usable: one bad map
	// entry cannot be allowed to take the whole zone down with it.
	_, _, tuples := imr.prioritizeServers("foo.example.", serverMap, false)
	if len(tuples) == 0 {
		t.Fatal("a nil entry suppressed the healthy server alongside it")
	}
	for _, tup := range tuples {
		if tup.NSName == "ns1.example." {
			t.Error("the nil entry produced a tuple")
		}
	}

	// And with ONLY a nil entry, still no panic and no tuples.
	_, _, tuples = imr.prioritizeServers("foo.example.", map[string]*cache.AuthServer{
		"ns1.example.": nil,
	}, false)
	if len(tuples) != 0 {
		t.Errorf("a nil-only server map produced %d tuples", len(tuples))
	}
}
