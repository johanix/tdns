package tdns

import (
	"strings"
	"testing"

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

// A permanently address-less server must be reported once, not on every query:
// it is a standing state, not an event.
func TestNoteServerWithoutAddressesIsReportedOnce(t *testing.T) {
	zone, ns := "dedupe-test.example.", "ns1.dedupe-test.example."
	serversWithoutAddresses.Delete(zone + "|" + ns)
	t.Cleanup(func() { serversWithoutAddresses.Delete(zone + "|" + ns) })

	noteServerWithoutAddresses(zone, ns)
	if _, ok := serversWithoutAddresses.Load(zone + "|" + ns); !ok {
		t.Fatal("first report did not record the pair")
	}
	// Second call must be a no-op rather than a second log line.
	noteServerWithoutAddresses(zone, ns)

	// A different server in the same zone is still reported.
	other := "ns2.dedupe-test.example."
	serversWithoutAddresses.Delete(zone + "|" + other)
	t.Cleanup(func() { serversWithoutAddresses.Delete(zone + "|" + other) })
	noteServerWithoutAddresses(zone, other)
	if _, ok := serversWithoutAddresses.Load(zone + "|" + other); !ok {
		t.Error("a second server in the same zone was suppressed; dedupe is too coarse")
	}
}
