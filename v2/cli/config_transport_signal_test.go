/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cli

import (
	"strings"
	"testing"

	"github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

// What "config transport-signal" prints is a zone-file fragment: pasted into
// a zone, it reads back as the records the daemon sent, and the state lines
// are comments.
func TestRenderTransportSignalIsAZoneFileFragment(t *testing.T) {
	previews := []tdns.TransportSignalPreview{
		{
			Name: "ns1.example.net.", Owner: "_dns.ns1.example.net.", Identity: true,
			Home: "example.net.", State: tdns.SignalStateSynthesized,
			Records: []string{
				`_dns.ns1.example.net.	10800	IN	SVCB	1 . oots="tcp:50,udp:50"`,
				`_dns.ns1.example.net.	10800	IN	SVCB	1 dot.provider.example. oots="dot:10"`,
				`_dns.ns1.example.net.	10800	IN	SVCB	1 . port="8853" oots="doq:20"`,
			},
		},
		{
			Name: "ns2.example.net.", Owner: "_dns.ns2.example.net.", Identity: true,
			Home: "example.net.", State: tdns.SignalStateProvisioned, Matches: true,
			Records: []string{`_dns.ns2.example.net.	10800	IN	SVCB	1 . oots="dot:30"`},
		},
	}
	out := renderTransportSignal(previews)

	zp := dns.NewZoneParser(strings.NewReader(out), "example.net.", "")
	var got []string
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		got = append(got, rr.String())
	}
	if err := zp.Err(); err != nil {
		t.Fatalf("the output does not parse as a zone file: %v\n%s", err, out)
	}
	var want []string
	for _, p := range previews {
		for _, line := range p.Records {
			rr, err := dns.NewRR(line)
			if err != nil {
				t.Fatal(err)
			}
			want = append(want, rr.String())
		}
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("the zone file reads back as\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line != "" && !strings.HasPrefix(line, ";") && !strings.HasPrefix(line, "_dns.") {
			t.Fatalf("a line that is neither a record nor a comment: %q", line)
		}
	}
}

func TestTransportSignalStateLines(t *testing.T) {
	for _, tc := range []struct {
		p    tdns.TransportSignalPreview
		want string
	}{
		{tdns.TransportSignalPreview{Name: "a.", Owner: "_dns.a.", Home: "z.", State: tdns.SignalStateSynthesized, Identity: true}, "synthesized in z. now; paste these records into the zone, then run transport-signal --release a."},
		{tdns.TransportSignalPreview{Owner: "_dns.a.", Home: "z.", State: tdns.SignalStateProvisioned, Matches: true, Identity: true}, "provisioned in z. as below"},
		{tdns.TransportSignalPreview{Owner: "_dns.a.", Home: "z.", State: tdns.SignalStateProvisioned, Identity: true}, "differing from below"},
		{tdns.TransportSignalPreview{Owner: "_dns.a.", Home: "z.", State: tdns.SignalStateNone, Identity: true}, "nothing there in z. yet"},
		{tdns.TransportSignalPreview{Name: "a.", Owner: "_dns.a.", State: tdns.SignalStateNotHosted, Identity: true}, "no zone served here holds a."},
		{tdns.TransportSignalPreview{Owner: "_dns.a.", Home: "z.", State: tdns.SignalStateNone}, "(not one of service.identities)"},
	} {
		if got := transportSignalStateLine(tc.p); !strings.Contains(got, tc.want) {
			t.Errorf("state %q: %q, want %q in it", tc.p.State, got, tc.want)
		}
	}
}
