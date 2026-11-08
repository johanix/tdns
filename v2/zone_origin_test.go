/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func originTestZone(name string) *ZoneData {
	return &ZoneData{
		ZoneName:  name,
		ZoneStore: MapZone,
		ZoneType:  Primary,
		Logger:    log.New(io.Discard, "", 0),
	}
}

func originTestRRs(t *testing.T, zd *ZoneData, owner string, rrtype uint16) []dns.RR {
	t.Helper()
	od, ok := zd.Data.Get(owner)
	if !ok || od.RRtypes == nil {
		t.Fatalf("no owner %s in zone %s", owner, zd.ZoneName)
	}
	return od.RRtypes.GetOnlyRRSet(rrtype).RRs
}

// The commonest shape of zone file: "@" and relative names, no $ORIGIN. It
// used to fail with `bad owner name: "@"`.
func TestZoneFileRelativeToTheZoneName(t *testing.T) {
	zd := originTestZone("r6.test.")
	_, _, err := zd.ReadZoneData(`$TTL 300
@	IN SOA	ns hostmaster 1 600 600 604800 600
	IN NS	ns
ns	IN A	192.0.2.53
www	IN A	192.0.2.1
sub	IN NS	ns.sub
`, false)
	if err != nil {
		t.Fatalf("a zone file relative to its zone's name did not load: %v", err)
	}
	soa := originTestRRs(t, zd, "r6.test.", dns.TypeSOA)[0].(*dns.SOA)
	if soa.Ns != "ns.r6.test." || soa.Mbox != "hostmaster.r6.test." {
		t.Errorf("SOA names not relative to the zone: %s", soa)
	}
	if ns := originTestRRs(t, zd, "r6.test.", dns.TypeNS)[0].(*dns.NS); ns.Ns != "ns.r6.test." {
		t.Errorf("apex NS target is %q, want ns.r6.test.", ns.Ns)
	}
	if len(originTestRRs(t, zd, "www.r6.test.", dns.TypeA)) != 1 {
		t.Error("www.r6.test. A not loaded")
	}
	if ns := originTestRRs(t, zd, "sub.r6.test.", dns.TypeNS)[0].(*dns.NS); ns.Ns != "ns.sub.r6.test." {
		t.Errorf("delegation NS target is %q, want ns.sub.r6.test.", ns.Ns)
	}
}

// A name written out in full but missing its trailing dot is refused, on
// purpose, wherever it appears.
func TestZoneFileRefusesADoubledSuffix(t *testing.T) {
	const head = "$TTL 300\nr1.test.\tIN SOA\tns.r1.test. hostmaster.r1.test. 1 600 600 604800 600\nr1.test.\tIN NS\tns.r1.test.\nns.r1.test.\tIN A\t192.0.2.53\n"
	cases := []struct {
		name, line, suffix string
	}{
		{"NS target", "sub.r1.test.\tIN NS\tns1.sub.r1.test\n", `"r1.test." twice`},
		{"owner", "www.r1.test\tIN A\t192.0.2.1\n", `"r1.test." twice`},
		{"MX exchange", "r1.test.\tIN MX\t10 mail.r1.test\n", `"r1.test." twice`},
		{"SRV target", "_x._tcp.r1.test.\tIN SRV\t0 0 1 host.r1.test\n", `"r1.test." twice`},
		{"under a sub-origin", "$ORIGIN sub.r1.test.\n@\tIN NS\tns1.sub.r1.test\n", `"sub.r1.test." twice`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			zd := originTestZone("r1.test.")
			_, _, err := zd.ReadZoneData(head+c.line, false)
			if err == nil {
				t.Fatal("a name missing its trailing dot was accepted")
			}
			if !strings.Contains(err.Error(), "trailing dot is probably missing") ||
				!strings.Contains(err.Error(), c.suffix) {
				t.Errorf("the error does not say what is wrong: %v", err)
			}
		})
	}
}

// Names that contain the zone's name but don't end in it twice load as before.
func TestZoneFileAcceptsNamesThatOnlyContainTheZone(t *testing.T) {
	zd := originTestZone("r1.test.")
	_, _, err := zd.ReadZoneData(`$TTL 300
r1.test.	IN SOA	ns.r1.test. hostmaster.r1.test. 1 600 600 604800 600
r1.test.	IN NS	ns.r1.test.
ns.r1.test.	IN A	192.0.2.53
www.r1.test.	IN CNAME	www.r1.test.edgekey.example.
test.r1.test.	IN A	192.0.2.2
r1.r1.test.	IN A	192.0.2.3
`, false)
	if err != nil {
		t.Fatalf("a name that only contains the zone's name was refused: %v", err)
	}
}

func TestDoubledZoneSuffix(t *testing.T) {
	cases := []struct {
		zone, name, want string
	}{
		{"example.test.", "ns1.example.test.example.test.", "example.test."},
		{"example.test.", "NS1.Example.Test.example.TEST.", "example.TEST."},
		{"example.test.", "ns1.sub.example.test.sub.example.test.", "sub.example.test."},
		{"example.test.", "example.test.example.test.", "example.test."},
		{"example.test.", "ns1.example.test.", ""},
		{"example.test.", "www.example.test.edgekey.example.", ""},
		{"example.test.", "test.example.test.", ""},
		{"example.test.", "example.example.test.", ""},
		{"test.", "a.test.test.", "test."},
		{"test.", "test.", ""},
	}
	for _, c := range cases {
		got, ok := doubledZoneSuffix(dns.SplitDomainName(c.zone), c.name)
		if ok != (c.want != "") || got != c.want {
			t.Errorf("doubledZoneSuffix(%s, %s) = %q, %v; want %q", c.zone, c.name, got, ok, c.want)
		}
	}
	if err := checkDoubledZoneSuffix(".", mustRR(t, "com.com. 300 IN NS a.com.com.")); err != nil {
		t.Errorf("the root zone has no suffix to double, but: %v", err)
	}
}

// An error inside an $INCLUDEd file quotes that file's line, not the line with
// the same number in the main file.
func TestZoneParseErrorQuotesTheIncludedFile(t *testing.T) {
	dir := t.TempDir()
	inc := filepath.Join(dir, "hosts.inc")
	main := filepath.Join(dir, "inc.test.zone")
	if err := os.WriteFile(inc, []byte("good\tIN A\t192.0.2.10\nbad\tIN A\tnot-an-address\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(main, []byte("$TTL 300\n"+
		"@\tIN SOA\tns hostmaster 1 600 600 604800 600\n"+
		"\tIN NS\tns\n"+
		"ns\tIN A\t192.0.2.53\n"+
		"$INCLUDE "+inc+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	zd := originTestZone("inc.test.")
	_, _, err := zd.ReadZoneFile(context.Background(), main, true)
	if err == nil {
		t.Fatal("a bad record in the included file was accepted")
	}
	msg := err.Error()
	if !strings.Contains(msg, "not-an-address") || !strings.Contains(msg, inc) {
		t.Errorf("the error does not quote the included file's line: %v", err)
	}
	if strings.Contains(msg, "IN SOA") {
		t.Errorf("the error quotes the main file's line 2: %v", err)
	}
}
