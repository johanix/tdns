/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package core

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// The DSYNC presentation form (RFC 9859, #757): the RRtype as a mnemonic or
// TYPEnnn, the scheme as a mnemonic or a decimal 0-255, the port as a decimal
// 0-65535. Every record goes text -> RR -> text -> RR through the zone-file
// parser, and the second text is the first one printed back.

func dsyncOf(t *testing.T, rr dns.RR) *DSYNC {
	t.Helper()
	prr, ok := rr.(*dns.PrivateRR)
	if !ok {
		t.Fatalf("%q is a %T, not a DSYNC", rr.String(), rr)
	}
	d, ok := prr.Data.(*DSYNC)
	if !ok {
		t.Fatalf("%q carries %T, not a DSYNC", rr.String(), prr.Data)
	}
	return d
}

func TestDsyncPresentationRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		rdata  string // what is parsed
		want   DSYNC  // what it parses to
		prints string // the rdata as String prints it
	}{
		{"CDS NOTIFY 5359 ns.example.", DSYNC{dns.TypeCDS, SchemeNotify, 5359, "ns.example."}, "CDS NOTIFY 5359 ns.example."},
		{"ANY UPDATE 53 upd.example.", DSYNC{dns.TypeANY, SchemeUpdate, 53, "upd.example."}, "ANY UPDATE 53 upd.example."},
		{"CSYNC SCANNER 53 s.example.", DSYNC{dns.TypeCSYNC, SchemeScanner, 53, "s.example."}, "CSYNC SCANNER 53 s.example."},
		{"CDS API 8443 api.example.", DSYNC{dns.TypeCDS, SchemeAPI, 8443, "api.example."}, "CDS API 8443 api.example."},
		{"CDS MSUPDATE 53 m.example.", DSYNC{dns.TypeCDS, SchemeMSUpdate, 53, "m.example."}, "CDS MSUPDATE 53 m.example."},
		{"CDS REPORT 53 r.example.", DSYNC{dns.TypeCDS, SchemeReport, 53, "r.example."}, "CDS REPORT 53 r.example."},
		{"CDS REPORTER 53 r.example.", DSYNC{dns.TypeCDS, SchemeReport, 53, "r.example."}, "CDS REPORT 53 r.example."},
		// A scheme by number: the null scheme, an unassigned one and a
		// private-use one print as their decimal; an assigned one as its
		// mnemonic.
		{"CDS 0 53 ns.example.", DSYNC{dns.TypeCDS, 0, 53, "ns.example."}, "CDS 0 53 ns.example."},
		{"CDS 5 53 ns.example.", DSYNC{dns.TypeCDS, 5, 53, "ns.example."}, "CDS 5 53 ns.example."},
		{"CDS 200 53 ns.example.", DSYNC{dns.TypeCDS, 200, 53, "ns.example."}, "CDS 200 53 ns.example."},
		{"CDS 255 53 ns.example.", DSYNC{dns.TypeCDS, 255, 53, "ns.example."}, "CDS 255 53 ns.example."},
		{"CDS 1 53 ns.example.", DSYNC{dns.TypeCDS, SchemeNotify, 53, "ns.example."}, "CDS NOTIFY 53 ns.example."},
		// The RRtype field in RFC 3597 form: TYPE59 is CDS; a type with no
		// mnemonic prints back as TYPEnnn.
		{"TYPE59 NOTIFY 53 ns.example.", DSYNC{dns.TypeCDS, SchemeNotify, 53, "ns.example."}, "CDS NOTIFY 53 ns.example."},
		{"TYPE4000 NOTIFY 53 ns.example.", DSYNC{4000, SchemeNotify, 53, "ns.example."}, "TYPE4000 NOTIFY 53 ns.example."},
		// Mnemonics are case-insensitive, as elsewhere in a zone file.
		{"cds notify 53 ns.example.", DSYNC{dns.TypeCDS, SchemeNotify, 53, "ns.example."}, "CDS NOTIFY 53 ns.example."},
		// The port's whole range.
		{"CDS NOTIFY 0 ns.example.", DSYNC{dns.TypeCDS, SchemeNotify, 0, "ns.example."}, "CDS NOTIFY 0 ns.example."},
		{"CDS NOTIFY 65535 ns.example.", DSYNC{dns.TypeCDS, SchemeNotify, 65535, "ns.example."}, "CDS NOTIFY 65535 ns.example."},
	} {
		text := "_dsync.example. 3600 IN DSYNC " + tc.rdata
		rr, err := dns.NewRR(text)
		if err != nil {
			t.Errorf("%q: %v", tc.rdata, err)
			continue
		}
		if got := *dsyncOf(t, rr); got != tc.want {
			t.Errorf("%q parsed to %+v, want %+v", tc.rdata, got, tc.want)
		}
		printed := rr.String()
		if got := strings.Join(strings.Fields(printed)[4:], " "); got != tc.prints {
			t.Errorf("%q prints as %q, want %q", tc.rdata, got, tc.prints)
		}
		again, err := dns.NewRR(printed)
		if err != nil {
			t.Errorf("%q printed %q, which does not parse: %v", tc.rdata, printed, err)
			continue
		}
		if got := *dsyncOf(t, again); got != tc.want {
			t.Errorf("%q printed and parsed again is %+v, want %+v", tc.rdata, got, tc.want)
		}
	}
}

func TestDsyncPresentationRefusals(t *testing.T) {
	for _, rdata := range []string{
		"CDS NOTIFY 65536 ns.example.", // the port is 16 bits
		"CDS NOTIFY 70000 ns.example.", // used to wrap to 4464
		"CDS NOTIFY -1 ns.example.",    // used to wrap to 65535
		"CDS NOTIFY x ns.example.",
		"CDS 256 53 ns.example.", // the scheme is 8 bits
		"CDS -1 53 ns.example.",
		"CDS NOSUCH 53 ns.example.",
		"NOSUCH NOTIFY 53 ns.example.",
		"TYPE65536 NOTIFY 53 ns.example.",
		"TYPE NOTIFY 53 ns.example.",
		"TYPE0 NOTIFY 53 ns.example.", // type 0 is reserved
		"CDS NOTIFY 53",
	} {
		if rr, err := dns.NewRR("_dsync.example. 3600 IN DSYNC " + rdata); err == nil {
			t.Errorf("%q parsed, to %q; want it refused", rdata, rr.String())
		}
	}
}

// Rdata that ends before the target is an error (#757). It used to unpack
// without one, with the missing fields left zero.
func TestDsyncUnpackTruncated(t *testing.T) {
	full := &DSYNC{Type: dns.TypeCDS, Scheme: SchemeNotify, Port: 5359, Target: "ns.example."}
	buf := make([]byte, full.Len())
	n, err := full.Pack(buf)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	buf = buf[:n]

	var whole DSYNC
	if _, err := whole.Unpack(buf); err != nil || whole != *full {
		t.Fatalf("the whole rdata unpacks to %+v, %v; want %+v", whole, err, *full)
	}
	for cut := 1; cut < len(buf); cut++ {
		var d DSYNC
		if _, err := d.Unpack(buf[:cut]); err == nil {
			t.Errorf("%d of %d rdata octets unpacked to %+v with no error", cut, len(buf), d)
		}
	}
}

// The same through a whole message, as a resolver receives it: a DSYNC whose
// rdata stops early, as the last record of the message, makes the message
// fail to unpack. Before the fix such a message unpacked: the rdlength
// matched the short rdata and the DSYNC stopped where the message did.
func TestDsyncTruncatedInAMessage(t *testing.T) {
	rr, err := dns.NewRR("_dsync.example. 3600 IN DSYNC CDS NOTIFY 5359 ns.example.")
	if err != nil {
		t.Fatal(err)
	}
	m := new(dns.Msg)
	m.SetQuestion("_dsync.example.", TypeDSYNC)
	m.Response = true
	m.Answer = []dns.RR{rr}
	wire, err := m.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	rdlen := 2 + 1 + 2 + len("\x02ns\x07example\x00")
	start := len(wire) - rdlen
	if got := int(wire[start-2])<<8 | int(wire[start-1]); got != rdlen {
		t.Fatalf("fixture: rdlength %d, want %d", got, rdlen)
	}
	if err := new(dns.Msg).Unpack(wire); err != nil {
		t.Fatalf("fixture: the whole message does not unpack: %v", err)
	}
	for cut := 1; cut < rdlen; cut++ {
		short := append([]byte(nil), wire[:start+cut]...)
		short[start-2], short[start-1] = byte(cut>>8), byte(cut)
		got := new(dns.Msg)
		if err := got.Unpack(short); err == nil {
			t.Errorf("a DSYNC with %d of %d rdata octets unpacked: %v", cut, rdlen, got.Answer)
		}
	}
}

// Usable is what a consumer selects on: a scheme (not the null scheme), a
// port (not 0), and a target other than the root.
func TestDsyncUsable(t *testing.T) {
	for _, tc := range []struct {
		d    *DSYNC
		want bool
	}{
		{&DSYNC{dns.TypeCDS, SchemeNotify, 53, "ns.example."}, true},
		{&DSYNC{dns.TypeANY, SchemeUpdate, 5302, "upd.example."}, true},
		{&DSYNC{dns.TypeCDS, 200, 53, "ns.example."}, true},
		{&DSYNC{dns.TypeCDS, 0, 53, "ns.example."}, false},
		{&DSYNC{dns.TypeCDS, SchemeNotify, 0, "ns.example."}, false},
		{&DSYNC{dns.TypeCDS, SchemeNotify, 53, "."}, false},
		{&DSYNC{dns.TypeCDS, SchemeNotify, 53, ""}, false},
		{nil, false},
	} {
		if got := tc.d.Usable(); got != tc.want {
			t.Errorf("%+v: Usable() = %v, want %v", tc.d, got, tc.want)
		}
	}
}
