/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package debug

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func packMsg(t *testing.T, rrs ...dns.RR) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion("example.test.", dns.TypeAXFR)
	m.Answer = rrs
	wire, err := m.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	return wire
}

func rr(t *testing.T, s string) dns.RR {
	t.Helper()
	r, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("parsing %q: %v", s, err)
	}
	return r
}

func TestWalkXfrMessageAcceptsAWellFormedMessage(t *testing.T) {
	wire := packMsg(t,
		rr(t, "example.test. 900 IN SOA ns.example.test. h.example.test. 1 1800 900 604800 900"),
		rr(t, "host1.example.test. 900 IN A 10.0.0.1"),
		rr(t, "example.test. 900 IN SOA ns.example.test. h.example.test. 1 1800 900 604800 900"),
	)
	f := WalkXfrMessage(1, wire)
	if !f.Clean() {
		t.Fatalf("clean message reported defective: %+v", f)
	}
	if f.Records != 3 || f.ParsedTo != len(wire) || f.Trailing != 0 {
		t.Fatalf("records=%d parsedTo=%d/%d trailing=%d", f.Records, f.ParsedTo, len(wire), f.Trailing)
	}
}

// The whole point of the tool: bytes the header does not account for.
func TestWalkXfrMessageReportsTrailingBytes(t *testing.T) {
	wire := packMsg(t, rr(t, "host1.example.test. 900 IN A 10.0.0.1"))
	junk := append(append([]byte{}, wire...), 0xde, 0xad, 0xbe, 0xef)

	f := WalkXfrMessage(1, junk)
	if f.Clean() {
		t.Fatal("four appended bytes went unreported")
	}
	if f.Trailing != 4 {
		t.Fatalf("Trailing = %d, want 4", f.Trailing)
	}
	if !strings.Contains(f.TrailingHex, "de ad be ef") {
		t.Fatalf("TrailingHex does not show the bytes:\n%s", f.TrailingHex)
	}
}

// An rdata that does not parse to exactly its RDLENGTH is the defect a strict
// client reports against the whole message; here it must name the record.
func TestWalkXfrMessageNamesARecordWithABadRdlength(t *testing.T) {
	wire := packMsg(t, rr(t, "host1.example.test. 900 IN A 10.0.0.1"))
	// The A record's RDLENGTH is the last two bytes before its 4 rdata bytes.
	rdlenAt := len(wire) - 6
	if got := binary.BigEndian.Uint16(wire[rdlenAt:]); got != 4 {
		t.Fatalf("expected to find RDLENGTH 4 at %d, found %d", rdlenAt, got)
	}
	binary.BigEndian.PutUint16(wire[rdlenAt:], 5)
	wire = append(wire, 0x00)

	f := WalkXfrMessage(1, wire)
	if f.Clean() {
		t.Fatal("an rdlength that overstates the rdata went unreported")
	}
	if len(f.Defects) != 1 {
		t.Fatalf("Defects = %+v, want exactly one", f.Defects)
	}
	d := f.Defects[0]
	if d.Owner != "host1.example.test." || d.Rrtype != "A" || d.Rdlength != 5 {
		t.Fatalf("defect does not name the record: %+v", d)
	}
}

// A lenient parser accepting a record is not the same as the record being
// safe, and this is the case that motivated the tool.
func TestWalkXfrMessageFlagsAliasModeSVCBWithParams(t *testing.T) {
	hazard := packMsg(t, rr(t, `alias.example.test. 900 IN SVCB 0 . key65282="unsigned"`))
	f := WalkXfrMessage(1, hazard)
	if !f.Clean() {
		t.Fatalf("the record parses cleanly here; that is the point: %+v", f)
	}
	if len(f.Hazards) != 1 {
		t.Fatalf("Hazards = %v, want the AliasMode SVCB flagged", f.Hazards)
	}
	if !strings.Contains(f.Hazards[0], "AliasMode") || !strings.Contains(f.Hazards[0], "9.18") {
		t.Fatalf("hazard text does not explain the risk: %q", f.Hazards[0])
	}

	// ServiceMode with the same param is fine and must not be flagged, or the
	// check would fire on every correctly published record.
	ok := packMsg(t, rr(t, `svc.example.test. 900 IN SVCB 1 . key65282="unsigned"`))
	if f := WalkXfrMessage(1, ok); len(f.Hazards) != 0 {
		t.Fatalf("ServiceMode SVCB was flagged: %v", f.Hazards)
	}
	// An AliasMode record with no params is a legitimate alias.
	plain := packMsg(t, rr(t, "alias.example.test. 900 IN SVCB 0 target.example.test."))
	if f := WalkXfrMessage(1, plain); len(f.Hazards) != 0 {
		t.Fatalf("a plain AliasMode alias was flagged: %v", f.Hazards)
	}
}

// dig's dump is often the only artifact of a failure on someone else's
// machine. The ASCII gutter is the trap: it can hold pairs of hex characters.
func TestParseDigHexdumpSkipsTheASCIIGutter(t *testing.T) {
	dump := `;; Got bad packet: extra input data
22186 bytes
e8 40 84 00 00 01 01 48 00 00 00 00 06 64 6e 73          .@.....H.....dns
6c 61 62 00 00 fc 00 01 06 64 6e 73 6c 61 62 00          lab......dnslab.
00 06 00 01                                              ab cd ef
`
	got, err := ParseDigHexdump(strings.NewReader(dump))
	if err != nil {
		t.Fatalf("ParseDigHexdump: %v", err)
	}
	if len(got) != 36 {
		t.Fatalf("recovered %d bytes, want 36 (the gutter's \"ab cd ef\" must not be read as data)", len(got))
	}
	if binary.BigEndian.Uint16(got[0:]) != 0xe840 || binary.BigEndian.Uint16(got[6:]) != 0x0148 {
		t.Fatalf("header did not survive: id=%#04x ancount=%d",
			binary.BigEndian.Uint16(got[0:]), binary.BigEndian.Uint16(got[6:]))
	}
}

func TestParseDigHexdumpRejectsInputWithNoDump(t *testing.T) {
	if _, err := ParseDigHexdump(strings.NewReader(";; connection timed out\n")); err == nil {
		t.Fatal("accepted input containing no hex dump")
	}
}
