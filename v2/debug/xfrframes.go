/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package debug

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Frame-level analysis of a zone-transfer stream: does the wire agree with
// itself?
//
// A transfer that a lenient client accepts can still be rejected by a strict
// one, and the strict one's error names the whole message rather than the
// record that caused it ("extra input data" for 22186 bytes tells you nothing
// about which of 328 records is wrong). This walks the stream the way a strict
// parser does -- section by section, record by record, each rdata bounded by
// its own RDLENGTH -- and reports where the accounting stops adding up.

// XfrDefect is one record whose rdata does not parse to exactly its RDLENGTH.
type XfrDefect struct {
	Record   int    `json:"record"`
	Offset   int    `json:"offset"`
	Owner    string `json:"owner,omitempty"`
	Rrtype   string `json:"rrtype,omitempty"`
	Rdlength uint16 `json:"rdlength,omitempty"`
	Err      string `json:"error"`
}

// XfrFrame is one length-prefixed message from the stream.
type XfrFrame struct {
	Frame     int    `json:"frame"`
	WireBytes int    `json:"wire_bytes"` // what the TCP length prefix claimed
	ParsedTo  int    `json:"parsed_to"`  // where the record-by-record parse ended
	Trailing  int    `json:"trailing_bytes"`
	Qdcount   uint16 `json:"qdcount"`
	Ancount   uint16 `json:"ancount"`
	Nscount   uint16 `json:"nscount"`
	Arcount   uint16 `json:"arcount"`
	Records   int    `json:"records_parsed"`

	Defects []XfrDefect `json:"defects,omitempty"`
	// Hazards are records this parser accepts that a strict one may not. They
	// are not defects here and are the reason a clean run is not a proof.
	Hazards     []string `json:"hazards,omitempty"`
	TrailingHex string   `json:"trailing_hex,omitempty"`
	Err         string   `json:"error,omitempty"`
}

// Clean reports whether the frame accounts for every byte with no defects.
func (f XfrFrame) Clean() bool { return f.Err == "" && f.Trailing == 0 && len(f.Defects) == 0 }

// WalkXfrMessage parses one DNS message strictly and reports the accounting.
func WalkXfrMessage(n int, msg []byte) XfrFrame {
	f := XfrFrame{Frame: n, WireBytes: len(msg)}
	if len(msg) < 12 {
		f.Err = fmt.Sprintf("short message: %d bytes, need at least a 12-byte header", len(msg))
		return f
	}
	f.Qdcount = binary.BigEndian.Uint16(msg[4:])
	f.Ancount = binary.BigEndian.Uint16(msg[6:])
	f.Nscount = binary.BigEndian.Uint16(msg[8:])
	f.Arcount = binary.BigEndian.Uint16(msg[10:])

	off := 12
	for i := 0; i < int(f.Qdcount); i++ {
		_, next, err := dns.UnpackDomainName(msg, off)
		if err != nil {
			f.Err = fmt.Sprintf("question %d: %v", i+1, err)
			f.ParsedTo = off
			return f
		}
		off = next + 4
	}

	counts := [3]uint16{f.Ancount, f.Nscount, f.Arcount}
	rec := 0
	for sec, count := range counts {
		for i := 0; i < int(count); i++ {
			rec++
			start := off
			// dns.UnpackRR, NOT a hand-rolled header plus UnpackRRWithHeader:
			// miekg's unpackHeader hands the type parser a msg TRUNCATED to
			// the end of that record's rdata, and several parsers (TXT, NSEC)
			// read to the end of whatever buffer they are given. Passing the
			// whole message makes them consume the rest of the zone and report
			// defects that are not there.
			rr, next, err := dns.UnpackRR(msg, off)
			if err != nil {
				d := XfrDefect{Record: rec, Offset: start, Err: err.Error()}
				if h, hoff, herr := peekRRHeader(msg, start); herr == nil {
					d.Owner, d.Rrtype, d.Rdlength = h.Name, dns.TypeToString[h.Rrtype], h.Rdlength
					off = hoff + int(h.Rdlength)
				} else {
					f.Defects = append(f.Defects, d)
					f.Err = fmt.Sprintf("section %d record %d: unrecoverable: %v", sec+1, rec, err)
					f.ParsedTo = start
					return f
				}
				f.Defects = append(f.Defects, d)
				continue
			}
			if h := svcbAliasModeHazard(rr); h != "" {
				f.Hazards = append(f.Hazards, h)
			}
			off = next
		}
	}

	f.Records = rec
	f.ParsedTo = off
	f.Trailing = len(msg) - off
	if f.Trailing > 0 {
		f.TrailingHex = strings.TrimRight(hex.Dump(msg[off:]), "\n")
	}
	return f
}

// svcbAliasModeHazard flags an AliasMode SVCB carrying SvcParams.
//
// RFC 9460 §2.4.2 requires recipients to IGNORE such params, and §2.5.1 makes
// a "." target in AliasMode mean the service does not exist -- so the params
// are unreadable by anything conforming. Worse in practice: BIND 9.18 refuses
// the record outright and reports "extra input data" against the whole
// message, so one such record makes a zone untransferable for those clients
// while lenient parsers (this one included) see nothing wrong.
func svcbAliasModeHazard(rr dns.RR) string {
	svcb, ok := rr.(*dns.SVCB)
	if !ok || svcb.Priority != 0 || len(svcb.Value) == 0 {
		return ""
	}
	return fmt.Sprintf("%s SVCB is AliasMode (SvcPriority 0) carrying %d SvcParam(s): "+
		"RFC 9460 §2.4.2 requires recipients to ignore them, and BIND 9.18 rejects the record",
		svcb.Hdr.Name, len(svcb.Value))
}

// peekRRHeader reads an RR header without consuming its rdata, so a record
// that failed to parse can still be named and stepped over.
func peekRRHeader(msg []byte, off int) (dns.RR_Header, int, error) {
	var h dns.RR_Header
	name, next, err := dns.UnpackDomainName(msg, off)
	if err != nil {
		return h, off, err
	}
	if next+10 > len(msg) {
		return h, next, fmt.Errorf("truncated RR header")
	}
	h.Name = name
	h.Rrtype = binary.BigEndian.Uint16(msg[next:])
	h.Class = binary.BigEndian.Uint16(msg[next+2:])
	h.Ttl = binary.BigEndian.Uint32(msg[next+4:])
	h.Rdlength = binary.BigEndian.Uint16(msg[next+8:])
	if next+10+int(h.Rdlength) > len(msg) {
		return h, next + 10, fmt.Errorf("rdlength %d overruns the message", h.Rdlength)
	}
	return h, next + 10, nil
}

// FetchXfrFrames runs a transfer and walks every frame. ixfrSerial > 0 sends
// IXFR from that serial; otherwise AXFR.
//
// The transfer is driven over a raw connection rather than dns.Transfer,
// because the question is what is ON the wire: the length prefix and the bytes
// behind it, both of which a library client consumes before a caller sees them.
func FetchXfrFrames(ctx context.Context, server, zone string, ixfrSerial uint32, maxFrames int) ([]XfrFrame, error) {
	zone = dns.Fqdn(zone)
	q := new(dns.Msg)
	if ixfrSerial > 0 {
		q.SetIxfr(zone, ixfrSerial, "ns."+zone, "hostmaster."+zone)
	} else {
		q.SetAxfr(zone)
	}
	raw, err := q.Pack()
	if err != nil {
		return nil, err
	}

	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, fmt.Errorf("dialling %s: %w", server, err)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	} else {
		conn.SetDeadline(time.Now().Add(120 * time.Second))
	}

	buf := make([]byte, 2+len(raw))
	binary.BigEndian.PutUint16(buf, uint16(len(raw)))
	copy(buf[2:], raw)
	if _, err := conn.Write(buf); err != nil {
		return nil, fmt.Errorf("sending the query: %w", err)
	}

	var frames []XfrFrame
	for n := 1; maxFrames <= 0 || n <= maxFrames; n++ {
		var lb [2]byte
		if _, err := io.ReadFull(conn, lb[:]); err != nil {
			if err == io.EOF && n > 1 {
				return frames, nil
			}
			return frames, fmt.Errorf("reading the length prefix of frame %d: %w", n, err)
		}
		msg := make([]byte, binary.BigEndian.Uint16(lb[:]))
		if _, err := io.ReadFull(conn, msg); err != nil {
			return frames, fmt.Errorf("frame %d claims %d bytes: %w", n, len(msg), err)
		}
		f := WalkXfrMessage(n, msg)
		frames = append(frames, f)
		if endsWithSOA(msg, f) {
			return frames, nil
		}
	}
	return frames, nil
}

// endsWithSOA reports whether this frame closes the transfer.
func endsWithSOA(msg []byte, f XfrFrame) bool {
	if f.Err != "" || f.Ancount == 0 {
		return false
	}
	m := new(dns.Msg)
	if err := m.Unpack(msg); err != nil || len(m.Answer) == 0 {
		return false
	}
	if _, ok := m.Answer[len(m.Answer)-1].(*dns.SOA); !ok {
		return false
	}
	// The opening SOA of a single-frame transfer is also its closing one.
	return f.Frame > 1 || len(m.Answer) > 1
}

var (
	digGutterSep = regexp.MustCompile(`\s{2,}`)
	digHexPair   = regexp.MustCompile(`^[0-9a-fA-F]{2}$`)
)

// ParseDigHexdump recovers the raw message from dig's "Got bad packet" output.
//
// That dump is often the only artifact of a failure seen on someone else's
// machine, and re-typing it is not an option.
//
// The parse is column-aware rather than token-aware, and has to be. dig lays
// each line out as up to 16 space-separated hex pairs, a run of padding, then
// an ASCII gutter -- and the gutter can hold text that tokenizes as hex pairs
// ("ab cd ef"), while the "22186 bytes" line above the dump begins with two hex
// digits. Splitting on the padding and requiring EVERY token of the first field
// to be a hex pair rejects both.
func ParseDigHexdump(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var out []byte
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		field := digGutterSep.Split(line, 2)[0]
		toks := strings.Fields(field)
		if len(toks) == 0 {
			continue
		}
		ok := true
		for _, tok := range toks {
			if !digHexPair.MatchString(tok) {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		for _, tok := range toks {
			b, err := hex.DecodeString(tok)
			if err != nil {
				return nil, fmt.Errorf("bad hex %q: %w", tok, err)
			}
			out = append(out, b...)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no hex dump lines found")
	}
	return out, nil
}

// RenderXfrFrames prints the per-frame accounting.
func RenderXfrFrames(w io.Writer, frames []XfrFrame) {
	clean := true
	for _, f := range frames {
		fmt.Fprintf(w, "frame %d: %d bytes on the wire, parses to %d -> %d trailing\n",
			f.Frame, f.WireBytes, f.ParsedTo, f.Trailing)
		fmt.Fprintf(w, "  qd=%d an=%d ns=%d ar=%d, %d record(s) parsed\n",
			f.Qdcount, f.Ancount, f.Nscount, f.Arcount, f.Records)
		if f.Err != "" {
			clean = false
			fmt.Fprintf(w, "  ERROR: %s\n", f.Err)
		}
		for _, d := range f.Defects {
			clean = false
			fmt.Fprintf(w, "  DEFECT record %d at offset %d", d.Record, d.Offset)
			if d.Owner != "" {
				fmt.Fprintf(w, " (%s %s rdlength=%d)", d.Owner, d.Rrtype, d.Rdlength)
			}
			fmt.Fprintf(w, ": %s\n", d.Err)
		}
		if f.Trailing > 0 {
			clean = false
			fmt.Fprintf(w, "  TRAILING %d byte(s) the header does not account for:\n%s\n",
				f.Trailing, indentBlock(f.TrailingHex))
		}
		for _, h := range f.Hazards {
			fmt.Fprintf(w, "  HAZARD: %s\n", h)
		}
	}
	if clean {
		// Said every time, because this tool's silence is the least
		// trustworthy thing about it: it is miekg, the same library tdns packs
		// with, so it agrees with tdns by construction about anything tdns
		// invented. A strict parser can still refuse what this accepts.
		fmt.Fprintf(w, "\nEvery byte accounted for. Note this parser is miekg/dns and is more\n"+
			"permissive than some: a clean report is not proof that a strict client accepts\n"+
			"the stream. Any HAZARD lines above are exactly that gap.\n")
	}
}

func indentBlock(s string) string {
	var b strings.Builder
	for _, l := range strings.Split(s, "\n") {
		if l != "" {
			fmt.Fprintf(&b, "    %s\n", l)
		}
	}
	return strings.TrimRight(b.String(), "\n")
}
