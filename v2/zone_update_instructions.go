/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"unicode"

	"github.com/miekg/dns"
)

// The update-instruction format: a zone change written as a list of
// operations rather than as a zone.
//
//	; tdns update instructions
//	; zone: dnslab.
//	ADD ns2.romeo.dnslab. 3600 IN A 172.16.91.18
//	DEL ns.romeo.dnslab. IN A 172.16.91.17
//
// It is deliberately BOTH an output and an input format. The journal CLI
// emits it (`journal list --instructions`, and the artefact `journal purge`
// writes before discarding anything), and `zone update from-file` reads it
// back. That symmetry is the point: an operator can take what the server
// produced, open it in an editor, delete the lines they agree with, keep the
// ones they do not, and replay what is left. A format that could only be
// printed would make that a retyping exercise.
//
// Being hand-edited is what sets the requirements below -- comments and blank
// lines tolerated everywhere, and parse errors that name a line number.

// Instruction keywords as they appear in the file. Case-insensitive on input,
// upper-case on output, matching the convention of RFC 2136 tooling and of
// `dig`'s update output.
const (
	InstrAdd = "ADD"
	InstrDel = "DEL"
)

// WriteUpdateInstructions renders insns to w, preceded by comment lines.
//
// Instructions are ZoneDeltaRR values -- the same type the journal stores --
// rather than a parallel type that would have to be kept in step with it. The
// journal IS a list of adds and deletes; this is that list, written down.
func WriteUpdateInstructions(w io.Writer, comments []string, insns []ZoneDeltaRR) error {
	bw := bufio.NewWriter(w)

	for _, c := range comments {
		if _, err := fmt.Fprintf(bw, "; %s\n", c); err != nil {
			return err
		}
	}
	if len(comments) > 0 {
		if _, err := fmt.Fprintln(bw); err != nil {
			return err
		}
	}

	for _, insn := range insns {
		kw := InstrAdd
		if insn.Action == ZoneDeltaDel {
			kw = InstrDel
		}
		if _, err := fmt.Fprintf(bw, "%s %s\n", kw, insn.RR); err != nil {
			return err
		}
	}
	return bw.Flush()
}

// ParseUpdateInstructions reads the format back.
//
// Errors name the line number and quote the offending text. That is not
// politeness: this file is meant to be edited by hand, under time pressure,
// after something has already gone wrong, and "invalid instruction file" sends
// an operator hunting through a hundred lines for the one they broke.
func ParseUpdateInstructions(r io.Reader) ([]ZoneDeltaRR, error) {
	var out []ZoneDeltaRR

	sc := bufio.NewScanner(r)
	// Zone records are short, but a long TXT or a large PQ DNSKEY is not, and
	// the default 64k token limit would turn one into a truncation rather than
	// an error. Match the generosity of the zone parser.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" {
			continue
		}
		// A comment is a line whose FIRST non-space character introduces one.
		// Trailing comments are deliberately not stripped: ';' is legal inside
		// a quoted TXT rdata, and a stripper naive enough to be useful here
		// would silently truncate such a record into a different one.
		if text[0] == ';' || text[0] == '#' {
			continue
		}

		// Split on the first run of whitespace, not on a literal space. Records
		// render with TABS -- rr.String() produces them, so every line this
		// program writes and every line pasted out of a zone file has them --
		// and a space-only split turns "ADD<tab>foo. IN A 1.2.3.4" into "not an
		// instruction", naming the wrong mistake in a file whose whole purpose
		// is to be edited by hand.
		sep := strings.IndexFunc(text, unicode.IsSpace)
		if sep < 0 {
			return nil, fmt.Errorf("line %d: %q is not an instruction"+
				" (expected %s or %s followed by a resource record)", line, text, InstrAdd, InstrDel)
		}
		kw, rest := text[:sep], text[sep:]

		var action string
		switch strings.ToUpper(strings.TrimSpace(kw)) {
		case InstrAdd:
			action = ZoneDeltaAdd
		case InstrDel:
			action = ZoneDeltaDel
		default:
			return nil, fmt.Errorf("line %d: unknown instruction %q (expected %s or %s)",
				line, kw, InstrAdd, InstrDel)
		}

		rest = strings.TrimSpace(rest)
		if rest == "" {
			return nil, fmt.Errorf("line %d: %s with no resource record", line, strings.ToUpper(kw))
		}

		// Validate here, so the operator learns which LINE is wrong. The server
		// parses these again when it builds the update -- validation belongs
		// where it is authoritative -- but by then the line numbers are gone.
		rr, err := dns.NewRR(rest)
		if err != nil {
			return nil, fmt.Errorf("line %d: cannot parse %q: %v", line, rest, err)
		}
		if rr == nil {
			return nil, fmt.Errorf("line %d: %q is not a resource record", line, rest)
		}

		// Store the record as the parser rendered it, not as it was typed:
		// downstream comparisons are textual, and two spellings of one record
		// must not become two records.
		out = append(out, ZoneDeltaRR{Action: action, RR: rr.String()})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading instructions: %v", err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no instructions found (the file is empty, or holds only comments)")
	}
	return out, nil
}

// instructionActions turns adds and deletes into RFC 2136 update-section
// records. ctx names the source for error messages ("delta 4->5", "line 12").
//
// EVERY delete becomes a per-record CLASS=NONE delete; nothing here emits
// CLASS=ANY. A deleted RRset is carried as one instruction per record, and
// deleting them individually reaches the same end state.
func instructionActions(insns []ZoneDeltaRR, ctx string) ([]dns.RR, error) {
	var actions []dns.RR
	for _, insn := range insns {
		rr, err := dns.NewRR(insn.RR)
		if err != nil {
			return nil, fmt.Errorf("%s: cannot parse %q: %v", ctx, insn.RR, err)
		}
		if rr == nil {
			return nil, fmt.Errorf("%s: %q is not a resource record", ctx, insn.RR)
		}
		switch insn.Action {
		case ZoneDeltaDel:
			rr.Header().Class = dns.ClassNONE
			rr.Header().Ttl = 0
		case ZoneDeltaAdd:
			rr.Header().Class = dns.ClassINET
		default:
			return nil, fmt.Errorf("%s: unknown action %q", ctx, insn.Action)
		}
		actions = append(actions, rr)
	}
	return actions, nil
}

// UpdateInstructionActions is instructionActions for instructions that came
// from a file rather than from the journal.
func UpdateInstructionActions(insns []ZoneDeltaRR) ([]dns.RR, error) {
	return instructionActions(insns, "instructions")
}
