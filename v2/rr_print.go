/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
	// "github.com/gookit/goutil/dump"
)

func printFieldsWithWrap(initial string, fields []string, leftpad, rightmargin int, closing string) {
	spaces := strings.Repeat(" ", leftpad)
	current := initial
	if strings.TrimSpace(current) == "" {
		current = spaces
	}

	appendField := func(field string) {
		if len(field) == 0 {
			return
		}
		trimmed := strings.TrimSpace(current)
		sep := " "
		if trimmed == "" || strings.HasSuffix(strings.TrimRight(current, " "), "(") {
			sep = ""
		}
		if len(current)+len(sep)+len(field) > rightmargin && trimmed != "" {
			fmt.Printf("%s\n", strings.TrimRight(current, " "))
			current = spaces + field
		} else {
			if sep == "" && trimmed != "" {
				current += " " + field
			} else if trimmed == "" {
				current = spaces + field
			} else {
				if sep == "" {
					current += field
				} else {
					current += sep + field
				}
			}
		}
	}

	for _, field := range fields {
		appendField(field)
	}

	if closing != "" {
		if len(current)+len(closing) > rightmargin {
			fmt.Printf("%s\n", strings.TrimRight(current, " "))
			current = spaces + strings.TrimSpace(closing)
		} else {
			current += closing
		}
	}

	fmt.Printf("%s\n", strings.TrimRight(current, " "))
}

func chunkString(s string, width int) []string {
	if width <= 0 || len(s) <= width {
		return []string{s}
	}
	var parts []string
	for len(s) > width {
		parts = append(parts, s[:width])
		s = s[width:]
	}
	if len(s) > 0 {
		parts = append(parts, s)
	}
	return parts
}

// leftpad = amount of white space instead of the domain name on continuation lines during multiline output
func PrintKeyRR(rr dns.RR, rrtype, ktype string, keyid uint16, leftpad, rightmargin int) {
	if leftpad == 0 {
		leftpad = len(fmt.Sprintf("%s %d", rr.Header().Name, rr.Header().Ttl))
	}
	p := strings.Fields(rr.String())
	// rhp := strings.Fields(parts[1])
	namepad := strings.Repeat(" ", leftpad-len(p[0])-len(p[1]))
	if len(namepad) < 1 {
		namepad = " "
	}
	// name ttl class type flags protocol alg
	initial := fmt.Sprintf("%s%s%s %s", p[0], namepad, p[1], p[2])
	fields := []string{p[3], p[4], p[5], p[6]}

	sigWidth := rightmargin - leftpad - 1
	if sigWidth < 10 {
		sigWidth = rightmargin - leftpad
	}
	keyparts := chunkString(p[7], sigWidth)

	fields = append(fields, "(")
	fields = append(fields, keyparts...)
	alg, _ := strconv.Atoi(p[6])
	algstr := dns.AlgorithmToString[uint8(alg)]
	commentStr := fmt.Sprintf("; %s alg = %s ; key id = %d", ktype, algstr, keyid)
	closing := " ) " + commentStr
	printFieldsWithWrap(initial, fields, leftpad+1, rightmargin, closing)
}

func PrintDsRR(rr dns.RR, leftpad, rightmargin int) {
	if leftpad == 0 {
		leftpad = len(fmt.Sprintf("%s %d", rr.Header().Name, rr.Header().Ttl))
	}
	p := strings.Fields(rr.String())
	if len(p) < 8 {
		fmt.Printf("%s\n", rr.String())
		return
	}
	namepad := strings.Repeat(" ", leftpad-len(p[0])-len(p[1]))
	if len(namepad) < 1 {
		namepad = " "
	}

	initial := fmt.Sprintf("%s%s%s %s %s %s", p[0], namepad, p[1], p[2], p[3], p[4])
	fields := []string{p[5], p[6]}

	sigWidth := rightmargin - leftpad - 1
	if sigWidth < 10 {
		sigWidth = rightmargin - leftpad
	}
	digestParts := chunkString(p[7], sigWidth)
	fields = append(fields, "(")
	fields = append(fields, digestParts...)

	printFieldsWithWrap(initial, fields, leftpad+1, rightmargin, " )")
}

func PrintRrsigRR(rr dns.RR, leftpad, rightmargin int) {
	if leftpad == 0 {
		leftpad = len(fmt.Sprintf("%s %d", rr.Header().Name, rr.Header().Ttl))
	}
	p := strings.Fields(rr.String())
	// rhp := strings.Fields(p[1])
	namepad := strings.Repeat(" ", leftpad-len(p[0])-len(p[1]))
	if len(namepad) < 1 {
		namepad = " "
	}
	if len(p) < 13 {
		fmt.Printf("%s%s%s %s\n", p[0], namepad, p[1], strings.Join(p[2:], " "))
		return
	}

	initial := fmt.Sprintf("%s%s%s %s", p[0], namepad, p[1], p[2])
	headerAndMiddle := append([]string{}, p[3:12]...)
	printFieldsWithWrap(initial, headerAndMiddle, leftpad+1, rightmargin, " (")

	spaces := strings.Repeat(" ", leftpad)

	sigWidth := rightmargin - leftpad - 1
	if sigWidth < 10 {
		sigWidth = rightmargin - leftpad
	}
	sigParts := chunkString(p[12], sigWidth)
	printFieldsWithWrap(spaces, sigParts, leftpad+1, rightmargin, " )")
}

func PrintJwkRR(rr dns.RR, leftpad, rightmargin int) {
	if leftpad == 0 {
		leftpad = len(fmt.Sprintf("%s %d", rr.Header().Name, rr.Header().Ttl))
	}
	p := strings.Fields(rr.String())
	if len(p) < 5 {
		PrintGenericRR(rr, leftpad, rightmargin)
		return
	}
	namepad := strings.Repeat(" ", leftpad-len(p[0])-len(p[1]))
	if len(namepad) < 1 {
		namepad = " "
	}
	// First line: name ttl IN JWK (, then fold the long quoted RDATA on continuation lines, then )
	initial := fmt.Sprintf("%s%s%s %s %s (", p[0], namepad, p[1], p[2], p[3])
	sigWidth := rightmargin - leftpad - 1
	if sigWidth < 10 {
		sigWidth = rightmargin - leftpad
	}
	jwkParts := chunkString(p[4], sigWidth)
	printFieldsWithWrap(initial, jwkParts, leftpad+1, rightmargin, " )")
}

func PrintSvcbRR(rr dns.RR, leftpad, rightmargin int) {
	if leftpad == 0 {
		leftpad = len(fmt.Sprintf("%s %d", rr.Header().Name, rr.Header().Ttl))
	}
	p := strings.Fields(rr.String())
	namepad := strings.Repeat(" ", leftpad-len(p[0])-len(p[1]))
	if len(namepad) < 1 {
		namepad = " "
	}
	// spaces := strings.Repeat(" ", leftpad)
	if len(p) < 6 {
		fmt.Printf("%s", rr.String())
		return
	}
	line := fmt.Sprintf("%s%s%s %s", p[0], namepad, p[1], strings.Join(p[2:6], " "))

	if len(p) == 6 {
		fmt.Printf("%s\n", line)
		return
	}

	// Print line, then subsequent fields, wrapping at rightmargin
	//fmt.Printf("%s (\n", line)
	fields := p[6:]
	printFieldsWithWrap(line+" (", fields, leftpad+1, rightmargin, " )")
}

func PrintSoaRR(rr dns.RR, leftpad, rightmargin int) {
	if leftpad == 0 {
		leftpad = len(fmt.Sprintf("%s %d", rr.Header().Name, rr.Header().Ttl))
	}
	p := strings.Fields(rr.String())
	// rhp := strings.Fields(p[1])
	namepad := strings.Repeat(" ", leftpad-len(p[0])-len(p[1]))
	if len(namepad) < 1 {
		namepad = " "
	}
	spaces := strings.Repeat(" ", leftpad)
	fmt.Printf("%s%s%s %s (\n", p[0], namepad, p[1], strings.Join(p[2:6], " "))
	fmt.Printf("%s %s%s ; SOA serial\n", spaces, p[6], strings.Repeat(" ", 10-len(p[6])))
	fmt.Printf("%s %s%s ; Refresh\n", spaces, p[7], strings.Repeat(" ", 10-len(p[7])))
	fmt.Printf("%s %s%s ; Retry\n", spaces, p[8], strings.Repeat(" ", 10-len(p[8])))
	fmt.Printf("%s %s%s ; Expire\n", spaces, p[9], strings.Repeat(" ", 10-len(p[9])))
	fmt.Printf("%s %s )%s ; Ncache TTL\n", spaces, p[10], strings.Repeat(" ", 10-len(p[10])-2))

}

func PrintGenericRR(rr dns.RR, leftpad, rightmargin int) {
	// fmt.Printf("%s\n", rr.String())
	p := strings.Fields(rr.String())
	namepad := strings.Repeat(" ", leftpad-len(p[0])-len(p[1]))
	if len(namepad) < 1 {
		namepad = " "
	}
	fmt.Printf("%s%s%s\n", p[0], namepad, strings.Join(p[1:], " "))
}

func ZoneTransferPrint(zname, upstream string, serial uint32, ttype uint16, options map[string]string) error {
	msg := new(dns.Msg)
	if ttype == dns.TypeIXFR {
		// msg.SetIxfr(zname, serial, soa.Ns, soa.Mbox)
		msg.SetIxfr(zname, serial, "", "")
	} else {
		msg.SetAxfr(zname)
	}

	var err error
	rightmargin := 78
	if options["width"] != "" {
		width, err := strconv.Atoi(options["width"])
		if err != nil {
			fmt.Printf("Error from strconv.Atoi: %v\n", err)
			return err
		}
		rightmargin = width - 2
	}

	transfer := new(dns.Transfer)
	answerChan, err := transfer.In(msg, upstream)
	if err != nil {
		fmt.Printf("Error from transfer.In: %v\n", err)
		return err
	}

	for envelope := range answerChan {
		leftpad := 20
		if envelope.Error != nil {
			fmt.Printf("Oops. Zone transfer envelope signals an error:\n")
			errstr := envelope.Error.Error()
			if strings.Contains(errstr, "bad xfr rcode: 9") {
				fmt.Printf("Error: %s: Not authoritative for zone %s\n",
					upstream, zname)
			} else {
				fmt.Printf("Error: zone %s error: %v\n", zname, errstr)
			}
			if !Globals.Debug {
				fmt.Printf("Xfr error: breaking off\n")
				break
			} else {
				fmt.Printf("DEBUG: envelope: %v\n", envelope)
			}
		}

		if Globals.Debug {
			fmt.Printf("Printing %d RRs in envelope\n", len(envelope.RR))
		}

		for _, rr := range envelope.RR {
			tmp := fmt.Sprintf("%s %d", rr.Header().Name, rr.Header().Ttl)
			if len(tmp) > leftpad {
				leftpad = len(tmp)
			}
		}

		fmt.Printf("Using leftpad = %d\n", leftpad)

		for _, rr := range envelope.RR {
			if options["multi"] == "true" {
				switch rr := rr.(type) {
				case *dns.KEY:
					keyid := rr.KeyTag()
					t := ""
					PrintKeyRR(rr, "KEY", t, keyid, leftpad, rightmargin)
				case *dns.DNSKEY:
					keyid := rr.KeyTag()
					t := " ZSK ;"
					if rr.Flags&0x0001 != 0 {
						t = " KSK ;"
					}
					PrintKeyRR(rr, "DNSKEY", t, keyid, leftpad, rightmargin)
				case *dns.CDNSKEY:
					keyid := rr.KeyTag()
					t := " CDNSKEY ;"
					PrintKeyRR(rr, "CDNSKEY", t, keyid, leftpad, rightmargin)

				case *dns.RRSIG:
					PrintRrsigRR(rr, leftpad, rightmargin)

				case *dns.SVCB, *dns.PrivateRR:
					switch rr.Header().Rrtype {
					case core.TypeDELEG, dns.TypeSVCB:
						PrintSvcbRR(rr, leftpad, rightmargin)
					case core.TypeJWK:
						PrintJwkRR(rr, leftpad, rightmargin)

					default:
						// fmt.Printf("This is a %s RR\n", dns.TypeToString[rr.Header().Rrtype])
						// This is most likely a DSYNC
						p := strings.Fields(rr.String())
						namepad := strings.Repeat(" ", leftpad-len(p[0])-len(p[1]))
						fmt.Printf("%s%s%s\n", p[0], namepad, strings.Join(p[1:], " "))
					}

				case *dns.SOA:
					PrintSoaRR(rr, leftpad, rightmargin)

				default:
					p := strings.Fields(rr.String())
					namepad := strings.Repeat(" ", leftpad-len(p[0])-len(p[1]))
					// fmt.Printf("len(qname)=%d, len(ttl)=%d, namepad=%d\n", len(p[0]), len(p[1]), len(namepad))
					fmt.Printf("%s%s%s\n", p[0], namepad, strings.Join(p[1:], " "))
				}
			} else {
				fmt.Printf("%s\n", rr.String())
			}
		}
		if Globals.Debug {
			fmt.Printf("Done printing %d RRs in envelope\n", len(envelope.RR))
		}
	}
	return nil
}

func MsgPrint(m *dns.Msg, server string, elapsed time.Duration, short bool, options map[string]string) {
	if short {
		for _, rr := range m.Answer {
			fmt.Printf("%s\n", rr.String())
		}
		return
	}

	flags := ""

	if m.MsgHdr.Response {
		flags += " qr"
	}
	if m.MsgHdr.Authoritative {
		flags += " aa"
	}
	if m.MsgHdr.RecursionDesired {
		flags += " rd"
	}
	if m.MsgHdr.RecursionAvailable {
		flags += " ra"
	}
	if m.MsgHdr.AuthenticatedData {
		flags += " ad"
	}
	if m.MsgHdr.CheckingDisabled {
		flags += " cd"
	}
	if m.MsgHdr.Truncated {
		flags += " tc"
	}

	fmt.Printf(";; opcode: %s, status: %s, id: %d\n", dns.OpcodeToString[m.Opcode], dns.RcodeToString[m.Rcode], m.Id)
	fmt.Printf(";; flags:%s; QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d\n",
		flags, len(m.Question), len(m.Answer), len(m.Ns), len(m.Extra))

	leftpad := 0
	for _, sec := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range sec {
			tmp := fmt.Sprintf("%s %d", rr.Header().Name, rr.Header().Ttl)
			if len(tmp) > leftpad {
				leftpad = len(tmp)
			}
		}
	}
	for _, rr := range m.Extra {
		switch rr := rr.(type) {
		case *dns.OPT:
			// Extract and display EDNS0 flags
			flags := []string{}
			if rr.Do() {
				flags = append(flags, "do")
			}
			if (rr.Hdr.Ttl & (1 << 14)) != 0 {
				flags = append(flags, "co")
			}
			if (rr.Hdr.Ttl & (1 << 13)) != 0 {
				// Bit 13 is DE (Delegation Extension)
				flags = append(flags, "de")
			}
			if (rr.Hdr.Ttl & (1 << 12)) != 0 {
				// Bit 12 is PR (Privacy Requested)
				flags = append(flags, "pr")
			}
			flagsStr := ""
			if len(flags) > 0 {
				flagsStr = " " + strings.Join(flags, " ")
			}
			fmt.Printf(";; EDNS: version: %d, flags:%s; udp: %d\n", rr.Version(), flagsStr, rr.UDPSize())
			for _, option := range rr.Option {
				// Format EDE options specially to avoid duplicate text from miekg/dns library
				if ede, ok := option.(*dns.EDNS0_EDE); ok {
					edeText := ede.ExtraText
					if edeText == "" {
						// Try to get text from our mapping or miekg/dns mapping
						if s, ok := edns0.EDECodeToString[ede.InfoCode]; ok {
							edeText = s
						} else if s, ok := dns.ExtendedErrorCodeToString[ede.InfoCode]; ok {
							edeText = s
						} else {
							edeText = fmt.Sprintf("Unknown EDE code: %d", ede.InfoCode)
						}
					}
					fmt.Printf(";; EDNS: option: %d (%s)\n", ede.InfoCode, edeText)
				} else {
					fmt.Printf(";; EDNS: option: %s\n", option.String())
				}
			}
		}
	}

	var err error
	fmt.Printf("\n;; QUESTION SECTION:\n")
	for _, rr := range m.Question {
		fmt.Printf("%s\n", rr.String())
	}
	fmt.Printf("\n;; ANSWER SECTION:\n")
	for _, rr := range m.Answer {
		if err = PrintRR(rr, leftpad, options); err != nil {
			fmt.Printf("Error from PrintRR: %v\n", err)
		}
	}
	fmt.Printf("\n;; AUTHORITY SECTION:\n")
	for _, rr := range m.Ns {
		if err = PrintRR(rr, leftpad, options); err != nil {
			fmt.Printf("Error from PrintRR: %v\n", err)
		}
	}
	fmt.Printf("\n;; ADDITIONAL SECTION:\n")
	for _, rr := range m.Extra {
		// Skip OPT RR - we already printed it above with custom format
		if _, ok := rr.(*dns.OPT); ok {
			continue
		}
		if err = PrintRR(rr, leftpad, options); err != nil {
			fmt.Printf("Error from PrintRR: %v\n", err)
		}
	}

	transport := "UDP"
	switch options["transport"] {
	case "tcp", "Do53-TCP":
		transport = "TCP"
	case "dot", "DoT":
		transport = "DoT"
	case "doh", "DoH":
		transport = "DoH"
		server = fmt.Sprintf("https://%s/dns-query", server)
	case "doq", "DoQ":
		transport = "DoQ"
	}

	fmt.Printf("\n;; Query time: %d msec\n", elapsed.Milliseconds())
	fmt.Printf(";; SERVER: %s (%s)\n", server, transport)
	fmt.Printf(";; WHEN: %s\n", time.Now().Format(TimeLayout))

	buf, err := m.Pack()
	if err != nil {
		fmt.Printf(";; ERROR: %s\n", err)
	}
	fmt.Printf(";; MSG SIZE rcvd: %d\n", len(buf))
}

func PrintRR(rr dns.RR, leftpad int, options map[string]string) error {
	if !(options["multi"] == "true") {
		fmt.Printf("%s\n", rr.String())
		return nil
	}

	rightmargin := 78
	if options["width"] != "" {
		width, err := strconv.Atoi(options["width"])
		if err != nil {
			fmt.Printf("Error from strconv.Atoi: %v\n", err)
			return err
		}
		rightmargin = width - 2
	}

	switch rr := rr.(type) {
	case *dns.SOA:
		PrintSoaRR(rr, leftpad, rightmargin)
	case *dns.DNSKEY:
		t := " ZSK ;"
		if rr.Flags&0x0001 == 1 {
			t = " KSK ;"
		}
		PrintKeyRR(rr, "DNSKEY", t, rr.KeyTag(), leftpad, rightmargin)
	case *dns.KEY:
		PrintKeyRR(rr, "KEY", " KEY ;", rr.KeyTag(), leftpad, rightmargin)
	case *dns.CDNSKEY:
		PrintKeyRR(rr, "CDNSKEY", " CDNSKEY ;", rr.KeyTag(), leftpad, rightmargin)
	case *dns.DS:
		PrintDsRR(rr, leftpad, rightmargin)
	case *dns.RRSIG:
		PrintRrsigRR(rr, leftpad, rightmargin)
	case *dns.SVCB:
		PrintSvcbRR(rr, leftpad, rightmargin)
	case *dns.PrivateRR:
		if rr.Header().Rrtype == core.TypeJWK {
			PrintJwkRR(rr, leftpad, rightmargin)
		} else {
			PrintGenericRR(rr, leftpad, rightmargin)
		}
	default:
		PrintGenericRR(rr, leftpad, rightmargin)
	}
	return nil
}

func PrintMsgSection(header string, section []dns.RR, width int) string {
	out := fmt.Sprintf("%s:\n", header)
	for _, rr := range section {
		line := fmt.Sprintf("%s\n", rr.String())
		if len(line) > width {
			line = line[:width-4] + "...\n"
		}
		out += line
	}
	return out
}

func PrintMsgFull(m *dns.Msg, width int) string {
	out := fmt.Sprintf(";; MSG ID: %d\n", m.MsgHdr.Id)
	// out += fmt.Sprintf("Question:\n%s", m.Question.String())
	out += PrintMsgSection("Answer", m.Answer, width)
	out += PrintMsgSection("Authority", m.Ns, width)
	out += PrintMsgSection("Additional", m.Extra, width)
	return out
}
