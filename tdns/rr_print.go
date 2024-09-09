/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	// "github.com/gookit/goutil/dump"
)

// leftpad = amount of white space instead of the domain name on continuation lines during multiline output
func KeyRRPrint(rr dns.RR, rrtype, ktype string, keyid uint16, leftpad, rightmargin int) {
	if leftpad == 0 {
		leftpad = len(fmt.Sprintf("%s %d", rr.Header().Name, rr.Header().Ttl))
	}
	p := strings.Fields(rr.String())
	// rhp := strings.Fields(parts[1])
	namepad := strings.Repeat(" ", leftpad-len(p[0])-len(p[1]))
	if len(namepad) < 1 {
		namepad = " "
	}
	// name ttl class type keyid alg
	fmt.Printf("%s%s%s %s %s %s %s %s (\n", p[0], namepad, p[1], p[2], p[3], p[4], p[5], p[6])
	spaces := strings.Repeat(" ", leftpad)
	var keyparts []string
	keystr := p[7]
	for len(keystr) > rightmargin-len(spaces) {
		keyparts = append(keyparts, keystr[:rightmargin-len(spaces)])
		keystr = keystr[rightmargin-len(spaces):]
	}
	keyparts = append(keyparts, keystr)
	for idx, part := range keyparts {
		if idx == len(keyparts)-1 {
			fmt.Printf("%s %s )\n", spaces, part)
		} else {
			fmt.Printf("%s %s\n", spaces, part)
		}
	}
	alg, _ := strconv.Atoi(p[6])
	algstr := dns.AlgorithmToString[uint8(alg)]
	fmt.Printf("%s ; %s alg = %s ; key id = %d\n", spaces, ktype, algstr, keyid)
}

func RrsigRRPrint(rr dns.RR, leftpad, rightmargin int) {
	if leftpad == 0 {
		leftpad = len(fmt.Sprintf("%s %d", rr.Header().Name, rr.Header().Ttl))
	}
	p := strings.Fields(rr.String())
	// rhp := strings.Fields(p[1])
	namepad := strings.Repeat(" ", leftpad-len(p[0])-len(p[1]))
	if len(namepad) < 1 {
		namepad = " "
	}
	fmt.Printf("%s%s%s %s (\n", p[0], namepad, p[1], strings.Join(p[2:8], " "))
	// spaces := strings.Repeat(" ", len(parts[0])+1)
	spaces := strings.Repeat(" ", leftpad)
	fmt.Printf("%s %s %s %s %s\n", spaces, p[8], p[9], p[10], p[11])
	var rrsigparts []string
	part := p[12]
	for len(part) > rightmargin-len(spaces) {
		rrsigparts = append(rrsigparts, part[:rightmargin-len(spaces)])
		part = part[rightmargin-len(spaces):]
	}
	rrsigparts = append(rrsigparts, part)
	for idx, part := range rrsigparts {
		if idx == len(rrsigparts)-1 {
			fmt.Printf("%s %s )\n", spaces, part)
		} else {
			fmt.Printf("%s %s\n", spaces, part)
		}
	}
}

func SvcbRRPrint(rr dns.RR, leftpad, rightmargin int) {
	if leftpad == 0 {
		leftpad = len(fmt.Sprintf("%s %d", rr.Header().Name, rr.Header().Ttl))
	}
	p := strings.Fields(rr.String())
	namepad := strings.Repeat(" ", leftpad-len(p[0])-len(p[1]))
	if len(namepad) < 1 {
		namepad = " "
	}
	spaces := strings.Repeat(" ", leftpad)
	fmt.Printf("%s%s%s %s", p[0], namepad, p[1], strings.Join(p[2:6], " "))

	if len(p) > 6 {
		fmt.Printf(" (\n")
		fmt.Printf("%s %s )\n", spaces, strings.Join(p[6:], " "))
	} else {
		fmt.Printf("\n")
	}
}

func SoaRRPrint(rr dns.RR, leftpad, rightmargin int) {
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

func GenericRRPrint(rr dns.RR, leftpad, rightmargin int) {
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

	rightmargin := 78

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
				switch rr.(type) {
				case *dns.KEY:
					keyid := rr.(*dns.KEY).KeyTag()
					t := ""
					KeyRRPrint(rr, "KEY", t, keyid, leftpad, rightmargin)
				case *dns.DNSKEY:
					keyid := rr.(*dns.DNSKEY).KeyTag()
					t := " ZSK ;"
					if rr.(*dns.DNSKEY).Flags == 257 {
						t = " KSK ;"
					}
					KeyRRPrint(rr, "DNSKEY", t, keyid, leftpad, rightmargin)

				case *dns.RRSIG:
					RrsigRRPrint(rr, leftpad, rightmargin)

				case *dns.SVCB, *dns.PrivateRR:
					switch rr.Header().Rrtype {
					case TypeDELEG, dns.TypeSVCB:
						SvcbRRPrint(rr, leftpad, rightmargin)

					default:
						// fmt.Printf("This is a %s RR\n", dns.TypeToString[rr.Header().Rrtype])
						// This is most likely a DSYNC
						p := strings.Fields(rr.String())
						namepad := strings.Repeat(" ", leftpad-len(p[0])-len(p[1]))
						fmt.Printf("%s%s%s\n", p[0], namepad, strings.Join(p[1:], " "))
					}

				case *dns.SOA:
					SoaRRPrint(rr, leftpad, rightmargin)

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

	fmt.Printf("\n;; QUESTION SECTION:\n")
	for _, rr := range m.Question {
		fmt.Printf("%s\n", rr.String())
	}
	fmt.Printf("\n;; ANSWER SECTION:\n")
	for _, rr := range m.Answer {
		PrintRR(rr, leftpad, options)
	}
	fmt.Printf("\n;; AUTHORITY SECTION:\n")
	for _, rr := range m.Ns {
		PrintRR(rr, leftpad, options)
	}
	fmt.Printf("\n;; ADDITIONAL SECTION:\n")
	for _, rr := range m.Extra {
		PrintRR(rr, leftpad, options)
	}

	transport := "UDP"
	if options["tcp"] == "true" {
		transport = "TCP"
	}
	fmt.Printf("\n;; Query time: %d msec\n", elapsed.Milliseconds())
	fmt.Printf(";; SERVER: %s (%s)\n", server, transport)
	fmt.Printf(";; WHEN: %s\n", time.Now().Format(time.RFC3339))

	buf, err := m.Pack()
	if err != nil {
		fmt.Printf(";; ERROR: %s\n", err)
	}
	fmt.Printf(";; MSG SIZE rcvd: %d\n", len(buf))
}

func PrintRR(rr dns.RR, leftpad int, options map[string]string) {
	if !(options["multi"] == "true") {
		fmt.Printf("%s\n", rr.String())
		return
	}

	switch rr.(type) {
	case *dns.SOA:
		SoaRRPrint(rr, leftpad, 78)
	case *dns.DNSKEY:
		t := " ZSK ;"
		if rr.(*dns.DNSKEY).Flags&0x0001 == 1 {
			t = " KSK ;"
		}
		KeyRRPrint(rr, "DNSKEY", t, rr.(*dns.DNSKEY).KeyTag(), leftpad, 78)
	case *dns.KEY:
		KeyRRPrint(rr, "KEY", "", rr.(*dns.KEY).KeyTag(), leftpad, 78)
	case *dns.RRSIG:
		RrsigRRPrint(rr, leftpad, 78)
	case *dns.SVCB:
		SvcbRRPrint(rr, leftpad, 78)
	default:
		GenericRRPrint(rr, leftpad, 78)
	}
}
