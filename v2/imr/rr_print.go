/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package imr

import (
	"fmt"

	"github.com/miekg/dns"
	// "github.com/gookit/goutil/dump"
)

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
