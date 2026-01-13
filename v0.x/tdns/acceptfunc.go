/*
 * This is a slightly modified version of the accept function in Miek's DNS library. TDNS
 * needs to be able to receive DNS UPDATE messages, which are not handled by the default
 * accept function in the DNS library.
 */

package tdns

import (
	"log"

	"github.com/miekg/dns"
)

// MsgAcceptFunc is used early in the server code to accept or reject a message with RcodeFormatError.
// It returns a MsgAcceptAction to indicate what should happen with the message.
// type MsgAcceptFunc func(dh Header) MsgAcceptAction

// DefaultMsgAcceptFunc checks the request and will reject if:
//
// * isn't a request (don't respond in that case)
//
// * opcode isn't OpcodeQuery or OpcodeNotify
//
// * does not have exactly 1 question in the question section
//
// * has more than 1 RR in the Answer section
//
// * has more than 0 RRs in the Authority section
//
// * has more than 2 RRs in the Additional section
// var DefaultMsgAcceptFunc MsgAcceptFunc = defaultMsgAcceptFunc

// func init() {
//      dns.MsgAcceptFunc = TdnsMsgAcceptFunc
// }

// MsgAcceptAction represents the action to be taken.
// type MsgAcceptAction int

// Allowed returned values from a MsgAcceptFunc.
const (
	MsgAccept               dns.MsgAcceptAction = iota // Accept the message
	MsgReject                                          // Reject the message with a RcodeFormatError
	MsgIgnore                                          // Ignore the error and send nothing back.
	MsgRejectNotImplemented                            // Reject the message with a RcodeNotImplemented
)

const (
	// Header.Bits
	_QR = 1 << 15 // query/response (response=1)
	_AA = 1 << 10 // authoritative
	_TC = 1 << 9  // truncated
	_RD = 1 << 8  // recursion desired
	_RA = 1 << 7  // recursion available
	_Z  = 1 << 6  // Z
	_AD = 1 << 5  // authenticated data
	_CD = 1 << 4  // checking disabled
)

func MsgAcceptFunc(dh dns.Header) dns.MsgAcceptAction {
	if isResponse := dh.Bits&_QR != 0; isResponse {
		return MsgIgnore
	}

	// Don't allow dynamic updates, because then the sections can contain a whole bunch of RRs.
	opcode := int(dh.Bits>>11) & 0xF
	if opcode != dns.OpcodeQuery && opcode != dns.OpcodeNotify && opcode != dns.OpcodeUpdate {
		log.Printf("TDNS: NOTIMP: %d (%s)", opcode, dns.OpcodeToString[opcode])
		return MsgRejectNotImplemented
	}

	if dh.Qdcount != 1 {
		log.Printf("TDNS: dh.Qdcount != 1")
		return MsgReject
	}
	// NOTIFY requests can have a SOA in the ANSWER section. See RFC 1996 Section 3.7 and 3.11.
	if dh.Ancount > 1 && opcode != dns.OpcodeUpdate {
		log.Printf("TDNS: dh.Ancount > 1")
		return MsgReject
	}
	// IXFR request could have one SOA RR in the NS section. See RFC 1995, section 3.
	if dh.Nscount > 1 && opcode != dns.OpcodeUpdate {
		log.Printf("TDNS: dh.Nscount > 1")
		return MsgReject
	}
	if dh.Arcount > 2 && opcode != dns.OpcodeUpdate {
		log.Printf("TDNS: dh.Arcount > 2")
		return MsgReject
	}
	return MsgAccept
}
