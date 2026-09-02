/*
 * Copyright (c) 2025 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package edns0

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// The PRIVACY EDNS(0) option replaces the PR ("Privacy Requested") flag bit
// that used to live at bit 12 of the OPT header TTL. Flag bits are a scarce,
// shared resource and each one can only ever say yes or no; an option code is
// cheap and carries a payload, so the signal can grow without needing another
// bit.
//
// The payload is exactly one octet. Its meaning depends on the direction of
// travel, because the two directions are answering different questions:
//
//   - In a QUERY the octet is a PrivacyLevel: what the client WANTS.
//   - In a RESPONSE the octet is a PrivacyStatus: what the resolver DID.
//
// Both directions use the same option code. A receiver always knows which
// direction it is looking at (dns.Msg.Response), so there is no ambiguity on
// the wire, and keeping one code avoids burning a second one on what is the
// same conversation.

// PrivacyLevel is the query-direction payload: how much the client cares about
// the transport its data is carried over between the resolver and the
// authoritative servers.
type PrivacyLevel uint8

const (
	// PrivacyNone is the absence of an opinion. Sending the option with this
	// value is legal and means exactly what sending no option at all means;
	// it exists so a client can say "I know about this option, and I am not
	// asking for anything" without special-casing its own message builder.
	PrivacyNone PrivacyLevel = 0

	// PrivacyOpportunistic asks the resolver to prefer an encrypted transport
	// but accepts cleartext when no encrypted transport is available.
	// Availability wins over privacy.
	PrivacyOpportunistic PrivacyLevel = 1

	// PrivacyStrict forbids the fallback: if the data cannot be fetched over
	// an encrypted transport the resolver must fail the query rather than
	// leak it in cleartext.
	PrivacyStrict PrivacyLevel = 2
)

func (l PrivacyLevel) String() string {
	switch l {
	case PrivacyNone:
		return "none"
	case PrivacyOpportunistic:
		return "opportunistic"
	case PrivacyStrict:
		return "strict"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(l))
	}
}

// ParsePrivacyLevel accepts either the numeric payload value or the name, in
// any case. It is the parser behind dog's "+PR=..." argument.
func ParsePrivacyLevel(s string) (PrivacyLevel, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "0", "none", "no", "off":
		return PrivacyNone, nil
	case "1", "opportunistic", "opp":
		return PrivacyOpportunistic, nil
	case "2", "strict":
		return PrivacyStrict, nil
	default:
		return PrivacyNone, fmt.Errorf("unknown privacy level %q (want none|opportunistic|strict, or 0|1|2)", s)
	}
}

// PrivacyStatus is the response-direction payload: what the resolver actually
// did to get the data it is returning.
type PrivacyStatus uint8

const (
	// PrivacyCleartext: the answer was fetched over an unencrypted transport.
	PrivacyCleartext PrivacyStatus = 0

	// PrivacyEncrypted: the answer was fetched over an encrypted transport.
	PrivacyEncrypted PrivacyStatus = 1

	// PrivacyCached: the answer came out of the resolver's cache, and the
	// resolver is not asserting anything about the transport the data
	// originally arrived over. This is deliberately its own value rather than
	// being folded into cleartext or encrypted: a cache entry records the
	// transport of the exchange that filled it, but the data may have been
	// assembled, revalidated or refreshed over other paths since, so the
	// honest answer to "was this private?" is "it came from cache".
	PrivacyCached PrivacyStatus = 2
)

func (s PrivacyStatus) String() string {
	switch s {
	case PrivacyCleartext:
		return "cleartext"
	case PrivacyEncrypted:
		return "encrypted"
	case PrivacyCached:
		return "from cache"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(s))
	}
}

// AddPrivacyOption appends the PRIVACY option, carrying the single payload
// octet, to an existing OPT RR. Any PRIVACY option already on the OPT is
// removed first: two of them would be a contradiction the receiver has no way
// to resolve.
func AddPrivacyOption(opt *dns.OPT, payload uint8) error {
	if opt == nil {
		return fmt.Errorf("OPT RR is nil")
	}
	RemovePrivacyOption(opt)
	opt.Option = append(opt.Option, &dns.EDNS0_LOCAL{
		Code: EDNS0_PRIVACY_OPTION_CODE,
		Data: []byte{payload},
	})
	return nil
}

// AddPrivacyLevelToMessage attaches the query-direction signal to msg,
// creating an OPT RR if the message does not already have one.
func AddPrivacyLevelToMessage(msg *dns.Msg, level PrivacyLevel) error {
	return addPrivacyToMessage(msg, uint8(level))
}

// AddPrivacyStatusToMessage attaches the response-direction signal to msg,
// creating an OPT RR if the message does not already have one.
func AddPrivacyStatusToMessage(msg *dns.Msg, status PrivacyStatus) error {
	return addPrivacyToMessage(msg, uint8(status))
}

func addPrivacyToMessage(msg *dns.Msg, payload uint8) error {
	if msg == nil {
		return fmt.Errorf("message is nil")
	}
	opt := msg.IsEdns0()
	if opt == nil {
		msg.SetEdns0(4096, false)
		opt = msg.IsEdns0()
	}
	return AddPrivacyOption(opt, payload)
}

// ExtractPrivacyPayload returns the raw payload octet of the PRIVACY option on
// opt, and whether a well-formed one was present.
//
// A PRIVACY option whose OPTION-LENGTH is not exactly 1 is reported as absent:
// it is not a signal this implementation can act on, and guessing at the
// intent of a malformed option is worse than ignoring it.
func ExtractPrivacyPayload(opt *dns.OPT) (uint8, bool) {
	if opt == nil {
		return 0, false
	}
	for _, option := range opt.Option {
		if localOpt, ok := option.(*dns.EDNS0_LOCAL); ok {
			if localOpt.Code == EDNS0_PRIVACY_OPTION_CODE {
				if len(localOpt.Data) != 1 {
					return 0, false
				}
				return localOpt.Data[0], true
			}
		}
	}
	return 0, false
}

// ExtractPrivacyLevel reads the query-direction signal from opt.
//
// A payload value this implementation does not know is mapped to PrivacyNone
// (while still reporting the option as present). A resolver cannot honor
// semantics it has never heard of, and the alternative -- assuming a higher
// value means "at least as strict as strict" -- would SERVFAIL queries on the
// strength of a signal it does not understand.
func ExtractPrivacyLevel(opt *dns.OPT) (PrivacyLevel, bool) {
	payload, found := ExtractPrivacyPayload(opt)
	if !found {
		return PrivacyNone, false
	}
	switch PrivacyLevel(payload) {
	case PrivacyNone, PrivacyOpportunistic, PrivacyStrict:
		return PrivacyLevel(payload), true
	default:
		return PrivacyNone, true
	}
}

// ExtractPrivacyStatus reads the response-direction signal from opt. Unlike
// the level, an unknown status is returned as-is: it is diagnostic output for
// a client, not something a resolver acts on, and printing "unknown(7)" is
// more useful than silently reporting cleartext.
func ExtractPrivacyStatus(opt *dns.OPT) (PrivacyStatus, bool) {
	payload, found := ExtractPrivacyPayload(opt)
	if !found {
		return PrivacyCleartext, false
	}
	return PrivacyStatus(payload), true
}

// RemovePrivacyOption strips every PRIVACY option from an OPT RR.
func RemovePrivacyOption(opt *dns.OPT) {
	if opt == nil {
		return
	}
	var kept []dns.EDNS0
	for _, option := range opt.Option {
		if localOpt, ok := option.(*dns.EDNS0_LOCAL); ok {
			if localOpt.Code == EDNS0_PRIVACY_OPTION_CODE {
				continue
			}
		}
		kept = append(kept, option)
	}
	opt.Option = kept
}
