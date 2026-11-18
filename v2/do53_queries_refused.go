/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"crypto/tls"
	"fmt"
	"strings"

	core "github.com/johanix/tdns/v2/core"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// debug-do53-queries-refused (#1066) makes tdns-auth a server whose zones can
// be read only over an encrypted transport, for testing resolvers against
// one: strict privacy, the Do53 fallback, the cold signal lookup (#1065).
// Moving Do53 to another port leaves the zones readable in cleartext there,
// and dropping the Do53 sockets loses NOTIFY and UPDATE, which senders send
// over Do53 (NOTIFY over an encrypted transport is not standardized).
//
// So the Do53 sockets stay, and over Do53 every QUERY is refused, with two
// exceptions: the transport signal (SVCB at a name whose first label is
// _dns) and DNSKEY, which validates it. They are what a resolver needs to
// find and trust the server's encrypted transports, they say nothing about
// what a client asked, and with them the server can serve the zone holding
// its own signal alone. NOTIFY, UPDATE and every other opcode are handled as
// usual. DoT, DoQ and DoH do not go through the Do53 mux, and are unchanged.
//
// The use case is a leaf server: a secondary at the edge still receives
// NOTIFY and still transfers its zones from its primary, since inbound
// transfers are its own outgoing queries. AXFR, IXFR and SOA queries sent to
// it over Do53 are refused like any other. An upstream server, a primary,
// has no use for the option.
//
// It breaks RFC requirements on purpose; the debug- prefix says so.

// do53RefusedText is the EDE text on a refused Do53 query.
const do53RefusedText = "queries over Do53 are refused here; use an encrypted transport"

// do53QueriesRefusedConfigured reports whether the parsed authengine options
// turn debug-do53-queries-refused on.
func do53QueriesRefusedConfigured(opts map[AuthOption]string) bool {
	return opts[AuthOptDebugDo53QueriesRefused] == "true"
}

// do53QueryLetThrough reports whether a query for q is answered over Do53
// with debug-do53-queries-refused on: the transport signal, an SVCB at a
// name whose first label is _dns, and DNSKEY, both of class IN.
func do53QueryLetThrough(q dns.Question) bool {
	if q.Qclass != dns.ClassINET {
		return false
	}
	switch q.Qtype {
	case dns.TypeDNSKEY:
		return true
	case dns.TypeSVCB:
		return strings.HasPrefix(core.CanonicalizeName(dns.Fqdn(q.Name)), oobTransportPrefix)
	}
	return false
}

// refuseDo53Queries wraps the Do53 handler for debug-do53-queries-refused.
// A QUERY other than those do53QueryLetThrough allows gets the refusal
// (do53QueryRefusal), and every other message goes to next: NOTIFY, UPDATE,
// the other opcodes, and a message without a question, which next answers
// with FORMERR.
//
// A query with more than one question does not get here: the Do53 servers'
// MsgAcceptFunc answers it with FORMERR, as on every transport. Should one
// arrive all the same, it is refused, since next would answer the first.
func refuseDo53Queries(next func(dns.ResponseWriter, *dns.Msg)) func(dns.ResponseWriter, *dns.Msg) {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		if r == nil || r.Opcode != dns.OpcodeQuery || len(r.Question) == 0 ||
			(len(r.Question) == 1 && do53QueryLetThrough(r.Question[0])) {
			next(w, r)
			return
		}
		lgDns.Debug("Do53: query refused (debug-do53-queries-refused)",
			"qname", r.Question[0].Name, "qtype", dns.TypeToString[r.Question[0].Qtype],
			"remote", w.RemoteAddr())
		_ = w.WriteMsg(do53QueryRefusal(r))
	}
}

// do53QueryRefusal is the answer to a query refused over Do53: REFUSED, AA
// clear, and for an EDNS query EDE 18 (Prohibited) saying to use an
// encrypted transport, so a resolver learns at once and does not time out.
// A query without EDNS gets no OPT (RFC 6891 section 7).
func do53QueryRefusal(r *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeRefused)
	m.Authoritative = false
	if opt := r.IsEdns0(); opt != nil {
		edns0.AttachEDEToResponseWithText(m, dns.ExtendedErrorCodeProhibited, do53RefusedText, opt.Do())
	}
	return m
}

// do53Handler is the handler the Do53 servers run: the auth handler, behind
// the refusal when debug-do53-queries-refused is on, then the UDP truncation
// and the TSIG signing (DnsEngine says why in that order).
func do53Handler(refuseQueries bool, authDNSHandler func(dns.ResponseWriter, *dns.Msg)) func(dns.ResponseWriter, *dns.Msg) {
	h := authDNSHandler
	if refuseQueries {
		h = refuseDo53Queries(h)
	}
	return TsigSigningHandler(udpTruncate(h))
}

// checkDo53QueriesRefused refuses a config with debug-do53-queries-refused
// on that leaves queries no transport at all: none of dot, doq and doh in
// listeners.transports, or no certificate and key that load. The daemon
// does not start with it, and a reload to it is refused.
func checkDo53QueriesRefused(conf *Config) error {
	if !do53QueriesRefusedConfigured(conf.AuthEngine.Options) {
		return nil
	}
	name := AuthOptionToString[AuthOptDebugDo53QueriesRefused]
	if !anyEncryptedTransport(conf.Listeners.Transports) {
		return fmt.Errorf("authengine option %q needs an encrypted transport (dot, doq or doh) in listeners.transports: queries are answered over nothing else", name)
	}
	cert, key := conf.Listeners.CertFile, conf.Listeners.KeyFile
	if cert == "" || key == "" {
		return fmt.Errorf("authengine option %q needs listeners.certfile and listeners.keyfile: without them no encrypted transport starts", name)
	}
	if _, err := tls.LoadX509KeyPair(cert, key); err != nil {
		return fmt.Errorf("authengine option %q needs a certificate that loads, for the encrypted transports: %w", name, err)
	}
	return nil
}

// Do53QueriesRefusedCheck parses the authengine options and reports whether
// debug-do53-queries-refused is present, at any value (tdns-agent refuses it
// then, "false" included), whether it is on, and the reason the daemon would
// refuse to start with it, if any (checkDo53QueriesRefused). For config check.
func (conf *Config) Do53QueriesRefusedCheck() (present, on bool, err error) {
	conf.ParseAuthOptions()
	_, present = conf.AuthEngine.Options[AuthOptDebugDo53QueriesRefused]
	return present, do53QueriesRefusedConfigured(conf.AuthEngine.Options), checkDo53QueriesRefused(conf)
}

// do53QueriesRefusedStartError is DnsEngine's verdict, with
// debug-do53-queries-refused on, once it has started the encrypted
// transports: an error when none came up, nil otherwise. certReason says why
// the certificate did not load, when it did not.
func do53QueriesRefusedStartError(certLoaded bool, certReason string, started []string) error {
	name := AuthOptionToString[AuthOptDebugDo53QueriesRefused]
	if !certLoaded {
		return fmt.Errorf("%s: no encrypted transport could start (%s), and queries over Do53 are refused", name, certReason)
	}
	if len(started) == 0 {
		return fmt.Errorf("%s: no encrypted transport started, and queries over Do53 are refused", name)
	}
	return nil
}
