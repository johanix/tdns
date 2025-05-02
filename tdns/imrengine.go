/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/spf13/viper"

	"github.com/miekg/dns"
)

type ImrRequest struct {
	Qname      string
	Qtype      uint16
	Qclass     uint16
	ResponseCh chan ImrResponse
}

type ImrResponse struct {
	RRset     *RRset
	Validated bool
	Error     bool
	ErrorMsg  string
	Msg       string
}

// The RecursorEngine is a simple caching DNS recursor. It is not a fully fledged, all singing,
// all dancing recursive server. It is just intended to get the job done for the particular cases
// that we need to support.

// var RecursorCache *RRsetCacheNG

func RecursorEngine(conf *Config, stopch chan struct{}) {
	var recursorch = conf.Internal.RecursorCh

	if !viper.GetBool("recursorengine.active") {
		log.Printf("RecursorEngine is NOT active.")
		for rrq := range recursorch {
			log.Printf("RecursorEngine: not active, but got a request: %v", rrq)
			continue // ensure that we keep reading to keep the channel open
		}
	} else {
		log.Printf("RecursorEngine: Starting")
	}

	// 1. Create the cache
	var err error
	// RecursorCache, err = NewRRsetCacheNG(viper.GetString("recursorengine.root-hints"))
	if !RRsetCache.Primed {
		RRsetCache.PrimeWithHints(viper.GetString("recursorengine.root-hints"))
		if err != nil {
			Shutdowner(conf, fmt.Sprintf("RecursorEngine: failed to initialize RecursorCache w/ root hints: %v", err))
		}
	}

	// var DnskeyCache = NewRRsetCache()

	for rrq := range recursorch {
		if Globals.Debug {
			log.Printf("RecursorEngine: received query for %s %s %s", rrq.Qname, dns.ClassToString[rrq.Qclass], dns.TypeToString[rrq.Qtype])
		}
		// resp := ImrResponse{
		//			Validated: false,
		// Msg:       "RecursorEngine: request to look up a RRset",
		// }
		var resp *ImrResponse

		// 1. Is the answer in the cache?
		crrset := RRsetCache.Get(rrq.Qname, rrq.Qtype)
		if crrset != nil {
			resp.RRset = crrset.RRset
		} else {
			var err error
			log.Printf("Recursor: <qname, qtype> tuple <%q, %s> not known, needs to be queried for", rrq.Qname, dns.TypeToString[rrq.Qtype])
			resp, err = IterateOverQuery(rrq.Qname, rrq.Qtype, rrq.Qclass)
			if err != nil {
				log.Printf("Error from IterateOverQuery: %v", err)
			}
		}
		if rrq.ResponseCh != nil {
			rrq.ResponseCh <- *resp
		}
	}
}

func IterateOverQuery(qname string, qtype uint16, qclass uint16) (*ImrResponse, error) {
	log.Printf("Recursor: <qname, qtype> tuple <%q, %s> not known, needs to be queried for", qname, dns.TypeToString[qtype])
	maxiter := 12

	resp := ImrResponse{
		Validated: false,
		Msg:       "ImrEngine: request to look up a RRset",
	}

	for {
		if maxiter <= 0 {
			log.Printf("*** Recursor: max iterations reached. Giving up.")
			return nil, fmt.Errorf("Max iterations reached. Giving up.")
		} else {
			maxiter--
		}
		bestmatch, servers, err := RRsetCache.FindClosestKnownZone(qname)
		if err != nil {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Error from FindClosestKnownZone: %v", err)
			return &resp, err
		}
		log.Printf("Recursor: best zone match for qname %q seems to be %q", qname, bestmatch)
		ss := servers
		if len(servers) > 4 {
			ss = servers[:3]
			ss = append(ss, "...")
		}
		log.Printf("Recursor: sending query to %d servers: %v", len(servers), ss)
		rrset, rcode, context, err := RRsetCache.AuthDNSQuery(qname, qtype, servers, log.Default(), true)
		// log.Printf("Recursor: response from AuthDNSQuery: rcode: %d, err: %v", rrset, rcode, err)
		if err != nil {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Error from AuthDNSQuery: %v", err)
			return &resp, err
		}
		if rrset != nil {
			log.Printf("Recursor: received response from AuthDNSQuery:")
			for _, rr := range rrset.RRs {
				log.Printf("Recursor: %s", rr.String())
			}
			resp.RRset = rrset
			return &resp, nil
		}
		if rcode == dns.RcodeNameError {
			// this is a negative response, which we need to figure out how to represent
			log.Printf("Recursor: received NXDOMAIN for qname %q, no point in continuing", qname)
			resp.Msg = "NXDOMAIN (negative response type 3)"
			return &resp, nil
		}
		switch context {
		case ContextReferral:
			continue // if all is good we will now hit the new referral and get further
		case ContextNoErrNoAns:
			resp.Msg = "negative response type 0"
			return &resp, nil
		}
	}
}

func ImrResponder(w dns.ResponseWriter, r *dns.Msg, qname string, qtype uint16, dnssec_ok bool) {
	//	qname := r.Question[0].Name
	//	qtype := r.Question[0].Rrtype
	//	var dnssec_ok bool
	//	opt := r.IsEdns0()
	//	if opt != nil {
	//		dnssec_ok = opt.Do()
	//	}

	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeSuccess)
	m.RecursionAvailable = true

	crrset := RRsetCache.Get(qname, qtype)
	if crrset != nil {
		m.SetRcode(r, dns.RcodeSuccess)
		// resp.RRset = crrset.RRset
		m.Answer = crrset.RRset.RRs
		if dnssec_ok {
			m.Answer = append(m.Answer, crrset.RRset.RRSIGs...)
		}
		// XXX: need to fill in more things in the response msg
		w.WriteMsg(m)
		return
	} else {
		log.Printf("Recursor: <qname, qtype> tuple <%q, %s> not known, needs to be queried for", qname, dns.TypeToString[qtype])
		maxiter := 12

		for {
			if maxiter <= 0 {
				log.Printf("*** Recursor: max iterations reached. Giving up.")
				return
			} else {
				maxiter--
			}
			bestmatch, servers, err := RRsetCache.FindClosestKnownZone(qname)
			if err != nil {
				// resp.Error = true
				// resp.ErrorMsg = fmt.Sprintf("Error from FindClosestKnownZone: %v", err)
				m.SetRcode(r, dns.RcodeServerFailure)
				w.WriteMsg(m)
				return
			}
			log.Printf("Recursor: best zone match for qname %q seems to be %q", qname, bestmatch)
			ss := servers
			if len(servers) > 4 {
				ss = servers[:3]
				ss = append(ss, "...")
			}
			log.Printf("Recursor: sending query to %d servers: %v", len(servers), ss)
			rrset, rcode, context, err := RRsetCache.AuthDNSQuery(qname, qtype, servers, log.Default(), true)
			// log.Printf("Recursor: response from AuthDNSQuery: rcode: %d, err: %v", rrset, rcode, err)
			if err != nil {
				// resp.Error = true
				// resp.ErrorMsg = fmt.Sprintf("Error from AuthDNSQuery: %v", err)
				m.SetRcode(r, dns.RcodeServerFailure)
				w.WriteMsg(m)
				return
			}
			if rrset != nil {
				log.Printf("Recursor: received response from AuthDNSQuery:")
				for _, rr := range rrset.RRs {
					log.Printf("Recursor: %s", rr.String())
				}
				m.Answer = rrset.RRs
				if dnssec_ok {
					m.Answer = append(m.Answer, rrset.RRSIGs...)
				}
				w.WriteMsg(m)
				return
			}
			if rcode == dns.RcodeNameError {
				// this is a negative response, which we need to figure out how to represent
				log.Printf("Recursor: received NXDOMAIN for qname %q, no point in continuing", qname)
				// resp.Msg = "NXDOMAIN (negative response type 3)"
				m.SetRcode(r, rcode)
				// XXX: we need the contents of the Authority section here
				w.WriteMsg(m)
			}
			switch context {
			case ContextReferral:
				continue // if all is good we will now hit the new referral and get further
			case ContextNoErrNoAns:
				// resp.Msg = "negative response type 0"
				// break outerLoop
				m.SetRcode(r, dns.RcodeSuccess)
				w.WriteMsg(m)
				return
			}
		}
	}
}

func (rrcache *RRsetCacheT) FindClosestKnownZone(qname string) (string, []string, error) {
	// Iterate through known zone names and return the longest match.
	var bestmatch string
	var servers []string
	log.Printf("FindClosestKnownZone: checking qname %q against %d zones with data in cache", qname, rrcache.Servers.Count())
	for item := range rrcache.Servers.IterBuffered() {
		z := item.Key
		ss := item.Val
		if strings.HasSuffix(qname, z) && len(z) > len(bestmatch) {
			bestmatch = z
			servers = ss
		}
	}
	return bestmatch, servers, nil
}

func ImrEngine(conf *Config, done chan struct{}) error {
	ImrHandler := createImrHandler(conf)
	dns.HandleFunc(".", ImrHandler)

	addresses := viper.GetStringSlice("imrengine.addresses")
	if CaseFoldContains(conf.ImrEngine.Transports, "do53") {
		log.Printf("ImrEngine: UDP/TCP addresses: %v", addresses)
		for _, addr := range addresses {
			for _, net := range []string{"udp", "tcp"} {
				go func(addr, net string) {
					log.Printf("ImrEngine: serving on %s (%s)\n", addr, net)
					server := &dns.Server{
						Addr:          addr,
						Net:           net,
						MsgAcceptFunc: MsgAcceptFunc, // We need a tweaked version for DNS UPDATE
					}

					// Must bump the buffer size of incoming UDP msgs, as updates
					// may be much larger then queries
					server.UDPSize = dns.DefaultMsgSize // 4096
					if err := server.ListenAndServe(); err != nil {
						log.Printf("Failed to setup the %s server: %s", net, err.Error())
					} else {
						log.Printf("ImrEngine: listening on %s/%s", addr, net)
					}
				}(addr, net)
			}
		}
	} else {
		log.Printf("ImrEngine: Not serving on transport Do53 (normal UDP/TCP)")
	}

	certFile := viper.GetString("imrengine.certfile")
	keyFile := viper.GetString("imrengine.keyfile")
	certKey := true

	if certFile == "" || keyFile == "" {
		log.Println("ImrEngine: no certificate file or key file provided. Not starting DoT, DoH or DoQ service.")
		certKey = false
	}

	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		log.Printf("ImrEngine: certificate file %q does not exist. Not starting DoT, DoH or DoQ service.", certFile)
		certKey = false
	}

	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		log.Printf("ImrEngine: key file %q does not exist. Not starting DoT, DoH or DoQ service.", keyFile)
		certKey = false
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Printf("ImrEngine: failed to load certificate: %v. Not starting DoT, DoH or DoQ service.", err)
		certKey = false
	}

	if certKey {
		// Strip port numbers from addresses before proceeding to modern transports
		tmp := make([]string, len(addresses))
		for i, addr := range addresses {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				log.Printf("Failed to parse address %s: %v", addr, err)
				tmp[i] = addr // Keep original if parsing fails
			} else {
				tmp[i] = host
			}
		}
		addresses = tmp

		if CaseFoldContains(conf.ImrEngine.Transports, "dot") {
			err := DnsDoTEngine(conf, addresses, &cert, ImrHandler)
			if err != nil {
				log.Printf("Failed to setup the DoT server: %s\n", err.Error())
			}
		} else {
			log.Printf("ImrEngine: Not serving on transport DoT")
		}

		if CaseFoldContains(conf.ImrEngine.Transports, "doh") {
			err := DnsDoHEngine(conf, addresses, certFile, keyFile, ImrHandler)
			if err != nil {
				log.Printf("Failed to setup the DoH server: %s\n", err.Error())
			}
		} else {
			log.Printf("ImrEngine: Not serving on transport DoH")
		}

		if CaseFoldContains(conf.ImrEngine.Transports, "doq") {
			err := DnsDoQEngine(conf, addresses, &cert, ImrHandler)
			if err != nil {
				log.Printf("Failed to setup the DoQ server: %s\n", err.Error())
			}
		} else {
			log.Printf("ImrEngine: Not serving on transport DoQ")
		}
	}
	return nil
}

func createImrHandler(conf *Config) func(w dns.ResponseWriter, r *dns.Msg) {
	//	dnsupdateq := conf.Internal.DnsUpdateQ
	//	dnsnotifyq := conf.Internal.DnsNotifyQ
	//	kdb := conf.Internal.KeyDB

	return func(w dns.ResponseWriter, r *dns.Msg) {
		qname := r.Question[0].Name
		var dnssec_ok bool
		opt := r.IsEdns0()
		if opt != nil {
			dnssec_ok = opt.Do()
		}
		// log.Printf("DNSSEC OK: %v", dnssec_ok)

		qtype := r.Question[0].Qtype
		log.Printf("ImrHandler: qname: %s qtype: %s opcode: %s (%d)", qname, dns.OpcodeToString[r.Opcode], r.Opcode)

		switch r.Opcode {
		case dns.OpcodeNotify, dns.OpcodeUpdate:
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeRefused)
			w.WriteMsg(m)
			return

		case dns.OpcodeQuery:
			log.Printf("Zone %s %s request from %s", qname, dns.TypeToString[qtype], w.RemoteAddr())

			qname = strings.ToLower(qname)
			if strings.HasSuffix(qname, ".server.") && r.Question[0].Qclass == dns.ClassCHAOS {
				ServerTldResponse(qname, w, r)
				return
			}

			go ImrResponder(w, r, qname, qtype, dnssec_ok)
			return

		default:
			log.Printf("Error: unable to handle msgs of type %s", dns.OpcodeToString[r.Opcode])
		}
	}
}

func ServerTldResponse(qname string, w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeRefused)
	qname = strings.ToLower(qname)
	// if strings.HasSuffix(qname, ".server.") && r.Question[0].Qclass == dns.ClassCHAOS {
	log.Printf("DnsHandler: Qname is '%s', which is not a known zone, but likely a query for the .server CH tld", qname)
	switch qname {
	case "id.server.":
		m.SetRcode(r, dns.RcodeSuccess)
		v := viper.GetString("server.id")
		if v == "" {
			v = "tdnsd - an authoritative name server for experiments and POCs"
		}
		m.Answer = append(m.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600}, Txt: []string{v},
		})
	case "version.server.":
		m.SetRcode(r, dns.RcodeSuccess)
		v := viper.GetString("server.version")
		if v == "" {
			v = fmt.Sprintf("%s version %s", Globals.App.Name, Globals.App.Version)
		} else if strings.Contains(v, "{version}") {
			v = strings.Replace(v, "{version}", Globals.App.Version, -1)
		}
		m.Answer = append(m.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600}, Txt: []string{v},
		})
	case "authors.server.":
		m.SetRcode(r, dns.RcodeSuccess)
		m.Answer = append(m.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600},
			Txt: []string{"Johan Stenstam <johan.stenstam@internetstiftelsen.se>", "Erik Bergström <erik.bergstrom@internetstiftelsen.se>"},
		})

	case "hostname.server.":
		m.SetRcode(r, dns.RcodeSuccess)
		v := viper.GetString("server.hostname")
		if v == "" {
			v = "a.random.internet.host."
		}
		m.Answer = append(m.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600}, Txt: []string{v},
		})
	default:
	}
	w.WriteMsg(m)
	return
	// }
}
