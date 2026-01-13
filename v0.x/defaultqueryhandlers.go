/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Default query handlers for TDNS - zone-based query handling and .server. queries
 */

package tdns

import (
	"context"
	"log"
	"strings"

	edns0 "github.com/johanix/tdns/v0.x/edns0"
	"github.com/miekg/dns"
)

// ServerQueryHandler handles queries for qnames ending in ".server." with ClassCHAOS.
// NOTE: This function is now optional. .server. queries are automatically handled
// by createAuthDnsHandler() in do53.go as a fallback before returning REFUSED.
// This exported function is kept for backward compatibility or for apps that want
// to handle .server. queries earlier in the handler chain.
func ServerQueryHandler(ctx context.Context, req *DnsQueryRequest) error {
	qname := strings.ToLower(req.Qname)

	// Only handle .server. queries with ClassCHAOS
	if !strings.HasSuffix(qname, ".server.") || req.Msg.Question[0].Qclass != dns.ClassCHAOS {
		return ErrNotHandled
	}

	log.Printf("DnsHandler: Qname is '%s', which is not a known zone, but likely a query for the .server CH tld", qname)
	DotServerQnameResponse(qname, req.ResponseWriter, req.Msg)
	return nil
}

// DefaultQueryHandler handles all other queries using zone-based query handling.
// This is registered with qtype=0 to catch all query types that aren't handled by other handlers.
// Exported so apps (like KDC) can register it even when no zones are in config.
func DefaultQueryHandler(ctx context.Context, req *DnsQueryRequest) error {
	conf := &Conf
	kdb := conf.Internal.KeyDB
	qname := req.Qname
	qtype := req.Qtype
	r := req.Msg
	w := req.ResponseWriter
	msgoptions := req.Options

	log.Printf("DnsHandler: qname: %s opcode: %s (%d) DO: %v", qname, dns.OpcodeToString[r.Opcode], r.Opcode, msgoptions.DO)
	log.Printf("Zone %s %s request from %s", qname, dns.TypeToString[qtype], w.RemoteAddr())

	// Check if this is a reporter app handling error channel queries (RFC9567)
	if Globals.App.Type == AppTypeReporter {
		if strings.HasPrefix(qname, "_er.") {
			edns0.ErrorChannelReporter(qname, qtype, w, r)
			return nil
		}
		log.Printf("DnsHandler: Qname is %q, which is not the correct format for error channel reports (expected to start with '_er.').", qname)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		w.WriteMsg(m)
		return nil
	}

	if zd, ok := Zones.Get(qname); ok {
		if zd.Error {
			if zd.ErrorType != RefreshError || zd.RefreshCount == 0 {
				log.Printf("DnsHandler: Qname is %q, which is a known zone, but it is in %s error state: %s",
					qname, ErrorTypeToString[zd.ErrorType], zd.ErrorMsg)
				m := new(dns.Msg)
				m.SetRcode(r, dns.RcodeServerFailure)
				w.WriteMsg(m)
				return nil
			}
		}

		log.Printf("DnsHandler: Qname is %q, which is a known zone.", qname)
		err := zd.QueryResponder(ctx, w, r, qname, qtype, msgoptions, kdb, conf.Internal.ImrEngine)
		if err != nil {
			log.Printf("Error in QueryResponder: %v", err)
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeServerFailure)
			w.WriteMsg(m)
		}
		return nil
	}

	log.Printf("DnsHandler: Qname is %q, which is not a known zone.", qname)
	log.Printf("DnsHandler: known zones are: %v", Zones.Keys())

	// Let's see if we can find the zone
	zd, folded := FindZone(qname)
	if zd == nil {
		// No zone found - return REFUSED
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		w.WriteMsg(m)
		return nil
	}

	log.Printf("DnsHandler: query %q refers to zone %q", qname, zd.ZoneName)

	log.Printf("DnsHandler: AppMode: \"%s\"", AppTypeToString[Globals.App.Type])
	if Globals.App.Type == AppTypeAgent {
		log.Printf("DnsHandler: Agent mode, not handling ordinary queries for zone %q", qname)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		w.WriteMsg(m)
		return nil
	}

	if zd.ZoneStore == XfrZone {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		w.WriteMsg(m)
		return nil
	}

	if folded {
		qname = strings.ToLower(qname)
	}

	if zd.Error && zd.ErrorType != RefreshError {
		log.Printf("DnsHandler: Qname is %q, which is belongs to a known zone (%q), but it is in %s error state: %s",
			qname, zd.ZoneName, ErrorTypeToString[zd.ErrorType], zd.ErrorMsg)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return nil
	}

	if zd.RefreshCount == 0 {
		log.Printf("DnsHandler: Qname is %q, which belongs to a known zone (%q), but it has not been refreshed at least once yet", qname, zd.ZoneName)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return nil
	}

	err := zd.QueryResponder(ctx, w, r, qname, qtype, msgoptions, kdb, conf.Internal.ImrEngine)
	if err != nil {
		log.Printf("Error in QueryResponder: %v", err)
	}
	return nil
}

// RegisterDefaultQueryHandlers registers the default zone-based query handler.
// This is called automatically during TDNS initialization.
// The default handler is only registered if zones are configured in the config (TDNS-internal check).
// Apps that need .server. query support should register ServerQueryHandler themselves.
func RegisterDefaultQueryHandlers(conf *Config) error {
	// Only register default query handler if zones are configured
	// Check if any zones are configured in the config (TDNS-internal check, not app-type specific)
	if conf != nil && len(conf.Zones) > 0 {
		if err := RegisterQueryHandler(0, DefaultQueryHandler); err != nil {
			return err
		}
		if Globals.Debug {
			log.Printf("RegisterDefaultQueryHandlers: Registered default zone-based query handler")
		}
	} else {
		if Globals.Debug {
			log.Printf("RegisterDefaultQueryHandlers: No zones configured, skipping default query handler registration")
		}
	}

	return nil
}
