/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Default query handlers for TDNS - zone-based query handling and .server. queries
 */

package tdns

import (
	"context"
	"strings"

	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

var lgHandler = Logger("handler")

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

	lgHandler.Debug("query for .server CH TLD", "qname", qname)
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

	lgHandler.Debug("query received", "qname", qname, "opcode", dns.OpcodeToString[r.Opcode], "opcodeNum", r.Opcode, "DO", msgoptions.DO, "qtype", dns.TypeToString[qtype], "from", w.RemoteAddr())

	// If the query contains a KeyState EDNS(0) option and we are a parent zone,
	// process the KeyState request and wrap the ResponseWriter to attach the
	// response option to whatever DNS reply is sent. Per draft-berra-dnsop-keystate-02,
	// the response is also signed with the UPDATE Receiver's SIG(0) key.
	if msgoptions.KeyState != nil && kdb != nil {
		if zd, _ := FindZone(qname); zd != nil && zd.Options[OptDelSyncParent] {
			lgHandler.Debug("processing KeyState option from query", "qname", qname, "keyid", msgoptions.KeyState.KeyID, "state", msgoptions.KeyState.KeyState)
			ksResponse, err := kdb.ProcessKeyState(msgoptions.KeyState, qname)
			if err != nil {
				lgHandler.Error("failed to process KeyState option", "err", err)
			} else {
				ksWriter := &keyStateResponseWriter{
					ResponseWriter:   w,
					keyStateResponse: ksResponse,
				}
				// Look up the parent's UPDATE Receiver SIG(0) key for signing
				signerName := DsyncUpdateTargetName(zd.ZoneName)
				if signerName != "" {
					sak, err := kdb.GetSig0Keys(signerName, Sig0StateActive)
					if err != nil {
						lgHandler.Debug("no SIG(0) key for KeyState response signing", "signer", signerName, "err", err)
					} else {
						ksWriter.sig0Signer = signerName
						ksWriter.sig0Keys = sak
					}
				}
				w = ksWriter
			}
		}
	}

	// Check if this is a reporter app handling error channel queries (RFC9567)
	if Globals.App.Type == AppTypeReporter {
		if strings.HasPrefix(qname, "_er.") {
			edns0.ErrorChannelReporter(qname, qtype, w, r)
			return nil
		}
		lgHandler.Warn("bad error channel query format, expected '_er.' prefix", "qname", qname)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		w.WriteMsg(m)
		return nil
	}

	if zd, ok := Zones.Get(qname); ok {
		if zd.Error {
			if zd.ErrorType != RefreshError || zd.RefreshCount == 0 {
				lgHandler.Warn("zone in error state", "qname", qname, "errorType", ErrorTypeToString[zd.ErrorType], "error", zd.ErrorMsg)
				m := new(dns.Msg)
				m.SetRcode(r, dns.RcodeServerFailure)
				w.WriteMsg(m)
				return nil
			}
		}

		lgHandler.Debug("query for known zone", "qname", qname)
		err := zd.QueryResponder(ctx, w, r, qname, qtype, msgoptions, kdb, conf.Internal.ImrEngine)
		if err != nil {
			lgHandler.Error("QueryResponder failed", "error", err)
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeServerFailure)
			w.WriteMsg(m)
		}
		return nil
	}

	lgHandler.Debug("qname is not a known zone", "qname", qname, "knownZones", Zones.Keys())

	// Let's see if we can find the zone
	zd, folded := FindZone(qname)
	if zd == nil {
		// No zone found - return REFUSED
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		w.WriteMsg(m)
		return nil
	}

	lgHandler.Debug("query refers to zone", "qname", qname, "zone", zd.ZoneName)

	lgHandler.Debug("app mode check", "appMode", AppTypeToString[Globals.App.Type])
	if Globals.App.Type == AppTypeAgent {
		lgHandler.Debug("agent mode, refusing ordinary query", "qname", qname)
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
		lgHandler.Warn("zone in error state", "qname", qname, "zone", zd.ZoneName, "errorType", ErrorTypeToString[zd.ErrorType], "error", zd.ErrorMsg)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return nil
	}

	if zd.RefreshCount == 0 {
		lgHandler.Warn("zone not yet refreshed", "qname", qname, "zone", zd.ZoneName)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return nil
	}

	err := zd.QueryResponder(ctx, w, r, qname, qtype, msgoptions, kdb, conf.Internal.ImrEngine)
	if err != nil {
		lgHandler.Error("QueryResponder failed", "error", err)
	}
	return nil
}

// RegisterDefaultQueryHandlers registers the default zone-based query handler.
// This is called automatically during TDNS initialization.
// The default handler is registered if (a) zones are configured in the config, or
// (b) app type is Agent (agent gets an autozone from SetupAgent, needed for SOA/AXFR).
// Apps that need .server. query support should register ServerQueryHandler themselves.
func RegisterDefaultQueryHandlers(conf *Config) error {
	// Register default query handler if we will have zones to serve:
	// - zones in config (auth, combiner, etc.), or
	// - agent (autozone is created later in SetupAgent; handler will serve SOA/AXFR at query time)
	needDefault := conf != nil && (len(conf.Zones) > 0 || Globals.App.Type == AppTypeAgent)
	if needDefault {
		if err := RegisterQueryHandler(0, DefaultQueryHandler); err != nil {
			return err
		}
		lgHandler.Debug("registered default zone-based query handler")
	} else {
		lgHandler.Debug("no zones configured and not agent, skipping default query handler registration")
	}

	return nil
}
