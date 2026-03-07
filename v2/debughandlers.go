/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Debug handlers for TDNS - generic logging handlers for queries and NOTIFYs
 */

package tdns

import (
	"context"

	"github.com/miekg/dns"
)

// RegisterDebugQueryHandler registers a debug handler that logs all DNS queries.
// The handler logs query details and always returns ErrNotHandled to pass through
// to the next handler. This is useful for debugging and monitoring.
//
// The handler is registered with qtype=0, meaning it will be called for ALL queries
// before any specific qtype handlers. It should be registered first (before other handlers).
//
// Example usage:
//
//	tdns.RegisterDebugQueryHandler()
//	tdns.RegisterQueryHandler(hpke.TypeKMREQ, myHandler)
func RegisterDebugQueryHandler() error {
	debugQueryHandler := func(ctx context.Context, dqr *DnsQueryRequest) error {
		lgHandler.Debug("query", "qname", dqr.Qname, "qtype", dns.TypeToString[dqr.Qtype], "from", dqr.ResponseWriter.RemoteAddr(), "msgid", dqr.Msg.MsgHdr.Id, "DO", dqr.Options.DO)
		// Always pass through to next handler
		return ErrNotHandled
	}
	return RegisterQueryHandler(0, debugQueryHandler)
}

// RegisterDebugNotifyHandler registers a debug handler that logs all DNS NOTIFY messages.
// The handler logs NOTIFY details and always returns ErrNotHandled to pass through
// to the next handler. This is useful for debugging and monitoring.
//
// The handler is registered with qtype=0, meaning it will be called for ALL NOTIFYs
// before any specific qtype handlers. It should be registered first (before other handlers).
//
// Example usage:
//
//	tdns.RegisterDebugNotifyHandler()
//	tdns.RegisterNotifyHandler(core.TypeCHUNK, myHandler)
func RegisterDebugNotifyHandler() error {
	debugNotifyHandler := func(ctx context.Context, dnr *DnsNotifyRequest) error {
		qtype := uint16(0)
		if len(dnr.Msg.Question) > 0 {
			qtype = dnr.Msg.Question[0].Qtype
		}
		lgHandler.Debug("notify", "qname", dnr.Qname, "qtype", dns.TypeToString[qtype], "from", dnr.ResponseWriter.RemoteAddr(), "msgid", dnr.Msg.MsgHdr.Id)
		// Always pass through to next handler
		return ErrNotHandled
	}
	return RegisterNotifyHandler(0, debugNotifyHandler)
}
