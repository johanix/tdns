/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Debug handlers for TDNS - generic logging handlers for queries and NOTIFYs
 */

package tdns

import (
	"context"
	"log"

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
//   tdns.RegisterDebugQueryHandler()
//   tdns.RegisterQueryHandler(hpke.TypeKMREQ, myHandler)
func RegisterDebugQueryHandler() error {
	debugQueryHandler := func(ctx context.Context, dqr *DnsQueryRequest) error {
		log.Printf("DEBUG QUERY: qname=%s, qtype=%s, from=%s, msgid=%d, do=%v",
			dqr.Qname,
			dns.TypeToString[dqr.Qtype],
			dqr.ResponseWriter.RemoteAddr(),
			dqr.Msg.MsgHdr.Id,
			dqr.Options.DO)
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
//   tdns.RegisterDebugNotifyHandler()
//   tdns.RegisterNotifyHandler(core.TypeMANIFEST, myHandler)
func RegisterDebugNotifyHandler() error {
	debugNotifyHandler := func(ctx context.Context, dnr *DnsNotifyRequest) error {
		qtype := uint16(0)
		if len(dnr.Msg.Question) > 0 {
			qtype = dnr.Msg.Question[0].Qtype
		}
		log.Printf("DEBUG NOTIFY: qname=%s, qtype=%s, from=%s, msgid=%d",
			dnr.Qname,
			dns.TypeToString[qtype],
			dnr.ResponseWriter.RemoteAddr(),
			dnr.Msg.MsgHdr.Id)
		// Always pass through to next handler
		return ErrNotHandled
	}
	return RegisterNotifyHandler(0, debugNotifyHandler)
}

