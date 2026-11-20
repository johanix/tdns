/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Registration APIs for external components to plug into TDNS
 */

package imr

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// OutboundQueryHookFunc is called before the IMR sends an iterative query
// to an authoritative server.
// Return nil to proceed with the query.
// Return a non-nil error to skip this server (behaves as if the server didn't respond).
type OutboundQueryHookFunc func(ctx context.Context, qname string,
	qtype uint16, serverName string, serverAddr string,
	transport core.Transport) error

// ResponseHookFunc is called after the IMR receives a response from an
// authoritative server. Observe-only — return value is ignored.
type ResponseHookFunc func(ctx context.Context, qname string, qtype uint16,
	serverName string, serverAddr string, transport core.Transport,
	response *dns.Msg, rcode int)

// RegisterOutboundQueryHook registers a hook that is called before the IMR
// sends an iterative query to an authoritative server. Multiple hooks can be
// registered and are called in registration order.
func RegisterOutboundQueryHook(hook OutboundQueryHookFunc) error {
	if hook == nil {
		return fmt.Errorf("hook cannot be nil")
	}
	globalImrOutboundQueryHooksMutex.Lock()
	globalImrOutboundQueryHooks = append(globalImrOutboundQueryHooks, hook)
	globalImrOutboundQueryHooksMutex.Unlock()
	slog.Debug("RegisterImrOutboundQueryHook: registered hook")
	return nil
}

// RegisterResponseHook registers a hook that is called after the IMR
// receives a response from an authoritative server. Multiple hooks can be
// registered and are called in registration order.
func RegisterResponseHook(hook ResponseHookFunc) error {
	if hook == nil {
		return fmt.Errorf("hook cannot be nil")
	}
	globalImrResponseHooksMutex.Lock()
	globalImrResponseHooks = append(globalImrResponseHooks, hook)
	globalImrResponseHooksMutex.Unlock()
	slog.Debug("RegisterImrResponseHook: registered hook")
	return nil
}

// getImrOutboundQueryHooks returns all registered outbound query hooks.
func getImrOutboundQueryHooks() []OutboundQueryHookFunc {
	globalImrOutboundQueryHooksMutex.RLock()
	defer globalImrOutboundQueryHooksMutex.RUnlock()
	return globalImrOutboundQueryHooks
}

// getImrResponseHooks returns all registered response hooks.
func getImrResponseHooks() []ResponseHookFunc {
	globalImrResponseHooksMutex.RLock()
	defer globalImrResponseHooksMutex.RUnlock()
	return globalImrResponseHooks
}

var (
	globalImrOutboundQueryHooks      []OutboundQueryHookFunc
	globalImrOutboundQueryHooksMutex sync.RWMutex

	globalImrResponseHooks      []ResponseHookFunc
	globalImrResponseHooksMutex sync.RWMutex
)
