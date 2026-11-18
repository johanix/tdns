/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Registration APIs for external components to plug into TDNS
 */

package imr

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/gorilla/mux"
	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// ImrOutboundQueryHookFunc is called before the IMR sends an iterative query
// to an authoritative server.
// Return nil to proceed with the query.
// Return a non-nil error to skip this server (behaves as if the server didn't respond).
type ImrOutboundQueryHookFunc func(ctx context.Context, qname string,
	qtype uint16, serverName string, serverAddr string,
	transport core.Transport) error

// ImrResponseHookFunc is called after the IMR receives a response from an
// authoritative server. Observe-only — return value is ignored.
type ImrResponseHookFunc func(ctx context.Context, qname string, qtype uint16,
	serverName string, serverAddr string, transport core.Transport,
	response *dns.Msg, rcode int)

// RegisterImrOutboundQueryHook registers a hook that is called before the IMR
// sends an iterative query to an authoritative server. Multiple hooks can be
// registered and are called in registration order.
func RegisterImrOutboundQueryHook(hook ImrOutboundQueryHookFunc) error {
	if hook == nil {
		return fmt.Errorf("hook cannot be nil")
	}
	globalImrOutboundQueryHooksMutex.Lock()
	globalImrOutboundQueryHooks = append(globalImrOutboundQueryHooks, hook)
	globalImrOutboundQueryHooksMutex.Unlock()
	lgImr.Debug("RegisterImrOutboundQueryHook: registered hook")
	return nil
}

// RegisterImrResponseHook registers a hook that is called after the IMR
// receives a response from an authoritative server. Multiple hooks can be
// registered and are called in registration order.
func RegisterImrResponseHook(hook ImrResponseHookFunc) error {
	if hook == nil {
		return fmt.Errorf("hook cannot be nil")
	}
	globalImrResponseHooksMutex.Lock()
	globalImrResponseHooks = append(globalImrResponseHooks, hook)
	globalImrResponseHooksMutex.Unlock()
	lgImr.Debug("RegisterImrResponseHook: registered hook")
	return nil
}

// getImrOutboundQueryHooks returns all registered outbound query hooks.
func getImrOutboundQueryHooks() []ImrOutboundQueryHookFunc {
	globalImrOutboundQueryHooksMutex.RLock()
	defer globalImrOutboundQueryHooksMutex.RUnlock()
	return globalImrOutboundQueryHooks
}

// getImrResponseHooks returns all registered response hooks.
func getImrResponseHooks() []ImrResponseHookFunc {
	globalImrResponseHooksMutex.RLock()
	defer globalImrResponseHooksMutex.RUnlock()
	return globalImrResponseHooks
}

var (
	globalImrOutboundQueryHooks      []ImrOutboundQueryHookFunc
	globalImrOutboundQueryHooksMutex sync.RWMutex

	globalImrResponseHooks      []ImrResponseHookFunc
	globalImrResponseHooksMutex sync.RWMutex
)
