/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Registration APIs for external components to plug into TDNS
 */

package tdns

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

// ErrNotHandled is returned by query/notify handlers to indicate they don't handle this request.
// TDNS will try the next handler or fall back to the default handler.
var ErrNotHandled = errors.New("query not handled by this handler")

// QueryHandlerFunc is the function signature for registered query handlers.
// Returns ErrNotHandled if the handler doesn't handle this query (allows fallthrough).
// Returns nil if the handler successfully handled the query.
// Returns other error if handler attempted to handle but encountered an error.
type QueryHandlerFunc func(ctx context.Context, req *DnsQueryRequest) error

var (
	// Global registration storage (used when conf is not available during registration)
	globalQueryHandlers      = make(map[uint16][]QueryHandlerFunc)
	globalQueryHandlersMutex sync.RWMutex

	globalNotifyHandlers      = make(map[uint16][]NotifyHandlerFunc)
	globalNotifyHandlersMutex sync.RWMutex

	globalUpdateHandlers      = make([]UpdateHandlerRegistration, 0)
	globalUpdateHandlersMutex sync.RWMutex

	globalEngines      = make([]EngineRegistration, 0)
	globalEnginesMutex sync.RWMutex

	globalAPIRoutes      = make([]APIRouteRegistration, 0)
	globalAPIRoutesMutex sync.RWMutex
)

// RegisterQueryHandler registers a handler for a specific query type.
// Multiple handlers can be registered for the same qtype - they will be called in registration order.
// If a handler returns ErrNotHandled, TDNS will try the next handler or fall back to default.
// If qtype is 0, handler is called for ALL query types (use with caution, e.g., for debug handlers).
// Handlers registered with qtype=0 are called before handlers registered for specific qtypes.
//
// This function can be called before TDNS is initialized (uses global storage),
// or after initialization (uses conf.Internal.QueryHandlers).
// During query processing, TDNS checks both locations.
func RegisterQueryHandler(qtype uint16, handler QueryHandlerFunc) error {
	if handler == nil {
		return fmt.Errorf("handler cannot be nil")
	}

	// Register in global storage (for early registration before conf is available)
	globalQueryHandlersMutex.Lock()
	globalQueryHandlers[qtype] = append(globalQueryHandlers[qtype], handler)
	globalQueryHandlersMutex.Unlock()

	// Also register in conf if available (and map is initialized)
	Conf.Internal.QueryHandlersMutex.Lock()
	if Conf.Internal.QueryHandlers != nil {
		if Conf.Internal.QueryHandlers[qtype] == nil {
			Conf.Internal.QueryHandlers[qtype] = make([]QueryHandlerFunc, 0)
		}
		Conf.Internal.QueryHandlers[qtype] = append(Conf.Internal.QueryHandlers[qtype], handler)
	}
	Conf.Internal.QueryHandlersMutex.Unlock()

	lg.Debug("RegisterQueryHandler: registered handler", "qtype", qtype)

	return nil
}

// getQueryHandlers returns the list of handlers for a given qtype, checking both
// global storage and conf storage. Handlers for the specific qtype are called first,
// followed by handlers registered with qtype=0 (all queries). This ensures application
// handlers (registered for specific qtypes) are called before default handlers.
func getQueryHandlers(conf *Config, qtype uint16) []QueryHandlerFunc {
	var handlers []QueryHandlerFunc

	// First, get handlers for the specific qtype (if qtype != 0)
	// These are application-specific handlers (like KDC) that should be called first
	if qtype != 0 {
		globalQueryHandlersMutex.RLock()
		if globalHandlers, ok := globalQueryHandlers[qtype]; ok {
			handlers = append(handlers, globalHandlers...)
		}
		globalQueryHandlersMutex.RUnlock()

		// Check conf storage
		if conf != nil && conf.Internal.QueryHandlers != nil {
			conf.Internal.QueryHandlersMutex.RLock()
			if confHandlers, ok := conf.Internal.QueryHandlers[qtype]; ok {
				handlers = append(handlers, confHandlers...)
			}
			conf.Internal.QueryHandlersMutex.RUnlock()
		}
	}

	// Then, get handlers for qtype=0 (all queries) - these are called after specific handlers
	// This includes debug handlers and default handlers (server, default zone-based)
	globalQueryHandlersMutex.RLock()
	if globalHandlers0, ok := globalQueryHandlers[0]; ok {
		handlers = append(handlers, globalHandlers0...)
	}
	globalQueryHandlersMutex.RUnlock()

	if conf != nil && conf.Internal.QueryHandlers != nil {
		conf.Internal.QueryHandlersMutex.RLock()
		if confHandlers0, ok := conf.Internal.QueryHandlers[0]; ok {
			handlers = append(handlers, confHandlers0...)
		}
		conf.Internal.QueryHandlersMutex.RUnlock()
	}

	return handlers
}

// NotifyHandlerFunc is the function signature for registered NOTIFY handlers.
// Returns ErrNotHandled if the handler doesn't handle this NOTIFY (allows fallthrough).
// Returns nil if the handler successfully handled the NOTIFY.
// Returns other error if handler attempted to handle but encountered an error.
type NotifyHandlerFunc func(ctx context.Context, req *DnsNotifyRequest) error

// RegisterNotifyHandler registers a handler for DNS NOTIFY messages.
// Multiple handlers can be registered for the same qtype - they will be called in registration order.
// If a handler returns ErrNotHandled, TDNS will try the next handler or fall back to default.
// If qtype is 0, handler is called for ALL NOTIFYs (use with caution, e.g., for debug handlers).
// Handlers registered with qtype=0 are called before handlers registered for specific qtypes.
//
// This function can be called before TDNS is initialized (uses global storage),
// or after initialization (uses conf.Internal.NotifyHandlers).
// During NOTIFY processing, TDNS checks both locations.
func RegisterNotifyHandler(qtype uint16, handler NotifyHandlerFunc) error {
	if handler == nil {
		return fmt.Errorf("handler cannot be nil")
	}

	// Register in conf if available; otherwise in global storage (copied to conf during MainInit).
	// Only one location to avoid getNotifyHandlers returning duplicates.
	Conf.Internal.NotifyHandlersMutex.Lock()
	if Conf.Internal.NotifyHandlers != nil {
		if Conf.Internal.NotifyHandlers[qtype] == nil {
			Conf.Internal.NotifyHandlers[qtype] = make([]NotifyHandlerFunc, 0)
		}
		Conf.Internal.NotifyHandlers[qtype] = append(Conf.Internal.NotifyHandlers[qtype], handler)
		Conf.Internal.NotifyHandlersMutex.Unlock()
	} else {
		Conf.Internal.NotifyHandlersMutex.Unlock()
		// Conf not initialized yet — register in global storage, will be copied to conf during MainInit
		globalNotifyHandlersMutex.Lock()
		globalNotifyHandlers[qtype] = append(globalNotifyHandlers[qtype], handler)
		globalNotifyHandlersMutex.Unlock()
	}

	lg.Debug("RegisterNotifyHandler: registered handler", "qtype", qtype)

	return nil
}

// getNotifyHandlers returns the list of handlers for a given qtype, checking both
// global storage and conf storage. Handlers registered with qtype=0 (all NOTIFYs)
// are included first, followed by handlers for the specific qtype.
func getNotifyHandlers(conf *Config, qtype uint16) []NotifyHandlerFunc {
	var handlers []NotifyHandlerFunc

	// First, get handlers for qtype=0 (all NOTIFYs) - these are called first
	globalNotifyHandlersMutex.RLock()
	if globalHandlers0, ok := globalNotifyHandlers[0]; ok {
		handlers = append(handlers, globalHandlers0...)
	}
	globalNotifyHandlersMutex.RUnlock()

	if conf != nil && conf.Internal.NotifyHandlers != nil {
		conf.Internal.NotifyHandlersMutex.RLock()
		if confHandlers0, ok := conf.Internal.NotifyHandlers[0]; ok {
			handlers = append(handlers, confHandlers0...)
		}
		conf.Internal.NotifyHandlersMutex.RUnlock()
	}

	// Then, get handlers for the specific qtype (if qtype != 0)
	if qtype != 0 {
		globalNotifyHandlersMutex.RLock()
		if globalHandlers, ok := globalNotifyHandlers[qtype]; ok {
			handlers = append(handlers, globalHandlers...)
		}
		globalNotifyHandlersMutex.RUnlock()

		// Check conf storage
		if conf != nil && conf.Internal.NotifyHandlers != nil {
			conf.Internal.NotifyHandlersMutex.RLock()
			if confHandlers, ok := conf.Internal.NotifyHandlers[qtype]; ok {
				handlers = append(handlers, confHandlers...)
			}
			conf.Internal.NotifyHandlersMutex.RUnlock()
		}
	}

	return handlers
}

// UpdateHandlerFunc is the function signature for registered UPDATE handlers.
// Returns ErrNotHandled if the handler doesn't handle this UPDATE (allows fallthrough).
// Returns nil if the handler successfully handled the UPDATE.
// Returns other error if handler attempted to handle but encountered an error.
type UpdateHandlerFunc func(ctx context.Context, req *DnsUpdateRequest) error

// UpdateMatcherFunc is the function signature for matching UPDATE messages.
// Returns true if the UPDATE should be handled by the associated handler.
// The matcher receives the DnsUpdateRequest and can inspect:
// - req.Qname (zone name from question section)
// - req.Msg.Ns (update section RRs)
// - req.Msg.Extra (additional section, e.g., SIG(0))
// - req.Options (EDNS0 options)
type UpdateMatcherFunc func(req *DnsUpdateRequest) bool

// UpdateHandlerRegistration stores an UPDATE handler registration
type UpdateHandlerRegistration struct {
	Matcher UpdateMatcherFunc
	Handler UpdateHandlerFunc
}

// RegisterUpdateHandler registers a handler for DNS UPDATE messages.
// The matcher function determines which UPDATEs should be handled by this handler.
// Multiple handlers can be registered - they will be called in registration order.
// If a handler returns ErrNotHandled, TDNS will try the next handler or fall back to default.
//
// This function can be called before TDNS is initialized (uses global storage),
// or after initialization (uses conf.Internal.UpdateHandlers).
// During UPDATE processing, TDNS checks both locations.
//
// Example usage:
//
//	// Match bootstrap UPDATEs (name pattern _bootstrap.*)
//	tdns.RegisterUpdateHandler(
//		func(req *tdns.DnsUpdateRequest) bool {
//			for _, rr := range req.Msg.Ns {
//				if strings.HasPrefix(rr.Header().Name, "_bootstrap.") {
//					return true
//				}
//			}
//			return false
//		},
//		func(ctx context.Context, req *tdns.DnsUpdateRequest) error {
//			return kdc.HandleBootstrapUpdate(ctx, req, kdcDB, &kdcConf)
//		},
//	)
func RegisterUpdateHandler(matcher UpdateMatcherFunc, handler UpdateHandlerFunc) error {
	if matcher == nil {
		return fmt.Errorf("matcher function cannot be nil")
	}
	if handler == nil {
		return fmt.Errorf("handler cannot be nil")
	}

	// Register in global storage (for early registration before conf is available)
	globalUpdateHandlersMutex.Lock()
	globalUpdateHandlers = append(globalUpdateHandlers, UpdateHandlerRegistration{
		Matcher: matcher,
		Handler: handler,
	})
	globalUpdateHandlersMutex.Unlock()

	// Also register in conf if available (and slice is initialized)
	Conf.Internal.UpdateHandlersMutex.Lock()
	if Conf.Internal.UpdateHandlers != nil {
		Conf.Internal.UpdateHandlers = append(Conf.Internal.UpdateHandlers, UpdateHandlerRegistration{
			Matcher: matcher,
			Handler: handler,
		})
	}
	Conf.Internal.UpdateHandlersMutex.Unlock()

	lg.Debug("RegisterUpdateHandler: registered UPDATE handler")

	return nil
}

// getUpdateHandlers returns the list of handlers that match the given UPDATE request,
// checking both global storage and conf storage.
func getUpdateHandlers(conf *Config, dur *DnsUpdateRequest) []UpdateHandlerFunc {
	var handlers []UpdateHandlerFunc

	// First, check global storage
	globalUpdateHandlersMutex.RLock()
	for _, reg := range globalUpdateHandlers {
		if reg.Matcher(dur) {
			handlers = append(handlers, reg.Handler)
		}
	}
	globalUpdateHandlersMutex.RUnlock()

	// Then, check conf storage
	if conf != nil && conf.Internal.UpdateHandlers != nil {
		conf.Internal.UpdateHandlersMutex.RLock()
		for _, reg := range conf.Internal.UpdateHandlers {
			if reg.Matcher(dur) {
				handlers = append(handlers, reg.Handler)
			}
		}
		conf.Internal.UpdateHandlersMutex.RUnlock()
	}

	return handlers
}

// EngineFunc is the function signature for registered engines.
// Engines are long-running goroutines that run until the context is cancelled.
// They should return nil when the context is cancelled, or an error if they fail.
type EngineFunc func(ctx context.Context) error

// EngineRegistration stores an engine registration
type EngineRegistration struct {
	Name   string
	Engine EngineFunc
}

// RegisterEngine registers a long-running engine that will be started by TDNS.
// Engines are started as goroutines and run until the context is cancelled.
// They are started after TDNS initialization is complete.
//
// Example usage:
//
//	tdns.RegisterEngine("KeyStateWorker", func(ctx context.Context) error {
//	    return kdc.KeyStateWorker(ctx, kdcDB, &kdcConf)
//	})
func RegisterEngine(name string, engine EngineFunc) error {
	if engine == nil {
		return fmt.Errorf("engine function cannot be nil")
	}
	if name == "" {
		return fmt.Errorf("engine name cannot be empty")
	}

	// Register in global storage
	globalEnginesMutex.Lock()
	globalEngines = append(globalEngines, EngineRegistration{Name: name, Engine: engine})
	globalEnginesMutex.Unlock()

	lg.Debug("RegisterEngine: registered engine", "name", name)

	return nil
}

// APIRouteFunc is the function signature for API route registration.
// The function receives the API router and should register routes on it.
type APIRouteFunc func(router *mux.Router) error

// APIRouteRegistration stores an API route registration
type APIRouteRegistration struct {
	RouteFunc APIRouteFunc
}

// RegisterAPIRoute registers a function that will add API routes to the router.
// IMPORTANT: The route registration function is called DURING SetupAPIRouter(),
// so routes must be registered BEFORE calling SetupAPIRouter().
// For apps that call SetupAPIRouter() before initializing their subsystems,
// routes should be registered directly on the router after SetupAPIRouter() returns,
// rather than using RegisterAPIRoute().
//
// Example usage:
//
//	tdns.RegisterAPIRoute(func(router *mux.Router) error {
//	    router.PathPrefix("/api/v1/kdc").HandlerFunc(kdc.APIKdcZone)
//	    return nil
//	})
func RegisterAPIRoute(routeFunc APIRouteFunc) error {
	if routeFunc == nil {
		return fmt.Errorf("route function cannot be nil")
	}

	// Register in global storage
	globalAPIRoutesMutex.Lock()
	globalAPIRoutes = append(globalAPIRoutes, APIRouteRegistration{RouteFunc: routeFunc})
	globalAPIRoutesMutex.Unlock()

	lg.Debug("RegisterAPIRoute: registered API route function")

	return nil
}

// getRegisteredEngines returns all registered engines
func getRegisteredEngines() []EngineRegistration {
	globalEnginesMutex.RLock()
	defer globalEnginesMutex.RUnlock()

	// Return a copy to avoid race conditions
	result := make([]EngineRegistration, len(globalEngines))
	copy(result, globalEngines)
	return result
}

// getRegisteredAPIRoutes returns all registered API route functions
func getRegisteredAPIRoutes() []APIRouteFunc {
	globalAPIRoutesMutex.RLock()
	defer globalAPIRoutesMutex.RUnlock()

	// Return a copy of the functions
	result := make([]APIRouteFunc, len(globalAPIRoutes))
	for i, reg := range globalAPIRoutes {
		result[i] = reg.RouteFunc
	}
	return result
}

// --- IMR Hook Registration ---
//
// These hooks allow external applications (like a dependency analysis tool) to
// observe and intercept IMR resolution without modifying the core resolver code.
// The pattern follows RegisterQueryHandler / RegisterNotifyHandler exactly.

// ImrClientQueryHookFunc is called when an external client query arrives at the IMR listener.
// Return nil ctx to keep the original context, or a new context to enrich it
// (e.g. to carry a parent query ID through the resolution chain).
// Return nil *dns.Msg to proceed with normal resolution.
// Return a non-nil *dns.Msg to short-circuit: the msg is sent as the response
// and resolution is skipped.
type ImrClientQueryHookFunc func(ctx context.Context, w dns.ResponseWriter,
	r *dns.Msg, qname string, qtype uint16,
	msgoptions *edns0.MsgOptions) (context.Context, *dns.Msg)

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

var (
	globalImrClientQueryHooks      []ImrClientQueryHookFunc
	globalImrClientQueryHooksMutex sync.RWMutex

	globalImrOutboundQueryHooks      []ImrOutboundQueryHookFunc
	globalImrOutboundQueryHooksMutex sync.RWMutex

	globalImrResponseHooks      []ImrResponseHookFunc
	globalImrResponseHooksMutex sync.RWMutex
)

// RegisterImrClientQueryHook registers a hook that is called when an external
// client query arrives at the IMR listener. Multiple hooks can be registered
// and are called in registration order.
func RegisterImrClientQueryHook(hook ImrClientQueryHookFunc) error {
	if hook == nil {
		return fmt.Errorf("hook cannot be nil")
	}
	globalImrClientQueryHooksMutex.Lock()
	globalImrClientQueryHooks = append(globalImrClientQueryHooks, hook)
	globalImrClientQueryHooksMutex.Unlock()
	lg.Debug("RegisterImrClientQueryHook: registered hook")
	return nil
}

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
	lg.Debug("RegisterImrOutboundQueryHook: registered hook")
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
	lg.Debug("RegisterImrResponseHook: registered hook")
	return nil
}

// getImrClientQueryHooks returns all registered client query hooks.
func getImrClientQueryHooks() []ImrClientQueryHookFunc {
	globalImrClientQueryHooksMutex.RLock()
	defer globalImrClientQueryHooksMutex.RUnlock()
	return globalImrClientQueryHooks
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

// StartRegisteredEngines starts all registered engines as goroutines.
// This should be called after TDNS initialization is complete.
// Engines run until the context is cancelled.
func StartRegisteredEngines(ctx context.Context) {
	engines := getRegisteredEngines()
	var names []string
	for _, e := range engines {
		names = append(names, e.Name)
	}
	lg.Info("starting registered engines", "count", len(engines), "names", names)
	// engines := getRegisteredEngines()
	for _, reg := range engines {
		name := reg.Name
		engine := reg.Engine
		lg.Info("StartRegisteredEngines: starting engine", "name", name)
		StartEngine(&Globals.App, name, func() error {
			return engine(ctx)
		})
	}
}
