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
	"log"
	"sync"

	"github.com/gorilla/mux"
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
	globalQueryHandlers   = make(map[uint16][]QueryHandlerFunc)
	globalQueryHandlersMutex sync.RWMutex
	
	globalNotifyHandlers   = make(map[uint16][]NotifyHandlerFunc)
	globalNotifyHandlersMutex sync.RWMutex
	
	globalEngines   = make([]EngineRegistration, 0)
	globalEnginesMutex sync.RWMutex
	
	globalAPIRoutes   = make([]APIRouteRegistration, 0)
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
	if Conf.Internal.QueryHandlers != nil {
		Conf.Internal.QueryHandlersMutex.Lock()
		if Conf.Internal.QueryHandlers[qtype] == nil {
			Conf.Internal.QueryHandlers[qtype] = make([]QueryHandlerFunc, 0)
		}
		Conf.Internal.QueryHandlers[qtype] = append(Conf.Internal.QueryHandlers[qtype], handler)
		Conf.Internal.QueryHandlersMutex.Unlock()
	} else {
		// Conf not initialized yet, will be copied from global storage during MainInit
	}

	if Globals.Debug {
		log.Printf("RegisterQueryHandler: Registered handler for qtype %d", qtype)
	}

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

	// Register in global storage (for early registration before conf is available)
	globalNotifyHandlersMutex.Lock()
	globalNotifyHandlers[qtype] = append(globalNotifyHandlers[qtype], handler)
	globalNotifyHandlersMutex.Unlock()

	// Also register in conf if available (and map is initialized)
	if Conf.Internal.NotifyHandlers != nil {
		Conf.Internal.NotifyHandlersMutex.Lock()
		if Conf.Internal.NotifyHandlers[qtype] == nil {
			Conf.Internal.NotifyHandlers[qtype] = make([]NotifyHandlerFunc, 0)
		}
		Conf.Internal.NotifyHandlers[qtype] = append(Conf.Internal.NotifyHandlers[qtype], handler)
		Conf.Internal.NotifyHandlersMutex.Unlock()
	} else {
		// Conf not initialized yet, will be copied from global storage during MainInit
	}

	if Globals.Debug {
		log.Printf("RegisterNotifyHandler: Registered handler for qtype %d", qtype)
	}

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

// EngineFunc is the function signature for registered engines.
// Engines are long-running goroutines that run until the context is cancelled.
// They should return nil when the context is cancelled, or an error if they fail.
type EngineFunc func(ctx context.Context) error

// EngineRegistration stores an engine registration
type EngineRegistration struct {
	Name    string
	Engine  EngineFunc
}

// RegisterEngine registers a long-running engine that will be started by TDNS.
// Engines are started as goroutines and run until the context is cancelled.
// They are started after TDNS initialization is complete.
//
// Example usage:
//   tdns.RegisterEngine("KeyStateWorker", func(ctx context.Context) error {
//       return kdc.KeyStateWorker(ctx, kdcDB, &kdcConf)
//   })
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

	if Globals.Debug {
		log.Printf("RegisterEngine: Registered engine '%s'", name)
	}

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
// The route registration function is called after SetupAPIRouter() completes,
// allowing external code to add routes without TDNS knowing about them.
//
// Example usage:
//   tdns.RegisterAPIRoute(func(router *mux.Router) error {
//       router.PathPrefix("/api/v1/kdc").HandlerFunc(kdc.APIKdcZone)
//       return nil
//   })
func RegisterAPIRoute(routeFunc APIRouteFunc) error {
	if routeFunc == nil {
		return fmt.Errorf("route function cannot be nil")
	}

	// Register in global storage
	globalAPIRoutesMutex.Lock()
	globalAPIRoutes = append(globalAPIRoutes, APIRouteRegistration{RouteFunc: routeFunc})
	globalAPIRoutesMutex.Unlock()

	if Globals.Debug {
		log.Printf("RegisterAPIRoute: Registered API route function")
	}

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

// StartRegisteredEngines starts all registered engines as goroutines.
// This should be called after TDNS initialization is complete.
// Engines run until the context is cancelled.
func StartRegisteredEngines(ctx context.Context) {
	engines := getRegisteredEngines()
	for _, reg := range engines {
		name := reg.Name
		engine := reg.Engine
		startEngine(&Globals.App, name, func() error {
			return engine(ctx)
		})
	}
}
