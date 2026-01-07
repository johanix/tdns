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
// global storage and conf storage. Handlers registered with qtype=0 (all queries)
// are included first, followed by handlers for the specific qtype.
func getQueryHandlers(conf *Config, qtype uint16) []QueryHandlerFunc {
	var handlers []QueryHandlerFunc

	// First, get handlers for qtype=0 (all queries) - these are called first
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

	// Then, get handlers for the specific qtype (if qtype != 0)
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

