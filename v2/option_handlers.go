/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdns

import "sync"

// ZoneOptionHandler is a callback invoked during ParseZones when a
// zone has a specific option set. Handlers are registered before
// ParseZones runs and fire synchronously during parsing.
//
// Parameters:
//   - zname: the FQDN zone name
//   - options: all parsed options for this zone (read-only)
type ZoneOptionHandler func(zname string, options map[ZoneOption]bool)

var (
	optionHandlersMu sync.Mutex
	optionHandlers   = make(map[ZoneOption][]ZoneOptionHandler)
)

// RegisterZoneOptionHandler registers a callback for a zone option.
// Multiple handlers can be registered for the same option.
// Handlers fire synchronously during ParseZones, in registration order.
func RegisterZoneOptionHandler(opt ZoneOption, handler ZoneOptionHandler) {
	optionHandlersMu.Lock()
	defer optionHandlersMu.Unlock()
	optionHandlers[opt] = append(optionHandlers[opt], handler)
}

// invokeOptionHandlers calls all registered handlers for the given
// zone's options. Returns the set of options that were handled by
// at least one registered handler (used for unknown-option detection).
func invokeOptionHandlers(zname string, options map[ZoneOption]bool) map[ZoneOption]bool {
	optionHandlersMu.Lock()
	defer optionHandlersMu.Unlock()
	handled := make(map[ZoneOption]bool)
	for opt, val := range options {
		if !val {
			continue
		}
		if handlers, ok := optionHandlers[opt]; ok && len(handlers) > 0 {
			for _, handler := range handlers {
				handler(zname, options)
			}
			handled[opt] = true
		}
	}
	return handled
}
