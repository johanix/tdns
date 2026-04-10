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

// ZoneOptionValidator is a callback invoked during parseZoneOptions
// when a specific zone option is encountered. Unlike handlers,
// validators run *during* the switch (not after) and can reject
// the option.
//
// Return true to accept the option, false to reject it.
// On rejection, the validator should call zd.SetError() to
// record a ConfigError explaining the rejection. The caller
// will skip this option and continue parsing the rest.
type ZoneOptionValidator func(conf *Config, zname string, zd *ZoneData, options map[ZoneOption]bool) bool

var (
	optionHandlersMu sync.Mutex
	optionHandlers   = make(map[ZoneOption][]ZoneOptionHandler)

	optionValidatorsMu sync.Mutex
	optionValidators   = make(map[ZoneOption]ZoneOptionValidator)
)

// RegisterZoneOptionHandler registers a callback for a zone option.
// Multiple handlers can be registered for the same option.
// Handlers fire synchronously during ParseZones, in registration order.
func RegisterZoneOptionHandler(opt ZoneOption, handler ZoneOptionHandler) {
	optionHandlersMu.Lock()
	defer optionHandlersMu.Unlock()
	optionHandlers[opt] = append(optionHandlers[opt], handler)
}

// RegisterZoneOptionValidator registers a validator for a zone option.
// Only one validator per option is supported; a second registration
// for the same option replaces the first.
//
// Validators run during parseZoneOptions (inside the switch) and
// can reject the option by returning false. They should call
// zd.SetError(ConfigError, ...) to record the reason for rejection.
//
// Register validators before ParseZones runs (e.g. from MainInit
// before calling the parent MainInit).
func RegisterZoneOptionValidator(opt ZoneOption, validator ZoneOptionValidator) {
	optionValidatorsMu.Lock()
	defer optionValidatorsMu.Unlock()
	optionValidators[opt] = validator
}

// invokeOptionValidator calls the registered validator for a zone
// option, if one exists. Returns true if the option is accepted
// (either because no validator is registered, or the validator
// returned true). Returns false only if a registered validator
// explicitly rejected the option.
func invokeOptionValidator(opt ZoneOption, conf *Config, zname string, zd *ZoneData, options map[ZoneOption]bool) bool {
	optionValidatorsMu.Lock()
	validator, ok := optionValidators[opt]
	optionValidatorsMu.Unlock()
	if !ok {
		return true // no validator registered, accept by default
	}
	return validator(conf, zname, zd, options)
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
