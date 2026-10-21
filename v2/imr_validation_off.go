/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

// DnssecValidationOffWarning is what a daemon says, first, while its resolver
// takes answers it did not validate (DnssecValidationOff).
const DnssecValidationOffWarning = "DNSSEC validation: OFF (imrengine.require-dnssec-validation: false)"

// DnssecValidationOff reports whether this daemon's resolver takes answers it
// could not validate for the lookups that require validation: TLSA, the
// discovery of peers, and the others that read RequireDnssecValidation
// (imrengine.require-dnssec-validation: false). It is the running resolver's
// setting once the resolver is up, and the configuration's before. A daemon
// that runs no resolver reports false.
//
// A setting that was turned off to get past a broken chain is easily
// forgotten, so the daemon says so where the operator looks (daemon status).
func (conf *Config) DnssecValidationOff() bool {
	if conf == nil {
		return false
	}
	if conf.Internal.ImrReady.Published() {
		imr := conf.Internal.ImrEngine
		return imr != nil && !imr.RequireDnssecValidation
	}
	if conf.Imr.Active != nil && !*conf.Imr.Active {
		return false
	}
	return conf.Imr.RequireDnssecValidation != nil && !*conf.Imr.RequireDnssecValidation
}
