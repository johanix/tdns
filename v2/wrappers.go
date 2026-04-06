/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Wrappers for unexported functions/methods needed by tdns-mp.
 * These export functionality that tdns-mp cannot access directly
 * because it is a different package.
 */
package tdns

import (
	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/miekg/dns"
)

// ZoneDataCombineWithLocalChanges wraps the CombineWithLocalChanges method
// for use by tdns-mp (will become standalone there).
func ZoneDataCombineWithLocalChanges(zd *ZoneData) (bool, error) {
	return zd.CombineWithLocalChanges()
}

// ZoneDataWeAreASigner wraps the unexported weAreASigner method.
func ZoneDataWeAreASigner(zd *ZoneData) (bool, error) {
	return zd.weAreASigner()
}

// CombinerStateSetChunkHandler wraps setting the unexported
// chunkHandler field on CombinerState.
func CombinerStateSetChunkHandler(cs *CombinerState, handler *transport.ChunkNotifyHandler) {
	if cs == nil {
		return
	}
	cs.ChunkNotifyHandler = handler
}

// OurHsyncIdentities wraps the unexported ourHsyncIdentities function.
func OurHsyncIdentities() []string {
	return ourHsyncIdentities()
}

// ZoneDataMatchHsyncProvider wraps the unexported matchHsyncProvider method.
func ZoneDataMatchHsyncProvider(zd *ZoneData, ourIdentities []string) (bool, string, error) {
	return zd.matchHsyncProvider(ourIdentities)
}

// ZoneDataSynthesizeCdsRRs wraps the unexported synthesizeCdsRRs method.
func ZoneDataSynthesizeCdsRRs(zd *ZoneData) ([]dns.RR, error) {
	return zd.synthesizeCdsRRs()
}
