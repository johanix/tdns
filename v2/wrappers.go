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
)

// ZoneDataWeAreASigner wraps the unexported weAreASigner method.
func ZoneDataWeAreASigner(zd *ZoneData) (bool, error) {
	return zd.weAreASigner()
}

// CombinerStateSetChunkHandler wraps setting the unexported
// chunkHandler field on CombinerState.
func CombinerStateSetChunkHandler(cs *CombinerState, handler *transport.ChunkNotifyHandler) {
	cs.chunkHandler = handler
}
