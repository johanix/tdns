/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Statistics middleware for tracking message counters per peer.
 */

package transport

import (
	"log"
)

// StatsMiddlewareConfig holds configuration for stats middleware.
type StatsMiddlewareConfig struct {
	// PeerRegistry for looking up peers and recording stats
	PeerRegistry *PeerRegistry

	// Verbose logging
	Verbose bool
}

// NewStatsMiddleware creates middleware for tracking message statistics.
// This middleware records:
//   - Per-message-type counters (hello, beat, sync, ping)
//   - Separate sent/received counters
//   - Last Used timestamp (updated on every message)
//   - Total distribution counts
//
// The middleware runs AFTER authorization, so we know the peer is valid.
func NewStatsMiddleware(cfg *StatsMiddlewareConfig) MiddlewareFunc {
	return func(ctx *MessageContext, next MessageHandlerFunc) error {
		// Skip if no peer registry
		if cfg.PeerRegistry == nil {
			return next(ctx)
		}

		// Skip if we don't have a peer ID
		if ctx.PeerID == "" {
			return next(ctx)
		}

		// Get or create peer in registry
		peer := cfg.PeerRegistry.GetOrCreate(ctx.PeerID)

		// Determine message type from context
		// The router has already parsed and validated the message type
		msgType := ""
		if incomingMsg, ok := ctx.Data["incoming_message"].(*IncomingMessage); ok {
			msgType = incomingMsg.Type
		}

		// Record incoming message statistics
		if msgType != "" {
			peer.Stats.RecordMessageReceived(msgType)

			lastUsed, totalSent, totalReceived := peer.Stats.GetStats()
			log.Printf("StatsMiddleware: Peer %s - %s received (total: %d sent, %d received, last used: %s)",
				ctx.PeerID, msgType, totalSent, totalReceived, lastUsed.Format("15:04:05"))
		} else {
			log.Printf("StatsMiddleware: Warning - no message type found for peer %s", ctx.PeerID)
		}

		// Continue processing
		return next(ctx)
	}
}
