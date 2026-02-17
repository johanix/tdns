/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Cryptographic middleware for DNS message router.
 * Provides two-stage security: JWS signature verification → JWE decryption.
 */

package transport

import (
	"fmt"
	"log"
)

// SecurityEvent represents a security-related event that should be logged/alerted.
type SecurityEvent struct {
	Type      string // "signature_failure", "decryption_failure", "missing_key", etc.
	PeerID    string
	Reason    string
	Severity  string // "info", "warning", "critical"
	Timestamp string
}

// SecurityEventLogger is an interface for logging security events.
type SecurityEventLogger interface {
	LogSecurityEvent(event SecurityEvent)
}

// DefaultSecurityLogger logs security events to standard log.
type DefaultSecurityLogger struct{}

func (l *DefaultSecurityLogger) LogSecurityEvent(event SecurityEvent) {
	log.Printf("[SECURITY-%s] %s: peer=%s reason=%s",
		event.Severity, event.Type, event.PeerID, event.Reason)
}

// CryptoMiddlewareConfig holds configuration for crypto middleware.
type CryptoMiddlewareConfig struct {
	// PayloadCrypto is the crypto backend for JWS/JWE operations
	PayloadCrypto *PayloadCrypto

	// SecurityLogger for logging security events (forgery attempts, missing keys, etc.)
	SecurityLogger SecurityEventLogger

	// TriggerDiscoveryOnMissingKey: when true, missing verification key triggers discovery
	// instead of rejecting the message. Useful for auto-bootstrapping peer relationships.
	TriggerDiscoveryOnMissingKey bool

	// AllowUnencrypted: when true, allows unencrypted payloads to pass through
	// even when crypto is enabled. Useful for backward compatibility or mixed deployments.
	AllowUnencrypted bool
}

// NewSignatureMiddleware creates middleware for JWS signature verification.
// This is stage 1 of two-stage crypto: authenticate the sender.
//
// Behavior:
//   - If signature is valid: sets ctx.SignatureValid=true, continues to next middleware
//   - If signature is invalid: logs CRITICAL security event (forgery attempt), returns error
//   - If peer verification key is missing:
//   - With TriggerDiscoveryOnMissingKey=true: logs INFO, triggers discovery, continues
//   - With TriggerDiscoveryOnMissingKey=false: logs WARNING, returns error
//   - If crypto is disabled: passes through without verification
func NewSignatureMiddleware(cfg *CryptoMiddlewareConfig) MiddlewareFunc {
	if cfg.SecurityLogger == nil {
		cfg.SecurityLogger = &DefaultSecurityLogger{}
	}

	return func(ctx *MessageContext, next MessageHandlerFunc) error {
		// Skip if crypto is disabled
		if cfg.PayloadCrypto == nil || !cfg.PayloadCrypto.Enabled {
			return next(ctx)
		}

		// Skip if no chunk payload (nothing to verify)
		if len(ctx.ChunkPayload) == 0 {
			return next(ctx)
		}

		// Skip if already processed (e.g., by RouteViaRouter)
		// ChunkCrypted=false with SignatureValid=true means it was already decrypted/verified upstream
		if !ctx.ChunkCrypted && ctx.SignatureValid {
			log.Printf("SignatureMiddleware: Skipping - payload already decrypted/verified upstream (peer %s)",
				ctx.PeerID)
			return next(ctx)
		}

		// Skip if payload is not encrypted/signed
		if !IsPayloadEncrypted(ctx.ChunkPayload) {
			if cfg.AllowUnencrypted {
				log.Printf("SignatureMiddleware: Allowing unencrypted payload from peer %s (AllowUnencrypted=true)",
					ctx.PeerID)
				return next(ctx)
			}
			return fmt.Errorf("unencrypted payload not allowed (crypto is enabled)")
		}

		// Check if we have the peer's verification key
		_, hasKey := cfg.PayloadCrypto.GetPeerVerificationKey(ctx.PeerID)
		if !hasKey {
			if cfg.TriggerDiscoveryOnMissingKey {
				// Missing key triggers discovery (expected during bootstrapping)
				cfg.SecurityLogger.LogSecurityEvent(SecurityEvent{
					Type:      "missing_verification_key",
					PeerID:    ctx.PeerID,
					Reason:    "no verification key available, triggering discovery",
					Severity:  "info",
					Timestamp: ctx.StartTime.Format("2006-01-02T15:04:05Z07:00"),
				})
				// TODO: Trigger discovery process here
				// For now, we'll allow the message through and let downstream handlers decide
				ctx.SignatureValid = false
				ctx.SignatureReason = "missing_verification_key"
				return next(ctx)
			}

			// Missing key without discovery is a warning
			cfg.SecurityLogger.LogSecurityEvent(SecurityEvent{
				Type:      "missing_verification_key",
				PeerID:    ctx.PeerID,
				Reason:    "no verification key available, rejecting message",
				Severity:  "warning",
				Timestamp: ctx.StartTime.Format("2006-01-02T15:04:05Z07:00"),
			})
			return fmt.Errorf("no verification key for peer %s", ctx.PeerID)
		}

		// At this point, we have an encrypted payload and the peer's verification key.
		// The payload is JWS(JWE(plaintext)). We need to verify the JWS signature.
		// Note: We don't decrypt here - that's stage 2 (DecryptionMiddleware).

		// For signature verification, we need to extract and verify just the JWS layer.
		// The DecryptAndVerifyPayload function does both stages, but we want to separate them.
		// For now, we'll use a simpler approach: if DecryptAndVerifyPayload succeeds,
		// the signature was valid. We'll refactor this later to truly separate the stages.

		// Create a wrapper for single-peer decryption
		wrapper := NewSecurePayloadWrapper(cfg.PayloadCrypto)
		decrypted, err := wrapper.UnwrapIncomingFromPeer(ctx.ChunkPayload, ctx.PeerID)
		if err != nil {
			// This could be either signature failure OR decryption failure
			// We can't distinguish without parsing the JWS structure
			cfg.SecurityLogger.LogSecurityEvent(SecurityEvent{
				Type:      "signature_verification_failure",
				PeerID:    ctx.PeerID,
				Reason:    fmt.Sprintf("signature verification failed: %v", err),
				Severity:  "critical",
				Timestamp: ctx.StartTime.Format("2006-01-02T15:04:05Z07:00"),
			})
			return fmt.Errorf("signature verification failed for peer %s: %w", ctx.PeerID, err)
		}

		// Signature is valid, store decrypted payload
		ctx.ChunkPayload = decrypted
		ctx.SignatureValid = true
		ctx.SignatureReason = "signature_verified"
		ctx.ChunkSigned = true
		ctx.ChunkCrypted = true

		return next(ctx)
	}
}

// NewDecryptionMiddleware creates middleware for JWE decryption.
// This is stage 2 of two-stage crypto: decrypt the confidential payload.
//
// Behavior:
//   - If decryption succeeds: replaces ctx.ChunkPayload with plaintext, continues
//   - If decryption fails: logs INFO (wrong recipient, not an error), silently drops message
//   - If crypto is disabled: passes through without decryption
//
// Note: This middleware runs AFTER signature verification, so we know the sender
// is authentic. Decryption failure just means the message wasn't for us (multi-recipient JWE).
func NewDecryptionMiddleware(cfg *CryptoMiddlewareConfig) MiddlewareFunc {
	if cfg.SecurityLogger == nil {
		cfg.SecurityLogger = &DefaultSecurityLogger{}
	}

	return func(ctx *MessageContext, next MessageHandlerFunc) error {
		// Skip if crypto is disabled
		if cfg.PayloadCrypto == nil || !cfg.PayloadCrypto.Enabled {
			return next(ctx)
		}

		// Skip if no chunk payload
		if len(ctx.ChunkPayload) == 0 {
			return next(ctx)
		}

		// Skip if payload is not encrypted
		if !IsPayloadEncrypted(ctx.ChunkPayload) {
			return next(ctx)
		}

		// Skip if already decrypted by SignatureMiddleware
		if ctx.ChunkCrypted && ctx.SignatureValid {
			// Already decrypted in signature middleware
			return next(ctx)
		}

		// Decrypt the payload
		wrapper := NewSecurePayloadWrapper(cfg.PayloadCrypto)
		decrypted, err := wrapper.UnwrapIncomingFromPeer(ctx.ChunkPayload, ctx.PeerID)
		if err != nil {
			// Decryption failure is not necessarily an error - could be wrong recipient
			// in multi-recipient JWE scenario. Log as INFO and silently drop.
			cfg.SecurityLogger.LogSecurityEvent(SecurityEvent{
				Type:      "decryption_failure",
				PeerID:    ctx.PeerID,
				Reason:    fmt.Sprintf("not intended recipient: %v", err),
				Severity:  "info",
				Timestamp: ctx.StartTime.Format("2006-01-02T15:04:05Z07:00"),
			})
			// Silently drop - don't call next()
			return nil
		}

		// Decryption succeeded
		ctx.ChunkPayload = decrypted
		ctx.ChunkCrypted = true

		return next(ctx)
	}
}

// NewAuthorizationMiddleware creates middleware for agent authorization checking.
// This runs BEFORE crypto middleware to prevent unauthorized peers from triggering
// expensive crypto operations.
//
// Authorization paths:
//  1. Explicit: agent.authorized_peers config
//  2. Implicit: HSYNC RRset membership for shared zones
//
// Behavior:
//   - If authorized: sets ctx.Authorized=true, ctx.AuthorizedVia, continues
//   - If not authorized: logs WARNING security event, returns error
func NewAuthorizationMiddleware(tm interface {
	IsPeerAuthorized(senderID string, zone string) (bool, string)
}) MiddlewareFunc {
	logger := &DefaultSecurityLogger{}

	return func(ctx *MessageContext, next MessageHandlerFunc) error {
		// Extract zone from context if available (for HSYNC check)
		zone := ""
		if zoneVal, ok := ctx.Data["zone"]; ok {
			if zoneStr, ok := zoneVal.(string); ok {
				zone = zoneStr
			}
		}

		// Check authorization
		authorized, reason := tm.IsPeerAuthorized(ctx.PeerID, zone)
		if !authorized {
			logger.LogSecurityEvent(SecurityEvent{
				Type:      "unauthorized_peer",
				PeerID:    ctx.PeerID,
				Reason:    reason,
				Severity:  "warning",
				Timestamp: ctx.StartTime.Format("2006-01-02T15:04:05Z07:00"),
			})
			return fmt.Errorf("peer %s not authorized: %s", ctx.PeerID, reason)
		}

		// Mark as authorized
		ctx.Authorized = true
		ctx.AuthReason = reason

		// Determine authorization path
		if len(reason) > 0 {
			if reason == "authorized via config (agent.authorized_peers)" {
				ctx.AuthorizedVia = "explicit"
			} else {
				ctx.AuthorizedVia = "implicit"
			}
		}

		return next(ctx)
	}
}

// NewLoggingMiddleware creates middleware for request/response logging.
func NewLoggingMiddleware(verbose bool) MiddlewareFunc {
	return func(ctx *MessageContext, next MessageHandlerFunc) error {
		if verbose {
			log.Printf("LoggingMiddleware: Processing message from %s (peer=%s, distrib=%s)",
				ctx.RemoteAddr, ctx.PeerID, ctx.DistributionID)
		}

		err := next(ctx)

		if verbose {
			if err != nil {
				log.Printf("LoggingMiddleware: Message processing failed: %v", err)
			} else {
				log.Printf("LoggingMiddleware: Message processed successfully")
			}
		}

		return err
	}
}

// NewMetricsMiddleware creates middleware for metrics collection.
func NewMetricsMiddleware(collector interface {
	RecordMetric(name string, value float64)
}) MiddlewareFunc {
	return func(ctx *MessageContext, next MessageHandlerFunc) error {
		err := next(ctx)

		// Record metrics after processing
		if collector != nil {
			if err != nil {
				collector.RecordMetric("message.errors", 1)
			} else {
				collector.RecordMetric("message.success", 1)
			}

			if ctx.Authorized {
				collector.RecordMetric("message.authorized", 1)
			}

			if ctx.SignatureValid {
				collector.RecordMetric("message.signature_valid", 1)
			}
		}

		return err
	}
}
