/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Router initialization and handler registration.
 */

package transport

import (
	"encoding/json"
	"log"

	"github.com/miekg/dns"
)

// RouterConfig holds configuration for router initialization.
type RouterConfig struct {
	// TransportManager for authorization middleware
	TransportManager interface {
		IsAgentAuthorized(senderID string, zone string) (bool, string)
	}

	// PeerRegistry for statistics tracking
	PeerRegistry *PeerRegistry

	// PayloadCrypto for signature and decryption middleware
	PayloadCrypto *PayloadCrypto

	// IncomingChan for routing messages to hsyncengine
	IncomingChan chan<- *IncomingMessage

	// ResponseWriter for sending DNS responses
	ResponseWriter dns.ResponseWriter

	// RequestMsg for DNS response correlation
	RequestMsg *dns.Msg

	// TriggerDiscoveryOnMissingKey enables auto-discovery
	TriggerDiscoveryOnMissingKey bool

	// AllowUnencrypted allows unencrypted payloads (for testing/compatibility)
	AllowUnencrypted bool

	// VerboseStats enables verbose logging for statistics middleware
	VerboseStats bool
}

// InitializeRouter registers all handlers and middleware with the router.
func InitializeRouter(router *DNSMessageRouter, cfg *RouterConfig) error {
	if router == nil {
		return nil // No router to initialize
	}

	log.Printf("InitializeRouter: Registering handlers and middleware")

	// Register global middleware (executed in order for all messages)
	// Order matters: outer middleware wraps inner middleware

	// 1. Authorization (outermost - prevents unauthorized access)
	if cfg.TransportManager != nil {
		router.Use(NewAuthorizationMiddleware(cfg.TransportManager))
		log.Printf("InitializeRouter: Registered authorization middleware")
	}

	// 2. Signature verification (authenticates sender)
	if cfg.PayloadCrypto != nil && cfg.PayloadCrypto.Enabled {
		cryptoCfg := &CryptoMiddlewareConfig{
			PayloadCrypto:                cfg.PayloadCrypto,
			TriggerDiscoveryOnMissingKey: cfg.TriggerDiscoveryOnMissingKey,
			AllowUnencrypted:             cfg.AllowUnencrypted,
		}
		router.Use(NewSignatureMiddleware(cryptoCfg))
		log.Printf("InitializeRouter: Registered signature middleware")
	}

	// 3. Statistics tracking (after authentication, before processing)
	if cfg.PeerRegistry != nil {
		statsCfg := &StatsMiddlewareConfig{
			PeerRegistry: cfg.PeerRegistry,
			Verbose:      cfg.VerboseStats,
		}
		router.Use(NewStatsMiddleware(statsCfg))
		log.Printf("InitializeRouter: Registered statistics middleware")
	}

	// 4. Logging (for visibility)
	router.Use(NewLoggingMiddleware(true))
	log.Printf("InitializeRouter: Registered logging middleware")

	// 5. Route to hsyncengine (after processing)
	if cfg.IncomingChan != nil {
		router.Use(RouteToHsyncEngine(cfg.IncomingChan))
		log.Printf("InitializeRouter: Registered hsyncengine routing middleware")
	}

	// Register message handlers (by message type)

	// Confirmation handler (priority: 100)
	err := router.Register(
		"ConfirmationHandler",
		MessageType("confirm"),
		HandleConfirmation,
		WithPriority(100),
		WithDescription("Processes confirmation messages for pending operations"),
	)
	if err != nil {
		return err
	}

	// Ping handler (priority: 100)
	err = router.Register(
		"PingHandler",
		MessageType("ping"),
		HandlePing,
		WithPriority(100),
		WithDescription("Processes ping messages and sends immediate echo response"),
	)
	if err != nil {
		return err
	}

	// Hello handler (priority: 100)
	err = router.Register(
		"HelloHandler",
		MessageType("hello"),
		HandleHello,
		WithPriority(100),
		WithDescription("Processes Hello messages for peer introduction"),
	)
	if err != nil {
		return err
	}

	// Beat handler (priority: 100)
	err = router.Register(
		"BeatHandler",
		MessageType("beat"),
		HandleBeat,
		WithPriority(100),
		WithDescription("Processes heartbeat messages from peers"),
	)
	if err != nil {
		return err
	}

	// Sync handler (priority: 100)
	err = router.Register(
		"SyncHandler",
		MessageType("sync"),
		HandleSync,
		WithPriority(100),
		WithDescription("Processes zone synchronization messages"),
	)
	if err != nil {
		return err
	}

	// Relocate handler (priority: 100)
	err = router.Register(
		"RelocateHandler",
		MessageType("relocate"),
		HandleRelocate,
		WithPriority(100),
		WithDescription("Processes relocate messages for DDoS mitigation"),
	)
	if err != nil {
		return err
	}

	log.Printf("InitializeRouter: Registered 6 message handlers")
	log.Printf("InitializeRouter: Router initialization complete")

	return nil
}

// DetermineMessageType parses the payload to determine the message type.
// MessageType is now a string field ("sync", "beat", "ping", etc.).
// Falls back to legacy "type" field for backwards compatibility.
func DetermineMessageType(payload []byte) MessageType {
	var fields struct {
		MessageType string `json:"MessageType"` // Standard format (string)
		Type        string `json:"type"`        // Legacy format (fallback)
	}
	if err := json.Unmarshal(payload, &fields); err != nil {
		return MessageTypeUnknown
	}

	msgType := fields.MessageType
	if msgType == "" {
		msgType = fields.Type
	}

	switch msgType {
	case "hello":
		return MessageType("hello")
	case "beat":
		return MessageType("beat")
	case "sync":
		return MessageType("sync")
	case "ping":
		return MessageType("ping")
	case "confirm":
		return MessageType("confirm")
	case "relocate":
		return MessageType("relocate")
	default:
		return MessageTypeUnknown
	}
}
