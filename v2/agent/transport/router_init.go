/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Router initialization and handler registration.
 */

package transport

import (
	"encoding/json"

	"github.com/miekg/dns"
)

// RouterConfig holds configuration for router initialization.
type RouterConfig struct {
	// TransportManager for authorization middleware
	TransportManager interface {
		IsPeerAuthorized(senderID string, zone string) (bool, string)
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

	lgTransport().Info("registering handlers and middleware")

	// Register default handler for unregistered message types
	router.SetDefaultHandler(DefaultUnsupportedHandler)

	// Register global middleware (executed in order for all messages)
	// Order matters: outer middleware wraps inner middleware

	// 1. Authorization (outermost - prevents unauthorized access)
	if cfg.TransportManager != nil {
		router.Use(NewAuthorizationMiddleware(cfg.TransportManager))
		lgTransport().Info("registered authorization middleware")
	}

	// 2. Signature verification (authenticates sender)
	if cfg.PayloadCrypto != nil && cfg.PayloadCrypto.Enabled {
		cryptoCfg := &CryptoMiddlewareConfig{
			PayloadCrypto:                cfg.PayloadCrypto,
			TriggerDiscoveryOnMissingKey: cfg.TriggerDiscoveryOnMissingKey,
			AllowUnencrypted:             cfg.AllowUnencrypted,
		}
		router.Use(NewSignatureMiddleware(cryptoCfg))
		lgTransport().Info("registered signature middleware")
	}

	// 3. Statistics tracking (after authentication, before processing)
	if cfg.PeerRegistry != nil {
		statsCfg := &StatsMiddlewareConfig{
			PeerRegistry: cfg.PeerRegistry,
			Verbose:      cfg.VerboseStats,
		}
		router.Use(NewStatsMiddleware(statsCfg))
		lgTransport().Info("registered statistics middleware")
	}

	// 4. Logging (for visibility)
	router.Use(NewLoggingMiddleware(true))
	lgTransport().Info("registered logging middleware")

	// 5. Route to message handler goroutine (after processing)
	if cfg.IncomingChan != nil {
		router.Use(RouteToMsgHandler(cfg.IncomingChan))
		lgTransport().Info("registered message handler routing middleware")
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

	// RFI handler (priority: 100)
	err = router.Register(
		"RfiHandler",
		MessageType("rfi"),
		HandleRfi,
		WithPriority(100),
		WithDescription("Processes RFI (Request For Information) messages"),
	)
	if err != nil {
		return err
	}

	// Keystate handler (priority: 100)
	err = router.Register(
		"KeystateHandler",
		MessageType("keystate"),
		HandleKeystate,
		WithPriority(100),
		WithDescription("Processes KEYSTATE messages for key lifecycle signaling"),
	)
	if err != nil {
		return err
	}

	lgTransport().Info("registered message handlers", "count", 8)
	lgTransport().Info("router initialization complete")

	return nil
}

// CombinerRouterConfig holds configuration for combiner router initialization.
// Handles 3 message types: ping, beat, update.
// Beat, hello, and update are routed to CombinerMsgHandler via IncomingChan.
type CombinerRouterConfig struct {
	// Authorizer for authorization middleware (optional).
	// If nil, authorization middleware is skipped.
	Authorizer interface {
		IsPeerAuthorized(senderID string, zone string) (bool, string)
	}

	// PeerRegistry for statistics tracking (optional).
	// If nil, StatsMiddleware is not registered.
	PeerRegistry *PeerRegistry

	// PayloadCrypto for signature verification and decryption middleware (optional).
	// Obtain from SecurePayloadWrapper.GetCrypto().
	PayloadCrypto *PayloadCrypto

	// AllowUnencrypted allows unencrypted payloads when crypto is enabled.
	AllowUnencrypted bool

	// HandleUpdate is a closure from NewCombinerSyncHandler (combiner_chunk.go).
	// Handles "update" messages (agent→combiner zone data contributions).
	HandleUpdate MessageHandlerFunc

	// IncomingChan for routing messages to the handler goroutine.
	// If nil, RouteToMsgHandler middleware is not registered.
	IncomingChan chan<- *IncomingMessage
}

// InitializeCombinerRouter registers combiner-specific handlers and middleware.
// The combiner uses the same router/middleware infrastructure as the agent but
// only handles 3 message types (ping, beat, update).
func InitializeCombinerRouter(router *DNSMessageRouter, cfg *CombinerRouterConfig) error {
	if router == nil {
		return nil
	}

	lgTransport().Info("registering combiner handlers and middleware")

	// Register default handler for unregistered message types
	router.SetDefaultHandler(DefaultUnsupportedHandler)

	// 1. Authorization (outermost — prevents unauthorized access)
	if cfg.Authorizer != nil {
		router.Use(NewAuthorizationMiddleware(cfg.Authorizer))
		lgTransport().Info("combiner: registered authorization middleware")
	}

	// 2. Signature verification (authenticates sender)
	if cfg.PayloadCrypto != nil && cfg.PayloadCrypto.Enabled {
		cryptoCfg := &CryptoMiddlewareConfig{
			PayloadCrypto:    cfg.PayloadCrypto,
			AllowUnencrypted: cfg.AllowUnencrypted,
		}
		router.Use(NewSignatureMiddleware(cryptoCfg))
		lgTransport().Info("combiner: registered signature middleware")
	}

	// 3. Statistics tracking (after authentication, before processing)
	if cfg.PeerRegistry != nil {
		statsCfg := &StatsMiddlewareConfig{
			PeerRegistry: cfg.PeerRegistry,
		}
		router.Use(NewStatsMiddleware(statsCfg))
		lgTransport().Info("combiner: registered statistics middleware")
	}

	// 4. Logging
	router.Use(NewLoggingMiddleware(true))
	lgTransport().Info("combiner: registered logging middleware")

	// 5. Route to message handler goroutine (after processing)
	if cfg.IncomingChan != nil {
		router.Use(RouteToMsgHandler(cfg.IncomingChan))
		lgTransport().Info("combiner: registered message handler routing middleware")
	}

	// Register shared handlers for ping and beat (same implementation as agent)
	if err := router.Register(
		"PingHandler",
		MessageType("ping"),
		HandlePing,
		WithPriority(100),
		WithDescription("Processes ping messages and echoes nonce"),
	); err != nil {
		return err
	}

	if err := router.Register(
		"BeatHandler",
		MessageType("beat"),
		HandleBeat,
		WithPriority(100),
		WithDescription("Processes heartbeat messages from peers"),
	); err != nil {
		return err
	}

	// Register combiner-specific update handler (agent→combiner zone contributions)
	handlerCount := 2
	if cfg.HandleUpdate != nil {
		if err := router.Register(
			"CombinerUpdateHandler",
			MessageType("update"),
			cfg.HandleUpdate,
			WithPriority(100),
			WithDescription("Combiner: processes zone update contributions from agents"),
		); err != nil {
			return err
		}
		handlerCount++
	}

	lgTransport().Info("combiner: registered message handlers", "count", handlerCount)
	lgTransport().Info("combiner: router initialization complete")

	return nil
}

// SignerRouterConfig holds configuration for signer (tdns-auth) router initialization.
// Handles ping + keystate. Beat messages are routed to SignerMsgHandler via IncomingChan.
type SignerRouterConfig struct {
	// Authorizer for authorization middleware (optional).
	// If nil, authorization middleware is skipped.
	Authorizer interface {
		IsPeerAuthorized(senderID string, zone string) (bool, string)
	}

	// PeerRegistry for statistics tracking (optional).
	// If nil, StatsMiddleware is not registered.
	PeerRegistry *PeerRegistry

	// PayloadCrypto for signature verification and decryption middleware (optional).
	PayloadCrypto *PayloadCrypto

	// AllowUnencrypted allows unencrypted payloads when crypto is enabled.
	AllowUnencrypted bool

	// IncomingChan for routing messages to the handler goroutine.
	// If nil, RouteToMsgHandler middleware is not registered.
	IncomingChan chan<- *IncomingMessage
}

// InitializeSignerRouter registers signer-specific handlers and middleware.
// The signer (tdns-auth) uses the same router/middleware infrastructure as agent/combiner
// but only handles ping and keystate.
func InitializeSignerRouter(router *DNSMessageRouter, cfg *SignerRouterConfig) error {
	if router == nil {
		return nil
	}

	lgTransport().Info("registering signer handlers and middleware")

	// Register default handler for unregistered message types
	router.SetDefaultHandler(DefaultUnsupportedHandler)

	// 1. Authorization (outermost — prevents unauthorized access)
	if cfg.Authorizer != nil {
		router.Use(NewAuthorizationMiddleware(cfg.Authorizer))
		lgTransport().Info("signer: registered authorization middleware")
	}

	// 2. Signature verification (authenticates sender)
	if cfg.PayloadCrypto != nil && cfg.PayloadCrypto.Enabled {
		cryptoCfg := &CryptoMiddlewareConfig{
			PayloadCrypto:    cfg.PayloadCrypto,
			AllowUnencrypted: cfg.AllowUnencrypted,
		}
		router.Use(NewSignatureMiddleware(cryptoCfg))
		lgTransport().Info("signer: registered signature middleware")
	}

	// 3. Statistics tracking (after authentication, before processing)
	if cfg.PeerRegistry != nil {
		statsCfg := &StatsMiddlewareConfig{
			PeerRegistry: cfg.PeerRegistry,
		}
		router.Use(NewStatsMiddleware(statsCfg))
		lgTransport().Info("signer: registered statistics middleware")
	}

	// 4. Logging
	router.Use(NewLoggingMiddleware(true))
	lgTransport().Info("signer: registered logging middleware")

	// 5. Route to message handler goroutine (after processing)
	if cfg.IncomingChan != nil {
		router.Use(RouteToMsgHandler(cfg.IncomingChan))
		lgTransport().Info("signer: registered message handler routing middleware")
	}

	// Register ping handler (shared implementation with agent/combiner)
	if err := router.Register(
		"PingHandler",
		MessageType("ping"),
		HandlePing,
		WithPriority(100),
		WithDescription("Processes ping messages and echoes nonce"),
	); err != nil {
		return err
	}

	// Register keystate handler (agent→signer: propagated/rejected/removed)
	if err := router.Register(
		"KeystateHandler",
		MessageType("keystate"),
		HandleKeystate,
		WithPriority(100),
		WithDescription("Processes KEYSTATE messages for key lifecycle signaling"),
	); err != nil {
		return err
	}

	// Register RFI handler (agent→signer: KEYSTATE requests trigger inventory push)
	if err := router.Register(
		"RfiHandler",
		MessageType("rfi"),
		HandleRfi,
		WithPriority(100),
		WithDescription("Processes RFI messages (e.g. KEYSTATE inventory requests)"),
	); err != nil {
		return err
	}

	lgTransport().Info("signer: registered message handlers", "count", 3)
	lgTransport().Info("signer: router initialization complete")

	return nil
}

// DetermineMessageType parses the payload to determine the message type.
// Reads the "MessageType" field (e.g. "sync", "update", "beat", "ping").
func DetermineMessageType(payload []byte) MessageType {
	var fields struct {
		MessageType string `json:"MessageType"`
	}
	if err := json.Unmarshal(payload, &fields); err != nil {
		return MessageTypeUnknown
	}

	switch fields.MessageType {
	case "hello":
		return MessageType("hello")
	case "beat":
		return MessageType("beat")
	case "sync":
		return MessageType("sync")
	case "update":
		return MessageType("update")
	case "ping":
		return MessageType("ping")
	case "confirm":
		return MessageType("confirm")
	case "relocate":
		return MessageType("relocate")
	case "rfi":
		return MessageType("rfi")
	case "keystate":
		return MessageType("keystate")
	default:
		return MessageTypeUnknown
	}
}
