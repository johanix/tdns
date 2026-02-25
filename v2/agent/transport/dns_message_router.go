/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * DNS Message Router - Registration-based routing for incoming DNS messages.
 * Provides standardized handler interface, middleware chain, and introspection.
 */

package transport

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// MessageType represents the type of DNS message being routed.
type MessageType string

const (
	MessageTypeChunkNotify MessageType = "CHUNK_NOTIFY"
	MessageTypeChunkQuery  MessageType = "CHUNK_QUERY"
	MessageTypeHello       MessageType = "HELLO"
	MessageTypeBeat        MessageType = "BEAT"
	MessageTypeRelocate    MessageType = "RELOCATE"
	MessageTypeUpdate      MessageType = "UPDATE"
	MessageTypeUnknown     MessageType = "UNKNOWN"
)

// MessageContext holds all context needed for message processing.
type MessageContext struct {
	// DNS message details
	Request        *dns.Msg
	Response       *dns.Msg
	RemoteAddr     string
	DistributionID string // Unique identifier for this CHUNK distribution

	// Extracted CHUNK payload (if any)
	ChunkPayload []byte
	ChunkSigned  bool
	ChunkCrypted bool

	// Peer information (populated by authorization middleware)
	PeerID          string
	Peer            *Peer
	Authorized      bool
	AuthReason      string // Why was this authorized (or not)
	AuthorizedVia   string // "explicit" or "implicit" (HSYNC)
	SignatureValid  bool
	SignatureReason string

	// Middleware can add custom data
	Data map[string]interface{}

	// Metrics
	StartTime time.Time
}

// NewMessageContext creates a new message context.
func NewMessageContext(request *dns.Msg, remoteAddr string) *MessageContext {
	return &MessageContext{
		Request:    request,
		Response:   new(dns.Msg),
		RemoteAddr: remoteAddr,
		Data:       make(map[string]interface{}),
		StartTime:  time.Now(),
	}
}

// MessageHandlerFunc is the function signature for message handlers.
// Handlers process the message and return an error if processing failed.
type MessageHandlerFunc func(ctx *MessageContext) error

// MiddlewareFunc is the function signature for middleware.
// Middleware can inspect/modify context and decide whether to continue the chain.
// Return nil to continue, or an error to stop processing.
type MiddlewareFunc func(ctx *MessageContext, next MessageHandlerFunc) error

// HandlerRegistration represents a registered message handler.
type HandlerRegistration struct {
	Name        string             // Unique handler name
	MessageType MessageType        // Type of message this handles
	Priority    int                // Lower number = higher priority (default: 100)
	Handler     MessageHandlerFunc // The actual handler function
	Description string             // Human-readable description
	Registered  time.Time          // When this handler was registered

	// Metrics
	CallCount    uint64
	ErrorCount   uint64
	TotalLatency time.Duration
}

// DNSMessageRouter routes incoming DNS messages to registered handlers.
type DNSMessageRouter struct {
	mu sync.RWMutex

	// Handler registry by message type
	handlers map[MessageType][]*HandlerRegistration

	// Default handler for unregistered message types (nil = return error)
	defaultHandler MessageHandlerFunc

	// Global middleware applied to all messages
	middleware []MiddlewareFunc

	// Metrics
	metrics RouterMetrics
}

// RouterMetrics tracks router-level metrics.
type RouterMetrics struct {
	mu sync.RWMutex

	TotalMessages    uint64
	UnknownMessages  uint64
	UnhandledTypes   map[MessageType]uint64
	MiddlewareErrors uint64
	HandlerErrors    uint64
}

// NewDNSMessageRouter creates a new router instance.
func NewDNSMessageRouter() *DNSMessageRouter {
	return &DNSMessageRouter{
		handlers: make(map[MessageType][]*HandlerRegistration),
		metrics: RouterMetrics{
			UnhandledTypes: make(map[MessageType]uint64),
		},
	}
}

// Register adds a handler for a specific message type.
func (r *DNSMessageRouter) Register(name string, msgType MessageType, handler MessageHandlerFunc, opts ...HandlerOption) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check for duplicate names
	for _, handlers := range r.handlers {
		for _, h := range handlers {
			if h.Name == name {
				return fmt.Errorf("handler with name %q already registered", name)
			}
		}
	}

	// Create registration with defaults
	reg := &HandlerRegistration{
		Name:        name,
		MessageType: msgType,
		Priority:    100, // Default priority
		Handler:     handler,
		Registered:  time.Now(),
	}

	// Apply options
	for _, opt := range opts {
		opt(reg)
	}

	// Add to handler list
	r.handlers[msgType] = append(r.handlers[msgType], reg)

	// Sort handlers by priority (lower number = higher priority)
	sort.Slice(r.handlers[msgType], func(i, j int) bool {
		return r.handlers[msgType][i].Priority < r.handlers[msgType][j].Priority
	})

	return nil
}

// HandlerOption configures a handler registration.
type HandlerOption func(*HandlerRegistration)

// WithPriority sets the handler priority (lower = higher priority).
func WithPriority(priority int) HandlerOption {
	return func(r *HandlerRegistration) {
		r.Priority = priority
	}
}

// WithDescription sets the handler description.
func WithDescription(desc string) HandlerOption {
	return func(r *HandlerRegistration) {
		r.Description = desc
	}
}

// SetDefaultHandler sets the handler called when no handler is registered for a message type.
// The default handler receives the message context and should return nil after storing
// an appropriate error response in ctx.Data. If no default handler is set, Route()
// returns an error for unregistered message types.
func (r *DNSMessageRouter) SetDefaultHandler(handler MessageHandlerFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.defaultHandler = handler
}

// Use adds middleware to the global middleware chain.
// Middleware is executed in the order it was added.
func (r *DNSMessageRouter) Use(middleware MiddlewareFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.middleware = append(r.middleware, middleware)
}

// Route processes a message through the middleware chain and handlers.
func (r *DNSMessageRouter) Route(ctx *MessageContext, msgType MessageType) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Update metrics
	r.metrics.mu.Lock()
	r.metrics.TotalMessages++
	r.metrics.mu.Unlock()

	// Get handlers for this message type
	handlers, ok := r.handlers[msgType]
	if !ok || len(handlers) == 0 {
		r.metrics.mu.Lock()
		r.metrics.UnhandledTypes[msgType]++
		r.metrics.mu.Unlock()

		// Use default handler if set, otherwise return error
		if r.defaultHandler == nil {
			return fmt.Errorf("no handlers registered for message type %s", msgType)
		}
		// Store message type so the default handler can report it
		ctx.Data["unhandled_message_type"] = string(msgType)
		// Route through middleware chain with the default handler
		handler := r.defaultHandler
		for i := len(r.middleware) - 1; i >= 0; i-- {
			mw := r.middleware[i]
			next := handler
			handler = func(ctx *MessageContext) error {
				return mw(ctx, next)
			}
		}
		return handler(ctx)
	}

	// Build the handler chain (all handlers for this type)
	finalHandler := r.buildHandlerChain(handlers)

	// Wrap with middleware chain
	handler := finalHandler
	for i := len(r.middleware) - 1; i >= 0; i-- {
		mw := r.middleware[i]
		next := handler
		handler = func(ctx *MessageContext) error {
			return mw(ctx, next)
		}
	}

	// Execute the chain
	if err := handler(ctx); err != nil {
		r.metrics.mu.Lock()
		r.metrics.HandlerErrors++
		r.metrics.mu.Unlock()
		return err
	}

	return nil
}

// buildHandlerChain creates a handler that executes all handlers for a message type.
func (r *DNSMessageRouter) buildHandlerChain(handlers []*HandlerRegistration) MessageHandlerFunc {
	return func(ctx *MessageContext) error {
		// Execute handlers in priority order
		for _, h := range handlers {
			start := time.Now()

			if err := h.Handler(ctx); err != nil {
				// Update handler metrics
				h.ErrorCount++
				h.CallCount++
				h.TotalLatency += time.Since(start)
				return fmt.Errorf("handler %q failed: %w", h.Name, err)
			}

			// Update handler metrics
			h.CallCount++
			h.TotalLatency += time.Since(start)
		}
		return nil
	}
}

// Walk traverses all registered handlers and calls the visitor function.
func (r *DNSMessageRouter) Walk(visitor func(*HandlerRegistration) error) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for msgType, handlers := range r.handlers {
		for _, h := range handlers {
			if err := visitor(h); err != nil {
				return fmt.Errorf("walk failed at %s/%s: %w", msgType, h.Name, err)
			}
		}
	}
	return nil
}

// List returns a list of all registered handlers grouped by message type.
func (r *DNSMessageRouter) List() map[MessageType][]*HandlerRegistration {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Create a deep copy to prevent external modification
	result := make(map[MessageType][]*HandlerRegistration)
	for msgType, handlers := range r.handlers {
		result[msgType] = make([]*HandlerRegistration, len(handlers))
		copy(result[msgType], handlers)
	}
	return result
}

// Describe returns a human-readable description of the router state.
func (r *DNSMessageRouter) Describe() string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var desc string
	desc += fmt.Sprintf("DNS Message Router\n")
	desc += fmt.Sprintf("==================\n\n")

	// Middleware
	desc += fmt.Sprintf("Middleware Chain (%d middleware):\n", len(r.middleware))
	for i := range r.middleware {
		desc += fmt.Sprintf("  %d. <middleware-%d>\n", i+1, i+1)
	}
	desc += "\n"

	// Handlers by message type
	desc += fmt.Sprintf("Registered Handlers (%d types):\n", len(r.handlers))
	for msgType, handlers := range r.handlers {
		desc += fmt.Sprintf("\n  %s (%d handlers):\n", msgType, len(handlers))
		for _, h := range handlers {
			avgLatency := time.Duration(0)
			if h.CallCount > 0 {
				avgLatency = h.TotalLatency / time.Duration(h.CallCount)
			}
			desc += fmt.Sprintf("    - %s (priority=%d)\n", h.Name, h.Priority)
			desc += fmt.Sprintf("      Description: %s\n", h.Description)
			desc += fmt.Sprintf("      Calls: %d, Errors: %d, Avg Latency: %v\n",
				h.CallCount, h.ErrorCount, avgLatency)
		}
	}

	// Metrics
	desc += fmt.Sprintf("\nRouter Metrics:\n")
	desc += fmt.Sprintf("  Total Messages: %d\n", r.metrics.TotalMessages)
	desc += fmt.Sprintf("  Unknown Messages: %d\n", r.metrics.UnknownMessages)
	desc += fmt.Sprintf("  Middleware Errors: %d\n", r.metrics.MiddlewareErrors)
	desc += fmt.Sprintf("  Handler Errors: %d\n", r.metrics.HandlerErrors)

	if len(r.metrics.UnhandledTypes) > 0 {
		desc += fmt.Sprintf("\n  Unhandled Types:\n")
		for msgType, count := range r.metrics.UnhandledTypes {
			desc += fmt.Sprintf("    %s: %d\n", msgType, count)
		}
	}

	return desc
}

// GetMetrics returns a copy of the current router metrics.
func (r *DNSMessageRouter) GetMetrics() RouterMetrics {
	r.metrics.mu.RLock()
	defer r.metrics.mu.RUnlock()

	// Create a copy
	metrics := RouterMetrics{
		TotalMessages:    r.metrics.TotalMessages,
		UnknownMessages:  r.metrics.UnknownMessages,
		MiddlewareErrors: r.metrics.MiddlewareErrors,
		HandlerErrors:    r.metrics.HandlerErrors,
		UnhandledTypes:   make(map[MessageType]uint64),
	}

	for k, v := range r.metrics.UnhandledTypes {
		metrics.UnhandledTypes[k] = v
	}

	return metrics
}

// Reset clears all metrics (useful for testing).
func (r *DNSMessageRouter) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.metrics.mu.Lock()
	defer r.metrics.mu.Unlock()

	r.metrics.TotalMessages = 0
	r.metrics.UnknownMessages = 0
	r.metrics.MiddlewareErrors = 0
	r.metrics.HandlerErrors = 0
	r.metrics.UnhandledTypes = make(map[MessageType]uint64)

	// Reset handler metrics
	for _, handlers := range r.handlers {
		for _, h := range handlers {
			h.CallCount = 0
			h.ErrorCount = 0
			h.TotalLatency = 0
		}
	}
}
