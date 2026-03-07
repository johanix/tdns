/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Unit tests for DNS Message Router.
 */

package transport

import (
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Test handler that records calls
type testHandler struct {
	name      string
	called    int
	shouldErr bool
}

func (h *testHandler) Handle(ctx *MessageContext) error {
	h.called++
	if h.shouldErr {
		return errors.New("test error")
	}
	return nil
}

// Test middleware that records calls
type testMiddleware struct {
	name      string
	called    int
	shouldErr bool
	skipNext  bool
}

func (m *testMiddleware) Middleware(ctx *MessageContext, next MessageHandlerFunc) error {
	m.called++
	if m.shouldErr {
		return errors.New("middleware error")
	}
	if m.skipNext {
		return nil // Don't call next
	}
	return next(ctx)
}

func TestNewDNSMessageRouter(t *testing.T) {
	router := NewDNSMessageRouter()
	if router == nil {
		t.Fatal("NewDNSMessageRouter returned nil")
	}
	if router.handlers == nil {
		t.Error("handlers map not initialized")
	}
	if router.middleware == nil {
		t.Error("middleware slice not initialized")
	}
}

func TestRegisterHandler(t *testing.T) {
	router := NewDNSMessageRouter()
	handler := &testHandler{name: "test"}

	err := router.Register("test-handler", MessageTypeChunkNotify, handler.Handle,
		WithPriority(10),
		WithDescription("Test handler"))
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Verify registration
	handlers := router.List()
	if len(handlers[MessageTypeChunkNotify]) != 1 {
		t.Fatalf("expected 1 handler, got %d", len(handlers[MessageTypeChunkNotify]))
	}

	reg := handlers[MessageTypeChunkNotify][0]
	if reg.Name != "test-handler" {
		t.Errorf("expected name 'test-handler', got %q", reg.Name)
	}
	if reg.Priority != 10 {
		t.Errorf("expected priority 10, got %d", reg.Priority)
	}
	if reg.Description != "Test handler" {
		t.Errorf("expected description 'Test handler', got %q", reg.Description)
	}
}

func TestRegisterDuplicateName(t *testing.T) {
	router := NewDNSMessageRouter()
	handler1 := &testHandler{name: "handler1"}
	handler2 := &testHandler{name: "handler2"}

	err := router.Register("duplicate", MessageTypeChunkNotify, handler1.Handle)
	if err != nil {
		t.Fatalf("First register failed: %v", err)
	}

	err = router.Register("duplicate", MessageTypeBeat, handler2.Handle)
	if err == nil {
		t.Error("Expected error registering duplicate name, got nil")
	}
}

func TestHandlerPriority(t *testing.T) {
	router := NewDNSMessageRouter()
	h1 := &testHandler{name: "low-priority"}
	h2 := &testHandler{name: "high-priority"}
	h3 := &testHandler{name: "medium-priority"}

	// Register in random order
	router.Register("low", MessageTypeChunkNotify, h1.Handle, WithPriority(100))
	router.Register("high", MessageTypeChunkNotify, h2.Handle, WithPriority(10))
	router.Register("medium", MessageTypeChunkNotify, h3.Handle, WithPriority(50))

	handlers := router.List()[MessageTypeChunkNotify]
	if len(handlers) != 3 {
		t.Fatalf("expected 3 handlers, got %d", len(handlers))
	}

	// Verify order (sorted by priority)
	if handlers[0].Name != "high" {
		t.Errorf("expected first handler 'high', got %q", handlers[0].Name)
	}
	if handlers[1].Name != "medium" {
		t.Errorf("expected second handler 'medium', got %q", handlers[1].Name)
	}
	if handlers[2].Name != "low" {
		t.Errorf("expected third handler 'low', got %q", handlers[2].Name)
	}
}

func TestRouteSuccess(t *testing.T) {
	router := NewDNSMessageRouter()
	handler := &testHandler{name: "test"}

	router.Register("test", MessageTypeChunkNotify, handler.Handle)

	ctx := NewMessageContext(&dns.Msg{}, "127.0.0.1:1234")
	err := router.Route(ctx, MessageTypeChunkNotify)
	if err != nil {
		t.Fatalf("Route failed: %v", err)
	}

	if handler.called != 1 {
		t.Errorf("expected handler called once, got %d", handler.called)
	}

	metrics := router.GetMetrics()
	if metrics.TotalMessages != 1 {
		t.Errorf("expected 1 total message, got %d", metrics.TotalMessages)
	}
}

func TestRouteNoHandler(t *testing.T) {
	router := NewDNSMessageRouter()
	ctx := NewMessageContext(&dns.Msg{}, "127.0.0.1:1234")

	err := router.Route(ctx, MessageTypeChunkNotify)
	if err == nil {
		t.Error("Expected error for unhandled message type, got nil")
	}

	metrics := router.GetMetrics()
	if metrics.UnhandledTypes[MessageTypeChunkNotify] != 1 {
		t.Errorf("expected 1 unhandled message, got %d",
			metrics.UnhandledTypes[MessageTypeChunkNotify])
	}
}

func TestRouteHandlerError(t *testing.T) {
	router := NewDNSMessageRouter()
	handler := &testHandler{name: "test", shouldErr: true}

	router.Register("test", MessageTypeChunkNotify, handler.Handle)

	ctx := NewMessageContext(&dns.Msg{}, "127.0.0.1:1234")
	err := router.Route(ctx, MessageTypeChunkNotify)
	if err == nil {
		t.Error("Expected error from handler, got nil")
	}

	metrics := router.GetMetrics()
	if metrics.HandlerErrors != 1 {
		t.Errorf("expected 1 handler error, got %d", metrics.HandlerErrors)
	}

	// Check handler metrics
	handlers := router.List()[MessageTypeChunkNotify]
	if handlers[0].ErrorCount != 1 {
		t.Errorf("expected 1 error count on handler, got %d", handlers[0].ErrorCount)
	}
}

func TestMiddlewareChain(t *testing.T) {
	router := NewDNSMessageRouter()
	handler := &testHandler{name: "handler"}
	mw1 := &testMiddleware{name: "mw1"}
	mw2 := &testMiddleware{name: "mw2"}

	// Add middleware in order
	router.Use(mw1.Middleware)
	router.Use(mw2.Middleware)
	router.Register("test", MessageTypeChunkNotify, handler.Handle)

	ctx := NewMessageContext(&dns.Msg{}, "127.0.0.1:1234")
	err := router.Route(ctx, MessageTypeChunkNotify)
	if err != nil {
		t.Fatalf("Route failed: %v", err)
	}

	// Verify execution order: mw1 -> mw2 -> handler
	if mw1.called != 1 {
		t.Errorf("expected mw1 called once, got %d", mw1.called)
	}
	if mw2.called != 1 {
		t.Errorf("expected mw2 called once, got %d", mw2.called)
	}
	if handler.called != 1 {
		t.Errorf("expected handler called once, got %d", handler.called)
	}
}

func TestMiddlewareError(t *testing.T) {
	router := NewDNSMessageRouter()
	handler := &testHandler{name: "handler"}
	mw := &testMiddleware{name: "mw", shouldErr: true}

	router.Use(mw.Middleware)
	router.Register("test", MessageTypeChunkNotify, handler.Handle)

	ctx := NewMessageContext(&dns.Msg{}, "127.0.0.1:1234")
	err := router.Route(ctx, MessageTypeChunkNotify)
	if err == nil {
		t.Error("Expected middleware error, got nil")
	}

	// Handler should not be called
	if handler.called != 0 {
		t.Errorf("expected handler not called, got %d calls", handler.called)
	}
}

func TestMiddlewareSkipNext(t *testing.T) {
	router := NewDNSMessageRouter()
	handler := &testHandler{name: "handler"}
	mw := &testMiddleware{name: "mw", skipNext: true}

	router.Use(mw.Middleware)
	router.Register("test", MessageTypeChunkNotify, handler.Handle)

	ctx := NewMessageContext(&dns.Msg{}, "127.0.0.1:1234")
	err := router.Route(ctx, MessageTypeChunkNotify)
	if err != nil {
		t.Fatalf("Route failed: %v", err)
	}

	// Handler should not be called
	if handler.called != 0 {
		t.Errorf("expected handler not called, got %d calls", handler.called)
	}
}

func TestMultipleHandlersSameType(t *testing.T) {
	router := NewDNSMessageRouter()
	h1 := &testHandler{name: "handler1"}
	h2 := &testHandler{name: "handler2"}

	router.Register("h1", MessageTypeChunkNotify, h1.Handle, WithPriority(10))
	router.Register("h2", MessageTypeChunkNotify, h2.Handle, WithPriority(20))

	ctx := NewMessageContext(&dns.Msg{}, "127.0.0.1:1234")
	err := router.Route(ctx, MessageTypeChunkNotify)
	if err != nil {
		t.Fatalf("Route failed: %v", err)
	}

	// Both handlers should be called
	if h1.called != 1 {
		t.Errorf("expected h1 called once, got %d", h1.called)
	}
	if h2.called != 1 {
		t.Errorf("expected h2 called once, got %d", h2.called)
	}
}

func TestWalk(t *testing.T) {
	router := NewDNSMessageRouter()
	h1 := &testHandler{name: "h1"}
	h2 := &testHandler{name: "h2"}

	router.Register("h1", MessageTypeChunkNotify, h1.Handle)
	router.Register("h2", MessageTypeBeat, h2.Handle)

	var count int
	err := router.Walk(func(reg *HandlerRegistration) error {
		count++
		return nil
	})
	if err != nil {
		t.Fatalf("Walk failed: %v", err)
	}

	if count != 2 {
		t.Errorf("expected walk to visit 2 handlers, got %d", count)
	}
}

func TestWalkError(t *testing.T) {
	router := NewDNSMessageRouter()
	h1 := &testHandler{name: "h1"}

	router.Register("h1", MessageTypeChunkNotify, h1.Handle)

	err := router.Walk(func(reg *HandlerRegistration) error {
		return errors.New("walk error")
	})
	if err == nil {
		t.Error("Expected walk error, got nil")
	}
}

func TestList(t *testing.T) {
	router := NewDNSMessageRouter()
	h1 := &testHandler{name: "h1"}
	h2 := &testHandler{name: "h2"}

	router.Register("h1", MessageTypeChunkNotify, h1.Handle)
	router.Register("h2", MessageTypeChunkNotify, h2.Handle)

	list := router.List()
	if len(list) != 1 {
		t.Errorf("expected 1 message type, got %d", len(list))
	}
	if len(list[MessageTypeChunkNotify]) != 2 {
		t.Errorf("expected 2 handlers for CHUNK_NOTIFY, got %d",
			len(list[MessageTypeChunkNotify]))
	}
}

func TestDescribe(t *testing.T) {
	router := NewDNSMessageRouter()
	handler := &testHandler{name: "test"}
	mw := &testMiddleware{name: "mw"}

	router.Use(mw.Middleware)
	router.Register("test", MessageTypeChunkNotify, handler.Handle,
		WithDescription("Test handler"))

	desc := router.Describe()
	if desc == "" {
		t.Error("Describe returned empty string")
	}

	// Should contain key information
	if len(desc) < 100 {
		t.Errorf("Describe output too short (%d chars), expected detailed description", len(desc))
	}
}

func TestHandlerMetrics(t *testing.T) {
	router := NewDNSMessageRouter()
	handler := &testHandler{name: "test"}

	router.Register("test", MessageTypeChunkNotify, handler.Handle)

	// Execute multiple times
	for i := 0; i < 5; i++ {
		ctx := NewMessageContext(&dns.Msg{}, "127.0.0.1:1234")
		router.Route(ctx, MessageTypeChunkNotify)
		time.Sleep(1 * time.Millisecond) // Add some latency
	}

	handlers := router.List()[MessageTypeChunkNotify]
	reg := handlers[0]

	if reg.CallCount != 5 {
		t.Errorf("expected 5 calls, got %d", reg.CallCount)
	}
	if reg.TotalLatency == 0 {
		t.Error("expected non-zero total latency")
	}
}

func TestReset(t *testing.T) {
	router := NewDNSMessageRouter()
	handler := &testHandler{name: "test"}

	router.Register("test", MessageTypeChunkNotify, handler.Handle)

	// Generate some metrics
	ctx := NewMessageContext(&dns.Msg{}, "127.0.0.1:1234")
	router.Route(ctx, MessageTypeChunkNotify)

	// Reset
	router.Reset()

	metrics := router.GetMetrics()
	if metrics.TotalMessages != 0 {
		t.Errorf("expected 0 total messages after reset, got %d", metrics.TotalMessages)
	}

	handlers := router.List()[MessageTypeChunkNotify]
	if handlers[0].CallCount != 0 {
		t.Errorf("expected 0 call count after reset, got %d", handlers[0].CallCount)
	}
}

func TestMessageContext(t *testing.T) {
	req := &dns.Msg{}
	ctx := NewMessageContext(req, "127.0.0.1:1234")

	if ctx.Request != req {
		t.Error("Request not set correctly")
	}
	if ctx.RemoteAddr != "127.0.0.1:1234" {
		t.Errorf("expected remote addr '127.0.0.1:1234', got %q", ctx.RemoteAddr)
	}
	if ctx.Response == nil {
		t.Error("Response not initialized")
	}
	if ctx.Data == nil {
		t.Error("Data map not initialized")
	}
	if ctx.StartTime.IsZero() {
		t.Error("StartTime not set")
	}
}

func TestConcurrentAccess(t *testing.T) {
	router := NewDNSMessageRouter()
	handler := &testHandler{name: "test"}

	router.Register("test", MessageTypeChunkNotify, handler.Handle)

	// Execute concurrently
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			ctx := NewMessageContext(&dns.Msg{}, "127.0.0.1:1234")
			router.Route(ctx, MessageTypeChunkNotify)
			done <- true
		}()
	}

	// Wait for all to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	if handler.called != 10 {
		t.Errorf("expected 10 calls, got %d", handler.called)
	}

	metrics := router.GetMetrics()
	if metrics.TotalMessages != 10 {
		t.Errorf("expected 10 total messages, got %d", metrics.TotalMessages)
	}
}
