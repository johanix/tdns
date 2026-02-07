# DNS Message Router Architecture

**Date:** 2026-02-06
**Status:** Implemented
**Related Issues:** DNS-58, DNS-65

## Overview

The DNS Message Router provides a registration-based routing system for DNS CHUNK NOTIFY messages, similar to HTTP API routers. It replaces hardcoded switch statements with a flexible, extensible handler registration system.

## Architecture Components

### 1. Handler Interface

**Location:** [tdns/v2/agent/transport/router.go](../../v2/agent/transport/router.go)

```go
type DNSMessageHandler interface {
    Handle(ctx *MessageContext) error
}
```

All message handlers implement this simple interface. The `MessageContext` provides:
- `PeerID`: Authenticated sender identity
- `CorrelationID`: Message correlation ID for tracking
- `ChunkPayload`: Raw message payload bytes
- `Data`: Map for sharing data between handlers and middleware
- `Request`: Original DNS message
- `RemoteAddr`: Remote address

### 2. Message Router

**Location:** [tdns/v2/agent/transport/router.go](../../v2/agent/transport/router.go)

The `DNSMessageRouter` manages handler registration and message dispatch:

```go
type DNSMessageRouter struct {
    handlers   map[MessageType][]*HandlerRegistration
    middleware []MiddlewareFunc
    metrics    RouterMetrics
    mu         sync.RWMutex
}
```

Key methods:
- `Register(msgType, name, description string, priority int, handler DNSMessageHandler)`: Register a handler
- `Use(middleware MiddlewareFunc)`: Add middleware to the chain
- `Route(ctx *MessageContext) error`: Route a message through middleware and handlers
- `List()`: List all registered handlers
- `GetMetrics()`: Get router-level metrics
- `Walk(visitor func(*HandlerRegistration) error)`: Visit all handlers
- `Reset()`: Reset all metrics

### 3. Handler Registration

Handlers are registered with metadata for introspection and debugging:

```go
type HandlerRegistration struct {
    Name         string
    MessageType  MessageType
    Priority     int
    Description  string
    Handler      DNSMessageHandler
    Registered   time.Time
    CallCount    uint64
    ErrorCount   uint64
    TotalLatency time.Duration
}
```

Handlers are executed in **priority order** (lower numbers = higher priority).

### 4. Middleware System

**Location:** [tdns/v2/agent/transport/middleware.go](../../v2/agent/transport/middleware.go)

Middleware functions wrap handler execution for cross-cutting concerns:

```go
type MiddlewareFunc func(next DNSMessageHandler) DNSMessageHandler
```

#### Built-in Middleware

1. **Authorization Middleware** (`AuthorizationMiddleware`)
   - Validates peer authentication
   - Checks working keys
   - Enforces access control

2. **Logging Middleware** (`LoggingMiddleware`)
   - Logs message routing events
   - Includes timing information
   - Tracks correlation IDs

3. **Metrics Middleware** (`MetricsMiddleware`)
   - Tracks handler call counts
   - Records error counts
   - Measures handler latency

Middleware is executed in **registration order** (first registered = outermost wrapper).

## Implementation Details

### Router Initialization

**Location:** [tdns/v2/agent/transport/router_init.go](../../v2/agent/transport/router_init.go)

```go
func InitializeRouter(cfg RouterConfig) *DNSMessageRouter {
    router := NewDNSMessageRouter()

    // Add middleware (order matters - first registered is outermost)
    router.Use(AuthorizationMiddleware(cfg.TransportManager))
    router.Use(LoggingMiddleware())
    router.Use(MetricsMiddleware())

    // Register handlers (priority determines execution order)
    router.Register("hello", "hello-handler", "Process hello messages", 10,
        HandlerFunc(HandleHello))
    router.Register("beat", "beat-handler", "Process beat messages", 20,
        HandlerFunc(HandleBeat))
    router.Register("sync", "sync-handler", "Process sync messages", 30,
        HandlerFunc(HandleSync))
    router.Register("relocate", "relocate-handler", "Process relocate messages", 40,
        HandlerFunc(HandleRelocate))

    return router
}
```

### Message Handlers

**Location:** [tdns/v2/agent/transport/handlers.go](../../v2/agent/transport/handlers.go)

Each message type has a dedicated handler function:

- `HandleHello`: Process hello messages from new peers
- `HandleBeat`: Process heartbeat messages
- `HandleSync`: Process zone synchronization messages
- `HandleRelocate`: Process DDoS mitigation relocate messages
- `HandlePing`: Process ping/diagnostic messages

Handlers parse the message, perform validation, and store results in `ctx.Data` for downstream processing.

### Response Middleware

**Location:** [tdns/v2/agent/transport/handlers.go:183-203](../../v2/agent/transport/handlers.go#L183-L203)

The `ResponseMiddleware` sends DNS responses based on handler results:

```go
func ResponseMiddleware() MiddlewareFunc {
    return func(next DNSMessageHandler) DNSMessageHandler {
        return HandlerFunc(func(ctx *MessageContext) error {
            err := next.Handle(ctx)
            rcode := dns.RcodeSuccess
            if err != nil {
                rcode = dns.RcodeServerFailure
            }

            // Check for payload responses (ping, sync)
            if payload, ok := ctx.Data["ping_response"].([]byte); ok {
                return sendChunkResponse(w, msg, payload, rcode)
            }

            return sendStandardResponse(w, msg, rcode)
        })
    }
}
```

## Message Flow

1. **Incoming Message** arrives via DNS CHUNK NOTIFY
2. **Transport Manager** extracts and validates the message
3. **Router** creates a `MessageContext`
4. **Middleware Chain** wraps the handler:
   - Authorization checks peer credentials
   - Logging records the routing event
   - Metrics tracks timing and counts
5. **Handler** processes the message
6. **Response Middleware** sends DNS response
7. **Metrics** are updated

## Adding New Message Types

To add a new message type:

1. **Create Handler Function:**
   ```go
   func HandleNewType(ctx *MessageContext) error {
       // Parse message
       var msg IncomingMessage
       if err := json.Unmarshal(ctx.ChunkPayload, &msg); err != nil {
           return err
       }

       // Process message
       ctx.Data["message_type"] = "newtype"
       ctx.Data["incoming_message"] = &msg

       return nil
   }
   ```

2. **Register Handler:**
   ```go
   router.Register("newtype", "newtype-handler",
       "Process newtype messages", 50, HandlerFunc(HandleNewType))
   ```

3. **Add CLI Commands (optional):**
   - Create debug commands in `tdns/v2/cli/agent_debug_cmds.go`

4. **Add Tests:**
   - Unit tests in `tdns/v2/agent/transport/router_test.go`
   - Integration tests in `tdns/v2/agent/transport/integration_test.go`

## API Introspection

**Location:** [tdns/v2/apihandler_agent_router.go](../../v2/apihandler_agent_router.go)

The router exposes API endpoints for runtime introspection:

- `router-list`: List all registered handlers grouped by message type
- `router-describe`: Detailed router state (middleware, handlers, metrics)
- `router-metrics`: Router-level metrics (total messages, errors, unhandled types)
- `router-walk`: Walk all handlers with visitor pattern
- `router-reset`: Reset all router metrics

### CLI Commands

**Location:** [tdns/v2/cli/agent_router_cmds.go](../../v2/cli/agent_router_cmds.go)

```bash
# List all registered handlers
tdns-cli agent router list

# Show detailed router state
tdns-cli agent router describe

# Show router metrics
tdns-cli agent router metrics

# Walk all handlers
tdns-cli agent router walk

# Reset metrics (confirmation required)
tdns-cli agent router reset
```

## Testing

### Unit Tests

**Location:** [tdns/v2/agent/transport/router_test.go](../../v2/agent/transport/router_test.go)

Tests cover:
- Handler registration and priority ordering
- Middleware execution order
- Error handling and propagation
- Metrics collection
- Concurrent routing

### Integration Tests

**Location:** [tdns/v2/agent/transport/integration_test.go](../../v2/agent/transport/integration_test.go)

Tests cover:
- End-to-end message routing
- Authorization middleware enforcement
- Real handler execution
- Response generation

Run tests:
```bash
cd tdns/v2/agent/transport
go test -v
```

## Benefits

### Before (Hardcoded Switch)

```go
func RouteIncomingMessage(msg *IncomingMessage) error {
    switch msg.Type {
    case "hello":
        return routeHelloMessage(msg)
    case "beat":
        return routeBeatMessage(msg)
    case "sync":
        return routeSyncMessage(msg)
    default:
        return fmt.Errorf("unknown message type: %s", msg.Type)
    }
}
```

Problems:
- Authorization duplicated in each handler
- Logging scattered across handlers
- Metrics tracking inconsistent
- Adding new types requires modifying core routing code

### After (Router-Based)

```go
func RouteIncomingMessage(ctx *MessageContext) error {
    return tm.router.Route(ctx)
}
```

Benefits:
- **DRY**: Authorization, logging, metrics in one place
- **Extensibility**: Add new message types without modifying core
- **Testability**: Test handlers in isolation
- **Observability**: Built-in metrics and introspection
- **Clear Contracts**: Standardized handler interface

## Performance Considerations

- Handler lookup is O(1) via map
- Handlers within a type are sorted once at registration
- Middleware chain is built once per message type
- Metrics use atomic operations for thread safety
- No allocations in hot path (handler execution)

## Future Enhancements

Potential improvements:
- Handler deregistration support
- Dynamic priority adjustment
- Handler-specific middleware
- Circuit breaker middleware
- Rate limiting middleware
- Request tracing/correlation
- Handler dependency injection
