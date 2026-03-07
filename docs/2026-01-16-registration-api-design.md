# Registration API Design for Query Handlers

## Problem Statement

When registering query handlers (e.g., for KDC), we need a way for handlers to indicate they don't handle a particular query, allowing TDNS to fall through to the default zone-based handler. This is similar to HTTP middleware chains where each handler can either handle the request or pass it to the next handler.

## Design Goals

1. **QType-based routing**: Handlers register for specific query types
2. **Chain-of-responsibility**: Handlers can pass queries they don't handle to the next handler
3. **Fallback to default**: If no handler handles a query, use the default zone-based responder
4. **Multiple handlers per qtype**: Allow multiple handlers to be registered for the same qtype (called in order)
5. **Backward compatible**: Existing code continues to work

## Proposed API

### 1. Error Type for "Not Handled"

```go
// ErrNotHandled is returned by query handlers to indicate they don't handle this query
// TDNS will try the next handler or fall back to default zone-based handler
var ErrNotHandled = errors.New("query not handled by this handler")
```

### 2. Query Handler Function Signature

```go
// QueryHandlerFunc is the function signature for registered query handlers
// Returns ErrNotHandled if the handler doesn't handle this query (allows fallthrough)
// Returns nil if the handler successfully handled the query
// Returns other error if handler attempted to handle but encountered an error
type QueryHandlerFunc func(ctx context.Context, req *DnsQueryRequest) error
```

### 3. Registration Function

```go
// RegisterQueryHandler registers a handler for a specific query type
// Multiple handlers can be registered for the same qtype - they will be called in registration order
// If a handler returns ErrNotHandled, TDNS will try the next handler or fall back to default
// If qtype is 0 (dns.TypeANY), handler is called for all query types (use with caution)
func RegisterQueryHandler(qtype uint16, handler QueryHandlerFunc) error
```

### 4. Internal Storage

```go
// In config.go InternalConf struct, add:
type InternalConf struct {
    // ... existing fields ...
    
    // Query handlers registered via RegisterQueryHandler
    QueryHandlers map[uint16][]QueryHandlerFunc // qtype -> list of handlers
    QueryHandlersMutex sync.RWMutex              // protects QueryHandlers map
}
```

## Flow Diagram

```
DNS Query Arrives
    ↓
authDNSHandler (do53.go)
    ↓
Check if QueryHandlers registered for this qtype
    ↓
If handlers exist:
    For each handler in order:
        Call handler(req)
        ↓
        If returns ErrNotHandled:
            Try next handler
        ↓
        If returns nil:
            Query handled, return
        ↓
        If returns other error:
            Log error, try next handler (or fall back)
    ↓
    If all handlers returned ErrNotHandled:
        Fall through to default handler
    ↓
If no handlers registered:
    Use default zone-based handler
```

## Example Usage (KDC)

```go
// In dzm/cmd/tdns-kdc/main.go

// Register handler for KMREQ queries
tdns.RegisterQueryHandler(hpke.TypeKMREQ, func(ctx context.Context, req *tdns.DnsQueryRequest) error {
    // Convert to KDC types
    kdcReq := &kdc.KdcQueryRequest{
        ResponseWriter: req.ResponseWriter,
        Msg:            req.Msg,
        Qname:          req.Qname,
        Qtype:          req.Qtype,
        Options:        req.Options,
    }
    
    // Call KDC handler
    err := kdc.HandleKdcQuery(ctx, kdcReq, kdcDB, &kdcConf)
    if err != nil {
        return err // Handler attempted to handle but failed
    }
    return nil // Successfully handled
})

// Register handler for KMCTRL queries
tdns.RegisterQueryHandler(hpke.TypeKMCTRL, func(ctx context.Context, req *tdns.DnsQueryRequest) error {
    // Similar conversion and call
    kdcReq := &kdc.KdcQueryRequest{...}
    err := kdc.HandleKdcQuery(ctx, kdcReq, kdcDB, &kdcConf)
    return err
})

// Register handler for JSONMANIFEST queries
tdns.RegisterQueryHandler(core.TypeJSONMANIFEST, func(ctx context.Context, req *tdns.DnsQueryRequest) error {
    kdcReq := &kdc.KdcQueryRequest{...}
    err := kdc.HandleKdcQuery(ctx, kdcReq, kdcDB, &kdcConf)
    return err
})

// Register handler for JSONCHUNK queries
tdns.RegisterQueryHandler(core.TypeJSONCHUNK, func(ctx context.Context, req *tdns.DnsQueryRequest) error {
    kdcReq := &kdc.KdcQueryRequest{...}
    err := kdc.HandleKdcQuery(ctx, kdcReq, kdcDB, &kdcConf)
    return err
})
```

## Implementation in do53.go

```go
case dns.OpcodeQuery:
    qtype := r.Question[0].Qtype
    
    // Check for registered handlers
    conf.Internal.QueryHandlersMutex.RLock()
    handlers, hasHandlers := conf.Internal.QueryHandlers[qtype]
    conf.Internal.QueryHandlersMutex.RUnlock()
    
    if hasHandlers && len(handlers) > 0 {
        // Try registered handlers
        handled := false
        for _, handler := range handlers {
            dqr := DnsQueryRequest{
                ResponseWriter: w,
                Msg:            r,
                Qname:          qname,
                Qtype:          qtype,
                Options:        msgoptions,
            }
            
            err := handler(ctx, &dqr)
            if err == nil {
                // Handler successfully handled the query
                handled = true
                break
            } else if err == ErrNotHandled {
                // Handler doesn't handle this query, try next
                continue
            } else {
                // Handler attempted to handle but failed
                log.Printf("Query handler error: %v", err)
                // Continue to next handler or fall back
                continue
            }
        }
        
        if handled {
            return // Query was handled by a registered handler
        }
        // All handlers returned ErrNotHandled, fall through to default
    }
    
    // No handlers registered or all handlers passed, use default zone-based handler
    // ... existing zone-based query handling code ...
```

## Alternative: Handler Returns (handled bool, err error)

Instead of using `ErrNotHandled`, we could use:

```go
type QueryHandlerFunc func(ctx context.Context, req *DnsQueryRequest) (handled bool, err error)
```

**Pros:**
- More explicit - handler explicitly says "I handled this" vs "I don't handle this"
- No need for special error type

**Cons:**
- Two return values instead of one
- Slightly more verbose

## Recommendation

Use the **ErrNotHandled** approach because:
1. Single return value is cleaner
2. Follows Go error handling patterns
3. Error can carry additional context if needed
4. Similar to HTTP middleware patterns (e.g., `next()` in Express.js)

## Migration Path

1. Add `ErrNotHandled` error
2. Add `RegisterQueryHandler` function
3. Add storage in `InternalConf`
4. Update `do53.go` to check registered handlers before default handler
5. Update `dzm/cmd/tdns-kdc/main.go` to use registration API instead of channel-based approach
6. Remove `DnsQueryQ` channel-based approach (or keep for backward compatibility)

