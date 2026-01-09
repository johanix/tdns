# Debug Handlers Design

## Requirements

1. **Debug NOTIFY Handler**: Register a handler for all NOTIFYs (qtype=0) that logs and passes through
2. **Debug Query Handler**: Register a handler for all queries (qtype=0) that logs and passes through
3. **Ordering**: Debug handlers should be called first (before other handlers)
4. **Pass-through**: Debug handlers should always return `ErrNotHandled` to pass to next handler

## Design Approach

### Option 1: Registration Order (Simplest)

**Principle**: Handlers are called in registration order. Register debug handlers first.

**Pros:**
- Simple implementation
- No special API needed
- Flexible - can register multiple debug handlers

**Cons:**
- Requires discipline to register debug handlers first
- No enforcement of ordering

**Implementation:**
```go
// Register debug handler first (for all NOTIFYs)
tdns.RegisterNotifyHandler(0, debugNotifyHandler)  // qtype=0 = all NOTIFYs

// Then register specific handlers
tdns.RegisterNotifyHandler(core.TypeJSONMANIFEST, kdcNotifyHandler)
```

### Option 2: Separate Pre-Handlers List

**Principle**: Maintain separate "pre-handlers" list that's always called first.

**Pros:**
- Explicit separation of debug handlers
- Guaranteed to be called first

**Cons:**
- More complex implementation
- Need separate registration function

**Implementation:**
```go
// Separate API for pre-handlers
tdns.RegisterPreNotifyHandler(debugNotifyHandler)
tdns.RegisterPreQueryHandler(debugQueryHandler)
```

### Option 3: Priority System

**Principle**: Add priority parameter to registration.

**Pros:**
- Flexible ordering
- Can have multiple priority levels

**Cons:**
- More complex
- User said ordering is out of scope for now

## Recommendation: Option 1 (Registration Order)

Use **Option 1** because:
- Simplest to implement
- No API changes needed
- User can control ordering by registration sequence
- Document that debug handlers should be registered first

## Implementation

### For NOTIFYs

```go
// Debug NOTIFY handler - logs all NOTIFYs and passes through
func DebugNotifyHandler(ctx context.Context, req *tdns.DnsNotifyRequest) error {
    qtype := uint16(0)
    if len(req.Msg.Question) > 0 {
        qtype = req.Msg.Question[0].Qtype
    }
    
    log.Printf("DEBUG NOTIFY: qname=%s, qtype=%s, from=%s, msgid=%d",
        req.Qname, dns.TypeToString[qtype], req.ResponseWriter.RemoteAddr(), req.Msg.MsgHdr.Id)
    
    // Always pass through to next handler
    return tdns.ErrNotHandled
}

// Register first (before other handlers)
tdns.RegisterNotifyHandler(0, DebugNotifyHandler)  // qtype=0 = all NOTIFYs
```

### For Queries

```go
// Debug query handler - logs all queries and passes through
func DebugQueryHandler(ctx context.Context, req *tdns.DnsQueryRequest) error {
    log.Printf("DEBUG QUERY: qname=%s, qtype=%s, from=%s, msgid=%d, do=%v",
        req.Qname, dns.TypeToString[req.Qtype], req.ResponseWriter.RemoteAddr(),
        req.Msg.MsgHdr.Id, req.Options.DO)
    
    // Always pass through to next handler
    return tdns.ErrNotHandled
}

// Register first (before other handlers)
tdns.RegisterQueryHandler(0, DebugQueryHandler)  // qtype=0 = all queries
```

## Updated Registration API

### Query Handlers

```go
// RegisterQueryHandler registers a handler for a specific query type.
// If qtype is 0, handler is called for ALL query types (use with caution, e.g., for debug handlers).
// Multiple handlers can be registered for the same qtype - they will be called in registration order.
// If a handler returns ErrNotHandled, TDNS will try the next handler or fall back to default.
func RegisterQueryHandler(qtype uint16, handler QueryHandlerFunc) error
```

### NOTIFY Handlers

```go
// RegisterNotifyHandler registers a handler for DNS NOTIFY messages.
// If qtype is 0, handler is called for ALL NOTIFYs (use with caution, e.g., for debug handlers).
// If qtype is non-zero, handler is only called for NOTIFYs with that qtype in the question.
// Multiple handlers can be registered for the same qtype - they will be called in registration order.
// If a handler returns ErrNotHandled, TDNS will try the next handler or fall back to default.
func RegisterNotifyHandler(qtype uint16, handler NotifyHandlerFunc) error
```

## Handler Call Order

When multiple handlers are registered for the same qtype (or qtype=0), they are called in **registration order**:

```
1. Debug handler (qtype=0) - registered first
   ↓ returns ErrNotHandled
2. Specific handler (qtype=TypeJSONMANIFEST) - registered second
   ↓ handles or returns ErrNotHandled
3. Default handler (if all handlers passed)
```

## Example: KDC with Debug Handler

```go
// In dzm/cmd/tdns-kdc/main.go

// 1. Register debug NOTIFY handler first (for all NOTIFYs)
debugNotifyHandler := func(ctx context.Context, dnr *tdns.DnsNotifyRequest) error {
    qtype := uint16(0)
    if len(dnr.Msg.Question) > 0 {
        qtype = dnr.Msg.Question[0].Qtype
    }
    log.Printf("DEBUG NOTIFY: qname=%s, qtype=%s, from=%s",
        dnr.Qname, dns.TypeToString[qtype], dnr.ResponseWriter.RemoteAddr())
    return tdns.ErrNotHandled  // Always pass through
}
tdns.RegisterNotifyHandler(0, debugNotifyHandler)

// 2. Register KDC NOTIFY handler (for JSONMANIFEST NOTIFYs)
kdcNotifyHandler := func(ctx context.Context, dnr *tdns.DnsNotifyRequest) error {
    return kdc.HandleKdcNotify(ctx, dnr.Msg, dnr.Qname, dnr.ResponseWriter, kdcDB, &kdcConf)
}
tdns.RegisterNotifyHandler(core.TypeJSONMANIFEST, kdcNotifyHandler)

// 3. Register debug query handler first (for all queries)
debugQueryHandler := func(ctx context.Context, dqr *tdns.DnsQueryRequest) error {
    log.Printf("DEBUG QUERY: qname=%s, qtype=%s, from=%s",
        dqr.Qname, dns.TypeToString[dqr.Qtype], dqr.ResponseWriter.RemoteAddr())
    return tdns.ErrNotHandled  // Always pass through
}
tdns.RegisterQueryHandler(0, debugQueryHandler)

// 4. Register KDC query handlers (for specific qtypes)
kdcQueryHandler := func(ctx context.Context, dqr *tdns.DnsQueryRequest) error {
    kdcReq := &kdc.KdcQueryRequest{...}
    return kdc.HandleKdcQuery(ctx, kdcReq, kdcDB, &kdcConf)
}
tdns.RegisterQueryHandler(hpke.TypeKMREQ, kdcQueryHandler)
tdns.RegisterQueryHandler(hpke.TypeKMCTRL, kdcQueryHandler)
// ... etc
```

## Implementation Notes

1. **QType 0 Handling**: When qtype=0 is registered, the handler is called for ALL queries/NOTIFYs of that opcode
2. **Ordering**: Handlers are stored in slices, so registration order is preserved
3. **Debug Handler Pattern**: Always return `ErrNotHandled` to ensure pass-through
4. **Multiple Debug Handlers**: Can register multiple debug handlers (e.g., one for logging, one for metrics)

## Benefits

1. **Simple**: No special API needed, just register first
2. **Flexible**: Can have multiple debug handlers
3. **Non-intrusive**: Debug handlers don't interfere with normal operation
4. **Easy to enable/disable**: Just comment out registration
5. **Works for both**: Same pattern for queries and NOTIFYs

