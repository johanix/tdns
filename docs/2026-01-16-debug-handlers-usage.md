# Debug Handlers Usage Guide

## Overview

Both query and NOTIFY handlers support registering debug handlers that log all requests before passing them to specific handlers. This is useful for debugging, monitoring, and auditing.

## Key Concept: qtype=0 Means "All"

- **For queries**: `RegisterQueryHandler(0, handler)` registers a handler for ALL query types
- **For NOTIFYs**: `RegisterNotifyHandler(0, handler)` registers a handler for ALL NOTIFYs (regardless of qtype in question)

## Handler Call Order

Handlers are called in this order:
1. **qtype=0 handlers** (debug handlers) - called first for all queries/NOTIFYs
2. **Specific qtype handlers** - called only for matching qtypes
3. **Default handler** - called if all handlers return `ErrNotHandled`

## Debug Query Handler Example

```go
// Debug query handler - logs all queries and passes through
debugQueryHandler := func(ctx context.Context, dqr *tdns.DnsQueryRequest) error {
    log.Printf("DEBUG QUERY: qname=%s, qtype=%s, from=%s, msgid=%d, do=%v",
        dqr.Qname, 
        dns.TypeToString[dqr.Qtype], 
        dqr.ResponseWriter.RemoteAddr(),
        dqr.Msg.MsgHdr.Id,
        dqr.Options.DO)
    
    // Always pass through to next handler
    return tdns.ErrNotHandled
}

// Register first (before other handlers) - qtype=0 means "all queries"
tdns.RegisterQueryHandler(0, debugQueryHandler)
```

## Debug NOTIFY Handler Example

```go
// Debug NOTIFY handler - logs all NOTIFYs and passes through
debugNotifyHandler := func(ctx context.Context, dnr *tdns.DnsNotifyRequest) error {
    qtype := uint16(0)
    if len(dnr.Msg.Question) > 0 {
        qtype = dnr.Msg.Question[0].Qtype
    }
    
    log.Printf("DEBUG NOTIFY: qname=%s, qtype=%s, from=%s, msgid=%d",
        dnr.Qname,
        dns.TypeToString[qtype],
        dnr.ResponseWriter.RemoteAddr(),
        dnr.Msg.MsgHdr.Id)
    
    // Always pass through to next handler
    return tdns.ErrNotHandled
}

// Register first (before other handlers) - qtype=0 means "all NOTIFYs"
tdns.RegisterNotifyHandler(0, debugNotifyHandler)
```

## Complete Example: KDC with Debug Handlers

```go
// In dzm/cmd/tdns-kdc/main.go

// 1. Register debug query handler FIRST (for all queries)
debugQueryHandler := func(ctx context.Context, dqr *tdns.DnsQueryRequest) error {
    log.Printf("DEBUG QUERY: qname=%s, qtype=%s, from=%s",
        dqr.Qname, dns.TypeToString[dqr.Qtype], dqr.ResponseWriter.RemoteAddr())
    return tdns.ErrNotHandled  // Always pass through
}
tdns.RegisterQueryHandler(0, debugQueryHandler)

// 2. Register KDC query handlers (for specific qtypes)
kdcQueryHandler := func(ctx context.Context, dqr *tdns.DnsQueryRequest) error {
    kdcReq := &kdc.KdcQueryRequest{
        ResponseWriter: dqr.ResponseWriter,
        Msg:            dqr.Msg,
        Qname:          dqr.Qname,
        Qtype:          dqr.Qtype,
        Options:        dqr.Options,
    }
    return kdc.HandleKdcQuery(ctx, kdcReq, kdcDB, &kdcConf)
}
tdns.RegisterQueryHandler(hpke.TypeKMREQ, kdcQueryHandler)
tdns.RegisterQueryHandler(hpke.TypeKMCTRL, kdcQueryHandler)
tdns.RegisterQueryHandler(core.TypeJSONMANIFEST, kdcQueryHandler)
tdns.RegisterQueryHandler(core.TypeJSONCHUNK, kdcQueryHandler)

// 3. Register debug NOTIFY handler FIRST (for all NOTIFYs)
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

// 4. Register KDC NOTIFY handler (for JSONMANIFEST NOTIFYs)
kdcNotifyHandler := func(ctx context.Context, dnr *tdns.DnsNotifyRequest) error {
    return kdc.HandleKdcNotify(ctx, dnr.Msg, dnr.Qname, dnr.ResponseWriter, kdcDB, &kdcConf)
}
tdns.RegisterNotifyHandler(core.TypeJSONMANIFEST, kdcNotifyHandler)
```

## Call Flow with Debug Handlers

### Query Flow
```
Query arrives (qtype=KMREQ)
    ↓
getQueryHandlers(qtype=KMREQ) returns:
    1. debugQueryHandler (qtype=0) - logs, returns ErrNotHandled
    2. kdcQueryHandler (qtype=KMREQ) - handles query
    ↓
Call debugQueryHandler → logs → returns ErrNotHandled
    ↓
Call kdcQueryHandler → handles → returns nil
    ↓
Done
```

### NOTIFY Flow
```
NOTIFY arrives (qtype=JSONMANIFEST in question)
    ↓
getNotifyHandlers(qtype=JSONMANIFEST) returns:
    1. debugNotifyHandler (qtype=0) - logs, returns ErrNotHandled
    2. kdcNotifyHandler (qtype=JSONMANIFEST) - handles NOTIFY
    ↓
Call debugNotifyHandler → logs → returns ErrNotHandled
    ↓
Call kdcNotifyHandler → handles → returns nil
    ↓
Done
```

## Benefits

1. **Non-intrusive**: Debug handlers don't interfere with normal operation
2. **Easy to enable/disable**: Just comment out registration
3. **Comprehensive logging**: See all queries/NOTIFYs before they're processed
4. **Multiple debug handlers**: Can register multiple (e.g., one for logging, one for metrics)
5. **Works for both**: Same pattern for queries and NOTIFYs

## Advanced: Conditional Debug Handler

You can make debug handlers conditional:

```go
debugQueryHandler := func(ctx context.Context, dqr *tdns.DnsQueryRequest) error {
    // Only log queries for specific zones
    if strings.HasSuffix(dqr.Qname, ".example.com.") {
        log.Printf("DEBUG QUERY: qname=%s, qtype=%s", dqr.Qname, dns.TypeToString[dqr.Qtype])
    }
    return tdns.ErrNotHandled
}
```

## Implementation Details

- **qtype=0 handlers are always called first** - before specific qtype handlers
- **Handlers are called in registration order** - register debug handlers first
- **ErrNotHandled always passes through** - debug handlers should always return this
- **No performance impact when disabled** - just comment out registration

