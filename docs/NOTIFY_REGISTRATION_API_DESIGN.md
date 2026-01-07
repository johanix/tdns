# NOTIFY Handler Registration API Design

## Current NOTIFY Flow

### Sequence of Calls

1. **DNS NOTIFY packet arrives**
   - UDP/TCP packet with `OpcodeNotify` arrives at configured address

2. **`tdns.DnsEngine()`** (started in main.go)
   - Creates DNS servers that listen on configured addresses
   - Calls `createAuthDnsHandler(ctx, conf)` to get handler function
   - Registers handler: `dnsMux.HandleFunc(".", authDNSHandler)`
   - Servers route incoming packets to `authDNSHandler`

3. **`createAuthDnsHandler()`** (in `tdns/v0.x/tdns/do53.go:183`)
   - Returns a function that processes DNS messages
   - Checks opcode: if `OpcodeNotify`, checks `conf.Internal.DnsNotifyQ`
   - If `DnsNotifyQ != nil`:
     - Creates `DnsNotifyRequest` struct
     - Sends it to channel: `dnsnotifyq <- DnsNotifyRequest{...}`
     - Returns immediately (async)

4. **`tdns.NotifyHandlerWithCallback()`** (started in `dzm/cmd/tdns-kdc/main.go:157`)
   - Reads from `conf.Internal.DnsNotifyQ` channel
   - For each `DnsNotifyRequest` received:
     - Calls the callback function provided in main.go
     - The callback converts `tdns.DnsNotifyRequest` → KDC types
     - Calls `kdc.HandleKdcNotify(ctx, dnr.Msg, dnr.Qname, dnr.ResponseWriter, kdcDB, &kdcConf)`

5. **`kdc.HandleKdcNotify()`** (in `dzm/v0.x/dzm/kdc/notify_handler.go`)
   - Extracts qtype from NOTIFY question
   - Only handles `TypeJSONMANIFEST` NOTIFYs
   - For other qtypes, sends ACK response and returns
   - Processes confirmation NOTIFY for distribution tracking

### Code Locations

```
DNS NOTIFY Packet Arrives
    ↓
tdns.DnsEngine() [tdns/v0.x/tdns/do53.go:32]
    ↓ creates servers and calls
createAuthDnsHandler() [tdns/v0.x/tdns/do53.go:183]
    ↓ returns handler function
authDNSHandler function [tdns/v0.x/tdns/do53.go:189]
    ↓ checks opcode == OpcodeNotify
    ↓ checks conf.Internal.DnsNotifyQ
    ↓ if non-nil, sends to channel
conf.Internal.DnsNotifyQ channel [created in dzm/cmd/tdns-kdc/main.go:153]
    ↓
tdns.NotifyHandlerWithCallback() [tdns/v0.x/tdns/notifyresponder.go:20]
    ↓ reads from channel, calls callback
Callback function [dzm/cmd/tdns-kdc/main.go:160-165]
    ↓ converts DnsNotifyRequest → KDC types
kdc.HandleKdcNotify() [dzm/v0.x/dzm/kdc/notify_handler.go:20]
    ↓ processes NOTIFY, sends ACK response
Response sent back to client
```

## Proposed Registration API

### Design Considerations

1. **NOTIFY vs Query differences:**
   - NOTIFYs have an opcode (`OpcodeNotify`) but also have a qtype in the question
   - KDC only handles NOTIFYs with `qtype == TypeJSONMANIFEST`
   - Default handler (`NotifyResponder`) handles SOA, CDS, CSYNC, DNSKEY NOTIFYs
   - We need to allow filtering by qtype within the NOTIFY

2. **Chain-of-responsibility:**
   - Handlers should be able to return `ErrNotHandled` to pass to next handler
   - If all handlers pass, use default `NotifyResponder`

3. **Optional qtype filtering:**
   - Allow handlers to register for specific qtypes (e.g., `TypeJSONMANIFEST`)
   - If qtype is 0, handler is called for all NOTIFYs (use with caution)

### Proposed API

#### 1. Error Type (reuse from query handlers)

```go
// ErrNotHandled is already defined in registration.go
// Reuse it for NOTIFY handlers as well
```

#### 2. NOTIFY Handler Function Signature

```go
// NotifyHandlerFunc is the function signature for registered NOTIFY handlers.
// Returns ErrNotHandled if the handler doesn't handle this NOTIFY (allows fallthrough).
// Returns nil if the handler successfully handled the NOTIFY.
// Returns other error if handler attempted to handle but encountered an error.
type NotifyHandlerFunc func(ctx context.Context, req *DnsNotifyRequest) error
```

#### 3. Registration Function

```go
// RegisterNotifyHandler registers a handler for DNS NOTIFY messages.
// If qtype is 0, handler is called for all NOTIFYs (use with caution).
// If qtype is non-zero, handler is only called for NOTIFYs with that qtype in the question.
// Multiple handlers can be registered for the same qtype - they will be called in registration order.
// If a handler returns ErrNotHandled, TDNS will try the next handler or fall back to default.
func RegisterNotifyHandler(qtype uint16, handler NotifyHandlerFunc) error
```

#### 4. Internal Storage

```go
// In config.go InternalConf struct, add:
type InternalConf struct {
    // ... existing fields ...
    
    // NOTIFY handlers registered via RegisterNotifyHandler
    NotifyHandlers   map[uint16][]NotifyHandlerFunc // qtype -> list of handlers (0 = all NOTIFYs)
    NotifyHandlersMutex sync.RWMutex                // protects NotifyHandlers map
}
```

## Flow Diagram

```
DNS NOTIFY Arrives
    ↓
authDNSHandler (do53.go)
    ↓
Check if NotifyHandlers registered
    ↓
If handlers exist:
    Extract qtype from NOTIFY question
    ↓
    Get handlers for this qtype (or qtype=0 for all)
    ↓
    For each handler in order:
        Call handler(req)
        ↓
        If returns ErrNotHandled:
            Try next handler
        ↓
        If returns nil:
            NOTIFY handled, return
        ↓
        If returns other error:
            Log error, try next handler (or fall back)
    ↓
    If all handlers returned ErrNotHandled:
        Fall through to default handler
    ↓
If no handlers registered:
    Use default NotifyResponder
```

## Implementation in do53.go

```go
case dns.OpcodeNotify:
    // Extract qtype from NOTIFY question (if present)
    var qtype uint16
    if len(r.Question) > 0 {
        qtype = r.Question[0].Qtype
    }
    
    // Check for registered NOTIFY handlers
    handlers := getNotifyHandlers(conf, qtype)
    if len(handlers) > 0 {
        // Try registered handlers
        handled := false
        for _, handler := range handlers {
            dnr := DnsNotifyRequest{
                ResponseWriter: w,
                Msg:            r,
                Qname:          qname,
                Options:        msgoptions,
            }
            
            err := handler(ctx, &dnr)
            if err == nil {
                // Handler successfully handled the NOTIFY
                handled = true
                if Globals.Debug {
                    log.Printf("DnsHandler: NOTIFY handled by registered handler (qname=%s, qtype=%s)", qname, dns.TypeToString[qtype])
                }
                return
            } else if err == ErrNotHandled {
                // Handler doesn't handle this NOTIFY, try next handler
                if Globals.Debug {
                    log.Printf("DnsHandler: NOTIFY handler returned ErrNotHandled, trying next handler")
                }
                continue
            } else {
                // Handler attempted to handle but failed
                log.Printf("DnsHandler: NOTIFY handler error: %v", err)
                // Continue to next handler or fall back to default
                continue
            }
        }
        
        if handled {
            return // NOTIFY was handled by a registered handler
        }
        // All handlers returned ErrNotHandled, fall through to default handler
        if Globals.Debug {
            log.Printf("DnsHandler: All registered NOTIFY handlers returned ErrNotHandled, falling back to default handler")
        }
    }
    
    // Backward compatibility: If DnsNotifyQ channel is provided, route NOTIFYs there
    // (This is the old way, kept for backward compatibility)
    if dnsnotifyq != nil {
        // ... existing channel-based code ...
        return
    }
    
    // Fall through to default NotifyResponder (if no channel and no handlers)
    // Note: Default NotifyResponder expects to be called via channel, so this
    // would need to be called directly or we need a different approach
```

## Example Usage (KDC)

```go
// In dzm/cmd/tdns-kdc/main.go

// Register handler for JSONMANIFEST NOTIFYs (confirmation NOTIFYs from KRS)
tdns.RegisterNotifyHandler(core.TypeJSONMANIFEST, func(ctx context.Context, dnr *tdns.DnsNotifyRequest) error {
    // Convert to KDC types
    err := kdc.HandleKdcNotify(ctx, dnr.Msg, dnr.Qname, dnr.ResponseWriter, kdcDB, &kdcConf)
    if err != nil {
        return err // Handler attempted to handle but failed
    }
    return nil // Successfully handled
})
```

## Special Considerations

### Default Handler Integration

The default `NotifyResponder` currently expects to be called via the `DnsNotifyQ` channel. We have two options:

1. **Option A**: Keep channel-based approach for default handler, registration API for custom handlers
   - Registered handlers are called first
   - If all return `ErrNotHandled`, send to `DnsNotifyQ` channel (if non-nil)
   - Default `NotifyHandler()` reads from channel

2. **Option B**: Make default handler callable directly
   - Create a wrapper that can be called directly
   - If no handlers registered and no channel, call default handler directly

**Recommendation**: Option A for backward compatibility. The default handler continues to work via channels, while custom handlers use the registration API.

### QType 0 (All NOTIFYs)

If a handler registers with `qtype = 0`, it will be called for ALL NOTIFYs. This is useful for:
- Logging/monitoring handlers
- Security/validation handlers
- But handlers should still return `ErrNotHandled` for NOTIFYs they don't process

## Migration Path

1. Add `NotifyHandlers` map and mutex to `InternalConf`
2. Add `RegisterNotifyHandler` function to `registration.go`
3. Add `getNotifyHandlers` helper function
4. Update `do53.go` to check registered handlers before channel
5. Update `dzm/cmd/tdns-kdc/main.go` to use registration API
6. Keep channel-based approach for backward compatibility

