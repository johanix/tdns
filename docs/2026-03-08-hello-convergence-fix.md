# Fix Slow HELLO Convergence on Simultaneous Agent Restart

**Date**: 2026-03-08
**Status**: Implemented

## Problem

When two agents restart simultaneously, they get stuck in KNOWN state for several minutes before reaching INTRODUCED/OPERATIONAL. Two contributing factors:

1. **Sequential transport timeouts**: `SendHelloWithFallback` tries API then DNS sequentially. Each failed attempt consumes ~5s (TCP dial timeout), so a single `sendHelloToAgent` call takes ~10-15s when both fail.
2. **Missing `isTransportSupported("api")` gate**: `tm.APITransport` is always non-nil (created unconditionally as an HTTP client), so API Hello is always attempted even when the local agent doesn't serve API. The DNS path correctly checks `tm.isTransportSupported("dns")`, but the API path didn't have the equivalent check.

## Transport Usage

- **Discovery queries** (URI, SVCB, JWK, KEY, TLSA): IMR -> `dns.Exchange()` -> **UDP** to stable secondaries. Fast, not the problem.
- **Hello/Beat/Sync messages**: `DNSTransport` with `dns.Client{Timeout: 5s, Net: "tcp"}` -> **TCP NOTIFY(CHUNK)**. Correct for CHUNK messaging. This is where the timeout lives.

Discovery always queries both transports (useful for status/diagnostics). Hello/Beat only use transports the local agent actually supports.

## The Asymmetry Bug

In `hsync_transport.go` `SendHelloWithFallback`:
- **DNS Hello**: `tm.DNSTransport != nil && agent.DnsMethod && tm.isTransportSupported("dns") && ...` -- gates on local support
- **API Hello**: `tm.APITransport != nil && agent.ApiMethod && ...` -- was **missing** `isTransportSupported("api")` check

Same asymmetry existed in `SendBeatWithFallback`.

## Timeout Analysis

### Before

```
SingleHello context: 15s
  API Hello: ~5s timeout (wasted if local doesn't support API)
  DNS Hello: ~5-10s timeout (remaining context budget)
  Total: ~10-15s per sendHelloToAgent

Phase 1 (3 attempts, 5s spacing): ~40-50s total, only 3 actual attempts
Phase 2 (15s ticker): one attempt every ~15-25s
```

### After

```
SingleHello context: 7s
  DNS Hello only: ~5s timeout
  Total: ~5s per sendHelloToAgent

Phase 1 (configurable, default 5 attempts, 3s spacing): ~40s total, 5 actual attempts
Phase 2 (15s ticker): one attempt every ~15-20s
```

## Changes

### 1. Added `isTransportSupported("api")` gate

**File**: `hsync_transport.go`

Added `tm.isTransportSupported("api")` to the API conditions in `SendHelloWithFallback` and `SendBeatWithFallback`. Stops wasting ~5s per attempt on a transport the local agent can't use for bidirectional communication.

### 2. Reduced SingleHello context timeout

**File**: `hsync_hello.go`

Reduced from 15s to 7s. When only one transport is tried, 5s TCP dial + 2s margin is sufficient.

### 3. Configurable Phase 1 fast path

**File**: `hsync_hello.go`

Replaced hardcoded constants with `configureInterval` calls (same pattern used by `helloretry` interval):

- `agent.syncengine.intervals.hello_fast_attempts`: number of fast attempts (min 3, max 20)
- `agent.syncengine.intervals.hello_fast_interval`: seconds between fast attempts (min 1, max 30)

Default values (5 attempts, 3s spacing) are more aggressive than the previous hardcoded values (3 attempts, 5s spacing), giving better coverage of the remote agent startup window.

## Expected Improvement

| Metric | Before | After |
|--------|--------|-------|
| Time per failed attempt | 10-15s (both transports) | ~5s (one transport) |
| Phase 1 attempts | 3 in ~45s | 5 in ~40s |
| Time to first success | 45-90s+ | 10-25s |
