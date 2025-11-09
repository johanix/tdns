# Project Operational Context (Ctx-based shutdown and API stop)

This document captures runtime and shutdown conventions we use across projects to keep behavior consistent and robust.

## Root Context and Signals
- Root context is derived in `main`:
```go
ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
defer stop()
```
- A separate lightweight goroutine listens for `SIGHUP` to trigger reload (e.g., config/zones); this must NOT cancel the app context.
- All long-running components accept `ctx context.Context` as the first parameter.

## Minimal MainLoop
MainLoop should only orchestrate shutdown, not re-handle signals:
```go
func MainLoop(ctx context.Context, cancel context.CancelFunc, conf *Config) {
	for {
		select {
		case <-ctx.Done():
			log.Println("mainloop: context cancelled. Cleaning up.")
			return
		case <-conf.Internal.APIStopCh:
			log.Println("mainloop: Stop command received. Cleaning up.")
			cancel()
			return
		}
	}
}
```

## API Stop Semantics
- Use a single broadcast channel `APIStopCh chan struct{}`.
- Only close it (never send values), guarded by `sync.Once`:
```go
conf.Internal.StopOnce.Do(func() {
	// Optional small delay to allow HTTP response write
	time.Sleep(200 * time.Millisecond)
	close(conf.Internal.APIStopCh)
})
```
- Producers: API “stop” handler and `Shutdowner`.
- Consumers: `MainLoop` (primary), ancillary components may optionally observe it but should primarily rely on `ctx.Done()`.

## Loop Patterns (Goroutine hygiene)
Every receiver loop should select on `ctx.Done()` and handle closed-channel reads:
```go
for {
	select {
	case <-ctx.Done():
		return
	case item, ok := <-in:
		if !ok { return }
		// process
	}
}
```
When sending during shutdown, either use non-blocking sends, or implement a short drain strategy that responds to `ctx.Done()`.

## Servers: Bounded Shutdown
- HTTP: use `Shutdown(ctxWithTimeout)` (~5s).
```go
shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
_ = httpServer.Shutdown(shutdownCtx)
```
- DNS (miekg/dns): wrap `Shutdown()` with a watchdog goroutine; continue past slow servers after timeout.
- QUIC (quic-go): accept with `Accept(ctx)`; on `ctx.Done()` call `listener.Close()`; treat streams as pointers (`*quic.Stream`); only return from accept loop when `ctx.Err() != nil`.

## Notifier and Refresh Engines (ctx-first)
- Engines that previously used a `stopch` now accept `ctx context.Context` and exit on `ctx.Done()`.
- Avoid owning or closing channels created and owned by other components.

## Channel Ownership and Safety
- Only the producer closes a channel.
- Readers always handle `ok := <-ch`.
- For request/response flows, provide typed response channels and guard sends with select (and timeouts if needed).

## Testing Shutdown
- Simulate shutdown with `stop()` (root cancel) and assert:
  - Engines exit in bounded time.
  - No deadlocks on channel reads/writes.
  - HTTP and other servers stop within their configured timeouts.

## Summary of Do/Don’t
- Do:
  - Pass `ctx` as the first param everywhere.
  - Use `signal.NotifyContext` only in `main`.
  - Close `APIStopCh` exactly once (broadcast) for stop.
  - Select on `ctx.Done()` in all loops; handle channel closure.
  - Bound server shutdown with timeouts.
- Don’t:
  - Send into `APIStopCh`.
  - Close channels you don’t own.
  - Put `signal.Notify` deep in library code.
  - Block indefinitely on shutdown.

This operational pattern keeps shutdown behavior consistent across binaries and projects, minimizes deadlocks, and ensures bounded termination. 


