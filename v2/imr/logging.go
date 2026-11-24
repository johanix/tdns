/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package imr

import "log/slog"

// The resolver logs through two loggers: lgImr for the engine and lgDns for
// the lookups. Both are slog.Default() as it is when the package initialises,
// until SetLoggers replaces them. An application that sets its own default
// logger later passes it to SetLoggers too; otherwise the resolver's records
// reach it through the log package's bridge, at the bridge's level.
var (
	lgImr = slog.Default()
	lgDns = slog.Default()
)

// SetLoggers sets the loggers the resolver logs through: engine for the engine,
// dns for the lookups. Call it before the first Imr is built; the loggers are
// read without a lock. tdns passes its "engine" and "dns" subsystem loggers.
func SetLoggers(engine, dns *slog.Logger) {
	lgImr = engine
	lgDns = dns
}
