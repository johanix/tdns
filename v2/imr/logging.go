/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package imr

import (
	"log"
	"log/slog"
)

// A resolver logs through the loggers it was built with (Options.Logger,
// Options.LookupLogger): the engine through lgImr, the lookups through lgDns,
// and its cache through log.Loggers over Options.Logger's handler: Logger at
// Info, and DebugLogger, for its per-RRset lines and its DNS clients' lines, at
// Debug. The forward upstreams' DNS clients log there too. Without them, and in
// an Imr built by hand, it is slog.Default() at the time of the call.

// lgImr is the logger the engine logs through.
func (imr *Imr) lgImr() *slog.Logger {
	if imr != nil && imr.logger != nil {
		return imr.logger
	}
	return slog.Default()
}

// lgDns is the logger the lookups log through: Options.LookupLogger, or the
// engine's.
func (imr *Imr) lgDns() *slog.Logger {
	if imr != nil && imr.lookupLogger != nil {
		return imr.lookupLogger
	}
	return imr.lgImr()
}

// cacheLogger is the log.Logger the cache and the family tracker log
// through: Options.Logger's handler at level Info, or the log package's.
func cacheLogger(lg *slog.Logger) *log.Logger {
	if lg == nil {
		return log.Default()
	}
	return slog.NewLogLogger(lg.Handler(), slog.LevelInfo)
}
