package transport

import "log/slog"

// Package-level loggers. These call slog.Default() to get the handler set by
// the main process's SetupLogging(). The "subsystem" attribute makes the
// plainHandler produce "[LEVEL/transport]" or "[LEVEL/crypto]" tags.

func lgTransport() *slog.Logger {
	return slog.Default().With("subsystem", "transport")
}

func lgCrypto() *slog.Logger {
	return slog.Default().With("subsystem", "crypto")
}
