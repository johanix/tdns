/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"context"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"gopkg.in/natefinch/lumberjack.v2"
)

var (
	defaultLevel    = new(slog.LevelVar) // default: Info
	subsystemLevels = map[string]*slog.LevelVar{}
	subsystemMu     sync.RWMutex
	logWriter       io.Writer // the underlying lumberjack (or stdout) writer
)

// SetupLogging configures the slog-based logging system with lumberjack rotation.
// It also bridges the old log package so that existing log.Printf calls flow
// through slog to the same output.
func SetupLogging(logfile string, logConf LogConf) error {
	if logfile == "" {
		return fmt.Errorf("log file not specified (key log.file)")
	}

	lj := &lumberjack.Logger{
		Filename:   logfile,
		MaxSize:    20,
		MaxBackups: 3,
		MaxAge:     14,
	}
	logWriter = lj

	// Parse default level from config (default: info)
	defaultLevel.Set(ParseLogLevel(logConf.Level))

	// Create the plain-format handler with source info
	handler := newPlainHandler(logWriter, defaultLevel, true)

	// Set as the default slog logger
	slog.SetDefault(slog.New(handler))

	// Bridge old log package through slog so existing log.Printf calls
	// go to the same lumberjack file with the same format.
	// Note: bridged messages appear at INFO level with no subsystem.
	bridgeLogger := slog.NewLogLogger(handler, slog.LevelInfo)
	log.SetOutput(bridgeLogger.Writer())
	log.SetFlags(0) // slog handles formatting; avoid double timestamps

	// Apply per-subsystem levels from config
	for name, levelStr := range logConf.Subsystems {
		SetSubsystemLevel(name, ParseLogLevel(levelStr))
	}

	return nil
}

// SetupCliLogging sets up logging for CLI commands.
// Default: no source info, no timestamps. Verbose/Debug: adds source info.
func SetupCliLogging() {
	logWriter = os.Stderr

	if Globals.Verbose {
		defaultLevel.Set(slog.LevelDebug)
	}
	if Globals.Debug {
		defaultLevel.Set(slog.LevelDebug)
	}

	addSource := Globals.Verbose || Globals.Debug
	handler := newPlainHandler(logWriter, defaultLevel, addSource)
	slog.SetDefault(slog.New(handler))

	// Bridge old log package
	bridgeLogger := slog.NewLogLogger(handler, slog.LevelInfo)
	log.SetOutput(bridgeLogger.Writer())
	log.SetFlags(0)
}

// Logger returns a *slog.Logger for the given subsystem. The subsystem gets
// its own level (defaulting to the global level). Call it freely — if the
// subsystem doesn't exist yet, it's created on first use.
func Logger(subsystem string) *slog.Logger {
	lv := getOrCreateLevel(subsystem)
	h := &subsystemHandler{
		subsystem: subsystem,
		level:     lv,
		inner:     slog.Default().Handler(),
	}
	return slog.New(h).With("subsystem", subsystem)
}

// SetSubsystemLevel sets or updates the log level for a subsystem.
// Goroutine-safe (uses atomic LevelVar).
func SetSubsystemLevel(name string, level slog.Level) {
	lv := getOrCreateLevel(name)
	lv.Set(level)
}

// ParseLogLevel converts a string like "debug", "info", "warn", "error"
// to an slog.Level. Defaults to Info for unrecognized strings.
func ParseLogLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "info", "":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// Fatal logs at Error level and exits. slog has no built-in Fatal.
func Fatal(msg string, args ...any) {
	slog.Error(msg, args...)
	os.Exit(1)
}

// getOrCreateLevel returns the LevelVar for a subsystem, creating it if needed.
func getOrCreateLevel(name string) *slog.LevelVar {
	subsystemMu.RLock()
	lv, ok := subsystemLevels[name]
	subsystemMu.RUnlock()
	if ok {
		return lv
	}

	subsystemMu.Lock()
	defer subsystemMu.Unlock()
	// Double-check after acquiring write lock
	if lv, ok = subsystemLevels[name]; ok {
		return lv
	}
	lv = new(slog.LevelVar)
	lv.Set(defaultLevel.Level()) // inherit current default
	subsystemLevels[name] = lv
	return lv
}

// --- subsystemHandler: filters by per-subsystem level ---

type subsystemHandler struct {
	subsystem string
	level     *slog.LevelVar
	inner     slog.Handler
}

func (h *subsystemHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level.Level()
}

func (h *subsystemHandler) Handle(ctx context.Context, r slog.Record) error {
	return h.inner.Handle(ctx, r)
}

func (h *subsystemHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &subsystemHandler{
		subsystem: h.subsystem,
		level:     h.level,
		inner:     h.inner.WithAttrs(attrs),
	}
}

func (h *subsystemHandler) WithGroup(name string) slog.Handler {
	return &subsystemHandler{
		subsystem: h.subsystem,
		level:     h.level,
		inner:     h.inner.WithGroup(name),
	}
}

// --- plainHandler: custom output format ---
// Produces: 12:34:56 file.go:42 [INFO/subsystem] message key=value

type plainHandler struct {
	writer    io.Writer
	level     *slog.LevelVar
	addSource bool
	mu        sync.Mutex
}

func newPlainHandler(w io.Writer, level *slog.LevelVar, addSource bool) *plainHandler {
	return &plainHandler{
		writer:    w,
		level:     level,
		addSource: addSource,
	}
}

func (h *plainHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level.Level()
}

func (h *plainHandler) Handle(_ context.Context, r slog.Record) error {
	var buf strings.Builder

	// Time
	if !r.Time.IsZero() {
		buf.WriteString(r.Time.Format("15:04:05"))
		buf.WriteByte(' ')
	}

	// Source file:line
	if h.addSource && r.PC != 0 {
		// Use runtime.CallersFrames to get the source
		frames := runtimeFrames(r.PC)
		if frames.File != "" {
			buf.WriteString(filepath.Base(frames.File))
			buf.WriteByte(':')
			fmt.Fprintf(&buf, "%d", frames.Line)
			buf.WriteByte(' ')
		}
	}

	// [LEVEL] or [LEVEL/subsystem]
	buf.WriteByte('[')
	buf.WriteString(r.Level.String())

	// Look for "subsystem" in attributes
	subsystem := ""
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "subsystem" {
			subsystem = a.Value.String()
			return false // stop iteration
		}
		return true
	})
	if subsystem != "" {
		buf.WriteByte('/')
		buf.WriteString(subsystem)
	}
	buf.WriteString("] ")

	// Message
	buf.WriteString(r.Message)

	// Remaining attributes (skip "subsystem" — already shown in bracket)
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "subsystem" {
			return true // skip
		}
		buf.WriteByte(' ')
		buf.WriteString(a.Key)
		buf.WriteByte('=')
		buf.WriteString(a.Value.String())
		return true
	})

	buf.WriteByte('\n')

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.writer, buf.String())
	return err
}

func (h *plainHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &plainHandlerWithAttrs{
		parent: h,
		attrs:  attrs,
	}
}

func (h *plainHandler) WithGroup(name string) slog.Handler {
	// Groups are not used in our logging; pass through
	return h
}

// plainHandlerWithAttrs wraps plainHandler with pre-set attributes.
// This is needed because slog.Logger.With() calls handler.WithAttrs().
type plainHandlerWithAttrs struct {
	parent *plainHandler
	attrs  []slog.Attr
}

func (h *plainHandlerWithAttrs) Enabled(ctx context.Context, level slog.Level) bool {
	return h.parent.Enabled(ctx, level)
}

func (h *plainHandlerWithAttrs) Handle(ctx context.Context, r slog.Record) error {
	// Prepend our pre-set attrs to the record
	r2 := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r2.AddAttrs(h.attrs...)
	r.Attrs(func(a slog.Attr) bool {
		r2.AddAttrs(a)
		return true
	})
	return h.parent.Handle(ctx, r2)
}

func (h *plainHandlerWithAttrs) WithAttrs(attrs []slog.Attr) slog.Handler {
	combined := make([]slog.Attr, len(h.attrs)+len(attrs))
	copy(combined, h.attrs)
	copy(combined[len(h.attrs):], attrs)
	return &plainHandlerWithAttrs{
		parent: h.parent,
		attrs:  combined,
	}
}

func (h *plainHandlerWithAttrs) WithGroup(name string) slog.Handler {
	return h
}

// runtimeFrames extracts source file and line from a program counter.
type sourceInfo struct {
	File string
	Line int
}

func runtimeFrames(pc uintptr) sourceInfo {
	fs := runtime.CallersFrames([]uintptr{pc})
	f, _ := fs.Next()
	return sourceInfo{File: f.File, Line: f.Line}
}
