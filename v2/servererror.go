/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Server-wide error registry with clear-ownership subtyping
 * (docs/2026-07-21-server-error-registry-design.md). Standalone by design:
 * low-frequency, multi-writer, plain-mutex server state that shares nothing
 * with the zone snapshot model. Errors are keyed by (Category, Subtype);
 * every mutation goes through a named owned helper so each set/clear point is
 * greppable and located with the code that owns the condition. The generic
 * set/clear are unexported.
 */
package tdns

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type ErrorCategory uint8

const (
	ErrCatTransport ErrorCategory = iota + 1 // a listener/transport is not serving
	ErrCatConfig                             // a configured input is missing/invalid
	ErrCatOther                              // catch-all until a category is defined
)

var errCategoryName = map[ErrorCategory]string{
	ErrCatTransport: "Transport",
	ErrCatConfig:    "Config",
	ErrCatOther:     "Other",
}

func (c ErrorCategory) String() string {
	if s, ok := errCategoryName[c]; ok {
		return s
	}
	return fmt.Sprintf("Category(%d)", c)
}

type ErrorSubtype uint8

const (
	ErrSubCert        ErrorSubtype = iota + 1 // Transport: cert/key could not be loaded
	ErrSubPort                                // Transport: a listener socket failed to bind
	ErrSubCertMissing                         // Config: a configured cert/key file is absent
)

var errSubtypeName = map[ErrorSubtype]string{
	ErrSubCert:        "Cert",
	ErrSubPort:        "Port",
	ErrSubCertMissing: "CertMissing",
}

func (s ErrorSubtype) String() string {
	if n, ok := errSubtypeName[s]; ok {
		return n
	}
	return fmt.Sprintf("Subtype(%d)", s)
}

// ServerError is one active server-wide error condition, identified by its
// (Category, Subtype). Serialized in the config-status API response.
type ServerError struct {
	Category  ErrorCategory `json:"category"`
	Subtype   ErrorSubtype  `json:"subtype"`
	Message   string        `json:"message"`
	FirstSeen time.Time     `json:"first_seen"`
	LastSeen  time.Time     `json:"last_seen"`
}

func (e ServerError) String() string {
	return fmt.Sprintf("[%s/%s] %s", e.Category, e.Subtype, e.Message)
}

type errKey struct {
	cat ErrorCategory
	sub ErrorSubtype
}

// ServerErrorRegistry holds the daemon-wide set of active error conditions,
// one live entry per (Category, Subtype).
type ServerErrorRegistry struct {
	mu   sync.Mutex
	errs map[errKey]ServerError
}

func NewServerErrorRegistry() *ServerErrorRegistry {
	return &ServerErrorRegistry{errs: map[errKey]ServerError{}}
}

func (r *ServerErrorRegistry) set(cat ErrorCategory, sub ErrorSubtype, msg string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	k := errKey{cat, sub}
	now := time.Now()
	e, ok := r.errs[k]
	if !ok {
		e = ServerError{Category: cat, Subtype: sub, FirstSeen: now}
	}
	e.Message = msg
	e.LastSeen = now
	r.errs[k] = e
}

func (r *ServerErrorRegistry) clear(cat ErrorCategory, sub ErrorSubtype) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.errs, errKey{cat, sub})
}

// List returns the active errors, sorted by (category, subtype) for stable
// output. Safe on a nil registry.
func (r *ServerErrorRegistry) List() []ServerError {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]ServerError, 0, len(r.errs))
	for _, e := range r.errs {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].Subtype < out[j].Subtype
	})
	return out
}

// HasAny reports whether any error is active. Safe on a nil registry.
func (r *ServerErrorRegistry) HasAny() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.errs) > 0
}

// --- named owned helpers: the ONLY blessed mutators ------------------------

// Owned by DnsEngine (v2/do53.go). Set when the DoT/DoH/DoQ cert+key could
// not be loaded so the encrypted listeners were skipped. Boot-scoped: the
// registry starts empty each boot, so a clean start needs no explicit clear.
func (r *ServerErrorRegistry) SetTransportCertError(msg string) {
	r.set(ErrCatTransport, ErrSubCert, msg)
}
func (r *ServerErrorRegistry) ClearTransportCertError() {
	r.clear(ErrCatTransport, ErrSubCert)
}

// Owned by DnsEngine (the transport engines). Set when a listener's socket
// failed to bind (privileged port, address-in-use). Multiple failing
// listeners aggregate into the single Port entry.
func (r *ServerErrorRegistry) SetTransportPortError(hostport string, cause error) {
	if r == nil {
		return
	}
	entry := fmt.Sprintf("%s: %v", hostport, cause)
	r.mu.Lock()
	defer r.mu.Unlock()
	k := errKey{ErrCatTransport, ErrSubPort}
	now := time.Now()
	e, ok := r.errs[k]
	if !ok {
		e = ServerError{Category: ErrCatTransport, Subtype: ErrSubPort, FirstSeen: now, Message: entry}
	} else if !strings.Contains(e.Message, hostport) {
		e.Message += "; " + entry
	}
	e.LastSeen = now
	r.errs[k] = e
}

// Owned by parseconfig. Set when a configured dnsengine cert/key file is
// absent/unreadable at (re)load; cleared by the same revalidation when the
// files are present (clear-then-reassert).
func (r *ServerErrorRegistry) SetConfigCertMissing(msg string) {
	r.set(ErrCatConfig, ErrSubCertMissing, msg)
}
func (r *ServerErrorRegistry) ClearConfigCertMissing() {
	r.clear(ErrCatConfig, ErrSubCertMissing)
}

// --- config-time cert validation (parseconfig, Config/CertMissing owner) ---

// anyEncryptedTransport reports whether dot, doh or doq appears in the list.
func anyEncryptedTransport(transports []string) bool {
	return CaseFoldContains(transports, "dot") ||
		CaseFoldContains(transports, "doh") ||
		CaseFoldContains(transports, "doq")
}

// validateDnsEngineCerts is parseconfig's owned check for Config/CertMissing:
// if any encrypted transport is configured, certfile and keyfile must exist
// and be readable. Clear-then-reassert, so it self-corrects on every reload.
func (conf *Config) validateDnsEngineCerts() {
	reg := conf.Internal.ServerErrors
	reg.ClearConfigCertMissing()
	de := conf.DnsEngine
	if !anyEncryptedTransport(de.Transports) {
		return
	}
	var problems []string
	if de.CertFile == "" {
		problems = append(problems, "certfile is unset")
	} else if _, err := os.Stat(de.CertFile); err != nil {
		problems = append(problems, fmt.Sprintf("certfile %s: %v", de.CertFile, err))
	}
	if de.KeyFile == "" {
		problems = append(problems, "keyfile is unset")
	} else if _, err := os.Stat(de.KeyFile); err != nil {
		problems = append(problems, fmt.Sprintf("keyfile %s: %v", de.KeyFile, err))
	}
	if len(problems) > 0 {
		reg.SetConfigCertMissing(fmt.Sprintf("encrypted transports %v configured but %s",
			de.Transports, strings.Join(problems, "; ")))
	}
}
